"""Framework-owned live canary, promotion, monitoring, and rollback runner.

RLM and GEPA remain proposal engines. This compatibility runner consumes only
their persisted, digest-verified guidance artifacts. Every live transition is
bound to the exact v3 policy, calibration, canary plan, and monitor plan that
authorized it; model output never owns a mutable pointer.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import time
from typing import Any, Callable, Mapping

from . import paths, state
from .guidance import GuidanceArtifact, validate_guidance_artifact
from .v3.operator_repository import SafeStoreOperatorReader
from .v3.repository import IntegrityFailure, V3Transaction
from .v3.schemas import TypedRecord
from .v3.schemas import canonical_json
from .v3.store_selection import open_runtime_reader, open_runtime_repository


SELECTION_LOOP_KEY = "dspy_rlm_autopilot_transition"
ARTIFACT_LOOP_KEY = "dspy_rlm_autopilot_transition_artifact"
FRAMEWORK_OUTCOME_KEY = "dspy_rlm_framework_outcome"
FRAMEWORK_HARD_FAILURE_KEY = "dspy_rlm_framework_hard_failure"
TERMINAL_OUTCOME_KEY = "dspy_rlm_terminal_outcome_observed"
RUNNER_ID = "autopilot-transition-runner.v1"


@dataclass(frozen=True, slots=True)
class TransitionSelection:
    candidate_id: str
    context_ref: str
    objective_bucket: str
    guidance_version: str
    state: str
    arm: str
    exposure_ref: str


@dataclass(frozen=True, slots=True)
class _AuthorityBinding:
    policy: TypedRecord
    calibration: TypedRecord
    canary_plan: TypedRecord
    monitor_plan: TypedRecord

    def identities(self) -> tuple[str, ...]:
        return (
            self.policy.record_id,
            self.policy.content_digest,
            self.calibration.record_id,
            self.calibration.content_digest,
            self.canary_plan.record_id,
            self.canary_plan.content_digest,
            self.monitor_plan.record_id,
            self.monitor_plan.content_digest,
        )


def _legacy_digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _authority_binding(
    context_ref: str, config: Mapping[str, Any]
) -> _AuthorityBinding | None:
    automation = config.get("automation")
    from .v3.autopilot_control_plane import AUTOPILOT_AUTHORITY_CONSENT_REVISION

    if (
        config.get("enabled") is not True
        or not isinstance(automation, Mapping)
        or automation.get("mode") != "autopilot"
        or automation.get("authority_consent_revision")
        != AUTOPILOT_AUTHORITY_CONSENT_REVISION
    ):
        return None
    try:
        with open_runtime_reader(
            pre_cutover_path=paths.SAFE_STORE_FILE,
            manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
        ) as reader:
            facts = SafeStoreOperatorReader(reader)
            from .v3.autopilot_control_plane import expected_autopilot_policy_id

            authority_facts = facts.list_records_by_kinds(
                context_ref,
                (
                    "activation_policy",
                    "policy_calibration",
                    "policy_calibration_mutation_receipt",
                ),
            )
            policies = tuple(
                item.record
                for item in authority_facts
                if item.record.record_kind == "activation_policy"
                and type(item.record.payload.get("policy_revision")) is int
            )
            if not policies:
                return None
            latest_revision = max(
                int(policy.payload["policy_revision"]) for policy in policies
            )
            latest = tuple(
                policy
                for policy in policies
                if policy.payload["policy_revision"] == latest_revision
            )
            if len(latest) != 1:
                return None
            policy = latest[0]
            expected_policy = expected_autopilot_policy_id(context_ref, config)
            policy_revision = policy.payload.get("policy_revision")
            if (
                policy.context_ref != context_ref
                or policy.payload.get("activation_mode") != "auto_after_canary"
                or type(policy_revision) is not int
                or policy.record_id not in {
                    expected_policy,
                    f"{expected_policy}:{policy_revision}",
                }
            ):
                return None
            calibrations = [
                item.record
                for item in authority_facts
                if item.record.record_kind == "policy_calibration"
                and item.record.payload.get("status") == "approved"
                and item.record.payload.get("policy_id") == policy.record_id
                and item.record.payload.get("policy_digest") == policy.content_digest
                and item.record.payload.get("policy_revision")
                == policy.payload.get("policy_revision")
            ]
            if len(calibrations) != 1:
                return None
            calibration = calibrations[0]
            cp = calibration.payload
            calibration_identity = {
                "record_id": calibration.record_id,
                "digest": calibration.content_digest,
            }
            if (
                cp.get("status") != "approved"
                or "automatic" not in cp.get("activation_authorities", ())
                or cp.get("soft_rollback_authorized") is not True
                or any(
                    item.record.record_kind
                    == "policy_calibration_mutation_receipt"
                    and item.record.payload.get("operation") == "withdraw"
                    and item.record.payload.get("calibration")
                    == calibration_identity
                    for item in authority_facts
                )
            ):
                return None
            canary_plan = facts.get_record(cp["canary_plan_id"])
            monitor_plan = facts.get_record(cp["monitor_plan_id"])
            if (
                canary_plan is None
                or monitor_plan is None
                or canary_plan.record_kind != "canary_plan"
                or monitor_plan.record_kind != "monitor_plan"
                or canary_plan.context_ref != context_ref
                or monitor_plan.context_ref != context_ref
                or canary_plan.content_digest != cp["canary_plan_digest"]
                or monitor_plan.content_digest != cp["monitor_plan_digest"]
            ):
                return None
            return _AuthorityBinding(policy, calibration, canary_plan, monitor_plan)
    except Exception:
        return None


def _row_identities(item: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(item.get(name) or "")
        for name in (
            "policy_id",
            "policy_digest",
            "calibration_id",
            "calibration_digest",
            "canary_plan_id",
            "canary_plan_digest",
            "monitor_plan_id",
            "monitor_plan_digest",
        )
    )


def _transition_binding_matches(
    item: Mapping[str, Any], binding: _AuthorityBinding,
) -> bool:
    """Revalidate both standing authority and the candidate's V3 scope bind."""

    source_digest = item.get("source_candidate_digest")
    return bool(
        _row_identities(item) == binding.identities()
        and type(source_digest) is str
        and len(source_digest) == 64
        and _published_candidate_matches(
            context_ref=str(item.get("context_id") or ""),
            objective_bucket=str(item.get("objective_bucket") or ""),
            source_digest=source_digest,
        )
        is True
    )


def _fraction(value: Mapping[str, Any]) -> float:
    numerator = int(value["numerator"])
    denominator = int(value["denominator"])
    if denominator <= 0:
        raise IntegrityFailure("calibrated rational denominator is invalid")
    return numerator / denominator


def _canary_settings(
    binding: _AuthorityBinding, objective_bucket: str
) -> tuple[int, int, int, float, int]:
    plan = binding.canary_plan.payload
    bucket = next(
        (item for item in plan["buckets"] if item["bucket_ref"] == objective_bucket),
        None,
    )
    if bucket is None:
        raise IntegrityFailure("objective bucket is absent from the calibrated plan")
    allocation = plan["candidate_allocation"]
    numerator = int(allocation["numerator"])
    denominator = int(allocation["denominator"])
    scaled, remainder = divmod(numerator * 100, denominator)
    percentage = scaled
    if remainder or not 1 <= percentage <= 99:
        raise IntegrityFailure("calibrated allocation cannot be represented")
    return (
        int(bucket["minimum_comparable"]),
        int(plan["horizon_exposures"]),
        percentage,
        _fraction(bucket["noninferiority_margin"]),
        int(plan["hard_veto_failure_limit"]),
    )


def _monitor_settings(binding: _AuthorityBinding) -> tuple[int, int, float, int]:
    plan = binding.monitor_plan.payload
    return (
        int(plan["look_interval_exposures"]),
        int(plan["horizon_exposures"]),
        abs(_fraction(plan["ordinary_regression_boundary"])),
        int(plan["hard_veto_failure_limit"]),
    )


def _automatic_grant(
    *, context_ref: str, action: str, target_ref: str, target_revision: int
):
    from .v3.authority import AuthorityClass, AuthorityPurpose, VerifiedGrant
    from .v3.autopilot_control_plane import issue_automatic_transition_grant

    grant = issue_automatic_transition_grant(
        authority_root=paths.AUTHORITY_DIR / "autopilot-transition",
        context_ref=context_ref,
        action=action,
        target_ref=target_ref,
        target_revision=target_revision,
    )
    if (
        type(grant) is not VerifiedGrant
        or grant.authority_class != AuthorityClass.AUTOMATIC_TRANSITION_GRANT.value
        or grant.purpose != AuthorityPurpose.AUTOMATIC_PROMOTION.value
        or grant.context_ref != context_ref
        or grant.action != action
        or grant.target_ref != target_ref
        or grant.target_revision != target_revision
        or grant.expires_at <= datetime.now(timezone.utc)
    ):
        raise PermissionError("automatic transition grant is invalid")
    return grant


def _require_current_binding(
    transaction: V3Transaction, *, context_ref: str, binding: _AuthorityBinding,
    transition: Mapping[str, Any],
) -> None:
    records = (
        (binding.policy, "activation_policy"),
        (binding.calibration, "policy_calibration"),
        (binding.canary_plan, "canary_plan"),
        (binding.monitor_plan, "monitor_plan"),
    )
    for expected, kind in records:
        current = transaction.get_record(expected.record_id)
        if (
            current is None
            or current.record_kind != kind
            or current.context_ref != context_ref
            or current.content_digest != expected.content_digest
        ):
            raise PermissionError("automatic transition authority changed")
    record_ids = tuple(
        str(row["record_id"])
        for row in transaction._connection.execute(
            """SELECT record_id FROM typed_records
                 WHERE context_ref=? AND record_kind IN (
                       'activation_policy', 'policy_calibration',
                       'policy_calibration_mutation_receipt')
                 ORDER BY record_id""",
            (context_ref,),
        ).fetchall()
    )
    observed = tuple(
        record
        for record_id in record_ids
        if (record := transaction.get_record(record_id)) is not None
    )
    revisions = [
        int(record.payload["policy_revision"])
        for record in observed
        if record.record_kind == "activation_policy"
    ]
    if not revisions or binding.policy.payload["policy_revision"] != max(revisions):
        raise PermissionError("automatic transition policy is no longer current")
    latest_policies = [
        record
        for record in observed
        if record.record_kind == "activation_policy"
        and record.payload["policy_revision"] == max(revisions)
    ]
    if len(latest_policies) != 1 or latest_policies[0] != binding.policy:
        raise PermissionError("automatic transition policy authority is ambiguous")
    calibration_identity = {
        "record_id": binding.calibration.record_id,
        "digest": binding.calibration.content_digest,
    }
    if any(
        record.record_kind == "policy_calibration_mutation_receipt"
        and record.payload.get("operation") == "withdraw"
        and record.payload.get("calibration") == calibration_identity
        for record in observed
    ):
        raise PermissionError("automatic transition calibration was withdrawn")
    matching_calibrations = [
        record
        for record in observed
        if record.record_kind == "policy_calibration"
        and record.payload.get("policy_id") == binding.policy.record_id
        and record.payload.get("policy_digest") == binding.policy.content_digest
        and record.payload.get("policy_revision")
        == binding.policy.payload["policy_revision"]
    ]
    if matching_calibrations != [binding.calibration]:
        raise PermissionError("automatic transition calibration authority is ambiguous")
    cp = binding.calibration.payload
    if (
        cp["status"] != "approved"
        or cp["policy_id"] != binding.policy.record_id
        or cp["policy_digest"] != binding.policy.content_digest
        or cp["canary_plan_id"] != binding.canary_plan.record_id
        or cp["canary_plan_digest"] != binding.canary_plan.content_digest
        or cp["monitor_plan_id"] != binding.monitor_plan.record_id
        or cp["monitor_plan_digest"] != binding.monitor_plan.content_digest
        or "automatic" not in cp["activation_authorities"]
        or cp["soft_rollback_authorized"] is not True
    ):
        raise PermissionError("automatic transition calibration is invalid")
    from .v3.autopilot_publication import AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID

    source_digest = transition.get("source_candidate_digest")
    if type(source_digest) is not str or len(source_digest) != 64:
        raise PermissionError("automatic transition publication binding is invalid")
    scope = transaction.get_activation_scope(context_ref)
    record_id = "autopilot_candidate_" + sha256(
        canonical_json([context_ref, source_digest])
    ).hexdigest()
    publication = transaction.get_record(record_id)
    if (
        scope is None
        or publication is None
        or publication.schema_id != AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID
        or publication.context_ref != context_ref
        or publication.payload.get("source_candidate_digest") != source_digest
        or publication.payload.get("objective_bucket")
        != transition.get("objective_bucket")
        or publication.payload.get("review_disposition") != "review_only"
        or publication.payload.get("observed_scope_revision")
        != scope.scope_revision
        or publication.payload.get("incumbent_profile_id")
        != scope.current_profile_id
        or publication.payload.get("incumbent_profile_digest")
        != scope.current_profile_digest
    ):
        raise PermissionError("automatic transition publication authority changed")


def _authorized_pointer_mutation(
    *, binding: _AuthorityBinding, context_ref: str, action: str,
    target_ref: str, target_revision: int,
    transition: Mapping[str, Any],
    mutate: Callable[[], tuple[bool, int]],
) -> tuple[bool, int]:
    """Fence authority writers while the exact legacy pointer CAS executes."""

    grant = _automatic_grant(
        context_ref=context_ref,
        action=action,
        target_ref=target_ref,
        target_revision=target_revision,
    )
    with open_runtime_repository(
        pre_cutover_path=paths.SAFE_STORE_FILE,
        manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
    ) as repository:
        with repository.transaction() as transaction:
            _require_current_binding(
                transaction,
                context_ref=context_ref,
                binding=binding,
                transition=transition,
            )
            if grant.expires_at <= datetime.now(timezone.utc):
                raise PermissionError("automatic transition grant expired")
            return mutate()


def _verified_candidate(
    *, context_ref: str, candidate_id: str, objective_bucket: str,
    guidance_version: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any], str] | None:
    store = state._store_for_root().store
    envelope = store.get_candidate(candidate_id, context_id=context_ref)
    if (
        not isinstance(envelope, Mapping)
        or envelope.get("objective_bucket") != objective_bucket
        or envelope.get("guidance_version") != guidance_version
    ):
        return None
    candidate = envelope.get("candidate")
    if (
        not isinstance(candidate, Mapping)
        or _legacy_digest(candidate) != envelope.get("candidate_digest")
        or candidate.get("candidate_id") != candidate_id
        or candidate.get("guidance_version") != guidance_version
    ):
        return None
    audit_id = candidate.get("replay_audit_id")
    if type(audit_id) is not str or not audit_id:
        return None
    with store._connect() as connection:
        audit_row = connection.execute(
            "SELECT candidate_id,audit_json,audit_digest FROM replay_audits WHERE audit_id=?",
            (audit_id,),
        ).fetchone()
    if audit_row is None or audit_row["candidate_id"] != candidate_id:
        return None
    try:
        replay = json.loads(audit_row["audit_json"])
    except (TypeError, ValueError):
        return None
    if not isinstance(replay, Mapping) or _legacy_digest(replay) != audit_row["audit_digest"]:
        return None
    return candidate, replay, str(envelope["candidate_digest"])


def _published_candidate_matches(
    *, context_ref: str, objective_bucket: str, source_digest: str
) -> bool | None:
    """Require the framework's immutable v3 publication checkpoint."""

    from .v3.autopilot_publication import AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID

    try:
        with open_runtime_reader(
            pre_cutover_path=paths.SAFE_STORE_FILE,
            manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
        ) as reader:
            facts = SafeStoreOperatorReader(reader)
            scope = facts.get_activation_scope(context_ref)
            if scope is None:
                return False
            record_id = "autopilot_candidate_" + sha256(
                canonical_json([context_ref, source_digest])
            ).hexdigest()
            record = facts.get_record(record_id)
            return bool(
                record is not None
                and record.schema_id == AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID
                and record.context_ref == context_ref
                and record.payload.get("source_candidate_digest") == source_digest
                and record.payload.get("objective_bucket") == objective_bucket
                and record.payload.get("review_disposition") == "review_only"
                and record.payload.get("observed_scope_revision") == scope.scope_revision
                and record.payload.get("incumbent_profile_id") == scope.current_profile_id
                and record.payload.get("incumbent_profile_digest")
                == scope.current_profile_digest
            )
    except Exception:
        return None


def _coordinator_candidate_approved(
    *, candidate_id: str, candidate_digest: str, config_digest: str
) -> bool:
    """Require fenced queue completion before a worker proposal is admissible."""

    store = state._store_for_root().store
    with store._connect() as connection:
        rows = connection.execute(
            """SELECT candidate_id
                 FROM autopilot_candidate_approvals
                WHERE candidate_id=? AND candidate_digest=? AND config_digest=?""",
            (candidate_id, candidate_digest, config_digest),
        ).fetchall()
    return len(rows) == 1


def _candidate_evidence_matches(
    *, context_ref: str, objective_bucket: str, guidance_version: str,
    candidate_id: str, active: Mapping[str, Any] | None,
) -> bool:
    from .promotion import PromotionCoordinator

    evidence, _reason = PromotionCoordinator(
        state_store=state._store_for_root(), coordinator_id=RUNNER_ID
    ).verified_evidence_chain(
        context_ref, objective_bucket, guidance_version, active,
        allow_missing_baseline=True,
        expected_candidate_id=candidate_id,
    )
    return evidence is not None


def consider_candidate(
    *, context_ref: str, candidate_id: str, objective_bucket: str,
    guidance_version: str, config: Mapping[str, Any],
) -> str:
    """Admit one exact, digest-verified optimizer result into a live canary."""

    binding = _authority_binding(context_ref, config)
    if binding is None:
        return "not_authorized"
    try:
        _canary_settings(binding, objective_bucket)
    except Exception:
        return "rejected"
    verified = _verified_candidate(
        context_ref=context_ref,
        candidate_id=candidate_id,
        objective_bucket=objective_bucket,
        guidance_version=guidance_version,
    )
    if verified is None:
        return "rejected"
    candidate, replay, candidate_digest = verified
    publication_match = _published_candidate_matches(
        context_ref=context_ref,
        objective_bucket=objective_bucket,
        source_digest=candidate_digest,
    )
    if publication_match is None:
        return "authority_unavailable"
    if not publication_match:
        return "rejected"
    from .v3.autopilot_control_plane import effective_config_digest

    if not _coordinator_candidate_approved(
        candidate_id=candidate_id,
        candidate_digest=candidate_digest,
        config_digest=effective_config_digest(config),
    ):
        return "pending_coordinator"
    validation = candidate.get("validation")
    if not isinstance(validation, Mapping) or validation.get("passed") is not True:
        return "rejected"
    replay_decision = str(replay.get("decision") or "")
    replay_reason = str(replay.get("reason") or "")
    store = state._store_for_root().store
    persisted = store.get_guidance_version(guidance_version)
    metadata = persisted.get("metadata") if isinstance(persisted, Mapping) else None
    serialized = metadata.get("guidance_artifact") if isinstance(metadata, Mapping) else None
    if candidate.get("guidance_artifact") != serialized:
        return "rejected"
    try:
        artifact = validate_guidance_artifact(serialized)
    except Exception:
        return "rejected"
    if (
        artifact.context_id != context_ref
        or artifact.objective_bucket != objective_bucket
        or artifact.artifact_id != guidance_version
        or artifact.is_expired()
    ):
        return "rejected"
    now = time.time()
    with store._connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        occupied = connection.execute(
            "SELECT candidate_id FROM autopilot_transitions WHERE context_id=? AND objective_bucket=? AND state IN ('canary','promoting','monitoring','rolling_back') LIMIT 1",
            (context_ref, objective_bucket),
        ).fetchone()
        if occupied is not None:
            connection.execute("ROLLBACK")
            return "already_running"
        active = connection.execute(
            "SELECT guidance_version FROM active_guidance WHERE context_id=? AND objective_bucket=?",
            (context_ref, objective_bucket),
        ).fetchone()
        revision_row = connection.execute(
            "SELECT revision FROM active_guidance_revisions WHERE context_id=? AND objective_bucket=?",
            (context_ref, objective_bucket),
        ).fetchone()
        baseline = str(active["guidance_version"]) if active else None
        revision = int(revision_row["revision"]) if revision_row else 0
        if not _candidate_evidence_matches(
            context_ref=context_ref,
            objective_bucket=objective_bucket,
            guidance_version=guidance_version,
            candidate_id=candidate_id,
            active={"guidance_version": baseline} if baseline else None,
        ):
            connection.execute("ROLLBACK")
            return "rejected"
        if replay_decision != "promotion_ready" and not (
            replay_reason == "missing_baseline" and baseline is None
        ):
            connection.execute("ROLLBACK")
            return "rejected"
        _automatic_grant(
            context_ref=context_ref,
            action="activate",
            target_ref=candidate_id,
            target_revision=revision,
        )
        connection.execute(
            "INSERT OR IGNORE INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,baseline_guidance_version,expected_active_revision,state,reason_code,created_at,updated_at,policy_id,policy_digest,calibration_id,calibration_digest,canary_plan_id,canary_plan_digest,monitor_plan_id,monitor_plan_digest,source_candidate_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                candidate_id, context_ref, objective_bucket, guidance_version,
                baseline, revision, "canary", "candidate_admitted", now, now,
                *binding.identities(), candidate_digest,
            ),
        )
        row = connection.execute(
            "SELECT state FROM autopilot_transitions WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        connection.execute("COMMIT")
    return str(row["state"]) if row is not None else "rejected"


def reconcile_candidates(*, context_ref: str, config: Mapping[str, Any]) -> str:
    """Reconsider persisted candidates after startup or authority provisioning."""

    resume_incomplete_transitions(context_ref=context_ref, config=config)
    binding = _authority_binding(context_ref, config)
    if binding is not None:
        _expire_canaries(context_ref=context_ref, binding=binding)
    store = state._store_for_root().store
    result = "none"
    cursor: tuple[float, str] | None = None
    while True:
        with store._connect() as connection:
            sql = """SELECT c.candidate_id,c.objective_bucket,c.guidance_version,c.created_at
                       FROM autopilot_candidate_approvals AS a
                       JOIN candidates AS c ON c.candidate_id=a.candidate_id
                  LEFT JOIN autopilot_transitions AS t ON t.candidate_id=c.candidate_id
                  LEFT JOIN autopilot_candidate_considerations AS d ON d.candidate_id=c.candidate_id
                      WHERE c.context_id=? AND t.candidate_id IS NULL AND d.candidate_id IS NULL"""
            args: list[Any] = [context_ref]
            if cursor is not None:
                sql += " AND (c.created_at>? OR (c.created_at=? AND c.candidate_id>?))"
                args.extend((cursor[0], cursor[0], cursor[1]))
            sql += " ORDER BY c.created_at,c.candidate_id LIMIT 128"
            page = [dict(row) for row in connection.execute(sql, args).fetchall()]
        if not page:
            break
        for envelope in page:
            result = consider_candidate(
                context_ref=context_ref,
                candidate_id=str(envelope.get("candidate_id") or ""),
                objective_bucket=str(envelope.get("objective_bucket") or "reasoning"),
                guidance_version=str(envelope.get("guidance_version") or ""),
                config=config,
            )
            if result in {"canary", "already_running"}:
                return result
            if result == "rejected":
                with store._connect() as connection:
                    connection.execute(
                        "INSERT OR IGNORE INTO autopilot_candidate_considerations(candidate_id,result,considered_at) VALUES(?,?,?)",
                        (str(envelope["candidate_id"]), result, time.time()),
                    )
        tail = page[-1]
        cursor = (float(tail["created_at"]), str(tail["candidate_id"]))
    return result


def resume_incomplete_transitions(
    *, context_ref: str, config: Mapping[str, Any] | None = None
) -> None:
    """Resolve crash-interrupted pointer transitions from durable state."""

    store = state._store_for_root().store
    with store._connect() as connection:
        rows = connection.execute(
            "SELECT * FROM autopilot_transitions WHERE context_id=? AND state IN ('promoting','rolling_back')",
            (context_ref,),
        ).fetchall()
    if not rows or config is None:
        return
    binding = _authority_binding(context_ref, config)
    if binding is None:
        return
    for raw in rows:
        item = dict(raw)
        if not _transition_binding_matches(item, binding):
            with store._connect() as connection:
                connection.execute(
                    "UPDATE autopilot_transitions SET state='recovery_required',reason_code='authority_drift',updated_at=? WHERE candidate_id=? AND state=?",
                    (time.time(), item["candidate_id"], item["state"]),
                )
            continue
        if item["state"] == "promoting":
            _promote_pending(item, binding=binding, store=store)
        else:
            _rollback_pending(item, binding=binding, store=store)


def _artifact(
    guidance_version: str, *, context_ref: str, objective_bucket: str
) -> GuidanceArtifact | None:
    persisted = state._store_for_root().store.get_guidance_version(guidance_version)
    if not isinstance(persisted, Mapping) or persisted.get("artifact_digest") != _legacy_digest(
        {
            "guidance_text": persisted.get("guidance_text"),
            "metadata": persisted.get("metadata"),
        }
    ):
        return None
    metadata = persisted.get("metadata") if isinstance(persisted, Mapping) else None
    serialized = metadata.get("guidance_artifact") if isinstance(metadata, Mapping) else None
    try:
        artifact = validate_guidance_artifact(serialized)
    except Exception:
        return None
    if (
        artifact.artifact_id != guidance_version
        or artifact.context_id != context_ref
        or artifact.objective_bucket != objective_bucket
        or artifact.is_expired()
    ):
        return None
    return artifact


def _canary_expired(
    item: Mapping[str, Any], binding: _AuthorityBinding, *, now: float | None = None
) -> bool:
    return (now if now is not None else time.time()) >= (
        float(item["created_at"]) + int(binding.canary_plan.payload["expiry_seconds"])
    )


def _expire_canaries(*, context_ref: str, binding: _AuthorityBinding) -> int:
    store = state._store_for_root().store
    now = time.time()
    expired = 0
    with store._connect() as connection:
        rows = connection.execute(
            "SELECT * FROM autopilot_transitions WHERE context_id=? AND state='canary'",
            (context_ref,),
        ).fetchall()
        for raw in rows:
            item = dict(raw)
            if _transition_binding_matches(item, binding) and _canary_expired(
                item, binding, now=now
            ):
                cursor = connection.execute(
                    "UPDATE autopilot_transitions SET state='rejected',reason_code='canary_expired',updated_at=? WHERE candidate_id=? AND state='canary'",
                    (now, item["candidate_id"]),
                )
                expired += int(cursor.rowcount or 0)
    return expired


def _active_slot(store: Any, item: Mapping[str, Any]) -> tuple[str | None, int]:
    active = store.get_active_guidance(
        str(item["context_id"]), str(item["objective_bucket"])
    )
    version = str(active["guidance_version"]) if active else None
    revision = store.get_active_guidance_revision(
        str(item["context_id"]), str(item["objective_bucket"])
    )
    return version, revision


def _promote_pending(
    item: Mapping[str, Any], *, binding: _AuthorityBinding, store: Any
) -> str:
    active_version, current_revision = _active_slot(store, item)
    expected = int(item["expected_active_revision"])
    candidate_version = str(item["guidance_version"])
    baseline = item.get("baseline_guidance_version")
    baseline_version = str(baseline) if baseline else None
    if active_version == candidate_version and current_revision == expected + 1:
        applied, revision = True, current_revision
        recovered = True
    elif _canary_expired(item, binding):
        with store._connect() as connection:
            connection.execute(
                "UPDATE autopilot_transitions SET state='rejected',reason_code='canary_expired',updated_at=? WHERE candidate_id=? AND state='promoting'",
                (time.time(), item["candidate_id"]),
            )
        return "rejected"
    elif active_version == baseline_version and current_revision == expected:
        if _artifact(
            candidate_version,
            context_ref=str(item["context_id"]),
            objective_bucket=str(item["objective_bucket"]),
        ) is None:
            with store._connect() as connection:
                connection.execute(
                    "UPDATE autopilot_transitions SET state='rejected',reason_code='candidate_artifact_unavailable',updated_at=? WHERE candidate_id=? AND state='promoting'",
                    (time.time(), item["candidate_id"]),
                )
            return "rejected"
        applied, revision = _authorized_pointer_mutation(
            binding=binding,
            context_ref=str(item["context_id"]),
            action="activate",
            target_ref=str(item["candidate_id"]),
            target_revision=expected,
            transition=item,
            mutate=lambda: store.compare_and_swap_active_guidance(
                str(item["context_id"]),
                str(item["objective_bucket"]),
                candidate_version,
                expected_revision=expected,
                actor_id=RUNNER_ID,
                detail={
                    "authority": "standing_autopilot_calibration",
                    "candidate_id": str(item["candidate_id"]),
                    "grant_class": "automatic_transition_grant",
                },
                action="automatic_promote",
            ),
        )
        recovered = False
        if not applied:
            observed_version, observed_revision = _active_slot(store, item)
            if (
                observed_version == candidate_version
                and observed_revision == expected + 1
            ):
                applied, revision, recovered = True, observed_revision, True
    else:
        applied, revision, recovered = False, current_revision, False
    with store._connect() as connection:
        connection.execute(
            "UPDATE autopilot_transitions SET state=?,reason_code=?,expected_active_revision=?,updated_at=? WHERE candidate_id=? AND state='promoting'",
            (
                "monitoring" if applied else "rejected",
                ("promotion_recovered" if recovered else "promoted")
                if applied
                else "active_revision_conflict",
                revision,
                time.time(),
                item["candidate_id"],
            ),
        )
    return "monitoring" if applied else "rejected"


def _rollback_pending(
    item: Mapping[str, Any], *, binding: _AuthorityBinding, store: Any
) -> str:
    active_version, current_revision = _active_slot(store, item)
    expected = int(item["expected_active_revision"])
    candidate_version = str(item["guidance_version"])
    baseline = item.get("baseline_guidance_version")
    baseline_version = str(baseline) if baseline else None
    if active_version == baseline_version and current_revision == expected + 1:
        applied, recovered = True, True
    elif active_version == candidate_version and current_revision == expected:
        detail = {
            "authority": "standing_autopilot_calibration",
            "candidate_id": str(item["candidate_id"]),
            "grant_class": "automatic_transition_grant",
        }

        def rollback() -> tuple[bool, int]:
            if baseline_version:
                return store.rollback_active_guidance(
                    str(item["context_id"]),
                    str(item["objective_bucket"]),
                    baseline_version,
                    expected_revision=expected,
                    actor_id=RUNNER_ID,
                    detail=detail,
                )
            return store.clear_active_guidance(
                str(item["context_id"]),
                str(item["objective_bucket"]),
                expected_revision=expected,
                actor_id=RUNNER_ID,
                detail=detail,
            )

        applied, _revision = _authorized_pointer_mutation(
            binding=binding,
            context_ref=str(item["context_id"]),
            action="rollback",
            target_ref=str(baseline or "null-baseline"),
            target_revision=expected,
            transition=item,
            mutate=rollback,
        )
        recovered = False
        if not applied:
            observed_version, observed_revision = _active_slot(store, item)
            if (
                observed_version == baseline_version
                and observed_revision == expected + 1
            ):
                applied, recovered = True, True
    else:
        applied, recovered = False, False
    with store._connect() as connection:
        connection.execute(
            "UPDATE autopilot_transitions SET state=?,reason_code=?,updated_at=? WHERE candidate_id=? AND state='rolling_back'",
            (
                "rolled_back" if applied else "recovery_required",
                ("rollback_recovered" if recovered else "monitor_rollback")
                if applied
                else "rollback_conflict",
                time.time(),
                item["candidate_id"],
            ),
        )
    return "rolled_back" if applied else "recovery_required"


def select_guidance(
    *, context_ref: str, objective_bucket: str, exposure_ref: str,
    config: Mapping[str, Any]
) -> tuple[TransitionSelection | None, GuidanceArtifact | None]:
    """Choose an exact-bucket incumbent or candidate and label both arms."""

    binding = _authority_binding(context_ref, config)
    if binding is None:
        return None, None
    store = state._store_for_root().store
    with store._connect() as connection:
        row = connection.execute(
            "SELECT * FROM autopilot_transitions WHERE context_id=? AND objective_bucket=? AND state IN ('canary','monitoring') ORDER BY created_at LIMIT 1",
            (context_ref, objective_bucket),
        ).fetchone()
    if row is None:
        active = store.get_active_guidance(context_ref, objective_bucket)
        if not active:
            return None, None
        return None, _artifact(
            str(active["guidance_version"]),
            context_ref=context_ref,
            objective_bucket=objective_bucket,
        )
    item = dict(row)
    if not _transition_binding_matches(item, binding):
        with store._connect() as connection:
            connection.execute(
                "UPDATE autopilot_transitions SET state='recovery_required',reason_code='authority_drift',updated_at=? WHERE candidate_id=? AND state IN ('canary','monitoring')",
                (time.time(), item["candidate_id"]),
            )
        return None, None
    state_name = str(item["state"])
    if state_name == "canary" and _canary_expired(item, binding):
        with store._connect() as connection:
            connection.execute(
                "UPDATE autopilot_transitions SET state='rejected',reason_code='canary_expired',updated_at=? WHERE candidate_id=? AND state='canary'",
                (time.time(), item["candidate_id"]),
            )
        return None, None
    if state_name == "canary":
        active_version, active_revision = _active_slot(store, item)
        baseline = item.get("baseline_guidance_version")
        if (
            active_version != (str(baseline) if baseline else None)
            or active_revision != int(item["expected_active_revision"])
        ):
            with store._connect() as connection:
                connection.execute(
                    "UPDATE autopilot_transitions SET state='recovery_required',reason_code='canary_baseline_drift',updated_at=? WHERE candidate_id=? AND state='canary'",
                    (time.time(), item["candidate_id"]),
                )
            return None, None
    if state_name == "monitoring":
        active_version, active_revision = _active_slot(store, item)
        if (
            active_version != str(item["guidance_version"])
            or active_revision != int(item["expected_active_revision"])
        ):
            with store._connect() as connection:
                connection.execute(
                    "UPDATE autopilot_transitions SET state='recovery_required',reason_code='active_pointer_drift',updated_at=? WHERE candidate_id=? AND state='monitoring'",
                    (time.time(), item["candidate_id"]),
                )
            return None, None
    arm = "candidate"
    selected_version = str(item["guidance_version"])
    if state_name == "canary":
        try:
            _minimum, _horizon, percentage, _margin, _hard_veto = _canary_settings(
                binding, objective_bucket
            )
            from .v3.autopilot_control_plane import canary_assignment_value

            assignment = canary_assignment_value(
                authority_root=paths.AUTHORITY_DIR / "autopilot-transition",
                context_ref=context_ref,
                candidate_ref=str(item["candidate_id"]),
                exposure_ref=exposure_ref,
                assignment_key_commitment=binding.canary_plan.payload[
                    "assignment_key_commitment"
                ],
            )
        except Exception:
            return None, None
        if assignment >= percentage:
            arm = "incumbent"
            baseline = item.get("baseline_guidance_version")
            selected_version = str(baseline) if baseline else ""
    artifact = (
        _artifact(
            selected_version,
            context_ref=context_ref,
            objective_bucket=objective_bucket,
        )
        if selected_version
        else None
    )
    if selected_version and artifact is None:
        with store._connect() as connection:
            connection.execute(
                "UPDATE autopilot_transitions SET state='recovery_required',reason_code='artifact_unavailable',updated_at=? WHERE candidate_id=? AND state IN ('canary','monitoring')",
                (time.time(), item["candidate_id"]),
            )
        return None, None
    return (
        TransitionSelection(
            str(item["candidate_id"]), context_ref, objective_bucket,
            str(item["guidance_version"]), state_name, arm, exposure_ref,
        ),
        artifact,
    )


def record_outcome(
    selection: TransitionSelection, *, success: bool | None,
    config: Mapping[str, Any], hard_failure: bool = False,
) -> str:
    """Record a known outcome and perform an authority-fenced pointer CAS."""

    if type(success) is not bool:
        return "outcome_unknown"
    if type(hard_failure) is not bool or not selection.exposure_ref:
        return "invalid_outcome"
    binding = _authority_binding(selection.context_ref, config)
    if binding is None:
        return "not_authorized"
    store = state._store_for_root().store
    now = time.time()
    with store._connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM autopilot_transitions WHERE candidate_id=?",
            (selection.candidate_id,),
        ).fetchone()
        if row is None or str(row["state"]) != selection.state:
            connection.execute("ROLLBACK")
            return "stale_selection"
        item = dict(row)
        if (
            item["context_id"] != selection.context_ref
            or item["objective_bucket"] != selection.objective_bucket
            or item["guidance_version"] != selection.guidance_version
            or not _transition_binding_matches(item, binding)
        ):
            connection.execute(
                "UPDATE autopilot_transitions SET state='recovery_required',reason_code='authority_drift',updated_at=? WHERE candidate_id=? AND state=?",
                (now, selection.candidate_id, selection.state),
            )
            connection.execute("COMMIT")
            return "recovery_required"
        if selection.state == "canary" and _canary_expired(item, binding, now=now):
            connection.execute(
                "UPDATE autopilot_transitions SET state='rejected',reason_code='canary_expired',updated_at=? WHERE candidate_id=? AND state='canary'",
                (now, selection.candidate_id),
            )
            connection.execute("COMMIT")
            return "rejected"
        active = connection.execute(
            "SELECT guidance_version FROM active_guidance WHERE context_id=? AND objective_bucket=?",
            (selection.context_ref, selection.objective_bucket),
        ).fetchone()
        revision_row = connection.execute(
            "SELECT revision FROM active_guidance_revisions WHERE context_id=? AND objective_bucket=?",
            (selection.context_ref, selection.objective_bucket),
        ).fetchone()
        active_version = str(active["guidance_version"]) if active else None
        active_revision = int(revision_row["revision"]) if revision_row else 0
        expected_version = (
            selection.guidance_version
            if selection.state == "monitoring"
            else (
                str(item["baseline_guidance_version"])
                if item.get("baseline_guidance_version")
                else None
            )
        )
        if (
            active_version != expected_version
            or active_revision != int(item["expected_active_revision"])
        ):
            if selection.state in {"canary", "monitoring"}:
                connection.execute(
                    "UPDATE autopilot_transitions SET state='recovery_required',reason_code=?,updated_at=? WHERE candidate_id=? AND state=?",
                    (
                        "canary_baseline_drift"
                        if selection.state == "canary"
                        else "active_pointer_drift",
                        now, selection.candidate_id, selection.state,
                    ),
                )
                connection.execute("COMMIT")
                return "recovery_required"
        receipt = connection.execute(
            "INSERT OR IGNORE INTO autopilot_transition_outcomes(candidate_id,exposure_ref,transition_state,arm,success,hard_failure,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                selection.candidate_id, selection.exposure_ref, selection.state,
                selection.arm, int(success), int(hard_failure), now,
            ),
        )
        if not receipt.rowcount:
            connection.execute("ROLLBACK")
            return "duplicate_outcome"
        next_state = selection.state
        reason = "outcome_recorded"
        if selection.state == "canary":
            if selection.arm not in {"candidate", "incumbent"}:
                connection.execute("ROLLBACK")
                return "stale_selection"
            column = "canary" if selection.arm == "candidate" else "canary_control"
            observations = int(item[f"{column}_observations"]) + 1
            failures = int(item[f"{column}_failures"]) + int(not success)
            item[f"{column}_observations"] = observations
            item[f"{column}_failures"] = failures
            minimum, horizon, _percentage, margin, hard_veto = _canary_settings(
                binding, selection.objective_bucket
            )
            total = int(item["canary_observations"]) + int(
                item["canary_control_observations"]
            )
            hard_failures = connection.execute(
                "SELECT COUNT(*) AS count FROM autopilot_transition_outcomes WHERE candidate_id=? AND transition_state='canary' AND arm='candidate' AND hard_failure=1",
                (selection.candidate_id,),
            ).fetchone()["count"]
            if hard_failures > hard_veto:
                next_state, reason = "rejected", "candidate_hard_failure"
            elif total >= horizon:
                candidate_count = int(item["canary_observations"])
                control_count = int(item["canary_control_observations"])
                if candidate_count < minimum or control_count < minimum:
                    next_state, reason = "rejected", "canary_underpowered"
                else:
                    candidate_rate = int(item["canary_failures"]) / candidate_count
                    control_rate = int(item["canary_control_failures"]) / control_count
                    if candidate_rate - control_rate > margin:
                        next_state, reason = "rolled_back", "canary_regression"
                    else:
                        next_state, reason = "promoting", "canary_passed"
            connection.execute(
                f"UPDATE autopilot_transitions SET {column}_observations=?,{column}_failures=?,state=?,reason_code=?,updated_at=? WHERE candidate_id=? AND state='canary'",
                (observations, failures, next_state, reason, now, selection.candidate_id),
            )
        elif selection.state == "monitoring":
            if selection.arm != "candidate":
                connection.execute("ROLLBACK")
                return "stale_selection"
            observations = int(item["monitor_observations"]) + 1
            failures = int(item["monitor_failures"]) + int(not success)
            item["monitor_observations"] = observations
            item["monitor_failures"] = failures
            look, horizon, margin, hard_veto = _monitor_settings(binding)
            control_count = int(item["canary_control_observations"])
            hard_failures = connection.execute(
                "SELECT COUNT(*) AS count FROM autopilot_transition_outcomes WHERE candidate_id=? AND transition_state='monitoring' AND hard_failure=1",
                (selection.candidate_id,),
            ).fetchone()["count"]
            if control_count < 1:
                next_state, reason = "recovery_required", "monitor_baseline_missing"
            elif hard_failures > hard_veto:
                next_state, reason = "rolling_back", "monitor_hard_failure"
            elif observations % look == 0 or observations >= horizon:
                monitor_rate = failures / observations
                control_rate = int(item["canary_control_failures"]) / control_count
                if monitor_rate - control_rate > margin:
                    next_state, reason = "rolling_back", "monitor_regression"
                elif observations >= horizon:
                    next_state, reason = "retained", "monitor_passed"
            connection.execute(
                "UPDATE autopilot_transitions SET monitor_observations=?,monitor_failures=?,state=?,reason_code=?,updated_at=? WHERE candidate_id=? AND state='monitoring'",
                (observations, failures, next_state, reason, now, selection.candidate_id),
            )
        else:
            connection.execute("ROLLBACK")
            return "stale_selection"
        connection.execute("COMMIT")

    item["state"] = next_state
    if next_state == "promoting":
        return _promote_pending(item, binding=binding, store=store)
    if next_state == "rolling_back":
        return _rollback_pending(item, binding=binding, store=store)
    return next_state


__all__ = [
    "ARTIFACT_LOOP_KEY",
    "FRAMEWORK_HARD_FAILURE_KEY",
    "FRAMEWORK_OUTCOME_KEY",
    "RUNNER_ID",
    "SELECTION_LOOP_KEY",
    "TERMINAL_OUTCOME_KEY",
    "TransitionSelection",
    "consider_candidate",
    "reconcile_candidates",
    "record_outcome",
    "resume_incomplete_transitions",
    "select_guidance",
]
