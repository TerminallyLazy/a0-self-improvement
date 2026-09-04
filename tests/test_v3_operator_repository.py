from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.candidate_publication import (
    CANDIDATE_PUBLICATION_REGISTRY,
    IMPROVEMENT_CANDIDATE_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    CANARY_CONCLUSION_SCHEMA_ID,
    CANARY_REGISTRY,
    BucketCalibration,
    Rational,
    activation_policy,
    canary_plan,
    monitor_plan,
    policy_calibration,
)
from usr.plugins.dspy_rlm.helpers.v3.operator_projection import (
    Axis,
    PrivacyMigrationSnapshot,
    PrivacyOperationSummary,
    project_candidates,
    project_overview,
    project_privacy_migration,
    project_policy_capabilities,
)
from usr.plugins.dspy_rlm.helpers.v3.operator_repository import (
    ObservedRecord,
    OperatorRepositoryAdapter,
    SafeStoreOperatorReader,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    ActivationScope,
    DomainEvent,
    OperationSlot,
    V3Reader,
    V3Repository,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import build_typed_record


_CONTEXT = "context:operator"
_NOW = "2026-08-26T12:00:00Z"
_DIGEST = "0" * 64


class _Facts:
    def __init__(self, *, scope=None, records=(), slots=()) -> None:
        self.scope = scope
        self.records = tuple(records)
        self.slots = {item.operation_kind: item for item in slots}
        self.by_id = {item.record.record_id: item.record for item in self.records}
        self.calls: list[tuple[str, str]] = []

    def get_activation_scope(self, context_ref):
        self.calls.append(("scope", context_ref))
        return self.scope

    def get_operation_slot(self, context_ref, operation_kind):
        self.calls.append(("slot", operation_kind))
        return self.slots.get(operation_kind)

    def get_record(self, record_id):
        self.calls.append(("record", record_id))
        return self.by_id.get(record_id)

    def list_records(self, context_ref):
        self.calls.append(("records", context_ref))
        return self.records

    def list_domain_events(self, context_ref):
        raise AssertionError("projection did not request raw events")

    def list_operator_commands(self, context_ref):
        raise AssertionError("projection did not request raw commands")


def _profile_facts() -> tuple[_Facts, str]:
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile:active",
        context_ref=_CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="test-v1",
    )
    scope = ActivationScope(
        _CONTEXT,
        profile.record_id,
        profile.content_digest,
        7,
        "normal",
        _NOW,
    )
    facts = _Facts(
        scope=scope,
        records=(ObservedRecord(profile, _NOW),),
        slots=(OperationSlot(_CONTEXT, "canary", None, None, 2, _NOW),),
    )
    return facts, profile.record_id


def test_overview_is_built_only_from_exact_scope_and_slots() -> None:
    facts, profile_id = _profile_facts()

    view = project_overview(OperatorRepositoryAdapter(facts), _CONTEXT)

    assert view["ordinary_runtime"]["state"] == "unavailable"
    assert view["activation"]["profile_ref"] == profile_id
    assert view["activation"]["scope_revision"] == 7
    assert [item["state"] for item in view["activation"]["slots"]] == [
        "active",
        "active",
        "inactive",
        "not_observed",
        "not_observed",
    ]
    assert {name for name, _ in facts.calls} <= {"scope", "slot", "record"}


def _candidate_records(profile_id: str) -> tuple[ObservedRecord, ObservedRecord]:
    links = [
        {"role": role, "ordinal": 0, "target_id": target, "target_digest": _DIGEST}
        for role, target in (
            ("artifact", "artifact:1"),
            ("incumbent_profile", profile_id),
            ("successor_profile", "profile:successor"),
            ("lineage", "lineage:1"),
            ("engine_profile", "engine:1"),
            ("artifact_generation_receipt", "receipt:generation"),
        )
    ]
    candidate = build_typed_record(
        record_id="candidate:1",
        context_ref=_CONTEXT,
        record_kind="improvement_candidate",
        schema_id=IMPROVEMENT_CANDIDATE_SCHEMA_ID,
        payload={
            "record_type": "improvement_candidate",
            "change_kind": "replace_structured_guidance",
            "artifact_slot": "structured_guidance",
            "artifact_id": "artifact:1",
            "artifact_digest": _DIGEST,
            "incumbent_profile_id": profile_id,
            "incumbent_profile_digest": _DIGEST,
            "successor_profile_id": "profile:successor",
            "successor_profile_digest": _DIGEST,
            "activation_scope_ref": _CONTEXT,
            "observed_scope_revision": 7,
            "lineage_id": "lineage:1",
            "lineage_digest": _DIGEST,
            "benefit_claim": {
                "kind": "outcome",
                "bucket": "ordinary_quality",
                "claim_ref": "claim:1",
                "claim_digest": _DIGEST,
            },
            "risk_tier": "standard",
            "engine_semantic_id": "a0.generate.guidance.deterministic_rules.v1",
            "engine_profile_id": "engine:1",
            "engine_profile_digest": _DIGEST,
            "artifact_generation_receipt_id": "receipt:generation",
            "artifact_generation_receipt_digest": _DIGEST,
            "links": links,
        },
        key_epoch="test-v1",
        registry=CANDIDATE_PUBLICATION_REGISTRY,
    )
    conclusion = build_typed_record(
        record_id="conclusion:diagnostic",
        context_ref=_CONTEXT,
        record_kind="canary_conclusion",
        schema_id=CANARY_CONCLUSION_SCHEMA_ID,
        payload={
            "fact_type": "canary_conclusion",
            "trial_id": "trial:diagnostic",
            "trial_digest": _DIGEST,
            "canary_kind": "diagnostic",
            "authority_ceiling": "no_promotion_authority",
            "conclusion": "passed",
            "activation_authoritative": False,
            "candidate_id": candidate.record_id,
            "candidate_digest": candidate.content_digest,
            "incumbent_profile_id": profile_id,
            "incumbent_profile_digest": _DIGEST,
            "scope_revision": 7,
            "policy_id": "policy:1",
            "policy_digest": _DIGEST,
            "policy_revision": 1,
            "calibration_id": None,
            "calibration_digest": None,
            "reason_codes": ["horizon_passed"],
            "links": [
                {
                    "role": "canary_trial",
                    "ordinal": 0,
                    "target_id": "trial:diagnostic",
                    "target_digest": _DIGEST,
                }
            ],
        },
        key_epoch="test-v1",
        registry=CANARY_REGISTRY,
    )
    return ObservedRecord(candidate, _NOW), ObservedRecord(conclusion, _NOW)


def test_diagnostic_canary_remains_non_authoritative_and_content_free() -> None:
    facts, profile_id = _profile_facts()
    candidate, conclusion = _candidate_records(profile_id)
    facts.records += (candidate, conclusion)
    facts.by_id.update({item.record.record_id: item.record for item in (candidate, conclusion)})

    view = project_candidates(OperatorRepositoryAdapter(facts), _CONTEXT)
    item = view["items"][0]

    assert item["canary"]["authority_ceiling"] == "no_promotion_authority"
    assert item["canary"]["activation_authoritative"] is False
    assert item["allowed_actions"] == [
        {
            "action": "activate",
            "state": "blocked",
            "reason_codes": ["diagnostic_canary_no_activation_authority"],
        }
    ]
    encoded = json.dumps(view)
    for forbidden in ("actor", "subject", "provider", "quarantine", "/tmp/"):
        assert forbidden not in encoded


def test_missing_authority_and_privacy_identifiers_are_fail_closed() -> None:
    facts = _Facts()
    missing = OperatorRepositoryAdapter(facts)
    overview = project_overview(missing, _CONTEXT)
    assert overview["activation"]["state"] == "not_observed"
    assert overview["improvement"]["state"] == "unavailable"

    privacy = PrivacyMigrationSnapshot(
        privacy=Axis("ready", _NOW, "current"),
        migration=Axis("completed", _NOW, "current"),
        migration_ref="migration:1",
        migration_phase="completed",
        checkpoint_count=9,
        disposition_counts=(("supported", 1),),
        key_custody_state="ready",
        cutover_readiness="ready",
        recovery_state="ready",
        operations=(
            PrivacyOperationSummary(
                "quarantine:secret",
                "quarantine_export",
                Axis("pending", _NOW, "current"),
                "challenge:secret",
                ("receipt:secret",),
                "run_local_export_command",
            ),
        ),
    )
    adapter = OperatorRepositoryAdapter(facts, privacy_migration_snapshot=privacy)
    view = project_privacy_migration(adapter, _CONTEXT)
    assert view["operations"] == []
    assert "quarantine:secret" not in json.dumps(view)


def test_safe_store_reader_enumerates_verified_context_facts_without_writes(
    tmp_path: Path,
) -> None:
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile:safe-store",
        context_ref=_CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="test-v1",
    )
    store = tmp_path / "safe-store.sqlite3"
    with V3Repository.create(store) as repository:
        with repository.transaction() as transaction:
            for record in (guidance, prompt, profile):
                transaction.insert_record(record)
            transaction.initialize_activation_scope(
                context_ref=_CONTEXT,
                profile_id=profile.record_id,
                profile_digest=profile.content_digest,
            )
            transaction.append_event(
                DomainEvent(
                    event_id="event:profile-created",
                    subject_id=profile.record_id,
                    subject_kind=profile.record_kind,
                    sequence=0,
                    event_type="profile_created",
                    payload_record_id=profile.record_id,
                    actor_authority_ref="authority:local",
                )
            )

    with V3Reader.open(store) as reader:
        safe = SafeStoreOperatorReader(reader)
        records = safe.list_records(_CONTEXT)
        events = safe.list_domain_events(_CONTEXT)

        assert [(item.record.record_id, item.observed_at.endswith("Z")) for item in records] == [
            (profile.record_id, True)
        ]
        assert [(item.event.event_id, item.observed_at.endswith("Z")) for item in events] == [
            ("event:profile-created", True)
        ]
        assert safe.list_operator_commands(_CONTEXT) == ()
        assert project_overview(OperatorRepositoryAdapter(safe), _CONTEXT)["activation"][
            "profile_ref"
        ] == profile.record_id


def test_policy_capabilities_derive_standing_automatic_authority_from_calibration() -> None:
    policy = activation_policy(
        record_id="policy:auto",
        context_ref=_CONTEXT,
        policy_revision=3,
        activation_mode="auto_after_canary",
        key_epoch="test-v1",
    )
    trial_plan = canary_plan(
        record_id="canary-plan:auto",
        context_ref=_CONTEXT,
        horizon_exposures=20,
        expiry_seconds=3600,
        candidate_allocation=Rational(1, 10),
        assignment_key_commitment="1" * 64,
        hard_veto_failure_limit=0,
        buckets=(
            BucketCalibration("reasoning", 10, Rational(1, 20), Rational(0, 1)),
        ),
        key_epoch="test-v1",
    )
    monitoring = monitor_plan(
        record_id="monitor-plan:auto",
        context_ref=_CONTEXT,
        horizon_exposures=40,
        look_interval_exposures=10,
        ordinary_regression_boundary=Rational(1, 20),
        hard_veto_failure_limit=0,
        key_epoch="test-v1",
    )
    calibration = policy_calibration(
        record_id="calibration:auto",
        context_ref=_CONTEXT,
        status="approved",
        environment_ref="agent-zero:local-production",
        policy=policy,
        canary_plan_record=trial_plan,
        monitor_plan_record=monitoring,
        activation_authorities=("automatic", "manual"),
        soft_rollback_authorized=True,
        key_epoch="test-v1",
    )
    facts = _Facts(
        records=tuple(
            ObservedRecord(record, _NOW)
            for record in (policy, trial_plan, monitoring, calibration)
        )
    )

    view = project_policy_capabilities(OperatorRepositoryAdapter(facts), _CONTEXT)

    assert view["policy"]["calibration_state"] == "approved"
    assert view["policy"]["activation_mode"] == "auto_after_canary"
    assert view["policy"]["automatic_authority_state"] == "authorized"
