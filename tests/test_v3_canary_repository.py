from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
from pathlib import Path

from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    GrantExpectation,
    GrantRequest,
    VerifiedGrant,
    bootstrap_local_issuer,
    issue_grant,
)
from usr.plugins.dspy_rlm.helpers.v3.authority_service import (
    LocalGrantVerifier,
    RevocationFileLedger,
)
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    Rational,
    activation_policy,
    canary_plan,
    monitor_plan,
    policy_calibration,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_command_adapter import (
    CANARY_COMMAND_REGISTRY,
    CANARY_START_COMMAND_SCHEMA,
    CANARY_STOP_COMMAND_SCHEMA,
    CanaryCommandAdapter,
    CanaryGrantBinding,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_repository import (
    RepositoryCanaryMutationCoordinator,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Repository
from usr.plugins.dspy_rlm.helpers.v3.schemas import (
    RecordSchema,
    SchemaRegistry,
    build_typed_record,
    canonical_json,
    canonical_loads,
    merge_schema_registries,
    strict_literal,
    strict_object,
    validate_links,
)


CONTEXT = "context:canary-repository"
NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
KEY_EPOCH = "test-v1"
TEST_EXACT_SCHEMA_ID = "a0.test.canary-exact.v1"
TEST_REGISTRY = merge_schema_registries(
    CANARY_COMMAND_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                TEST_EXACT_SCHEMA_ID,
                "test_exact",
                strict_object(
                    {
                        "fact_type": strict_literal("test_exact"),
                        "links": validate_links,
                    }
                ),
            ),
        )
    ),
)


def digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def exact(record) -> dict[str, str]:
    return {"record_id": record.record_id, "digest": record.content_digest}


def row_count(repository: V3Repository, table: str) -> int:
    assert table in ("domain_events", "operator_commands")
    return int(repository._connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])


def target(record_id: str):
    return build_typed_record(
        record_id=record_id,
        context_ref=CONTEXT,
        record_kind="test_exact",
        schema_id=TEST_EXACT_SCHEMA_ID,
        payload={"fact_type": "test_exact", "links": []},
        key_epoch=KEY_EPOCH,
        registry=TEST_REGISTRY,
    )


class ExactGrant:
    def __init__(self) -> None:
        self.bindings: list[CanaryGrantBinding] = []

    def __call__(self, binding: CanaryGrantBinding) -> VerifiedGrant:
        self.bindings.append(binding)
        return VerifiedGrant(
            grant_id=binding.authority_grant_id,
            authority_class=binding.authority_class,
            issuer_id=binding.issuer_ref,
            key_epoch=1,
            subject_ref=binding.subject_ref,
            context_ref=binding.context_ref,
            action=binding.action,
            purpose=binding.purpose,
            target_ref=binding.target_ref,
            target_revision=binding.target_revision,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            idempotency_key_digest=binding.idempotency_key_digest,
            session_nonce=binding.session_nonce,
        )


class LocalEnvelopeGrant:
    """Exercise the production verifier against one immutable signed envelope file."""

    def __init__(self, tmp_path: Path) -> None:
        secret = tmp_path / "issuer.secret"
        profile_path = tmp_path / "issuer.json"
        revocations_path = tmp_path / "revocations"
        revocations_path.mkdir(mode=0o700)
        self.profile = bootstrap_local_issuer(
            secret,
            issuer_id="issuer:local",
            key_epoch=1,
            allowed_authority_classes=(AuthorityClass.OPERATOR_AUTHORITY_GRANT,),
            confirmation=BOOTSTRAP_CONFIRMATION,
        )
        profile_path.write_bytes(canonical_json(self.profile.to_record()))
        os.chmod(profile_path, 0o600)
        self.verifier = LocalGrantVerifier(
            secret, profile_path, RevocationFileLedger(revocations_path)
        )
        self.envelope_path = tmp_path / "canary-grant.json"
        self.expires_at = NOW + timedelta(minutes=5)

    def issue_start(self, payload: dict) -> str:
        envelope = issue_grant(
            self.verifier.secret_path,
            self.profile,
            GrantRequest(
                authority_class="operator_authority_grant",
                issuer_id="issuer:local",
                key_epoch=1,
                subject_ref="operator:test",
                context_ref=payload["context_ref"],
                action="canary_start",
                purpose="operator_mutation",
                target_ref=payload["trial_id"],
                target_revision=payload["expected_scope_revision"],
                issued_at=NOW - timedelta(seconds=1),
                expires_at=self.expires_at,
                idempotency_key_digest=sha256(
                    b"a0.authority.idempotency.v1\0"
                    + payload["idempotency_key"].encode()
                ).hexdigest(),
                session_nonce="session:canary",
            ),
        )
        self.envelope_path.write_bytes(canonical_json(envelope))
        os.chmod(self.envelope_path, 0o600)
        return envelope["payload"]["grant_id"]

    def __call__(self, binding: CanaryGrantBinding) -> VerifiedGrant:
        envelope = canonical_loads(self.envelope_path.read_bytes())
        assert type(envelope) is dict
        assert envelope["payload"]["grant_id"] == binding.authority_grant_id
        return self.verifier.authorize(
            envelope,
            GrantExpectation(
                authority_class=binding.authority_class,
                issuer_id=binding.issuer_ref,
                subject_ref=binding.subject_ref,
                context_ref=binding.context_ref,
                action=binding.action,
                purpose=binding.purpose,
                target_ref=binding.target_ref,
                target_revision=binding.target_revision,
                expires_at=self.expires_at,
                idempotency_key_digest=binding.idempotency_key_digest,
                session_nonce=binding.session_nonce,
            ),
            now=binding.now,
        )


def setup_repository(path: Path):
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile:incumbent",
        context_ref=CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch=KEY_EPOCH,
    )
    policy = activation_policy(
        record_id="policy:1",
        context_ref=CONTEXT,
        policy_revision=1,
        activation_mode="canary_required",
        key_epoch=KEY_EPOCH,
    )
    plan = canary_plan(
        record_id="canary-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=10,
        expiry_seconds=900,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=digest("assignment"),
        hard_veto_failure_limit=0,
        buckets=(BucketCalibration("shell", 5, Rational(0, 1), Rational(0, 1)),),
        key_epoch=KEY_EPOCH,
    )
    monitor = monitor_plan(
        record_id="monitor-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=20,
        look_interval_exposures=5,
        ordinary_regression_boundary=Rational(0, 1),
        hard_veto_failure_limit=0,
        key_epoch=KEY_EPOCH,
    )
    calibration = policy_calibration(
        record_id="calibration:1",
        context_ref=CONTEXT,
        status="approved",
        environment_ref="environment:test",
        policy=policy,
        canary_plan_record=plan,
        monitor_plan_record=monitor,
        activation_authorities=("manual",),
        soft_rollback_authorized=True,
        key_epoch=KEY_EPOCH,
    )
    refs = {name: target(f"record:{name}") for name in ("candidate", "disposition")}
    repository = V3Repository.create(path, registry=TEST_REGISTRY)
    with repository.transaction() as transaction:
        for record in (
            guidance,
            prompt,
            profile,
            policy,
            plan,
            monitor,
            calibration,
            *refs.values(),
        ):
            transaction.insert_record(record)
        transaction.initialize_activation_scope(
            context_ref=CONTEXT,
            profile_id=profile.record_id,
            profile_digest=profile.content_digest,
        )
    return repository, profile, policy, plan, calibration, refs


def adapter(repository: V3Repository, grant: ExactGrant) -> CanaryCommandAdapter:
    return CanaryCommandAdapter(
        key_epoch=KEY_EPOCH,
        mutation_coordinator=RepositoryCanaryMutationCoordinator(repository),
        start_grant_revalidator=grant,
        stop_grant_revalidator=grant,
    )


def handle(instance: CanaryCommandAdapter, payload: dict):
    return instance.handle(
        payload,
        bound_context_ref=CONTEXT,
        issuer_ref="issuer:local",
        subject_ref="operator:test",
        session_nonce="session:canary",
        now=NOW,
    )


def start_payload(profile, policy, plan, calibration, refs) -> dict:
    return {
        "schema": CANARY_START_COMMAND_SCHEMA,
        "action": "canary_start",
        "context_ref": CONTEXT,
        "key_epoch": KEY_EPOCH,
        "expected_scope_revision": 0,
        "slot": {"revision": 0, "occupant": None},
        "idempotency_key": "start-authoritative",
        "authority_grant_id": "grant:start:repository",
        "receipt_id": "receipt:start",
        "trial_id": "trial:1",
        "canary_kind": "authoritative",
        "candidate": exact(refs["candidate"]),
        "incumbent_profile": exact(profile),
        "disposition": {
            "record": exact(refs["disposition"]),
            "state": "promotion_ready",
        },
        "policy": exact(policy),
        "calibration": exact(calibration),
        "canary_plan": exact(plan),
        "environment_ref": "environment:test",
        "operator_reason_code": "authoritative_canary_requested",
    }


def stop_payload(trial, policy, plan, calibration, refs) -> dict:
    return {
        "schema": CANARY_STOP_COMMAND_SCHEMA,
        "action": "canary_stop",
        "context_ref": CONTEXT,
        "key_epoch": KEY_EPOCH,
        "expected_scope_revision": 0,
        "slot": {"revision": 1, "occupant": exact(trial)},
        "idempotency_key": "stop-authoritative",
        "authority_grant_id": "grant:stop:repository",
        "receipt_id": "receipt:stop",
        "conclusion_id": "conclusion:1",
        "trial": exact(trial),
        "candidate": exact(refs["candidate"]),
        "disposition": {
            "record": exact(refs["disposition"]),
            "state": "promotion_ready",
        },
        "policy": exact(policy),
        "calibration": exact(calibration),
        "canary_plan": exact(plan),
        "signals": {
            "eligible_exposure_count": 0,
            "candidate_hard_failure_count": 0,
            "shared_failure": False,
            "identity_drift": False,
            "cancelled": False,
            "boundary_uncertain": False,
            "operator_stopped": True,
            "bucket_outcomes": [
                {
                    "bucket_ref": "shell",
                    "comparable_count": 0,
                    "candidate_delta": {"numerator": 0, "denominator": 1},
                    "boundary_uncertain": False,
                }
            ],
        },
        "operator_reason_code": "operator_stopped",
    }


def test_start_commits_fact_slot_receipt_event_and_command_atomically(tmp_path: Path):
    repository, profile, policy, plan, calibration, refs = setup_repository(
        tmp_path / "store.sqlite3"
    )
    with repository:
        grant = ExactGrant()
        assert repository.get_record("grant:start:repository") is None
        response = handle(
            adapter(repository, grant),
            start_payload(profile, policy, plan, calibration, refs),
        )
        assert response.status_code == 200
        assert response.body["result_state"] == "authoritative_started"
        slot = repository.get_operation_slot(CONTEXT, "canary")
        assert (slot.operation_id, slot.operation_revision) == ("trial:1", 1)
        assert repository.get_record("receipt:start") is not None
        authority_use = repository.get_record("grant:start:repository")
        assert authority_use is not None
        assert authority_use.schema_id == "a0.canary-authority-grant-use.v1"
        assert row_count(repository, "domain_events") == 1
        assert row_count(repository, "operator_commands") == 1
        assert len(grant.bindings) == 2


def test_exact_replay_returns_receipt_without_regrant_or_duplicate_and_changed_key_conflicts(
    tmp_path: Path,
):
    repository, profile, policy, plan, calibration, refs = setup_repository(
        tmp_path / "store.sqlite3"
    )
    with repository:
        grant = ExactGrant()
        instance = adapter(repository, grant)
        payload = start_payload(profile, policy, plan, calibration, refs)
        first = handle(instance, payload)
        replay = handle(instance, payload)
        assert first.status_code == replay.status_code == 200
        assert replay.body["receipt_ref"] == first.body["receipt_ref"]
        assert replay.body["replayed"] is True
        assert len(grant.bindings) == 3
        changed = handle(instance, {**payload, "receipt_id": "receipt:changed"})
        assert changed.status_code == 409
        assert changed.body["receipt_ref"] is None
        assert repository.get_record("receipt:changed") is None
        assert row_count(repository, "domain_events") == 1
        assert row_count(repository, "operator_commands") == 1


def test_stop_inserts_conclusion_and_clears_only_exact_trial_slot(tmp_path: Path):
    repository, profile, policy, plan, calibration, refs = setup_repository(
        tmp_path / "store.sqlite3"
    )
    with repository:
        grant = ExactGrant()
        instance = adapter(repository, grant)
        started = handle(instance, start_payload(profile, policy, plan, calibration, refs))
        assert started.status_code == 200
        trial = repository.get_record("trial:1")
        assert trial is not None
        stopped = handle(instance, stop_payload(trial, policy, plan, calibration, refs))
        assert stopped.status_code == 200
        assert stopped.body["result_state"] == "stopped"
        assert stopped.body["activation_authoritative"] is False
        slot = repository.get_operation_slot(CONTEXT, "canary")
        assert (slot.operation_id, slot.operation_digest, slot.operation_revision) == (
            None,
            None,
            2,
        )
        assert repository.get_record("conclusion:1") is not None
        assert repository.get_record("receipt:stop") is not None
        events = repository._connection.execute(
            "SELECT event_type FROM domain_events ORDER BY sequence"
        ).fetchall()
        assert [item[0] for item in events] == [
            "canary_started",
            "canary_stopped",
        ]
        assert row_count(repository, "operator_commands") == 2


def test_signed_envelope_verifier_needs_no_preexisting_grant_record(tmp_path: Path):
    repository, profile, policy, plan, calibration, refs = setup_repository(
        tmp_path / "store.sqlite3"
    )
    with repository:
        verifier = LocalEnvelopeGrant(tmp_path)
        payload = start_payload(profile, policy, plan, calibration, refs)
        payload["authority_grant_id"] = verifier.issue_start(payload)
        assert repository.get_record(payload["authority_grant_id"]) is None

        response = handle(adapter(repository, verifier), payload)

        assert response.status_code == 200
        authority_use = repository.get_record(payload["authority_grant_id"])
        assert authority_use is not None
        assert authority_use.payload["record_type"] == "canary_authority_grant_use"
