from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256

from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    Rational,
    activation_policy,
    canary_plan,
    monitor_plan,
    policy_calibration,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_command_adapter import (
    CANARY_START_COMMAND_SCHEMA,
    CANARY_STOP_COMMAND_SCHEMA,
    CanaryCommandAdapter,
    CanaryGrantBinding,
    CanaryMutationResult,
    ExactRecord,
    build_canary_mutation_receipt,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import OperationSlot, RevisionConflict


CONTEXT = "context:canary-command"
NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)


def digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def exact(record):
    return {"record_id": record.record_id, "digest": record.content_digest}


def opaque(label: str):
    return {"record_id": f"record:{label}", "digest": digest(label)}


def planning_records():
    policy = activation_policy(
        record_id="policy:1",
        context_ref=CONTEXT,
        policy_revision=3,
        activation_mode="canary_required",
        key_epoch="test-v1",
    )
    plan = canary_plan(
        record_id="canary-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=10,
        expiry_seconds=900,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=digest("assignment"),
        hard_veto_failure_limit=0,
        buckets=(
            BucketCalibration(
                "shell",
                minimum_comparable=5,
                noninferiority_margin=Rational(0, 1),
                benefit_threshold=Rational(0, 1),
            ),
        ),
        key_epoch="test-v1",
    )
    monitor = monitor_plan(
        record_id="monitor-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=20,
        look_interval_exposures=5,
        ordinary_regression_boundary=Rational(0, 1),
        hard_veto_failure_limit=0,
        key_epoch="test-v1",
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
        key_epoch="test-v1",
    )
    return policy, plan, calibration


class ExactGrant:
    def __init__(self):
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


class FakeMutationCoordinator:
    def __init__(self, records, *, failure=None, replayed=False):
        self.records = {record.record_id: record for record in records}
        self.failure = failure
        self.replayed = replayed
        self.operations = []

    def get_record(self, identity):
        record = self.records.get(identity.record_id)
        if record is None or record.content_digest != identity.digest:
            return None
        return record

    def commit(self, operation, *, revalidate_grant):
        if self.failure is not None:
            raise self.failure
        self.operations.append(operation)
        grant = revalidate_grant(operation.grant_binding)
        if operation.action == "canary_start":
            slot = OperationSlot(
                operation.context_ref,
                "canary",
                operation.planned_fact.record_id,
                operation.planned_fact.content_digest,
                operation.slot.revision + 1,
                "2026-08-26T12:00:00.000Z",
            )
            self.records[operation.planned_fact.record_id] = operation.planned_fact
        else:
            slot = OperationSlot(
                operation.context_ref,
                "canary",
                None,
                None,
                operation.slot.revision + 1,
                "2026-08-26T12:00:00.000Z",
            )
        receipt = build_canary_mutation_receipt(
            operation, resulting_slot=slot, verified_grant=grant
        )
        return CanaryMutationResult(
            operation.planned_fact,
            receipt,
            slot,
            grant.grant_id,
            self.replayed,
        )


def start_payload(policy, plan, calibration, *, kind="authoritative"):
    authoritative = kind == "authoritative"
    return {
        "schema": CANARY_START_COMMAND_SCHEMA,
        "action": "canary_start",
        "context_ref": CONTEXT,
        "key_epoch": "test-v1",
        "expected_scope_revision": 8,
        "slot": {"revision": 0, "occupant": None},
        "idempotency_key": f"start-{kind}",
        "authority_grant_id": f"grant:start:{kind}",
        "receipt_id": f"receipt:start:{kind}",
        "trial_id": f"trial:{kind}",
        "canary_kind": kind,
        "candidate": opaque(f"candidate-{kind}"),
        "incumbent_profile": opaque("incumbent"),
        "disposition": {
            "record": opaque(f"disposition-{kind}"),
            "state": "promotion_ready" if authoritative else "review_only",
        },
        "policy": exact(policy),
        "calibration": exact(calibration) if authoritative else None,
        "canary_plan": exact(plan),
        "environment_ref": "environment:test",
        "operator_reason_code": (
            "authoritative_canary_requested"
            if authoritative
            else "diagnostic_canary_requested"
        ),
    }


def adapter(coordinator, grant):
    return CanaryCommandAdapter(
        key_epoch="test-v1",
        mutation_coordinator=coordinator,
        start_grant_revalidator=grant,
        stop_grant_revalidator=grant,
    )


def handle(instance, payload):
    return instance.handle(
        payload,
        bound_context_ref=CONTEXT,
        issuer_ref="issuer:local",
        subject_ref="operator:test",
        session_nonce="session:canary",
        now=NOW,
    )


def test_authoritative_start_is_exact_grant_bound_and_receipt_bearing():
    policy, plan, calibration = planning_records()
    grant = ExactGrant()
    coordinator = FakeMutationCoordinator((policy, plan, calibration))
    response = handle(adapter(coordinator, grant), start_payload(policy, plan, calibration))

    assert response.status_code == 200
    assert response.body["accepted"] is True
    assert response.body["result_state"] == "authoritative_started"
    assert response.body["authority_ceiling"] == "activation_authority"
    assert response.body["activation_authoritative"] is False
    assert response.body["receipt_ref"] == "receipt:start:authoritative"
    binding = grant.bindings[-1]
    assert binding.action == "canary_start"
    assert binding.purpose == "operator_mutation"
    assert binding.context_ref == CONTEXT
    assert binding.target_revision == 8
    coordinator.replayed = True
    replay = handle(adapter(coordinator, grant), start_payload(policy, plan, calibration))
    assert replay.status_code == 200
    assert replay.body["receipt_ref"] == response.body["receipt_ref"]
    assert replay.body["replayed"] is True


def test_diagnostic_start_and_stop_never_gain_activation_authority():
    policy, plan, calibration = planning_records()
    grant = ExactGrant()
    coordinator = FakeMutationCoordinator((policy, plan, calibration))
    started = handle(
        adapter(coordinator, grant),
        start_payload(policy, plan, calibration, kind="diagnostic"),
    )
    assert started.status_code == 200
    assert started.body["authority_ceiling"] == "no_promotion_authority"
    assert started.body["activation_authoritative"] is False
    trial = coordinator.records["trial:diagnostic"]
    stop = {
        "schema": CANARY_STOP_COMMAND_SCHEMA,
        "action": "canary_stop",
        "context_ref": CONTEXT,
        "key_epoch": "test-v1",
        "expected_scope_revision": 8,
        "slot": {"revision": 1, "occupant": exact(trial)},
        "idempotency_key": "stop-diagnostic",
        "authority_grant_id": "grant:stop:diagnostic",
        "receipt_id": "receipt:stop:diagnostic",
        "conclusion_id": "conclusion:diagnostic",
        "trial": exact(trial),
        "candidate": opaque("candidate-diagnostic"),
        "disposition": {
            "record": opaque("disposition-diagnostic"),
            "state": "review_only",
        },
        "policy": exact(policy),
        "calibration": None,
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
    stopped = handle(adapter(coordinator, grant), stop)
    assert stopped.status_code == 200
    assert stopped.body["result_state"] == "stopped"
    assert stopped.body["canary_kind"] == "diagnostic"
    assert stopped.body["authority_ceiling"] == "no_promotion_authority"
    assert stopped.body["activation_authoritative"] is False
    assert grant.bindings[-1].action == "canary_stop"


def test_closed_schema_is_400_and_context_authority_mismatch_is_422():
    policy, plan, calibration = planning_records()
    grant = ExactGrant()
    coordinator = FakeMutationCoordinator((policy, plan, calibration))
    instance = adapter(coordinator, grant)
    malformed = {**start_payload(policy, plan, calibration), "unexpected": True}
    assert handle(instance, malformed).status_code == 400
    wrong_context = {**start_payload(policy, plan, calibration), "context_ref": "context:other"}
    assert handle(instance, wrong_context).status_code == 422


def test_cas_conflict_is_409_and_missing_mutation_coordinator_is_503():
    policy, plan, calibration = planning_records()
    grant = ExactGrant()
    conflict = FakeMutationCoordinator(
        (policy, plan, calibration), failure=RevisionConflict("stale")
    )
    payload = start_payload(policy, plan, calibration)
    assert handle(adapter(conflict, grant), payload).status_code == 409
    unavailable = CanaryCommandAdapter(
        key_epoch="test-v1",
        mutation_coordinator=None,
        start_grant_revalidator=grant,
        stop_grant_revalidator=grant,
    )
    assert handle(unavailable, payload).status_code == 503
