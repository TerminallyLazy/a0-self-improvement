from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.authority import (
    AuthorityAction,
    AuthorityClass,
    AuthorityPurpose,
    VerifiedGrant,
)
from usr.plugins.dspy_rlm.helpers.v3.calibration_authority import (
    CALIBRATION_AUTHORITY_REGISTRY,
    CalibrationApprovalRequest,
    CalibrationGrantBinding,
    CalibrationLifecycleFact,
    CalibrationWithdrawalRequest,
    ExactRecord,
    approve_policy_calibration,
    reduce_calibration_eligibility,
    withdraw_policy_calibration,
)
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    Rational,
    activation_policy,
    canary_plan,
    monitor_plan,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
    IntegrityFailure,
    V3Repository,
)


CONTEXT = "context:calibration"
OTHER_CONTEXT = "context:other"
NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)


def digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def create_repository(tmp_path):
    repository = V3Repository.create(
        tmp_path / "calibration.sqlite", registry=CALIBRATION_AUTHORITY_REGISTRY
    )
    policy = activation_policy(
        record_id="policy:1",
        context_ref=CONTEXT,
        policy_revision=4,
        activation_mode="canary_required",
        key_epoch="test-v1",
    )
    canary = canary_plan(
        record_id="canary-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=10,
        expiry_seconds=3600,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=digest("assignment-key"),
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
    with repository.transaction() as transaction:
        for record in (policy, canary, monitor):
            transaction.insert_record(record)
    return repository, policy, canary, monitor


def approval_request(policy, canary, monitor, *, key="approval-key"):
    return CalibrationApprovalRequest(
        calibration_id="calibration:1",
        receipt_id="calibration-approval-receipt:1",
        context_ref=CONTEXT,
        expected_policy_revision=4,
        environment_ref="environment:test-only",
        policy=ExactRecord.of(policy),
        canary_plan=ExactRecord.of(canary),
        monitor_plan=ExactRecord.of(monitor),
        activation_authorities=("manual",),
        soft_rollback_authorized=True,
        issuer_ref="issuer:local",
        subject_ref="operator:test",
        idempotency_key_digest=digest(key),
        session_nonce="session:calibration",
        reason_code="calibration_approved",
        key_epoch="test-v1",
    )


def repository_counts(repository, context_ref):
    records = repository._connection.execute(
        "SELECT count(*) FROM typed_records WHERE context_ref = ?", (context_ref,)
    ).fetchone()[0]
    events = repository._connection.execute(
        """SELECT count(*) FROM domain_events event
           LEFT JOIN typed_records payload ON payload.record_id = event.payload_record_id
           LEFT JOIN typed_records subject ON subject.record_id = event.subject_id
           WHERE COALESCE(payload.context_ref, subject.context_ref) = ?""",
        (context_ref,),
    ).fetchone()[0]
    commands = repository._connection.execute(
        "SELECT count(*) FROM operator_commands WHERE context_ref = ?", (context_ref,)
    ).fetchone()[0]
    return records, events, commands


class ExactGrantRevalidator:
    def __init__(self) -> None:
        self.bindings: list[CalibrationGrantBinding] = []

    def __call__(self, binding: CalibrationGrantBinding) -> VerifiedGrant:
        self.bindings.append(binding)
        return VerifiedGrant(
            grant_id=f"grant:{binding.operation}:{len(self.bindings)}",
            authority_class=AuthorityClass.POLICY_CALIBRATION_APPROVAL.value,
            issuer_id=binding.issuer_ref,
            key_epoch=1,
            subject_ref=binding.subject_ref,
            context_ref=binding.context_ref,
            action=AuthorityAction.POLICY_CALIBRATE.value,
            purpose=AuthorityPurpose.POLICY_CALIBRATION.value,
            target_ref=binding.target_ref,
            target_revision=binding.target_revision,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            idempotency_key_digest=binding.idempotency_key_digest,
            session_nonce=binding.session_nonce,
        )


def test_approval_is_exact_grant_bound_and_current(tmp_path):
    repository, policy, canary, monitor = create_repository(tmp_path)
    revalidator = ExactGrantRevalidator()
    request = approval_request(policy, canary, monitor)
    result = approve_policy_calibration(
        repository, request=request, revalidate_grant=revalidator
    )

    assert result.replayed is False
    assert result.calibration.payload["status"] == "approved"
    assert result.receipt.payload["operation"] == "approve"
    assert result.event.event_type == "policy_calibration_approved"
    binding = revalidator.bindings[-1]
    assert binding.action == AuthorityAction.POLICY_CALIBRATE.value
    assert binding.purpose == AuthorityPurpose.POLICY_CALIBRATION.value
    assert binding.policy == ExactRecord.of(policy)
    assert binding.canary_plan == ExactRecord.of(canary)
    assert binding.monitor_plan == ExactRecord.of(monitor)
    assert binding.environment_ref == request.environment_ref
    assert binding.target_revision == 4
    eligibility = reduce_calibration_eligibility(
        result.calibration, (CalibrationLifecycleFact(result.receipt, result.event),)
    )
    assert eligibility.state == "approved"
    repository.close()


def test_withdrawal_is_append_only_and_pure_reducer_returns_withdrawn(tmp_path):
    repository, policy, canary, monitor = create_repository(tmp_path)
    revalidator = ExactGrantRevalidator()
    approved = approve_policy_calibration(
        repository,
        request=approval_request(policy, canary, monitor),
        revalidate_grant=revalidator,
    )
    request = CalibrationWithdrawalRequest(
        receipt_id="calibration-withdrawal-receipt:1",
        context_ref=CONTEXT,
        expected_policy_revision=4,
        environment_ref="environment:test-only",
        calibration=ExactRecord.of(approved.calibration),
        issuer_ref="issuer:local",
        subject_ref="operator:test",
        idempotency_key_digest=digest("withdrawal-key"),
        session_nonce="session:calibration",
        reason_code="calibration_withdrawn",
        key_epoch="test-v1",
    )
    withdrawn = withdraw_policy_calibration(
        repository, request=request, revalidate_grant=revalidator
    )

    assert withdrawn.calibration == approved.calibration
    assert withdrawn.calibration.payload["status"] == "approved"
    assert withdrawn.receipt.payload["operation"] == "withdraw"
    assert withdrawn.event.sequence == 1
    eligibility = reduce_calibration_eligibility(
        approved.calibration,
        (
            CalibrationLifecycleFact(approved.receipt, approved.event),
            CalibrationLifecycleFact(withdrawn.receipt, withdrawn.event),
        ),
    )
    assert eligibility.state == "withdrawn"
    assert eligibility.reason_codes == ("calibration_withdrawn",)
    repository.close()


def test_same_request_replays_exactly_and_changed_request_fails_before_writes(tmp_path):
    repository, policy, canary, monitor = create_repository(tmp_path)
    revalidator = ExactGrantRevalidator()
    request = approval_request(policy, canary, monitor)
    first = approve_policy_calibration(
        repository, request=request, revalidate_grant=revalidator
    )
    replay = approve_policy_calibration(
        repository, request=request, revalidate_grant=revalidator
    )
    assert replay.replayed is True
    assert replay.calibration == first.calibration
    assert replay.receipt == first.receipt
    assert replay.event == first.event

    counts = repository_counts(repository, CONTEXT)
    with pytest.raises(IdempotencyConflict):
        approve_policy_calibration(
            repository,
            request=replace(request, receipt_id="calibration-approval-receipt:changed"),
            revalidate_grant=revalidator,
        )
    assert counts == repository_counts(repository, CONTEXT)
    repository.close()


def test_missing_tampered_or_cross_context_exact_records_fail_closed(tmp_path):
    repository, policy, canary, monitor = create_repository(tmp_path)
    revalidator = ExactGrantRevalidator()
    request = approval_request(policy, canary, monitor)
    for changed in (
        replace(request, policy=ExactRecord("policy:missing", digest("missing"))),
        replace(request, canary_plan=ExactRecord(canary.record_id, digest("tampered"))),
        replace(
            request,
            context_ref=OTHER_CONTEXT,
            idempotency_key_digest=digest("cross-context-key"),
        ),
    ):
        with pytest.raises(IntegrityFailure):
            approve_policy_calibration(
                repository, request=changed, revalidate_grant=revalidator
            )
    assert repository_counts(repository, CONTEXT)[1:] == (0, 0)
    repository.close()
