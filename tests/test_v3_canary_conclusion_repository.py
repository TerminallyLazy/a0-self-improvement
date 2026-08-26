from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    BucketOutcome,
    CanaryConclusionRequest,
    CanaryCoordinator,
    CanaryStartRequest,
    Rational,
    RecordIdentity,
    activation_policy,
    canary_plan,
    monitor_plan,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.canary_command_adapter import (
    CANARY_COMMAND_REGISTRY,
    ExactRecord,
    SlotBinding,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_conclusion_repository import (
    CANARY_CONCLUSION_ACTION,
    CANARY_CONCLUSION_REPOSITORY_REGISTRY,
    CanaryConclusionAuthority,
    CanaryConclusionOperation,
    RepositoryCanaryConclusionCoordinator,
    build_certified_canary_outcome_authority,
    digest_canary_conclusion_request,
)
from usr.plugins.dspy_rlm.helpers.v3.calibration_authority import (
    CALIBRATION_AUTHORITY_REGISTRY,
    CalibrationApprovalRequest,
    CalibrationWithdrawalRequest,
    ExactRecord as CalibrationExactRecord,
    approve_policy_calibration,
    withdraw_policy_calibration,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
    IntegrityFailure,
    RevisionConflict,
    V3Repository,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import (
    RecordSchema,
    SchemaRegistry,
    build_typed_record,
    merge_schema_registries,
    strict_literal,
    strict_object,
    validate_links,
)


CONTEXT = "context:canary-conclusion"
KEY_EPOCH = "test-v1"
EXACT_SCHEMA_ID = "test.canary-conclusion-exact.v1"
TEST_REGISTRY = merge_schema_registries(
    CANARY_COMMAND_REGISTRY,
    CANARY_CONCLUSION_REPOSITORY_REGISTRY,
    CALIBRATION_AUTHORITY_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                EXACT_SCHEMA_ID,
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


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _exact_record(record_id: str):
    return build_typed_record(
        record_id=record_id,
        context_ref=CONTEXT,
        record_kind="test_exact",
        schema_id=EXACT_SCHEMA_ID,
        payload={"fact_type": "test_exact", "links": []},
        key_epoch=KEY_EPOCH,
        registry=TEST_REGISTRY,
    )


def _calibration_grant(binding):
    now = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
    return VerifiedGrant(
        grant_id=f"grant:calibration:{binding.operation}",
        authority_class=binding.authority_class,
        issuer_id=binding.issuer_ref,
        key_epoch=1,
        subject_ref=binding.subject_ref,
        context_ref=binding.context_ref,
        action=binding.action,
        purpose=binding.purpose,
        target_ref=binding.target_ref,
        target_revision=binding.target_revision,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        idempotency_key_digest=binding.idempotency_key_digest,
        session_nonce=binding.session_nonce,
    )


def _seed(tmp_path, *, admission_kind: str, diagnostic: bool = False):
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
        activation_mode=(
            "auto_after_canary" if admission_kind == "automation" else "canary_required"
        ),
        key_epoch=KEY_EPOCH,
    )
    plan = canary_plan(
        record_id="canary-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=4,
        expiry_seconds=900,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=_digest("assignment"),
        hard_veto_failure_limit=0,
        buckets=(
            BucketCalibration("ordinary", 2, Rational(0, 1), Rational(0, 1)),
        ),
        key_epoch=KEY_EPOCH,
    )
    monitoring = monitor_plan(
        record_id="monitor-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=8,
        look_interval_exposures=2,
        ordinary_regression_boundary=Rational(0, 1),
        hard_veto_failure_limit=0,
        key_epoch=KEY_EPOCH,
    )
    candidate = _exact_record("candidate:1")
    disposition = _exact_record("disposition:1")
    grant = _exact_record("grant:start")
    producer = _exact_record("producer:certified-outcome-reducer")
    reducer_profile = _exact_record("profile:outcome-reducer")
    reducer = build_certified_canary_outcome_authority(
        record_id="authority:certified-outcome-reducer",
        context_ref=CONTEXT,
        producer=ExactRecord.of(producer),
        reducer_profile=ExactRecord.of(reducer_profile),
        canary_plan=ExactRecord.of(plan),
        key_epoch=KEY_EPOCH,
    )
    repository = V3Repository.create(
        tmp_path / "canary-conclusion.sqlite3", registry=TEST_REGISTRY
    )
    with repository.transaction() as transaction:
        for record in (
            guidance,
            prompt,
            profile,
            policy,
            plan,
            monitoring,
            candidate,
            disposition,
            grant,
            producer,
            reducer_profile,
            reducer,
        ):
            transaction.insert_record(record)
        transaction.initialize_activation_scope(
            context_ref=CONTEXT,
            profile_id=profile.record_id,
            profile_digest=profile.content_digest,
        )

    calibration = None
    if not diagnostic:
        calibration = approve_policy_calibration(
            repository,
            request=CalibrationApprovalRequest(
                calibration_id="calibration:1",
                receipt_id="calibration-approval-receipt:1",
                context_ref=CONTEXT,
                expected_policy_revision=1,
                environment_ref="environment:test",
                policy=CalibrationExactRecord.of(policy),
                canary_plan=CalibrationExactRecord.of(plan),
                monitor_plan=CalibrationExactRecord.of(monitoring),
                activation_authorities=("automatic", "manual"),
                soft_rollback_authorized=True,
                issuer_ref="issuer:calibration",
                subject_ref="subject:calibration",
                idempotency_key_digest=_digest("calibration-approve"),
                session_nonce="session:calibration",
                reason_code="calibration_approved",
                key_epoch=KEY_EPOCH,
            ),
            revalidate_grant=_calibration_grant,
        ).calibration

    trial = CanaryCoordinator(key_epoch=KEY_EPOCH).plan_start(
        CanaryStartRequest(
            record_id="trial:1",
            context_ref=CONTEXT,
            canary_kind="diagnostic" if diagnostic else "authoritative",
            disposition="review_only" if diagnostic else "promotion_ready",
            disposition_ref=RecordIdentity.of(disposition),
            candidate=RecordIdentity.of(candidate),
            incumbent_profile=RecordIdentity.of(profile),
            expected_scope_revision=0,
            observed_scope_revision=0,
            environment_ref="environment:test",
            policy=policy,
            calibration=calibration,
            plan=plan,
            authority_grant=RecordIdentity.of(grant),
            authority_purpose=(
                "diagnostic_canary" if diagnostic else "authoritative_canary"
            ),
            occupied_canary_ref=None,
        )
    )
    with repository.transaction() as transaction:
        transaction.insert_record(trial)
        slot = transaction.claim_empty_operation_slot(
            context_ref=CONTEXT,
            operation_kind="canary",
            expected_revision=0,
            expected_scope_revision=0,
            operation_id=trial.record_id,
            operation_digest=trial.content_digest,
        )
    return repository, policy, plan, monitoring, calibration, trial, reducer, slot


def _operation(
    policy,
    plan,
    calibration,
    trial,
    reducer,
    slot,
    *,
    admission_kind: str,
    request_overrides=None,
):
    values = {
        "record_id": "conclusion:1",
        "trial": trial,
        "eligible_exposure_count": 4,
        "bucket_outcomes": (
            BucketOutcome("ordinary", 2, Rational(0, 1), False),
        ),
        "candidate_hard_failure_count": 0,
        "shared_failure": False,
        "identity_drift": False,
        "cancelled": False,
        "boundary_uncertain": False,
        "operator_stopped": False,
    }
    values.update(request_overrides or {})
    request = CanaryConclusionRequest(**values)
    authority = CanaryConclusionAuthority(
        admission_kind,
        calibration.record_id if admission_kind == "automation" else "grant:conclude",
        "issuer:policy" if admission_kind == "automation" else "issuer:operator",
        "subject:automation" if admission_kind == "automation" else "subject:operator",
    )
    operation = CanaryConclusionOperation(
        context_ref=CONTEXT,
        expected_scope_revision=0,
        slot=SlotBinding(slot.operation_revision, ExactRecord.of(trial)),
        request=request,
        canary_plan=ExactRecord.of(plan),
        policy=ExactRecord.of(policy),
        calibration=None if calibration is None else ExactRecord.of(calibration),
        certified_reducer_authority=ExactRecord.of(reducer),
        authority=authority,
        idempotency_key_digest=_digest("conclude-key"),
        request_digest="0" * 64,
        key_epoch=KEY_EPOCH,
    )
    return replace(
        operation, request_digest=digest_canary_conclusion_request(operation)
    )


class _Authority:
    def __init__(self):
        self.calls = 0

    def __call__(self, transaction, operation):
        self.calls += 1
        assert transaction.get_operation_slot(CONTEXT, "canary").operation_id == (
            operation.request.trial.record_id
        )
        return operation.authority


@pytest.mark.parametrize("admission_kind", ("operator", "automation"))
def test_exact_conclusion_is_atomic_replayable_and_admitted(tmp_path, admission_kind):
    repository, policy, plan, _monitor, calibration, trial, reducer, slot = _seed(
        tmp_path, admission_kind=admission_kind
    )
    operation = _operation(
        policy,
        plan,
        calibration,
        trial,
        reducer,
        slot,
        admission_kind=admission_kind,
    )
    authority = _Authority()
    coordinator = RepositoryCanaryConclusionCoordinator(
        repository, key_epoch=KEY_EPOCH
    )

    result = coordinator.commit(operation, revalidate_authority=authority)

    assert result.conclusion.payload["conclusion"] == "passed"
    assert result.conclusion.payload["activation_authoritative"] is True
    assert result.slot.operation_id is None
    assert result.receipt.payload["admission_kind"] == admission_kind
    assert authority.calls == 1
    with repository.transaction() as transaction:
        event = transaction.get_domain_event(
            trial.record_id, result.receipt.payload["event_sequence"]
        )
        assert event.event_type == "canary_concluded"
        command = transaction.get_operator_command(
            issuer_ref=operation.authority.issuer_ref,
            subject_ref=operation.authority.subject_ref,
            context_ref=CONTEXT,
            action=CANARY_CONCLUSION_ACTION,
            idempotency_key_digest=operation.idempotency_key_digest,
        )
        assert (command is not None) is (admission_kind == "operator")
        automation_trigger = transaction.get_record(result.admission_ref)
        assert (automation_trigger is not None) is (admission_kind == "automation")

    replay = coordinator.commit(operation, revalidate_authority=authority)
    assert replay.replayed is True
    assert replay.receipt == result.receipt
    assert authority.calls == 1

    changed = replace(
        operation,
        request=replace(operation.request, candidate_hard_failure_count=1),
        request_digest="0" * 64,
    )
    changed = replace(
        changed, request_digest=digest_canary_conclusion_request(changed)
    )
    with pytest.raises(IdempotencyConflict):
        coordinator.commit(changed, revalidate_authority=authority)
    repository.close()


def test_passed_diagnostic_conclusion_never_has_activation_authority(tmp_path):
    repository, policy, plan, _monitor, calibration, trial, reducer, slot = _seed(
        tmp_path, admission_kind="operator", diagnostic=True
    )
    operation = _operation(
        policy,
        plan,
        calibration,
        trial,
        reducer,
        slot,
        admission_kind="operator",
    )

    result = RepositoryCanaryConclusionCoordinator(
        repository, key_epoch=KEY_EPOCH
    ).commit(operation, revalidate_authority=_Authority())

    assert result.conclusion.payload["conclusion"] == "passed"
    assert result.conclusion.payload["canary_kind"] == "diagnostic"
    assert result.conclusion.payload["activation_authoritative"] is False
    assert result.receipt.payload["activation_authoritative"] is False
    repository.close()


def test_stale_state_or_failed_authority_writes_no_conclusion(tmp_path):
    repository, policy, plan, _monitor, calibration, trial, reducer, slot = _seed(
        tmp_path, admission_kind="automation"
    )
    operation = _operation(
        policy,
        plan,
        calibration,
        trial,
        reducer,
        slot,
        admission_kind="automation",
    )
    coordinator = RepositoryCanaryConclusionCoordinator(
        repository, key_epoch=KEY_EPOCH
    )

    stale = replace(operation, expected_scope_revision=1, request_digest="0" * 64)
    stale = replace(stale, request_digest=digest_canary_conclusion_request(stale))
    with pytest.raises(RevisionConflict):
        coordinator.commit(stale, revalidate_authority=_Authority())

    arbitrary_reducer = replace(
        operation,
        certified_reducer_authority=ExactRecord.of(trial),
        request_digest="0" * 64,
    )
    arbitrary_reducer = replace(
        arbitrary_reducer,
        request_digest=digest_canary_conclusion_request(arbitrary_reducer),
    )
    with pytest.raises(IntegrityFailure, match="exact record binding"):
        coordinator.commit(arbitrary_reducer, revalidate_authority=_Authority())

    def denied(_transaction, _operation):
        raise IntegrityFailure("authority_refused")

    with pytest.raises(IntegrityFailure, match="authority_refused"):
        coordinator.commit(operation, revalidate_authority=denied)

    withdraw_policy_calibration(
        repository,
        request=CalibrationWithdrawalRequest(
            receipt_id="calibration-withdrawal-receipt:1",
            context_ref=CONTEXT,
            expected_policy_revision=1,
            environment_ref="environment:test",
            calibration=CalibrationExactRecord.of(calibration),
            issuer_ref="issuer:calibration",
            subject_ref="subject:calibration",
            idempotency_key_digest=_digest("calibration-withdraw"),
            session_nonce="session:calibration",
            reason_code="calibration_withdrawn",
            key_epoch=KEY_EPOCH,
        ),
        revalidate_grant=_calibration_grant,
    )
    with pytest.raises(IntegrityFailure, match="not currently approved"):
        coordinator.commit(operation, revalidate_authority=_Authority())
    with repository.transaction() as transaction:
        assert transaction.get_record(operation.request.record_id) is None
        assert transaction.get_operation_slot(CONTEXT, "canary").operation_id == trial.record_id
    repository.close()
