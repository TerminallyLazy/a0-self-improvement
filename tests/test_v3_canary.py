from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    BucketOutcome,
    CanaryConclusionRequest,
    CanaryCoordinator,
    CanaryPolicyDenied,
    CanaryStartRequest,
    Rational,
    RecordIdentity,
    activation_policy,
    canary_plan,
    monitor_plan,
    policy_calibration,
)


_CONTEXT = "context:canary"
_SECRET = b"canary-assignment-secret-for-tests"


def _ref(name: str, digit: str) -> RecordIdentity:
    return RecordIdentity(name, digit * 64)


def _policy_bundle(*, activation_mode: str = "manual_only"):
    policy = activation_policy(
        record_id="policy:1",
        context_ref=_CONTEXT,
        policy_revision=3,
        activation_mode=activation_mode,
        key_epoch="test",
    )
    trial_plan = canary_plan(
        record_id="canary-plan:1",
        context_ref=_CONTEXT,
        horizon_exposures=4,
        expiry_seconds=900,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=sha256(
            b"a0-canary-assignment-key\0" + _SECRET
        ).hexdigest(),
        hard_veto_failure_limit=0,
        buckets=(
            BucketCalibration("ordinary", 2, Rational(1, 10), Rational(0, 1)),
            BucketCalibration("protected", 2, Rational(0, 1), Rational(0, 1)),
        ),
        key_epoch="test",
    )
    monitoring = monitor_plan(
        record_id="monitor-plan:1",
        context_ref=_CONTEXT,
        horizon_exposures=8,
        look_interval_exposures=2,
        ordinary_regression_boundary=Rational(-1, 10),
        hard_veto_failure_limit=0,
        key_epoch="test",
    )
    authorities = ("automatic", "manual") if activation_mode == "auto_after_canary" else ("manual",)
    calibration = policy_calibration(
        record_id="calibration:1",
        context_ref=_CONTEXT,
        status="approved",
        environment_ref="env:test",
        policy=policy,
        canary_plan_record=trial_plan,
        monitor_plan_record=monitoring,
        activation_authorities=authorities,
        soft_rollback_authorized=True,
        key_epoch="test",
    )
    return policy, trial_plan, monitoring, calibration


def _start_request(*, kind: str, disposition: str, calibration, occupied=None):
    policy, trial_plan, _, approved = _policy_bundle()
    return CanaryStartRequest(
        record_id=f"trial:{kind}",
        context_ref=_CONTEXT,
        canary_kind=kind,
        disposition=disposition,
        disposition_ref=_ref("disposition:1", "d"),
        candidate=_ref("candidate:1", "c"),
        incumbent_profile=_ref("profile:1", "b"),
        expected_scope_revision=4,
        observed_scope_revision=4,
        environment_ref="env:test",
        policy=policy,
        calibration=approved if calibration is True else calibration,
        plan=trial_plan,
        authority_grant=_ref("grant:1", "a"),
        authority_purpose=(
            "authoritative_canary" if kind == "authoritative" else "diagnostic_canary"
        ),
        occupied_canary_ref=occupied,
    )


def _authoritative_trial():
    coordinator = CanaryCoordinator(key_epoch="test")
    request = _start_request(
        kind="authoritative", disposition="promotion_ready", calibration=True
    )
    return coordinator, coordinator.plan_start(request), request.plan


def _outcomes(*, uncertain: bool = False):
    return (
        BucketOutcome("ordinary", 2, Rational(0, 1), uncertain),
        BucketOutcome("protected", 2, Rational(0, 1), False),
    )


def _conclusion_request(trial, **overrides):
    values = {
        "record_id": "conclusion:1",
        "trial": trial,
        "eligible_exposure_count": 4,
        "bucket_outcomes": _outcomes(),
        "candidate_hard_failure_count": 0,
        "shared_failure": False,
        "identity_drift": False,
        "cancelled": False,
        "boundary_uncertain": False,
        "operator_stopped": False,
    }
    values.update(overrides)
    return CanaryConclusionRequest(**values)


def test_policy_facts_require_explicit_integer_and_rational_calibration() -> None:
    policy, trial_plan, monitoring, calibration = _policy_bundle()

    assert policy.payload["calibration_required"] is True
    assert trial_plan.payload["horizon_exposures"] == 4
    assert trial_plan.payload["candidate_allocation"] == {"numerator": 1, "denominator": 2}
    assert calibration.payload["environment_ref"] == "env:test"
    assert calibration.payload["canary_plan_digest"] == trial_plan.content_digest
    assert calibration.payload["monitor_plan_digest"] == monitoring.content_digest
    with pytest.raises(TypeError, match="exact integers"):
        Rational(1.0, 2)  # type: ignore[arg-type]


def test_authoritative_start_requires_promotion_calibration_revision_and_empty_slot() -> None:
    coordinator = CanaryCoordinator(key_epoch="test")
    valid = _start_request(
        kind="authoritative", disposition="promotion_ready", calibration=True
    )
    trial = coordinator.plan_start(valid)

    assert trial.payload["authority_ceiling"] == "activation_authority"
    assert trial.payload["scope_revision"] == 4
    for request, reason in (
        (replace(valid, disposition="review_only"), "authoritative_canary_requires_promotion_ready"),
        (replace(valid, calibration=None), "policy_uncalibrated"),
        (replace(valid, observed_scope_revision=5), "scope_revision_conflict"),
        (replace(valid, occupied_canary_ref="trial:other"), "canary_slot_occupied"),
    ):
        with pytest.raises(CanaryPolicyDenied, match=reason):
            coordinator.plan_start(request)


def test_diagnostic_pass_remains_permanently_non_authoritative() -> None:
    coordinator = CanaryCoordinator(key_epoch="test")
    request = _start_request(kind="diagnostic", disposition="review_only", calibration=None)
    trial = coordinator.plan_start(request)
    conclusion = coordinator.plan_conclusion(
        _conclusion_request(trial), frozen_plan=request.plan
    )

    assert trial.payload["authority_ceiling"] == "no_promotion_authority"
    assert conclusion.payload["conclusion"] == "passed"
    assert conclusion.payload["activation_authoritative"] is False
    with pytest.raises(CanaryPolicyDenied, match="passed_authoritative_canary_required"):
        coordinator.activation_eligibility(
            candidate=request.candidate,
            conclusion=conclusion,
            policy=request.policy,
            calibration=None,
            environment_ref="env:test",
            expected_scope_revision=4,
            observed_scope_revision=4,
            requested_authority="manual",
        )


def test_exposure_receipt_precedes_outcome_and_assignment_is_frozen() -> None:
    coordinator, trial, trial_plan = _authoritative_trial()
    assert not coordinator.observation_eligible(
        trial=trial,
        receipt=None,
        exposure_unit_ref="unit:1",
        envelope_ref="envelope:1",
        arm="candidate",
    )
    receipt = coordinator.plan_exposure(
        record_id="exposure:1",
        trial=trial,
        active_trial=RecordIdentity.of(trial),
        observed_scope_revision=4,
        exposure_unit_ref="unit:1",
        envelope_ref="envelope:1",
        eligible=True,
        already_receipted=False,
        assignment_secret=_SECRET,
        frozen_plan=trial_plan,
    )
    assert coordinator.observation_eligible(
        trial=trial,
        receipt=receipt,
        exposure_unit_ref="unit:1",
        envelope_ref="envelope:1",
        arm=receipt.payload["arm"],
    )
    with pytest.raises(CanaryPolicyDenied, match="exposure_already_receipted"):
        coordinator.plan_exposure(
            record_id="exposure:duplicate",
            trial=trial,
            active_trial=RecordIdentity.of(trial),
            observed_scope_revision=4,
            exposure_unit_ref="unit:1",
            envelope_ref="envelope:1",
            eligible=True,
            already_receipted=True,
            assignment_secret=_SECRET,
            frozen_plan=trial_plan,
        )


def test_fixed_horizon_conclusions_fail_closed_by_reason() -> None:
    coordinator, trial, trial_plan = _authoritative_trial()
    cases = (
        ({}, "passed"),
        ({"eligible_exposure_count": 3}, "inconclusive"),
        ({"shared_failure": True}, "inconclusive"),
        ({"identity_drift": True}, "inconclusive"),
        ({"cancelled": True}, "inconclusive"),
        ({"boundary_uncertain": True}, "inconclusive"),
        ({"operator_stopped": True}, "stopped"),
        ({"candidate_hard_failure_count": 1}, "failed"),
        ({"bucket_outcomes": _outcomes(uncertain=True)}, "inconclusive"),
    )
    for index, (overrides, expected) in enumerate(cases):
        conclusion = coordinator.plan_conclusion(
            replace(_conclusion_request(trial), record_id=f"conclusion:{index}", **overrides),
            frozen_plan=trial_plan,
        )
        assert conclusion.payload["conclusion"] == expected
        assert conclusion.payload["activation_authoritative"] is (expected == "passed")


def test_activation_and_soft_rollback_require_exact_approved_calibration() -> None:
    policy, trial_plan, monitoring, calibration = _policy_bundle()
    coordinator = CanaryCoordinator(key_epoch="test")
    start = _start_request(
        kind="authoritative", disposition="promotion_ready", calibration=True
    )
    trial = coordinator.plan_start(start)
    conclusion = coordinator.plan_conclusion(
        _conclusion_request(trial), frozen_plan=trial_plan
    )
    eligibility = coordinator.activation_eligibility(
        candidate=start.candidate,
        conclusion=conclusion,
        policy=policy,
        calibration=calibration,
        environment_ref="env:test",
        expected_scope_revision=4,
        observed_scope_revision=4,
        requested_authority="manual",
    )
    monitor = coordinator.plan_monitor_start(
        record_id="monitor:1",
        context_ref=_CONTEXT,
        eligibility=eligibility,
        incumbent_profile=start.incumbent_profile,
        conclusion=conclusion,
        policy=policy,
        calibration=calibration,
        monitor_plan_record=monitoring,
    )

    assert eligibility.resulting_scope_revision == 5
    assert monitor.payload["canary_conclusion_digest"] == conclusion.content_digest
    assert coordinator.soft_rollback_eligible(
        policy=policy,
        calibration=calibration,
        environment_ref="env:test",
        expected_scope_revision=5,
        observed_scope_revision=5,
        monitor_plan_record=monitoring,
    )
    for operation in (
        lambda: coordinator.activation_eligibility(
            candidate=start.candidate,
            conclusion=conclusion,
            policy=policy,
            calibration=None,
            environment_ref="env:test",
            expected_scope_revision=4,
            observed_scope_revision=4,
            requested_authority="manual",
        ),
        lambda: coordinator.soft_rollback_eligible(
            policy=policy,
            calibration=None,
            environment_ref="env:test",
            expected_scope_revision=5,
            observed_scope_revision=5,
            monitor_plan_record=monitoring,
        ),
    ):
        with pytest.raises(CanaryPolicyDenied, match="policy_uncalibrated"):
            operation()
