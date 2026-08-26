from __future__ import annotations

from dataclasses import replace

import pytest

from usr.plugins.dspy_rlm.helpers.v3.evidence import (
    EVIDENCE_BUNDLE_SCHEMA_ID,
    EVIDENCE_REGISTRY,
    ActivationPolicyInput,
    BucketEvidence,
    BucketRule,
    EvidenceError,
    FamilyEvidence,
    FamilyRequirement,
    Rational,
    ReductionContext,
    build_activation_policy,
    build_evaluation_envelope,
    build_evidence_bundle,
    reduce_evidence,
)
from usr.plugins.dspy_rlm.helpers.v3.fixtures import assessment_profile, execution_profile
from usr.plugins.dspy_rlm.helpers.v3.schemas import SchemaValidationError, build_typed_record


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
NOW = 1_788_000_000


def _policy_input(*, calibrated: bool = True, hard_failures=("safety_veto",)):
    return ActivationPolicyInput(
        policy_ref="policy.strict.v1",
        revision=1,
        calibration_state="approved" if calibrated else "unapproved",
        calibration_artifact_ref="calibration.test.v1" if calibrated else None,
        calibration_artifact_digest=DIGEST_C if calibrated else None,
        maximum_evidence_age_seconds=300,
        required_families=("family.alpha",),
        family_requirements=(FamilyRequirement("family.alpha", 10),),
        required_buckets=("decision_making",),
        bucket_rules=(
            BucketRule(
                bucket_ref="decision_making",
                minimum_completed_pairs=10,
                minimum_candidate_pass_rate=Rational(4, 5),
                maximum_candidate_failure_rate=Rational(1, 5),
                maximum_noninferiority_gap=Rational(1, 10),
            ),
        ),
        candidate_hard_failure_codes=tuple(hard_failures),
    )


def _authorities(*, calibrated: bool = True, hard_failures=("safety_veto",)):
    policy = build_activation_policy(
        _policy_input(calibrated=calibrated, hard_failures=hard_failures),
        context_ref="context.alpha",
        key_epoch="evidence.v1",
    )
    execution = execution_profile(
        runtime_digest=DIGEST_A,
        model_configuration_digest=DIGEST_B,
        replay_adapter_digest=DIGEST_C,
        behavior_configuration_digest=DIGEST_A,
    )
    assessment = assessment_profile(
        validator_profile_digest=DIGEST_A,
        activation_policy_digest=policy.content_digest,
        threshold_profile_digest=DIGEST_B,
        freshness_policy_digest=DIGEST_C,
        replay_seed=7,
        required_buckets=("decision_making",),
    )
    envelope = build_evaluation_envelope(
        context_ref="context.alpha",
        frozen_at_epoch_seconds=NOW - 20,
        execution_profile=execution,
        assessment_profile=assessment,
        fixture_manifest_id="fixture_manifest.alpha",
        fixture_manifest_digest=DIGEST_A,
        activation_policy=policy,
        capability_certificate_id="replay_certificate.alpha",
        capability_certificate_digest=DIGEST_B,
        key_epoch="evidence.v1",
    )
    return policy, envelope


def _bundle(
    envelope,
    *,
    observed_at=NOW - 10,
    scope_revision=3,
    candidate_passes=9,
    incumbent_passes=9,
    unavailable=(),
    family_hard_failures=(),
    bucket_hard_failures=(),
):
    return build_evidence_bundle(
        context_ref="context.alpha",
        candidate_id="candidate.alpha",
        candidate_digest=DIGEST_C,
        incumbent_profile_id="profile.incumbent",
        incumbent_profile_digest=DIGEST_B,
        activation_scope_ref="scope.alpha",
        activation_scope_revision=scope_revision,
        evaluation_envelope=envelope,
        evidence_observed_at_epoch_seconds=observed_at,
        global_unavailability_codes=tuple(unavailable),
        global_candidate_hard_failure_codes=(),
        family_summaries=(
            FamilyEvidence(
                "family.alpha",
                10,
                10,
                (),
                tuple(family_hard_failures),
            ),
        ),
        bucket_summaries=(
            BucketEvidence(
                "family.alpha",
                "decision_making",
                10,
                candidate_passes,
                incumbent_passes,
                (),
                tuple(bucket_hard_failures),
            ),
        ),
        key_epoch="evidence.v1",
    )


def _context(*, now=NOW, revision=3, incumbent_digest=DIGEST_B):
    return ReductionContext(
        observed_at_epoch_seconds=now,
        current_scope_revision=revision,
        current_incumbent_profile_id="profile.incumbent",
        current_incumbent_profile_digest=incumbent_digest,
    )


def test_exact_rational_policy_and_bound_envelope_reduce_to_promotion_ready() -> None:
    policy, envelope = _authorities()
    bundle = _bundle(envelope)

    result = reduce_evidence(
        bundle,
        envelope,
        policy,
        context=_context(),
        key_epoch="evidence.v1",
    )

    assert result.disposition == "promotion_ready"
    assert result.record.payload["global_reason_codes"] == ["all_requirements_satisfied"]
    assert result.record.payload["family_reasons"][0]["reason_codes"] == [
        "family_coverage_satisfied"
    ]
    assert result.record.payload["bucket_reasons"][0]["reason_codes"] == [
        "bucket_policy_satisfied"
    ]
    result.record.verify(EVIDENCE_REGISTRY)


def test_unavailability_cannot_turn_bad_partial_metrics_into_candidate_rejection() -> None:
    policy, envelope = _authorities()
    bundle = _bundle(
        envelope,
        candidate_passes=1,
        incumbent_passes=10,
        unavailable=("provider_unavailable",),
    )

    result = reduce_evidence(
        bundle, envelope, policy, context=_context(), key_epoch="evidence.v1"
    )

    assert result.disposition == "review_only"
    assert "provider_unavailable" in result.record.payload["global_reason_codes"]
    assert "authoritative_evidence_unavailable" in result.record.payload["global_reason_codes"]
    assert "candidate_pass_rate_below_minimum" in result.record.payload["bucket_reasons"][0][
        "reason_codes"
    ]


def test_policy_recognized_candidate_hard_failure_is_rejected_even_when_harness_is_unavailable() -> None:
    policy, envelope = _authorities(hard_failures=("safety_veto",))
    bundle = _bundle(
        envelope,
        unavailable=("harness_unavailable",),
        family_hard_failures=("safety_veto",),
    )

    result = reduce_evidence(
        bundle, envelope, policy, context=_context(), key_epoch="evidence.v1"
    )

    assert result.disposition == "rejected"
    assert "candidate_hard_failure" in result.record.payload["global_reason_codes"]
    assert result.record.payload["family_reasons"][0]["reason_codes"] == ["safety_veto"]


def test_evidence_stale_and_lineage_stale_are_independent_review_only_conditions() -> None:
    policy, envelope = _authorities()
    old_bundle = _bundle(envelope, observed_at=NOW - 301)
    fresh_bundle = _bundle(envelope)

    evidence_stale = reduce_evidence(
        old_bundle, envelope, policy, context=_context(), key_epoch="evidence.v1"
    )
    lineage_stale = reduce_evidence(
        fresh_bundle,
        envelope,
        policy,
        context=_context(revision=4),
        key_epoch="evidence.v1",
    )

    assert (evidence_stale.disposition, evidence_stale.evidence_stale, evidence_stale.lineage_stale) == (
        "review_only",
        True,
        False,
    )
    assert (lineage_stale.disposition, lineage_stale.evidence_stale, lineage_stale.lineage_stale) == (
        "review_only",
        False,
        True,
    )
    assert "evidence_stale" in evidence_stale.record.payload["global_reason_codes"]
    assert "lineage_stale" in lineage_stale.record.payload["global_reason_codes"]


def test_inputs_are_explicit_integer_only_and_records_reject_content_fields() -> None:
    with pytest.raises(EvidenceError):
        Rational(0.8, 1)  # type: ignore[arg-type]
    with pytest.raises(EvidenceError):
        replace(_policy_input(), family_requirements=())

    _, envelope = _authorities()
    bundle = _bundle(envelope)
    payload = bundle.payload | {"transcript": "must not enter the safe store"}
    with pytest.raises(SchemaValidationError):
        build_typed_record(
            record_id=bundle.record_id,
            context_ref=bundle.context_ref,
            record_kind="evidence_bundle",
            schema_id=EVIDENCE_BUNDLE_SCHEMA_ID,
            payload=payload,
            key_epoch=bundle.key_epoch,
            registry=EVIDENCE_REGISTRY,
        )
    encoded = bundle.canonical_bytes.decode("utf-8")
    assert all(token not in encoded for token in ("transcript", "provider_name", "raw_content", "/tmp/"))
