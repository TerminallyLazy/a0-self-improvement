from __future__ import annotations

from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.fixtures import FIXTURE_MANIFEST_SCHEMA_ID
from usr.plugins.dspy_rlm.helpers.v3.model_routes import BoundIdentity
from usr.plugins.dspy_rlm.helpers.v3.outcome_gepa import (
    LEGACY_RULE_LABEL_METRIC_ID,
    LEGACY_TOKEN_OVERLAP_TELEMETRY_ID,
    OPTIMIZATION_BUDGET_DIMENSIONS,
    CandidateBenefitClaim,
    GepaAdmissionRequest,
    OutcomeGepaError,
    Rational,
    StagedCompiledOutput,
    WeightedMetricSource,
    admit_outcome_gepa,
    build_legacy_search_telemetry,
    build_optimization_metric_profile,
    build_optimization_run_budget_plan,
    evaluate_optimization_metric,
    validate_staged_compiled_output,
    OUTCOME_GEPA_REGISTRY,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import SchemaValidationError, build_typed_record


CONTEXT = "context:gepa"
KEY_EPOCH = "test-v1"


def identity(name: str) -> BoundIdentity:
    return BoundIdentity(f"ref:{name}", sha256(name.encode()).hexdigest())


def manifest(name: str, partition: str, family: str):
    execution = identity("execution")
    assessment = identity("assessment")
    payload = {
        "record_type": "fixture_manifest",
        "selection_policy_ref": "policy:partition-v1",
        "execution_profile_id": execution.ref,
        "execution_profile_digest": execution.digest,
        "assessment_profile_id": assessment.ref,
        "assessment_profile_digest": assessment.digest,
        "entries": [
            {
                "ordinal": 0,
                "draft_id": f"draft:{name}",
                "draft_digest": sha256(f"draft:{name}".encode()).hexdigest(),
                "admission_id": f"fixture-admission:{name}",
                "admission_digest": sha256(f"admit:{name}".encode()).hexdigest(),
                "family_id": family,
                "family_digest": sha256(family.encode()).hexdigest(),
                "partition": partition,
            }
        ],
        "links": [],
    }
    return build_typed_record(
        record_id=f"manifest:{name}",
        context_ref=CONTEXT,
        record_kind="fixture_manifest",
        schema_id=FIXTURE_MANIFEST_SCHEMA_ID,
        payload=payload,
        key_epoch=KEY_EPOCH,
        registry=OUTCOME_GEPA_REGISTRY,
    )


def metric_profile():
    return build_optimization_metric_profile(
        record_id="metric:1",
        context_ref=CONTEXT,
        key_epoch=KEY_EPOCH,
        benefit_claim=CandidateBenefitClaim(identity("claim"), "outcome", "shell"),
        scalar_minimum=Rational(0, 1),
        scalar_maximum=Rational(100, 1),
        failure_score=Rational(0, 1),
        outcome_dimensions=(WeightedMetricSource(identity("outcome"), Rational(1, 1)),),
        bucket_validators=(
            WeightedMetricSource(identity("validator"), Rational(1, 1), "shell"),
        ),
    )


def budget_plan():
    limits = {name: 100 for name in OPTIMIZATION_BUDGET_DIMENSIONS}
    limits.update(
        run_concurrency=2,
        context_concurrency=2,
        provider_concurrency=2,
        host_concurrency=2,
    )
    return build_optimization_run_budget_plan(
        record_id="budget:1",
        context_ref=CONTEXT,
        key_epoch=KEY_EPOCH,
        budget_profile=identity("budget-profile"),
        budget_ledger_ref="ledger:1",
        budget_reservation_ref="reservation:1",
        limits=limits,
        dspy_gepa_max_metric_calls=20,
        dspy_rlm_max_llm_calls=10,
        dspy_gepa_num_threads=2,
    )


def admission_request(*, training=None, tuning=None):
    return GepaAdmissionRequest(
        receipt_id="gepa-admission:1",
        context_ref=CONTEXT,
        key_epoch=KEY_EPOCH,
        incumbent_profile=identity("incumbent"),
        activation_scope=identity("scope"),
        observed_scope_revision=7,
        target_slot="structured_guidance",
        successor_shape=identity("successor-shape"),
        candidate_risk_tier="standard",
        benefit_claim=CandidateBenefitClaim(identity("claim"), "outcome", "shell"),
        execution_profile=identity("execution"),
        assessment_profile=identity("assessment"),
        metric_profile=metric_profile(),
        training_manifest=training or manifest("train", "training", "family:train"),
        tuning_manifest=tuning or manifest("tune", "tuning", "family:tune"),
        replay_capability=identity("replay-capability"),
        worker_dependency_profile=identity("worker-dependency"),
        model_use_grant=identity("model-use-grant"),
        budget_plan=budget_plan(),
    )


def test_metric_is_exact_claim_aligned_search_only_and_reason_coded():
    profile = metric_profile()
    result = evaluate_optimization_metric(
        profile,
        component_values={
            identity("outcome").ref: Rational(1, 1),
            identity("validator").ref: Rational(1, 2),
        },
    )
    assert result.score == Rational(75, 1)
    assert result.authority_ceiling == "search_only"
    assert result.feedback_reason_codes == (
        "claim_bucket_below_full_score",
        "metric_component_below_full_score",
    )
    invalid = evaluate_optimization_metric(profile, component_values={}, proposal_state="invalid")
    assert invalid.score == Rational(0, 1)
    assert invalid.feedback_reason_codes == ("proposal_invalid",)

    with pytest.raises(SchemaValidationError, match="claim bucket"):
        build_optimization_metric_profile(
            record_id="metric:bad",
            context_ref=CONTEXT,
            key_epoch=KEY_EPOCH,
            benefit_claim=CandidateBenefitClaim(identity("other-claim"), "outcome", "reasoning"),
            scalar_minimum=Rational(0, 1),
            scalar_maximum=Rational(1, 1),
            failure_score=Rational(0, 1),
            outcome_dimensions=(WeightedMetricSource(identity("dimension-2"), Rational(1, 1)),),
            bucket_validators=(WeightedMetricSource(identity("validator-2"), Rational(1, 1), "shell"),),
        )


def test_cumulative_budget_makes_every_library_knob_subordinate():
    plan = budget_plan()
    assert plan.payload["library_knob_authority"] == "subordinate_only"
    assert [item["dimension"] for item in plan.payload["limits"]] == list(
        OPTIMIZATION_BUDGET_DIMENSIONS
    )
    limits = {name: 1 for name in OPTIMIZATION_BUDGET_DIMENSIONS}
    with pytest.raises(OutcomeGepaError, match="max_metric_calls"):
        build_optimization_run_budget_plan(
            record_id="budget:bad",
            context_ref=CONTEXT,
            key_epoch=KEY_EPOCH,
            budget_profile=identity("budget-profile"),
            budget_ledger_ref="ledger:bad",
            budget_reservation_ref="reservation:bad",
            limits=limits,
            dspy_gepa_max_metric_calls=2,
            dspy_rlm_max_llm_calls=1,
            dspy_gepa_num_threads=1,
        )


def test_admission_freezes_authority_and_blocks_overlap_or_holdout():
    receipt = admit_outcome_gepa(admission_request())
    assert receipt.payload["status"] == "admitted"
    assert receipt.payload["engine_semantic_id"] == "a0.generate.guidance.outcome_gepa.v1"
    assert receipt.payload["partition_contract"] == "family_disjoint_training_tuning_only.v1"
    assert receipt.payload["certification_holdout_access"] == "forbidden_until_artifact_locked"
    assert receipt.payload["promotion_authority"] == "none"

    with pytest.raises(OutcomeGepaError, match="overlap"):
        admit_outcome_gepa(
            admission_request(
                training=manifest("train-overlap", "training", "family:same"),
                tuning=manifest("tune-overlap", "tuning", "family:same"),
            )
        )
    with pytest.raises(OutcomeGepaError, match="Holdout"):
        admit_outcome_gepa(
            admission_request(
                tuning=manifest("holdout", "certification_holdout", "family:holdout")
            )
        )


def test_compiled_output_is_staged_only_and_boundary_breach_aborts():
    admission = admit_outcome_gepa(admission_request())
    exact_admission = BoundIdentity(admission.record_id, admission.content_digest)
    valid = StagedCompiledOutput(
        validation_id="compiled-validation:ok",
        admission=exact_admission,
        target_slot="structured_guidance",
        successor_shape=identity("successor-shape"),
        artifact=identity("compiled-artifact"),
        budget_terminal_receipt=identity("budget-terminal"),
        worker_completed=True,
        schema_valid=True,
        cleanup_verified=True,
        live_tool_boundary_intact=True,
        secret_boundary_intact=True,
        fixture_authority_boundary_intact=True,
        sandbox_boundary_intact=True,
        protected_constraints_intact=True,
    )
    receipt = validate_staged_compiled_output(
        admission=admission, output=valid, context_ref=CONTEXT, key_epoch=KEY_EPOCH
    )
    assert receipt.payload["status"] == "valid"
    assert receipt.payload["publication_state"] == "not_published"
    assert receipt.payload["publication_planner_eligible"] is True
    assert receipt.payload["promotion_authority"] == "none"
    assert receipt.payload["evidence_authority"] == "none"

    breached = StagedCompiledOutput(
        **{
            field: getattr(valid, field)
            for field in valid.__dataclass_fields__
            if field not in ("validation_id", "live_tool_boundary_intact")
        },
        validation_id="compiled-validation:breach",
        live_tool_boundary_intact=False,
    )
    aborted = validate_staged_compiled_output(
        admission=admission, output=breached, context_ref=CONTEXT, key_epoch=KEY_EPOCH
    )
    assert aborted.payload["status"] == "aborted"
    assert aborted.payload["reason_codes"] == ["live_tool_boundary_breach"]


def test_legacy_surrogates_keep_exact_labels_and_no_authority():
    for method_id in (LEGACY_RULE_LABEL_METRIC_ID, LEGACY_TOKEN_OVERLAP_TELEMETRY_ID):
        record = build_legacy_search_telemetry(
            record_id=f"telemetry:{method_id}",
            context_ref=CONTEXT,
            key_epoch=KEY_EPOCH,
            method_id=method_id,
            run=identity("legacy-run"),
            input_identity=identity("legacy-input"),
            score=Rational(1, 2),
        )
        assert record.payload["method_id"] == method_id
        assert record.payload["telemetry_class"] == "search_diagnostic"
        assert record.payload["promotion_authority"] == "none"
        assert record.payload["evidence_authority"] == "none"
