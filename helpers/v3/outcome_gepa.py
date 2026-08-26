"""Pure, content-free authority contracts for outcome-aligned GEPA.

This module deliberately imports neither DSPy nor a provider SDK.  It freezes
the exact inputs that a future worker adapter may consume, evaluates an
explicit rational search metric, and validates staged compiled-output metadata.
Search scores and compiled-output validation never become evidence or
promotion authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import gcd
from typing import Any, Mapping, Sequence

from .fixtures import FIXTURE_MANIFEST_SCHEMA_ID, FIXTURE_REGISTRY
from .model_routes import BoundIdentity, MODEL_ROUTE_REGISTRY
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    merge_schema_registries,
    strict_boolean,
    strict_enum,
    strict_integer,
    strict_list,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


OPTIMIZATION_METRIC_PROFILE_SCHEMA_ID = "a0.optimization-metric-profile.v1"
OPTIMIZATION_RUN_BUDGET_PLAN_SCHEMA_ID = "a0.optimization-run-budget-plan.v1"
GEPA_ADMISSION_RECEIPT_SCHEMA_ID = "a0.gepa-admission-receipt.v1"
COMPILED_OUTPUT_VALIDATION_SCHEMA_ID = "a0.compiled-output-validation.v1"
LEGACY_SEARCH_TELEMETRY_SCHEMA_ID = "a0.legacy-search-telemetry.v1"

OUTCOME_GEPA_ENGINE_IDS = {
    "structured_guidance": "a0.generate.guidance.outcome_gepa.v1",
    "prompt_patch": "a0.generate.prompt_patch.outcome_gepa.v1",
}
LEGACY_RULE_LABEL_METRIC_ID = "a0.metric.legacy.rule_label_jaccard.v1"
LEGACY_TOKEN_OVERLAP_TELEMETRY_ID = (
    "a0.telemetry.legacy.output_token_jaccard.v1"
)
LEGACY_DIAGNOSTIC_METHOD_IDS = (
    LEGACY_RULE_LABEL_METRIC_ID,
    LEGACY_TOKEN_OVERLAP_TELEMETRY_ID,
)

OPTIMIZATION_STAGES = (
    "deterministic_preparation",
    "semantic_judging",
    "gepa_reflection",
    "task_model_evaluation",
    "replay_metric",
    "compiled_output_validation",
    "cache_miss",
    "retry",
    "prompt_components",
)
OPTIMIZATION_BUDGET_DIMENSIONS = (
    "cases",
    "cost_microunits",
    "fixture_families",
    "host_concurrency",
    "input_bytes",
    "input_tokens",
    "judge_model_calls",
    "metric_invocations",
    "output_bytes",
    "output_tokens",
    "provider_concurrency",
    "reflection_model_calls",
    "retry_attempts",
    "rlm_iterations",
    "rlm_tool_queries",
    "root_model_calls",
    "run_concurrency",
    "context_concurrency",
    "submodel_calls",
    "task_model_calls",
    "unique_variants",
    "wall_time_ms",
)
METRIC_FEEDBACK_CODES = (
    "claim_bucket_below_full_score",
    "metric_all_components_satisfied",
    "metric_component_below_full_score",
    "proposal_invalid",
    "proposal_unsafe",
)
COMPILED_OUTPUT_REASON_CODES = (
    "admission_binding_mismatch",
    "budget_terminal_receipt_missing",
    "cleanup_unverified",
    "compiled_output_valid",
    "fixture_authority_boundary_breach",
    "live_tool_boundary_breach",
    "protected_constraint_breach",
    "sandbox_boundary_breach",
    "schema_invalid",
    "secret_boundary_breach",
    "successor_shape_mismatch",
    "worker_incomplete",
)

_MAX_INTEGER = (1 << 63) - 1


class OutcomeGepaError(ValueError):
    """Raised when search authority is missing, ambiguous, or contaminated."""


@dataclass(frozen=True, slots=True)
class Rational:
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if (
            type(self.numerator) is not int
            or not -_MAX_INTEGER <= self.numerator <= _MAX_INTEGER
            or type(self.denominator) is not int
            or not 1 <= self.denominator <= _MAX_INTEGER
        ):
            raise OutcomeGepaError("rational values require bounded integer terms")
        if gcd(abs(self.numerator), self.denominator) != 1:
            raise OutcomeGepaError("rational values must be in canonical lowest terms")

    @property
    def fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)

    def as_dict(self) -> dict[str, int]:
        return {"numerator": self.numerator, "denominator": self.denominator}


@dataclass(frozen=True, slots=True)
class CandidateBenefitClaim:
    identity: BoundIdentity
    kind: str
    bucket: str

    def __post_init__(self) -> None:
        if type(self.identity) is not BoundIdentity:
            raise OutcomeGepaError("benefit claim requires an exact identity")
        if self.kind not in ("outcome", "efficiency"):
            raise OutcomeGepaError("benefit claim kind is not admitted")
        _bounded_ref(self.bucket, "benefit claim bucket", maximum=128)


@dataclass(frozen=True, slots=True)
class WeightedMetricSource:
    identity: BoundIdentity
    weight: Rational
    bucket: str | None = None

    def __post_init__(self) -> None:
        if type(self.identity) is not BoundIdentity:
            raise OutcomeGepaError("metric source requires an exact identity")
        if type(self.weight) is not Rational or self.weight.numerator <= 0:
            raise OutcomeGepaError("metric source weight must be an explicit positive rational")
        if self.bucket is not None:
            _bounded_ref(self.bucket, "validator bucket", maximum=128)


@dataclass(frozen=True, slots=True)
class OptimizationMetricResult:
    score: Rational
    feedback_reason_codes: tuple[str, ...]
    authority_ceiling: str = "search_only"


@dataclass(frozen=True, slots=True)
class GepaAdmissionRequest:
    receipt_id: str
    context_ref: str
    key_epoch: str
    incumbent_profile: BoundIdentity
    activation_scope: BoundIdentity
    observed_scope_revision: int
    target_slot: str
    successor_shape: BoundIdentity
    candidate_risk_tier: str
    benefit_claim: CandidateBenefitClaim
    execution_profile: BoundIdentity
    assessment_profile: BoundIdentity
    metric_profile: TypedRecord
    training_manifest: TypedRecord
    tuning_manifest: TypedRecord
    replay_capability: BoundIdentity
    worker_dependency_profile: BoundIdentity
    model_use_grant: BoundIdentity
    budget_plan: TypedRecord


@dataclass(frozen=True, slots=True)
class StagedCompiledOutput:
    validation_id: str
    admission: BoundIdentity
    target_slot: str
    successor_shape: BoundIdentity
    artifact: BoundIdentity
    budget_terminal_receipt: BoundIdentity | None
    worker_completed: bool
    schema_valid: bool
    cleanup_verified: bool
    live_tool_boundary_intact: bool
    secret_boundary_intact: bool
    fixture_authority_boundary_intact: bool
    sandbox_boundary_intact: bool
    protected_constraints_intact: bool


def _bounded_ref(value: Any, name: str, *, maximum: int = 512) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise OutcomeGepaError(f"{name} must be a bounded opaque reference")
    return value


def _identity_payload(identity: BoundIdentity) -> dict[str, str]:
    if type(identity) is not BoundIdentity:
        raise OutcomeGepaError("authority input is not an exact identity")
    return {"ref": identity.ref, "digest": identity.digest}


def _link(role: str, ordinal: int, identity: BoundIdentity | TypedRecord) -> dict[str, Any]:
    if type(identity) is TypedRecord:
        target_id, target_digest = identity.record_id, identity.content_digest
    elif type(identity) is BoundIdentity:
        target_id, target_digest = identity.ref, identity.digest
    else:
        raise OutcomeGepaError("record links require exact identities")
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": target_id,
        "target_digest": target_digest,
    }


_RATIONAL_VALIDATOR = strict_object(
    {
        "numerator": strict_integer(minimum=-_MAX_INTEGER, maximum=_MAX_INTEGER),
        "denominator": strict_integer(minimum=1, maximum=_MAX_INTEGER),
    }
)
_IDENTITY_VALIDATOR = strict_object(
    {"ref": strict_string(maximum=512), "digest": validate_digest}
)
_CLAIM_VALIDATOR = strict_object(
    {
        "ref": strict_string(maximum=512),
        "digest": validate_digest,
        "kind": strict_enum(("outcome", "efficiency")),
        "bucket": strict_string(maximum=128),
    }
)
_WEIGHTED_SOURCE_VALIDATOR = strict_object(
    {
        "ref": strict_string(maximum=512),
        "digest": validate_digest,
        "weight": _RATIONAL_VALIDATOR,
    }
)
_WEIGHTED_BUCKET_VALIDATOR = strict_object(
    {
        "ref": strict_string(maximum=512),
        "digest": validate_digest,
        "bucket": strict_string(maximum=128),
        "weight": _RATIONAL_VALIDATOR,
    }
)


def _metric_profile_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("optimization_metric_profile"),
            "aggregation": strict_literal("weighted_rational_mean.v1"),
            "authority_ceiling": strict_literal("search_only"),
            "benefit_claim": _CLAIM_VALIDATOR,
            "scalar_minimum": _RATIONAL_VALIDATOR,
            "scalar_maximum": _RATIONAL_VALIDATOR,
            "failure_score": _RATIONAL_VALIDATOR,
            "outcome_dimensions": strict_list(
                _WEIGHTED_SOURCE_VALIDATOR, minimum=1, maximum=128
            ),
            "bucket_validators": strict_list(
                _WEIGHTED_BUCKET_VALIDATOR, minimum=1, maximum=128
            ),
            "feedback_reason_codes": strict_list(
                strict_enum(METRIC_FEEDBACK_CODES),
                minimum=len(METRIC_FEEDBACK_CODES),
                maximum=len(METRIC_FEEDBACK_CODES),
            ),
            "links": validate_links,
        }
    )(value, path)
    if payload["feedback_reason_codes"] != list(METRIC_FEEDBACK_CODES):
        raise SchemaValidationError(f"{path}.feedback_reason_codes must be the frozen contract")
    for field in ("scalar_minimum", "scalar_maximum", "failure_score"):
        item = payload[field]
        if gcd(abs(item["numerator"]), item["denominator"]) != 1:
            raise SchemaValidationError(f"{path}.{field} is not a canonical rational")
    for group in ("outcome_dimensions", "bucket_validators"):
        refs: set[str] = set()
        for item in payload[group]:
            weight = item["weight"]
            if weight["numerator"] <= 0 or gcd(weight["numerator"], weight["denominator"]) != 1:
                raise SchemaValidationError(f"{path}.{group} has a non-canonical positive weight")
            if item["ref"] in refs:
                raise SchemaValidationError(f"{path}.{group} repeats a source")
            refs.add(item["ref"])
    claim_bucket = payload["benefit_claim"]["bucket"]
    if sum(item["bucket"] == claim_bucket for item in payload["bucket_validators"]) != 1:
        raise SchemaValidationError(f"{path} must align exactly one validator with the claim bucket")
    low = Fraction(**payload["scalar_minimum"])
    high = Fraction(**payload["scalar_maximum"])
    failure = Fraction(**payload["failure_score"])
    if not low < high or not low <= failure <= high:
        raise SchemaValidationError(f"{path} has invalid scalar bounds or failure score")
    return payload


_BUDGET_ENTRY_VALIDATOR = strict_object(
    {
        "dimension": strict_enum(OPTIMIZATION_BUDGET_DIMENSIONS),
        "limit": strict_integer(minimum=0, maximum=_MAX_INTEGER),
    }
)


def _budget_entries(value: Any, path: str) -> list[dict[str, Any]]:
    result = strict_list(
        _BUDGET_ENTRY_VALIDATOR,
        minimum=len(OPTIMIZATION_BUDGET_DIMENSIONS),
        maximum=len(OPTIMIZATION_BUDGET_DIMENSIONS),
    )(value, path)
    if [item["dimension"] for item in result] != list(OPTIMIZATION_BUDGET_DIMENSIONS):
        raise SchemaValidationError(f"{path} must explicitly cover every cumulative dimension")
    return result


_BUDGET_PLAN_BASE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("optimization_run_budget_plan"),
        "budget_profile": _IDENTITY_VALIDATOR,
        "budget_ledger_ref": strict_string(maximum=512),
        "budget_reservation_ref": strict_string(maximum=512),
        "covered_stages": strict_list(
            strict_enum(OPTIMIZATION_STAGES),
            minimum=len(OPTIMIZATION_STAGES),
            maximum=len(OPTIMIZATION_STAGES),
        ),
        "limits": _budget_entries,
        "dspy_gepa_max_metric_calls": strict_integer(minimum=0, maximum=_MAX_INTEGER),
        "dspy_rlm_max_llm_calls": strict_integer(minimum=0, maximum=_MAX_INTEGER),
        "dspy_gepa_num_threads": strict_integer(minimum=1, maximum=_MAX_INTEGER),
        "library_knob_authority": strict_literal("subordinate_only"),
        "links": validate_links,
    }
)


def _budget_plan_validator(value: Any, path: str) -> dict[str, Any]:
    payload = _BUDGET_PLAN_BASE_VALIDATOR(value, path)
    if payload["covered_stages"] != list(OPTIMIZATION_STAGES):
        raise SchemaValidationError(f"{path}.covered_stages must be the frozen cumulative set")
    limits = {item["dimension"]: item["limit"] for item in payload["limits"]}
    if payload["dspy_gepa_max_metric_calls"] > limits["metric_invocations"]:
        raise SchemaValidationError(f"{path}.dspy_gepa_max_metric_calls exceeds authority")
    if payload["dspy_rlm_max_llm_calls"] > limits["submodel_calls"]:
        raise SchemaValidationError(f"{path}.dspy_rlm_max_llm_calls exceeds authority")
    if payload["dspy_gepa_num_threads"] > min(
        limits[name]
        for name in (
            "run_concurrency",
            "context_concurrency",
            "provider_concurrency",
            "host_concurrency",
        )
    ):
        raise SchemaValidationError(f"{path}.dspy_gepa_num_threads exceeds authority")
    return payload


_ADMISSION_BASE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("gepa_admission_receipt"),
        "status": strict_literal("admitted"),
        "engine_semantic_id": strict_enum(tuple(OUTCOME_GEPA_ENGINE_IDS.values())),
        "incumbent_profile": _IDENTITY_VALIDATOR,
        "activation_scope": _IDENTITY_VALIDATOR,
        "observed_scope_revision": strict_integer(minimum=0, maximum=_MAX_INTEGER),
        "target_slot": strict_enum(tuple(OUTCOME_GEPA_ENGINE_IDS)),
        "successor_shape": _IDENTITY_VALIDATOR,
        "candidate_risk_tier": strict_enum(("standard", "elevated", "restricted")),
        "benefit_claim": _CLAIM_VALIDATOR,
        "execution_profile": _IDENTITY_VALIDATOR,
        "assessment_profile": _IDENTITY_VALIDATOR,
        "metric_profile": _IDENTITY_VALIDATOR,
        "training_manifest": _IDENTITY_VALIDATOR,
        "tuning_manifest": _IDENTITY_VALIDATOR,
        "training_family_count": strict_integer(minimum=1, maximum=10_000),
        "tuning_family_count": strict_integer(minimum=1, maximum=10_000),
        "partition_contract": strict_literal("family_disjoint_training_tuning_only.v1"),
        "certification_holdout_access": strict_literal("forbidden_until_artifact_locked"),
        "replay_capability": _IDENTITY_VALIDATOR,
        "worker_dependency_profile": _IDENTITY_VALIDATOR,
        "model_use_grant": _IDENTITY_VALIDATOR,
        "budget_plan": _IDENTITY_VALIDATOR,
        "search_score_authority": strict_literal("search_only"),
        "promotion_authority": strict_literal("none"),
        "evidence_authority": strict_literal("none"),
        "links": validate_links,
    }
)


def _admission_validator(value: Any, path: str) -> dict[str, Any]:
    payload = _ADMISSION_BASE_VALIDATOR(value, path)
    if payload["engine_semantic_id"] != OUTCOME_GEPA_ENGINE_IDS[payload["target_slot"]]:
        raise SchemaValidationError(f"{path}.engine_semantic_id does not match target slot")
    return payload


_COMPILED_OUTPUT_BASE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("compiled_output_validation"),
        "status": strict_enum(("valid", "invalid", "aborted")),
        "reason_codes": strict_list(
            strict_enum(COMPILED_OUTPUT_REASON_CODES), minimum=1, maximum=16
        ),
        "admission": _IDENTITY_VALIDATOR,
        "target_slot": strict_enum(tuple(OUTCOME_GEPA_ENGINE_IDS)),
        "successor_shape": _IDENTITY_VALIDATOR,
        "artifact": _IDENTITY_VALIDATOR,
        "budget_terminal_receipt": strict_nullable(_IDENTITY_VALIDATOR),
        "publication_state": strict_literal("not_published"),
        "publication_planner_eligible": strict_boolean(),
        "promotion_authority": strict_literal("none"),
        "evidence_authority": strict_literal("none"),
        "links": validate_links,
    }
)


def _compiled_output_validator(value: Any, path: str) -> dict[str, Any]:
    payload = _COMPILED_OUTPUT_BASE_VALIDATOR(value, path)
    eligible = payload["publication_planner_eligible"]
    if eligible != (payload["status"] == "valid"):
        raise SchemaValidationError(f"{path}.publication_planner_eligible disagrees with status")
    if payload["status"] == "valid" and payload["reason_codes"] != ["compiled_output_valid"]:
        raise SchemaValidationError(f"{path}.reason_codes disagree with valid status")
    if payload["status"] != "valid" and "compiled_output_valid" in payload["reason_codes"]:
        raise SchemaValidationError(f"{path}.reason_codes disagree with non-valid status")
    return payload


_LEGACY_TELEMETRY_BASE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("legacy_search_telemetry"),
        "method_id": strict_enum(LEGACY_DIAGNOSTIC_METHOD_IDS),
        "run": _IDENTITY_VALIDATOR,
        "input": _IDENTITY_VALIDATOR,
        "score": _RATIONAL_VALIDATOR,
        "telemetry_class": strict_literal("search_diagnostic"),
        "promotion_authority": strict_literal("none"),
        "evidence_authority": strict_literal("none"),
        "links": validate_links,
    }
)


def _legacy_telemetry_validator(value: Any, path: str) -> dict[str, Any]:
    payload = _LEGACY_TELEMETRY_BASE_VALIDATOR(value, path)
    score = payload["score"]
    if gcd(abs(score["numerator"]), score["denominator"]) != 1:
        raise SchemaValidationError(f"{path}.score is not a canonical rational")
    if not 0 <= Fraction(**score) <= 1:
        raise SchemaValidationError(f"{path}.score must be in [0,1]")
    return payload


_OWN_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            OPTIMIZATION_METRIC_PROFILE_SCHEMA_ID,
            "optimization_metric_profile",
            _metric_profile_validator,
        ),
        RecordSchema(
            OPTIMIZATION_RUN_BUDGET_PLAN_SCHEMA_ID,
            "optimization_run_budget_plan",
            _budget_plan_validator,
        ),
        RecordSchema(
            GEPA_ADMISSION_RECEIPT_SCHEMA_ID,
            "gepa_admission_receipt",
            _admission_validator,
        ),
        RecordSchema(
            COMPILED_OUTPUT_VALIDATION_SCHEMA_ID,
            "compiled_output_validation",
            _compiled_output_validator,
        ),
        RecordSchema(
            LEGACY_SEARCH_TELEMETRY_SCHEMA_ID,
            "legacy_search_telemetry",
            _legacy_telemetry_validator,
        ),
    )
)
OUTCOME_GEPA_REGISTRY = merge_schema_registries(
    FIXTURE_REGISTRY, MODEL_ROUTE_REGISTRY, _OWN_REGISTRY
)


def _record(
    record_id: str,
    context_ref: str,
    key_epoch: str,
    kind: str,
    schema_id: str,
    payload: Mapping[str, Any],
) -> TypedRecord:
    return build_typed_record(
        record_id=_bounded_ref(record_id, "record_id"),
        context_ref=_bounded_ref(context_ref, "context_ref"),
        record_kind=kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=_bounded_ref(key_epoch, "key_epoch", maximum=128),
        registry=OUTCOME_GEPA_REGISTRY,
    )


def build_optimization_metric_profile(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    benefit_claim: CandidateBenefitClaim,
    scalar_minimum: Rational,
    scalar_maximum: Rational,
    failure_score: Rational,
    outcome_dimensions: Sequence[WeightedMetricSource],
    bucket_validators: Sequence[WeightedMetricSource],
) -> TypedRecord:
    """Freeze an explicit exact-rational search metric aligned to one claim."""

    if type(benefit_claim) is not CandidateBenefitClaim:
        raise OutcomeGepaError("benefit_claim must be exact")
    dimensions = tuple(outcome_dimensions)
    validators = tuple(bucket_validators)
    if not dimensions or not validators:
        raise OutcomeGepaError("metric requires outcome and validator inputs")
    if any(item.bucket is not None for item in dimensions):
        raise OutcomeGepaError("outcome dimensions cannot masquerade as bucket validators")
    if any(item.bucket is None for item in validators):
        raise OutcomeGepaError("bucket validators require explicit buckets")
    sources = (*dimensions, *validators)
    if len({item.identity.ref for item in sources}) != len(sources):
        raise OutcomeGepaError("metric sources must have unique identities")
    payload = {
        "record_type": "optimization_metric_profile",
        "aggregation": "weighted_rational_mean.v1",
        "authority_ceiling": "search_only",
        "benefit_claim": {
            **_identity_payload(benefit_claim.identity),
            "kind": benefit_claim.kind,
            "bucket": benefit_claim.bucket,
        },
        "scalar_minimum": scalar_minimum.as_dict(),
        "scalar_maximum": scalar_maximum.as_dict(),
        "failure_score": failure_score.as_dict(),
        "outcome_dimensions": [
            {**_identity_payload(item.identity), "weight": item.weight.as_dict()}
            for item in dimensions
        ],
        "bucket_validators": [
            {
                **_identity_payload(item.identity),
                "bucket": item.bucket,
                "weight": item.weight.as_dict(),
            }
            for item in validators
        ],
        "feedback_reason_codes": list(METRIC_FEEDBACK_CODES),
        "links": [
            _link("benefit_claim", 0, benefit_claim.identity),
            *(_link("outcome_dimension", index, item.identity) for index, item in enumerate(dimensions)),
            *(_link("bucket_validator", index, item.identity) for index, item in enumerate(validators)),
        ],
    }
    return _record(
        record_id,
        context_ref,
        key_epoch,
        "optimization_metric_profile",
        OPTIMIZATION_METRIC_PROFILE_SCHEMA_ID,
        payload,
    )


def evaluate_optimization_metric(
    profile: TypedRecord,
    *,
    component_values: Mapping[str, Rational],
    proposal_state: str = "valid",
) -> OptimizationMetricResult:
    """Evaluate only the frozen weighted rational contract; emit fixed feedback."""

    profile.verify(OUTCOME_GEPA_REGISTRY)
    if profile.schema_id != OPTIMIZATION_METRIC_PROFILE_SCHEMA_ID:
        raise OutcomeGepaError("record is not an Optimization Metric Profile")
    payload = profile.payload
    if proposal_state not in ("valid", "invalid", "unsafe"):
        raise OutcomeGepaError("proposal_state is not admitted")
    if proposal_state != "valid":
        failure = Rational(**payload["failure_score"])
        return OptimizationMetricResult(failure, (f"proposal_{proposal_state}",))

    sources = (*payload["outcome_dimensions"], *payload["bucket_validators"])
    if type(component_values) is not dict or set(component_values) != {
        item["ref"] for item in sources
    }:
        raise OutcomeGepaError("component values must exactly cover the frozen metric sources")
    weighted = Fraction(0)
    total_weight = Fraction(0)
    reasons: set[str] = set()
    claim_bucket = payload["benefit_claim"]["bucket"]
    for item in sources:
        value = component_values[item["ref"]]
        if type(value) is not Rational or not 0 <= value.fraction <= 1:
            raise OutcomeGepaError("metric component values must be exact rationals in [0,1]")
        weight = Rational(**item["weight"]).fraction
        weighted += value.fraction * weight
        total_weight += weight
        if value.fraction < 1:
            reasons.add("metric_component_below_full_score")
            if item.get("bucket") == claim_bucket:
                reasons.add("claim_bucket_below_full_score")
    normalized = weighted / total_weight
    low = Rational(**payload["scalar_minimum"]).fraction
    high = Rational(**payload["scalar_maximum"]).fraction
    score = low + (high - low) * normalized
    if not reasons:
        reasons.add("metric_all_components_satisfied")
    return OptimizationMetricResult(
        Rational(score.numerator, score.denominator), tuple(sorted(reasons))
    )


def build_optimization_run_budget_plan(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    budget_profile: BoundIdentity,
    budget_ledger_ref: str,
    budget_reservation_ref: str,
    limits: Mapping[str, int],
    dspy_gepa_max_metric_calls: int,
    dspy_rlm_max_llm_calls: int,
    dspy_gepa_num_threads: int,
) -> TypedRecord:
    """Freeze one cumulative authority plan with subordinate library knobs."""

    if type(limits) is not dict or set(limits) != set(OPTIMIZATION_BUDGET_DIMENSIONS):
        raise OutcomeGepaError("limits must explicitly cover every optimization dimension")
    for name, value in limits.items():
        if type(value) is not int or not 0 <= value <= _MAX_INTEGER:
            raise OutcomeGepaError(f"budget limit {name!r} is not a bounded integer")
    knobs = (
        dspy_gepa_max_metric_calls,
        dspy_rlm_max_llm_calls,
        dspy_gepa_num_threads,
    )
    if any(type(value) is not int for value in knobs) or dspy_gepa_num_threads < 1:
        raise OutcomeGepaError("library knobs must be explicit bounded integers")
    if not 0 <= dspy_gepa_max_metric_calls <= limits["metric_invocations"]:
        raise OutcomeGepaError("DSPy max_metric_calls exceeds cumulative metric authority")
    if not 0 <= dspy_rlm_max_llm_calls <= limits["submodel_calls"]:
        raise OutcomeGepaError("RLM max_llm_calls exceeds cumulative submodel authority")
    concurrency_limit = min(
        limits[name]
        for name in (
            "run_concurrency",
            "context_concurrency",
            "provider_concurrency",
            "host_concurrency",
        )
    )
    if dspy_gepa_num_threads > concurrency_limit:
        raise OutcomeGepaError("GEPA num_threads exceeds reserved aggregate concurrency")
    payload = {
        "record_type": "optimization_run_budget_plan",
        "budget_profile": _identity_payload(budget_profile),
        "budget_ledger_ref": _bounded_ref(budget_ledger_ref, "budget_ledger_ref"),
        "budget_reservation_ref": _bounded_ref(
            budget_reservation_ref, "budget_reservation_ref"
        ),
        "covered_stages": list(OPTIMIZATION_STAGES),
        "limits": [
            {"dimension": name, "limit": limits[name]}
            for name in OPTIMIZATION_BUDGET_DIMENSIONS
        ],
        "dspy_gepa_max_metric_calls": dspy_gepa_max_metric_calls,
        "dspy_rlm_max_llm_calls": dspy_rlm_max_llm_calls,
        "dspy_gepa_num_threads": dspy_gepa_num_threads,
        "library_knob_authority": "subordinate_only",
        "links": [_link("budget_profile", 0, budget_profile)],
    }
    return _record(
        record_id,
        context_ref,
        key_epoch,
        "optimization_run_budget_plan",
        OPTIMIZATION_RUN_BUDGET_PLAN_SCHEMA_ID,
        payload,
    )


def _manifest_families(
    manifest: TypedRecord,
    *,
    expected_partition: str,
    context_ref: str,
    execution_profile: BoundIdentity,
    assessment_profile: BoundIdentity,
) -> frozenset[str]:
    manifest.verify(OUTCOME_GEPA_REGISTRY)
    if manifest.schema_id != FIXTURE_MANIFEST_SCHEMA_ID or manifest.context_ref != context_ref:
        raise OutcomeGepaError("GEPA requires an exact same-context Fixture Manifest")
    payload = manifest.payload
    if (
        payload["execution_profile_id"], payload["execution_profile_digest"]
    ) != (execution_profile.ref, execution_profile.digest):
        raise OutcomeGepaError("fixture manifest execution profile drifted")
    if (
        payload["assessment_profile_id"], payload["assessment_profile_digest"]
    ) != (assessment_profile.ref, assessment_profile.digest):
        raise OutcomeGepaError("fixture manifest assessment profile drifted")
    families: set[str] = set()
    drafts: set[str] = set()
    for entry in payload["entries"]:
        if entry["partition"] == "certification_holdout":
            raise OutcomeGepaError("Certification Holdout is inaccessible before artifact lock")
        if entry["partition"] != expected_partition:
            raise OutcomeGepaError(f"manifest is not {expected_partition}-only")
        if entry["family_id"] in families or entry["draft_id"] in drafts:
            raise OutcomeGepaError("manifest repeats a Fixture Family or fixture")
        families.add(entry["family_id"])
        drafts.add(entry["draft_id"])
    if not families:
        raise OutcomeGepaError("GEPA partitions cannot be empty")
    return frozenset(families)


def admit_outcome_gepa(request: GepaAdmissionRequest) -> TypedRecord:
    """Purely validate and freeze a passing, training/tuning-only admission."""

    if type(request) is not GepaAdmissionRequest:
        raise OutcomeGepaError("request must be a strict GEPA admission request")
    if request.observed_scope_revision < 0 or type(request.observed_scope_revision) is not int:
        raise OutcomeGepaError("scope revision must be a non-negative integer")
    if request.target_slot not in OUTCOME_GEPA_ENGINE_IDS:
        raise OutcomeGepaError("target slot is not admitted for outcome GEPA")
    if request.candidate_risk_tier not in ("standard", "elevated", "restricted"):
        raise OutcomeGepaError("candidate risk tier is not admitted")
    request.metric_profile.verify(OUTCOME_GEPA_REGISTRY)
    request.budget_plan.verify(OUTCOME_GEPA_REGISTRY)
    if request.metric_profile.schema_id != OPTIMIZATION_METRIC_PROFILE_SCHEMA_ID:
        raise OutcomeGepaError("metric profile schema is not admitted")
    if request.budget_plan.schema_id != OPTIMIZATION_RUN_BUDGET_PLAN_SCHEMA_ID:
        raise OutcomeGepaError("budget plan schema is not admitted")
    for record in (
        request.metric_profile,
        request.training_manifest,
        request.tuning_manifest,
        request.budget_plan,
    ):
        if record.context_ref != request.context_ref:
            raise OutcomeGepaError("GEPA authorities must share one exact context")
    claim = request.metric_profile.payload["benefit_claim"]
    if claim != {
        **_identity_payload(request.benefit_claim.identity),
        "kind": request.benefit_claim.kind,
        "bucket": request.benefit_claim.bucket,
    }:
        raise OutcomeGepaError("metric profile does not align to the exact Benefit Claim")
    training_families = _manifest_families(
        request.training_manifest,
        expected_partition="training",
        context_ref=request.context_ref,
        execution_profile=request.execution_profile,
        assessment_profile=request.assessment_profile,
    )
    tuning_families = _manifest_families(
        request.tuning_manifest,
        expected_partition="tuning",
        context_ref=request.context_ref,
        execution_profile=request.execution_profile,
        assessment_profile=request.assessment_profile,
    )
    if training_families & tuning_families:
        raise OutcomeGepaError("training and tuning Fixture Families overlap")
    identities = (
        ("incumbent_profile", request.incumbent_profile),
        ("activation_scope", request.activation_scope),
        ("successor_shape", request.successor_shape),
        ("benefit_claim", request.benefit_claim.identity),
        ("execution_profile", request.execution_profile),
        ("assessment_profile", request.assessment_profile),
        ("metric_profile", request.metric_profile),
        ("training_manifest", request.training_manifest),
        ("tuning_manifest", request.tuning_manifest),
        ("replay_capability", request.replay_capability),
        ("worker_dependency_profile", request.worker_dependency_profile),
        ("model_use_grant", request.model_use_grant),
        ("budget_plan", request.budget_plan),
    )
    payload = {
        "record_type": "gepa_admission_receipt",
        "status": "admitted",
        "engine_semantic_id": OUTCOME_GEPA_ENGINE_IDS[request.target_slot],
        "incumbent_profile": _identity_payload(request.incumbent_profile),
        "activation_scope": _identity_payload(request.activation_scope),
        "observed_scope_revision": request.observed_scope_revision,
        "target_slot": request.target_slot,
        "successor_shape": _identity_payload(request.successor_shape),
        "candidate_risk_tier": request.candidate_risk_tier,
        "benefit_claim": {
            **_identity_payload(request.benefit_claim.identity),
            "kind": request.benefit_claim.kind,
            "bucket": request.benefit_claim.bucket,
        },
        "execution_profile": _identity_payload(request.execution_profile),
        "assessment_profile": _identity_payload(request.assessment_profile),
        "metric_profile": _identity_payload(
            BoundIdentity(request.metric_profile.record_id, request.metric_profile.content_digest)
        ),
        "training_manifest": _identity_payload(
            BoundIdentity(request.training_manifest.record_id, request.training_manifest.content_digest)
        ),
        "tuning_manifest": _identity_payload(
            BoundIdentity(request.tuning_manifest.record_id, request.tuning_manifest.content_digest)
        ),
        "training_family_count": len(training_families),
        "tuning_family_count": len(tuning_families),
        "partition_contract": "family_disjoint_training_tuning_only.v1",
        "certification_holdout_access": "forbidden_until_artifact_locked",
        "replay_capability": _identity_payload(request.replay_capability),
        "worker_dependency_profile": _identity_payload(request.worker_dependency_profile),
        "model_use_grant": _identity_payload(request.model_use_grant),
        "budget_plan": _identity_payload(
            BoundIdentity(request.budget_plan.record_id, request.budget_plan.content_digest)
        ),
        "search_score_authority": "search_only",
        "promotion_authority": "none",
        "evidence_authority": "none",
        "links": [_link(role, 0, identity) for role, identity in identities],
    }
    return _record(
        request.receipt_id,
        request.context_ref,
        request.key_epoch,
        "gepa_admission_receipt",
        GEPA_ADMISSION_RECEIPT_SCHEMA_ID,
        payload,
    )


def validate_staged_compiled_output(
    *,
    admission: TypedRecord,
    output: StagedCompiledOutput,
    context_ref: str,
    key_epoch: str,
) -> TypedRecord:
    """Validate metadata only; never publish a candidate or claim evidence."""

    admission.verify(OUTCOME_GEPA_REGISTRY)
    if admission.schema_id != GEPA_ADMISSION_RECEIPT_SCHEMA_ID:
        raise OutcomeGepaError("compiled output requires a GEPA Admission Receipt")
    reasons: list[str] = []
    if output.admission != BoundIdentity(admission.record_id, admission.content_digest):
        reasons.append("admission_binding_mismatch")
    if output.target_slot != admission.payload["target_slot"]:
        reasons.append("successor_shape_mismatch")
    expected_shape = admission.payload["successor_shape"]
    if _identity_payload(output.successor_shape) != expected_shape:
        reasons.append("successor_shape_mismatch")
    if not output.worker_completed:
        reasons.append("worker_incomplete")
    if not output.schema_valid:
        reasons.append("schema_invalid")
    if not output.cleanup_verified:
        reasons.append("cleanup_unverified")
    boundary_checks = (
        (output.live_tool_boundary_intact, "live_tool_boundary_breach"),
        (output.secret_boundary_intact, "secret_boundary_breach"),
        (output.fixture_authority_boundary_intact, "fixture_authority_boundary_breach"),
        (output.sandbox_boundary_intact, "sandbox_boundary_breach"),
        (output.protected_constraints_intact, "protected_constraint_breach"),
    )
    breach_reasons = [reason for intact, reason in boundary_checks if not intact]
    reasons.extend(breach_reasons)
    if output.budget_terminal_receipt is None:
        reasons.append("budget_terminal_receipt_missing")
    terminal = output.budget_terminal_receipt
    status = "aborted" if breach_reasons else "invalid" if reasons else "valid"
    if status == "valid":
        reasons = ["compiled_output_valid"]
    # A later Candidate Publication Planner may consume a valid receipt only
    # after coordinator revalidation.  This receipt itself authorizes nothing.
    payload = {
        "record_type": "compiled_output_validation",
        "status": status,
        "reason_codes": sorted(set(reasons)),
        "admission": _identity_payload(output.admission),
        "target_slot": output.target_slot,
        "successor_shape": _identity_payload(output.successor_shape),
        "artifact": _identity_payload(output.artifact),
        "budget_terminal_receipt": (
            _identity_payload(terminal) if terminal is not None else None
        ),
        "publication_state": "not_published",
        "publication_planner_eligible": status == "valid",
        "promotion_authority": "none",
        "evidence_authority": "none",
        "links": [
            _link("admission", 0, output.admission),
            _link("successor_shape", 0, output.successor_shape),
            _link("artifact", 0, output.artifact),
            *(
                (_link("budget_terminal_receipt", 0, terminal),)
                if terminal is not None
                else ()
            ),
        ],
    }
    return _record(
        output.validation_id,
        context_ref,
        key_epoch,
        "compiled_output_validation",
        COMPILED_OUTPUT_VALIDATION_SCHEMA_ID,
        payload,
    )


def build_legacy_search_telemetry(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    method_id: str,
    run: BoundIdentity,
    input_identity: BoundIdentity,
    score: Rational,
) -> TypedRecord:
    """Label frozen surrogate methods truthfully as diagnostic-only telemetry."""

    if method_id not in LEGACY_DIAGNOSTIC_METHOD_IDS:
        raise OutcomeGepaError("legacy telemetry method is not an exact stable identifier")
    if not 0 <= score.fraction <= 1:
        raise OutcomeGepaError("legacy diagnostic score must be in [0,1]")
    payload = {
        "record_type": "legacy_search_telemetry",
        "method_id": method_id,
        "run": _identity_payload(run),
        "input": _identity_payload(input_identity),
        "score": score.as_dict(),
        "telemetry_class": "search_diagnostic",
        "promotion_authority": "none",
        "evidence_authority": "none",
        "links": [_link("run", 0, run), _link("input", 0, input_identity)],
    }
    return _record(
        record_id,
        context_ref,
        key_epoch,
        "legacy_search_telemetry",
        LEGACY_SEARCH_TELEMETRY_SCHEMA_ID,
        payload,
    )
