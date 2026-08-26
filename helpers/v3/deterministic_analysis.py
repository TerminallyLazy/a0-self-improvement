"""Deterministic, content-free analysis and structured-guidance rule authority.

This module has no model, provider, repository, or Agent Zero dependency.  It
builds immutable metadata records and performs pure validation only.  In
particular, it cannot silently change an analysis route or publish a candidate.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence

from .artifacts import DEFAULT_REGISTRY
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    schema_digest,
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


OBSERVATION_FACT_SCHEMA_ID = "a0.analysis-observation-fact.v1"
ANALYSIS_PROFILE_SCHEMA_ID = "a0.analysis-profile.v1"
SAFE_ANALYSIS_VIEW_SCHEMA_ID = "a0.safe-analysis-view.v1"
ANALYSIS_ATTEMPT_SCHEMA_ID = "a0.analysis-attempt.v1"
GUIDANCE_RULE_CATALOG_SCHEMA_ID = "a0.guidance-rule-catalog.v1"

DETERMINISTIC_ENGINE_ID = "a0.analysis.deterministic.aggregate.v1"
GUIDANCE_RENDERER_CONTRACT_ID = "a0.structured-guidance.system-prompt-renderer.v1"
GUIDANCE_RENDERER_CONTRACT = {
    "contract_id": GUIDANCE_RENDERER_CONTRACT_ID,
    "input_schema": "a0.structured-guidance.v2",
    "rule_order": "catalog_ordinal",
    "unknown_rule_disposition": "incompatible",
    "unknown_parameter_disposition": "incompatible",
}
GUIDANCE_RENDERER_CONTRACT_DIGEST = schema_digest(
    "renderer-contract",
    GUIDANCE_RENDERER_CONTRACT_ID,
    canonical_json(GUIDANCE_RENDERER_CONTRACT),
)

OBJECTIVE_BUCKETS = ("decision_making", "reasoning", "shell", "tool_retrieval")
PROTECTED_CONSTRAINTS = (
    "activation_authority_forbidden",
    "reasoning_benefit_forbidden",
    "safety_policy_override_forbidden",
)
MAX_SELECTED_GUIDANCE_RULES = 4
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class DeterministicAnalysisError(ValueError):
    """An analysis input or rule projection violates deterministic authority."""


def _opaque(value: Any, name: str, *, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or _OPAQUE.fullmatch(value) is None
    ):
        raise DeterministicAnalysisError(f"{name} must be a bounded opaque reference")
    return value


def _positive_integer(value: Any, name: str) -> int:
    if type(value) is not int or value < 1:
        raise DeterministicAnalysisError(f"{name} must be a positive integer")
    return value


def _sorted_unique(
    values: Sequence[str],
    name: str,
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    result = tuple(values)
    if not allow_empty and not result:
        raise DeterministicAnalysisError(f"{name} must not be empty")
    if result != tuple(sorted(result)) or len(result) != len(set(result)):
        raise DeterministicAnalysisError(f"{name} must be sorted and unique")
    if any(item not in OBJECTIVE_BUCKETS for item in result):
        raise DeterministicAnalysisError(f"{name} contains an unknown objective bucket")
    return result


@dataclass(frozen=True, slots=True)
class ExactIdentity:
    ref: str
    digest: str

    def __post_init__(self) -> None:
        _opaque(self.ref, "identity.ref")
        try:
            validate_digest(self.digest, "identity.digest")
        except SchemaValidationError as exc:
            raise DeterministicAnalysisError("identity.digest is not an exact digest") from exc


def _identity(ref: str, digest: str) -> ExactIdentity:
    return ExactIdentity(ref=ref, digest=digest)


def _identity_object(value: Any, path: str) -> dict[str, Any]:
    return strict_object(
        {"ref": strict_string(maximum=512), "digest": validate_digest}
    )(value, path)


def _identities(value: Any, path: str) -> list[dict[str, Any]]:
    items = strict_list(_identity_object)(value, path)
    refs = [item["ref"] for item in items]
    if refs != sorted(refs) or len(refs) != len(set(refs)):
        raise SchemaValidationError(f"{path} must be sorted and unique by ref")
    return items


def _link(role: str, ordinal: int, identity: ExactIdentity | TypedRecord) -> dict[str, Any]:
    if isinstance(identity, TypedRecord):
        ref, digest = identity.record_id, identity.content_digest
    else:
        ref, digest = identity.ref, identity.digest
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": ref,
        "target_digest": digest,
    }


def _payload_link(payload: Mapping[str, Any], prefix: str, ordinal: int) -> dict[str, Any]:
    return {
        "role": prefix,
        "ordinal": ordinal,
        "target_id": payload[f"{prefix}_ref"],
        "target_digest": payload[f"{prefix}_digest"],
    }


_FACT_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("analysis_observation_fact"),
        "fact_kind": strict_literal("categorical_count"),
        "bucket_ref": strict_enum(OBJECTIVE_BUCKETS),
        "outcome_code": strict_string(maximum=128),
        "occurrences": strict_integer(minimum=1),
        "source_profile_ref": strict_string(maximum=512),
        "source_profile_digest": validate_digest,
        "window_ref": strict_string(maximum=512),
        "window_digest": validate_digest,
        "evidence_ref": strict_string(maximum=512),
        "evidence_digest": validate_digest,
        "contains_raw_content": strict_literal(False),
        "contains_quarantine_content": strict_literal(False),
        "contains_certification_holdout": strict_literal(False),
        "links": validate_links,
    }
)


def _fact_validator(value: Any, path: str) -> dict[str, Any]:
    payload = _FACT_VALIDATOR(value, path)
    expected = [
        _payload_link(payload, "source_profile", 0),
        _payload_link(payload, "window", 0),
        _payload_link(payload, "evidence", 0),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact fact authorities")
    if _OPAQUE.fullmatch(payload["outcome_code"]) is None:
        raise SchemaValidationError(f"{path}.outcome_code must be a content-free code")
    return payload


_ZERO_EXTERNAL_USAGE_VALIDATOR = strict_object(
    {
        "calls": strict_literal(0),
        "input_tokens": strict_literal(0),
        "output_tokens": strict_literal(0),
        "input_bytes": strict_literal(0),
        "output_bytes": strict_literal(0),
        "cost_microunits": strict_literal(0),
    }
)


def _profile_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("analysis_profile"),
            "route": strict_literal("deterministic"),
            "semantic_engine_id": strict_literal(DETERMINISTIC_ENGINE_ID),
            "authority_ceiling": strict_literal("factual_typed_reduction"),
            "model_authority": strict_literal("none"),
            "analysis_output_schema": strict_literal(SAFE_ANALYSIS_VIEW_SCHEMA_ID),
            "analytical_question_ref": strict_string(maximum=512),
            "analytical_question_digest": validate_digest,
            "worker_dependency_profile_ref": strict_string(maximum=512),
            "worker_dependency_profile_digest": validate_digest,
            "maximum_view_rows": strict_integer(minimum=1),
            "maximum_view_bytes": strict_integer(minimum=1),
            "external_model_usage_ceiling": _ZERO_EXTERNAL_USAGE_VALIDATOR,
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _payload_link(payload, "analytical_question", 0),
        _payload_link(payload, "worker_dependency_profile", 0),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact analysis profile")
    return payload


_AGGREGATE_ROW_VALIDATOR = strict_object(
    {
        "bucket_ref": strict_enum(OBJECTIVE_BUCKETS),
        "outcome_code": strict_string(maximum=128),
        "occurrences": strict_integer(minimum=1),
    }
)


def _view_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("safe_analysis_view"),
            "semantic_engine_id": strict_literal(DETERMINISTIC_ENGINE_ID),
            "analysis_profile_ref": strict_string(maximum=512),
            "analysis_profile_digest": validate_digest,
            "window_ref": strict_string(maximum=512),
            "window_digest": validate_digest,
            "source_profiles": _identities,
            "evidence_inputs": _identities,
            "observation_inputs": _identities,
            "input_fact_count": strict_integer(minimum=1),
            "maximum_view_rows": strict_integer(minimum=1),
            "maximum_view_bytes": strict_integer(minimum=1),
            "rows": strict_list(_AGGREGATE_ROW_VALIDATOR, minimum=1),
            "contains_raw_content": strict_literal(False),
            "contains_quarantine_content": strict_literal(False),
            "contains_certification_holdout": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    rows = payload["rows"]
    row_keys = [(row["bucket_ref"], row["outcome_code"]) for row in rows]
    if row_keys != sorted(row_keys) or len(row_keys) != len(set(row_keys)):
        raise SchemaValidationError(f"{path}.rows must be deterministically sorted and unique")
    if len(rows) > payload["maximum_view_rows"]:
        raise SchemaValidationError(f"{path}.rows exceed the explicit Analysis Profile ceiling")
    if len(canonical_json(payload)) > payload["maximum_view_bytes"]:
        raise SchemaValidationError(f"{path} exceeds the explicit Analysis Profile byte ceiling")
    if payload["input_fact_count"] != len(payload["observation_inputs"]):
        raise SchemaValidationError(f"{path}.input_fact_count does not match observations")
    expected = [
        _payload_link(payload, "analysis_profile", 0),
        _payload_link(payload, "window", 0),
    ]
    expected.extend(
        {
            "role": "source_profile",
            "ordinal": ordinal,
            "target_id": item["ref"],
            "target_digest": item["digest"],
        }
        for ordinal, item in enumerate(payload["source_profiles"])
    )
    expected.extend(
        {
            "role": "evidence",
            "ordinal": ordinal,
            "target_id": item["ref"],
            "target_digest": item["digest"],
        }
        for ordinal, item in enumerate(payload["evidence_inputs"])
    )
    expected.extend(
        {
            "role": "observation",
            "ordinal": ordinal,
            "target_id": item["ref"],
            "target_digest": item["digest"],
        }
        for ordinal, item in enumerate(payload["observation_inputs"])
    )
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact safe-view inputs")
    return payload


def _attempt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("analysis_attempt"),
            "requested_route": strict_literal("deterministic"),
            "selected_route": strict_literal("deterministic"),
            "selection_reason": strict_literal("declared_deterministic_reduction"),
            "semantic_engine_id": strict_literal(DETERMINISTIC_ENGINE_ID),
            "analysis_profile_ref": strict_string(maximum=512),
            "analysis_profile_digest": validate_digest,
            "safe_analysis_view_ref": strict_string(maximum=512),
            "safe_analysis_view_digest": validate_digest,
            "work_item_ref": strict_string(maximum=512),
            "work_item_digest": validate_digest,
            "worker_dependency_profile_ref": strict_string(maximum=512),
            "worker_dependency_profile_digest": validate_digest,
            "budget_reservation_ref": strict_string(maximum=512),
            "budget_reservation_digest": validate_digest,
            "budget_reconciliation_ref": strict_string(maximum=512),
            "budget_reconciliation_digest": validate_digest,
            "model_ref": strict_nullable(strict_string(maximum=512)),
            "model_source": strict_nullable(strict_string(maximum=512)),
            "model_use_grant_ref": strict_nullable(strict_string(maximum=512)),
            "reserved_external_model_usage": _ZERO_EXTERNAL_USAGE_VALIDATOR,
            "actual_external_model_usage": _ZERO_EXTERNAL_USAGE_VALIDATOR,
            "invalid_output_count": strict_literal(0),
            "dropped_output_count": strict_literal(0),
            "proposal_hashes": strict_list(validate_digest, maximum=0),
            "terminal_state": strict_literal("completed"),
            "cleanup_state": strict_literal("complete"),
            "reason_codes": strict_list(
                strict_literal("deterministic_reduction_completed"), minimum=1, maximum=1
            ),
            "links": validate_links,
        }
    )(value, path)
    if any(payload[name] is not None for name in ("model_ref", "model_source", "model_use_grant_ref")):
        raise SchemaValidationError(f"{path} deterministic analysis cannot bind a model")
    expected = [
        _payload_link(payload, "analysis_profile", 0),
        _payload_link(payload, "safe_analysis_view", 0),
        _payload_link(payload, "work_item", 0),
        _payload_link(payload, "worker_dependency_profile", 0),
        _payload_link(payload, "budget_reservation", 0),
        _payload_link(payload, "budget_reconciliation", 0),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact attempt authorities")
    return payload


_RULE_ORDER = {
    "verify_tool_contract": 0,
    "check_tool_result": 1,
    "retry_after_failure": 2,
    "prefer_reversible_action": 3,
    "bound_tool_scope": 4,
}
_TOOL_BUCKETS = ["shell", "tool_retrieval"]
_REVERSIBLE_BUCKETS = ["decision_making", "shell"]
_INITIAL_RULES = [
    {
        "rule_id": "verify_tool_contract",
        "ordinal": 0,
        "parameter_schema": [],
        "allowed_benefit_buckets": _TOOL_BUCKETS,
        "required_evaluation_buckets": _TOOL_BUCKETS,
        "protected_constraints": list(PROTECTED_CONSTRAINTS),
    },
    {
        "rule_id": "check_tool_result",
        "ordinal": 1,
        "parameter_schema": [],
        "allowed_benefit_buckets": _TOOL_BUCKETS,
        "required_evaluation_buckets": _TOOL_BUCKETS,
        "protected_constraints": list(PROTECTED_CONSTRAINTS),
    },
    {
        "rule_id": "retry_after_failure",
        "ordinal": 2,
        "parameter_schema": [
            {
                "name": "max_retries",
                "type": "integer",
                "required": True,
                "minimum": 0,
                "maximum": 2,
            }
        ],
        "allowed_benefit_buckets": _TOOL_BUCKETS,
        "required_evaluation_buckets": _TOOL_BUCKETS,
        "protected_constraints": list(PROTECTED_CONSTRAINTS),
    },
    {
        "rule_id": "prefer_reversible_action",
        "ordinal": 3,
        "parameter_schema": [],
        "allowed_benefit_buckets": _REVERSIBLE_BUCKETS,
        "required_evaluation_buckets": _REVERSIBLE_BUCKETS,
        "protected_constraints": list(PROTECTED_CONSTRAINTS),
    },
    {
        "rule_id": "bound_tool_scope",
        "ordinal": 4,
        "parameter_schema": [],
        "allowed_benefit_buckets": _TOOL_BUCKETS,
        "required_evaluation_buckets": _TOOL_BUCKETS,
        "protected_constraints": list(PROTECTED_CONSTRAINTS),
    },
]


def _catalog_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("guidance_rule_catalog"),
            "catalog_id": strict_literal(GUIDANCE_RULE_CATALOG_SCHEMA_ID),
            "maximum_selected_rules": strict_literal(MAX_SELECTED_GUIDANCE_RULES),
            "renderer_contract_id": strict_literal(GUIDANCE_RENDERER_CONTRACT_ID),
            "renderer_contract_digest": strict_literal(GUIDANCE_RENDERER_CONTRACT_DIGEST),
            "protected_constraints": strict_list(
                strict_enum(PROTECTED_CONSTRAINTS),
                minimum=len(PROTECTED_CONSTRAINTS),
                maximum=len(PROTECTED_CONSTRAINTS),
            ),
            "rules": strict_list(lambda item, _path: item, minimum=5, maximum=5),
            "links": validate_links,
        }
    )(value, path)
    if payload["protected_constraints"] != list(PROTECTED_CONSTRAINTS):
        raise SchemaValidationError(f"{path}.protected_constraints are not the initial contract")
    if payload["rules"] != _INITIAL_RULES:
        raise SchemaValidationError(f"{path}.rules are not the immutable initial catalog")
    expected = [
        {
            "role": "renderer_contract",
            "ordinal": 0,
            "target_id": GUIDANCE_RENDERER_CONTRACT_ID,
            "target_digest": GUIDANCE_RENDERER_CONTRACT_DIGEST,
        }
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the fixed renderer contract")
    return payload


DETERMINISTIC_ANALYSIS_REGISTRY = SchemaRegistry(
    (
        *DEFAULT_REGISTRY.schemas.values(),
        RecordSchema(OBSERVATION_FACT_SCHEMA_ID, "analysis_observation_fact", _fact_validator),
        RecordSchema(ANALYSIS_PROFILE_SCHEMA_ID, "analysis_profile", _profile_validator),
        RecordSchema(SAFE_ANALYSIS_VIEW_SCHEMA_ID, "safe_analysis_view", _view_validator),
        RecordSchema(ANALYSIS_ATTEMPT_SCHEMA_ID, "analysis_attempt", _attempt_validator),
        RecordSchema(
            GUIDANCE_RULE_CATALOG_SCHEMA_ID,
            "guidance_rule_catalog",
            _catalog_validator,
            context_required=False,
        ),
    )
)


def _record(
    *,
    context_ref: str | None,
    kind: str,
    schema_id: str,
    payload: Mapping[str, Any],
    key_epoch: str,
) -> TypedRecord:
    if context_ref is not None:
        _opaque(context_ref, "context_ref")
    _opaque(key_epoch, "key_epoch")
    encoded = canonical_json(dict(payload))
    return build_typed_record(
        record_id=kind + "_" + schema_digest("record-identity", schema_id, encoded),
        context_ref=context_ref,
        record_kind=kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=key_epoch,
        registry=DETERMINISTIC_ANALYSIS_REGISTRY,
    )


def build_observation_fact(
    *,
    context_ref: str,
    key_epoch: str,
    bucket_ref: str,
    outcome_code: str,
    occurrences: int,
    source_profile: ExactIdentity,
    window: ExactIdentity,
    evidence: ExactIdentity,
    contains_raw_content: bool,
    contains_quarantine_content: bool,
    contains_certification_holdout: bool,
) -> TypedRecord:
    """Build one typed, content-free factual count or fail closed."""

    for name, identity in (
        ("source_profile", source_profile),
        ("window", window),
        ("evidence", evidence),
    ):
        if type(identity) is not ExactIdentity:
            raise DeterministicAnalysisError(f"{name} must be an ExactIdentity")
    unsafe_flags = {
        "contains_raw_content": contains_raw_content,
        "contains_quarantine_content": contains_quarantine_content,
        "contains_certification_holdout": contains_certification_holdout,
    }
    if any(type(value) is not bool for value in unsafe_flags.values()):
        raise DeterministicAnalysisError("content classification flags must be booleans")
    if any(unsafe_flags.values()):
        raise DeterministicAnalysisError("unsafe content cannot enter deterministic analysis")
    payload = {
        "record_type": "analysis_observation_fact",
        "fact_kind": "categorical_count",
        "bucket_ref": bucket_ref,
        "outcome_code": outcome_code,
        "occurrences": occurrences,
        "source_profile_ref": source_profile.ref,
        "source_profile_digest": source_profile.digest,
        "window_ref": window.ref,
        "window_digest": window.digest,
        "evidence_ref": evidence.ref,
        "evidence_digest": evidence.digest,
        **unsafe_flags,
        "links": [
            _link("source_profile", 0, source_profile),
            _link("window", 0, window),
            _link("evidence", 0, evidence),
        ],
    }
    return _record(
        context_ref=context_ref,
        kind="analysis_observation_fact",
        schema_id=OBSERVATION_FACT_SCHEMA_ID,
        payload=payload,
        key_epoch=key_epoch,
    )


def build_deterministic_analysis_profile(
    *,
    context_ref: str,
    key_epoch: str,
    analytical_question: ExactIdentity,
    worker_dependency_profile: ExactIdentity,
    maximum_view_rows: int,
    maximum_view_bytes: int,
) -> TypedRecord:
    """Freeze a deterministic-only profile with explicit Safe View ceilings."""

    if type(analytical_question) is not ExactIdentity:
        raise DeterministicAnalysisError("analytical_question must be an ExactIdentity")
    if type(worker_dependency_profile) is not ExactIdentity:
        raise DeterministicAnalysisError("worker_dependency_profile must be an ExactIdentity")
    _positive_integer(maximum_view_rows, "maximum_view_rows")
    _positive_integer(maximum_view_bytes, "maximum_view_bytes")
    payload = {
        "record_type": "analysis_profile",
        "route": "deterministic",
        "semantic_engine_id": DETERMINISTIC_ENGINE_ID,
        "authority_ceiling": "factual_typed_reduction",
        "model_authority": "none",
        "analysis_output_schema": SAFE_ANALYSIS_VIEW_SCHEMA_ID,
        "analytical_question_ref": analytical_question.ref,
        "analytical_question_digest": analytical_question.digest,
        "worker_dependency_profile_ref": worker_dependency_profile.ref,
        "worker_dependency_profile_digest": worker_dependency_profile.digest,
        "maximum_view_rows": maximum_view_rows,
        "maximum_view_bytes": maximum_view_bytes,
        "external_model_usage_ceiling": _zero_external_usage(),
        "links": [
            _link("analytical_question", 0, analytical_question),
            _link("worker_dependency_profile", 0, worker_dependency_profile),
        ],
    }
    return _record(
        context_ref=context_ref,
        kind="analysis_profile",
        schema_id=ANALYSIS_PROFILE_SCHEMA_ID,
        payload=payload,
        key_epoch=key_epoch,
    )


def _unique_identities(values: Sequence[ExactIdentity], name: str) -> tuple[ExactIdentity, ...]:
    by_ref: dict[str, ExactIdentity] = {}
    for item in values:
        existing = by_ref.get(item.ref)
        if existing is not None and existing.digest != item.digest:
            raise DeterministicAnalysisError(f"{name} contains an identity collision")
        by_ref[item.ref] = item
    return tuple(by_ref[ref] for ref in sorted(by_ref))


def _identity_payload(values: Sequence[ExactIdentity]) -> list[dict[str, str]]:
    return [{"ref": item.ref, "digest": item.digest} for item in values]


def build_safe_analysis_view(
    *,
    context_ref: str,
    key_epoch: str,
    analysis_profile: TypedRecord,
    window: ExactIdentity,
    observation_facts: Sequence[TypedRecord],
) -> TypedRecord:
    """Aggregate exact observation facts into a bounded, sorted Safe View."""

    analysis_profile.verify(DETERMINISTIC_ANALYSIS_REGISTRY)
    if analysis_profile.record_kind != "analysis_profile":
        raise DeterministicAnalysisError("analysis_profile must be an Analysis Profile")
    if analysis_profile.context_ref != context_ref:
        raise DeterministicAnalysisError("analysis_profile belongs to a different context")
    if type(window) is not ExactIdentity:
        raise DeterministicAnalysisError("window must be an ExactIdentity")
    facts = tuple(observation_facts)
    if not facts:
        raise DeterministicAnalysisError("observation_facts must not be empty")
    profile_payload = analysis_profile.payload
    maximum_rows = profile_payload["maximum_view_rows"]
    maximum_bytes = profile_payload["maximum_view_bytes"]
    if len(facts) > maximum_rows:
        raise DeterministicAnalysisError("observation facts exceed the declared row ceiling")

    aggregates: dict[tuple[str, str], int] = {}
    sources: list[ExactIdentity] = []
    evidence: list[ExactIdentity] = []
    observations: list[ExactIdentity] = []
    for fact in facts:
        fact.verify(DETERMINISTIC_ANALYSIS_REGISTRY)
        if fact.record_kind != "analysis_observation_fact" or fact.context_ref != context_ref:
            raise DeterministicAnalysisError("observation fact is not valid for this context")
        payload = fact.payload
        fact_window = _identity(payload["window_ref"], payload["window_digest"])
        if fact_window != window:
            raise DeterministicAnalysisError("observation fact has a different analysis window")
        key = (payload["bucket_ref"], payload["outcome_code"])
        aggregates[key] = aggregates.get(key, 0) + payload["occurrences"]
        sources.append(_identity(payload["source_profile_ref"], payload["source_profile_digest"]))
        evidence.append(_identity(payload["evidence_ref"], payload["evidence_digest"]))
        observations.append(_identity(fact.record_id, fact.content_digest))

    rows = [
        {"bucket_ref": bucket, "outcome_code": outcome, "occurrences": aggregates[(bucket, outcome)]}
        for bucket, outcome in sorted(aggregates)
    ]
    if len(rows) > maximum_rows:
        raise DeterministicAnalysisError("aggregated rows exceed the declared row ceiling")
    source_identities = _unique_identities(sources, "source_profiles")
    evidence_identities = _unique_identities(evidence, "evidence_inputs")
    observation_identities = _unique_identities(observations, "observation_inputs")
    links = [
        _link("analysis_profile", 0, analysis_profile),
        _link("window", 0, window),
    ]
    links.extend(_link("source_profile", ordinal, item) for ordinal, item in enumerate(source_identities))
    links.extend(_link("evidence", ordinal, item) for ordinal, item in enumerate(evidence_identities))
    links.extend(_link("observation", ordinal, item) for ordinal, item in enumerate(observation_identities))
    payload = {
        "record_type": "safe_analysis_view",
        "semantic_engine_id": DETERMINISTIC_ENGINE_ID,
        "analysis_profile_ref": analysis_profile.record_id,
        "analysis_profile_digest": analysis_profile.content_digest,
        "window_ref": window.ref,
        "window_digest": window.digest,
        "source_profiles": _identity_payload(source_identities),
        "evidence_inputs": _identity_payload(evidence_identities),
        "observation_inputs": _identity_payload(observation_identities),
        "input_fact_count": len(facts),
        "maximum_view_rows": maximum_rows,
        "maximum_view_bytes": maximum_bytes,
        "rows": rows,
        "contains_raw_content": False,
        "contains_quarantine_content": False,
        "contains_certification_holdout": False,
        "links": links,
    }
    if len(canonical_json(payload)) > maximum_bytes:
        raise DeterministicAnalysisError("Safe Analysis View exceeds the declared byte ceiling")
    _view_validator(payload, "payload")
    return _record(
        context_ref=context_ref,
        kind="safe_analysis_view",
        schema_id=SAFE_ANALYSIS_VIEW_SCHEMA_ID,
        payload=payload,
        key_epoch=key_epoch,
    )


def build_completed_deterministic_attempt(
    *,
    context_ref: str,
    key_epoch: str,
    analysis_profile: TypedRecord,
    safe_analysis_view: TypedRecord,
    work_item: ExactIdentity,
    budget_reservation: ExactIdentity,
    budget_reconciliation: ExactIdentity,
) -> TypedRecord:
    """Build a completed deterministic receipt; model routes cannot be relabelled."""

    for name, record, kind in (
        ("analysis_profile", analysis_profile, "analysis_profile"),
        ("safe_analysis_view", safe_analysis_view, "safe_analysis_view"),
    ):
        record.verify(DETERMINISTIC_ANALYSIS_REGISTRY)
        if record.record_kind != kind or record.context_ref != context_ref:
            raise DeterministicAnalysisError(f"{name} is not valid for this context")
    view_payload = safe_analysis_view.payload
    if (
        view_payload["analysis_profile_ref"] != analysis_profile.record_id
        or view_payload["analysis_profile_digest"] != analysis_profile.content_digest
    ):
        raise DeterministicAnalysisError("Safe Analysis View does not bind the Analysis Profile")
    for name, identity in (
        ("work_item", work_item),
        ("budget_reservation", budget_reservation),
        ("budget_reconciliation", budget_reconciliation),
    ):
        if type(identity) is not ExactIdentity:
            raise DeterministicAnalysisError(f"{name} must be an ExactIdentity")
    profile_payload = analysis_profile.payload
    dependency = _identity(
        profile_payload["worker_dependency_profile_ref"],
        profile_payload["worker_dependency_profile_digest"],
    )
    payload = {
        "record_type": "analysis_attempt",
        "requested_route": "deterministic",
        "selected_route": "deterministic",
        "selection_reason": "declared_deterministic_reduction",
        "semantic_engine_id": DETERMINISTIC_ENGINE_ID,
        "analysis_profile_ref": analysis_profile.record_id,
        "analysis_profile_digest": analysis_profile.content_digest,
        "safe_analysis_view_ref": safe_analysis_view.record_id,
        "safe_analysis_view_digest": safe_analysis_view.content_digest,
        "work_item_ref": work_item.ref,
        "work_item_digest": work_item.digest,
        "worker_dependency_profile_ref": dependency.ref,
        "worker_dependency_profile_digest": dependency.digest,
        "budget_reservation_ref": budget_reservation.ref,
        "budget_reservation_digest": budget_reservation.digest,
        "budget_reconciliation_ref": budget_reconciliation.ref,
        "budget_reconciliation_digest": budget_reconciliation.digest,
        "model_ref": None,
        "model_source": None,
        "model_use_grant_ref": None,
        "reserved_external_model_usage": _zero_external_usage(),
        "actual_external_model_usage": _zero_external_usage(),
        "invalid_output_count": 0,
        "dropped_output_count": 0,
        "proposal_hashes": [],
        "terminal_state": "completed",
        "cleanup_state": "complete",
        "reason_codes": ["deterministic_reduction_completed"],
        "links": [
            _link("analysis_profile", 0, analysis_profile),
            _link("safe_analysis_view", 0, safe_analysis_view),
            _link("work_item", 0, work_item),
            _link("worker_dependency_profile", 0, dependency),
            _link("budget_reservation", 0, budget_reservation),
            _link("budget_reconciliation", 0, budget_reconciliation),
        ],
    }
    return _record(
        context_ref=context_ref,
        kind="analysis_attempt",
        schema_id=ANALYSIS_ATTEMPT_SCHEMA_ID,
        payload=payload,
        key_epoch=key_epoch,
    )


def _zero_external_usage() -> dict[str, int]:
    return {
        "calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "input_bytes": 0,
        "output_bytes": 0,
        "cost_microunits": 0,
    }


def build_initial_guidance_rule_catalog(*, key_epoch: str) -> TypedRecord:
    """Return the one immutable initial catalog and fixed renderer binding."""

    renderer = ExactIdentity(
        GUIDANCE_RENDERER_CONTRACT_ID, GUIDANCE_RENDERER_CONTRACT_DIGEST
    )
    payload = {
        "record_type": "guidance_rule_catalog",
        "catalog_id": GUIDANCE_RULE_CATALOG_SCHEMA_ID,
        "maximum_selected_rules": MAX_SELECTED_GUIDANCE_RULES,
        "renderer_contract_id": renderer.ref,
        "renderer_contract_digest": renderer.digest,
        "protected_constraints": list(PROTECTED_CONSTRAINTS),
        "rules": _INITIAL_RULES,
        "links": [_link("renderer_contract", 0, renderer)],
    }
    return _record(
        context_ref=None,
        kind="guidance_rule_catalog",
        schema_id=GUIDANCE_RULE_CATALOG_SCHEMA_ID,
        payload=payload,
        key_epoch=key_epoch,
    )


@dataclass(frozen=True, slots=True)
class ProjectedRule:
    rule_id: str
    parameters: tuple[tuple[str, int], ...]

    def as_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "parameters": dict(self.parameters)}


@dataclass(frozen=True, slots=True)
class GuidanceRuleProjection:
    catalog: ExactIdentity
    renderer_contract: ExactIdentity
    benefit_bucket: str
    rules: tuple[ProjectedRule, ...]
    required_evaluation_buckets: tuple[str, ...]
    protected_constraints: tuple[str, ...]


def _projected_rule(value: Mapping[str, Any]) -> ProjectedRule:
    if type(value) is not dict or set(value) != {"rule_id", "parameters"}:
        raise DeterministicAnalysisError("each selected rule needs exact rule_id and parameters")
    rule_id = value["rule_id"]
    if rule_id not in _RULE_ORDER:
        raise DeterministicAnalysisError("selected rule is not in the catalog")
    parameters = value["parameters"]
    if type(parameters) is not dict:
        raise DeterministicAnalysisError("rule parameters must be an object")
    if rule_id == "retry_after_failure":
        if set(parameters) != {"max_retries"}:
            raise DeterministicAnalysisError("retry_after_failure requires typed max_retries")
        maximum = parameters["max_retries"]
        if type(maximum) is not int or not 0 <= maximum <= 2:
            raise DeterministicAnalysisError("max_retries must be an integer from 0 to 2")
        return ProjectedRule(rule_id, (("max_retries", maximum),))
    if parameters:
        raise DeterministicAnalysisError("this rule does not admit parameters")
    return ProjectedRule(rule_id, ())


def project_guidance_rules(
    *,
    catalog: TypedRecord,
    selected_rules: Sequence[Mapping[str, Any]],
    benefit_bucket: str,
    slot_required_buckets: Sequence[str],
    risk_required_buckets: Sequence[str],
    policy_required_buckets: Sequence[str],
    preserved_protected_constraints: Sequence[str],
) -> GuidanceRuleProjection:
    """Validate one pure rule projection and compute its exact coverage union."""

    catalog.verify(DETERMINISTIC_ANALYSIS_REGISTRY)
    if catalog.record_kind != "guidance_rule_catalog" or catalog.context_ref is not None:
        raise DeterministicAnalysisError("catalog is not the immutable system catalog")
    if benefit_bucket not in OBJECTIVE_BUCKETS:
        raise DeterministicAnalysisError("benefit_bucket is unknown")
    rules = tuple(_projected_rule(item) for item in selected_rules)
    if not rules or len(rules) > MAX_SELECTED_GUIDANCE_RULES:
        raise DeterministicAnalysisError("selected rules must contain between one and four rules")
    ids = tuple(rule.rule_id for rule in rules)
    if len(ids) != len(set(ids)) or ids != tuple(sorted(ids, key=_RULE_ORDER.__getitem__)):
        raise DeterministicAnalysisError("selected rules must be unique and in catalog order")

    catalog_rules = {item["rule_id"]: item for item in catalog.payload["rules"]}
    for rule in rules:
        if benefit_bucket not in catalog_rules[rule.rule_id]["allowed_benefit_buckets"]:
            raise DeterministicAnalysisError("benefit claim is not allowed by every selected rule")
    if benefit_bucket == "reasoning":
        raise DeterministicAnalysisError("the initial catalog grants no reasoning benefit")

    slot = _sorted_unique(slot_required_buckets, "slot_required_buckets", allow_empty=True)
    risk = _sorted_unique(risk_required_buckets, "risk_required_buckets", allow_empty=True)
    policy = _sorted_unique(policy_required_buckets, "policy_required_buckets", allow_empty=True)
    rule_coverage = {
        bucket
        for rule in rules
        for bucket in catalog_rules[rule.rule_id]["required_evaluation_buckets"]
    }
    required_coverage = tuple(sorted(rule_coverage | set(slot) | set(risk) | set(policy)))
    required_constraints = tuple(
        sorted(
            {
                constraint
                for rule in rules
                for constraint in catalog_rules[rule.rule_id]["protected_constraints"]
            }
        )
    )
    supplied_constraints = tuple(preserved_protected_constraints)
    if (
        supplied_constraints != tuple(sorted(supplied_constraints))
        or len(supplied_constraints) != len(set(supplied_constraints))
        or supplied_constraints != required_constraints
    ):
        raise DeterministicAnalysisError("protected constraints must be preserved exactly")
    payload = catalog.payload
    return GuidanceRuleProjection(
        catalog=ExactIdentity(catalog.record_id, catalog.content_digest),
        renderer_contract=ExactIdentity(
            payload["renderer_contract_id"], payload["renderer_contract_digest"]
        ),
        benefit_bucket=benefit_bucket,
        rules=rules,
        required_evaluation_buckets=required_coverage,
        protected_constraints=required_constraints,
    )


__all__ = [name for name in globals() if not name.startswith("_")]
