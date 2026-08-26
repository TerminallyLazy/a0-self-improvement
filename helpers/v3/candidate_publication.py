"""Pure, fail-closed planning for candidate publication.

Workers may stage only the small canonical result accepted by this module.  All
identity-bearing authority is supplied separately by the coordinator, so a
worker cannot manufacture provenance links in its result.  The planner has no
repository, filesystem, provider, or network dependency.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence

from .artifacts import ACTIVATION_PROFILE_SCHEMA_ID
from .evidence import EVIDENCE_REGISTRY
from .repository import DomainEvent
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    canonical_loads,
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
from .work_authority import PublicationWriteSet


STAGED_RESULT_SCHEMA_ID = "a0.candidate-publication-staged-result.v1"
STRUCTURED_GUIDANCE_SCHEMA_ID = "a0.structured-guidance.v2"
ATTEMPT_CONCLUSION_SCHEMA_ID = "a0.attempt-conclusion.v1"
OPTIMIZATION_RUN_RECEIPT_SCHEMA_ID = "a0.optimization-run-receipt.v1"
ARTIFACT_GENERATION_RECEIPT_SCHEMA_ID = "a0.artifact-generation-receipt.v1"
IMPROVEMENT_CANDIDATE_SCHEMA_ID = "a0.improvement-candidate.v1"
PUBLICATION_RESULT_SCHEMA_ID = "a0.publication-result.v1"

ATTEMPT_CONCLUSIONS = (
    "succeeded",
    "no_candidate",
    "partial",
    "unavailable",
    "budget_exhausted",
    "cancelled",
    "stopped",
    "failed",
    "incompatible",
)
PUBLICATION_RESULTS = ("none", "artifact_locked", "candidate_published")
RUN_REASON_CODES = (
    "budget_exhausted",
    "cancelled",
    "capability_drift",
    "cleanup_uncertain",
    "completed",
    "deadline_exceeded",
    "dependency_drift",
    "fence_lost",
    "fixture_authority_drift",
    "grant_revoked",
    "holdout_access_denied",
    "incumbent_drift",
    "lease_lost",
    "no_candidate",
    "provider_unavailable",
    "schema_invalid",
    "scope_revision_drift",
    "stopped",
    "unknown_usage",
)
USAGE_DIMENSIONS = (
    "calls",
    "tokens",
    "cost_microunits",
    "wall_time_ms",
    "cases",
    "variants",
    "outputs",
    "retries",
)
ENGINE_SEMANTIC_IDS = (
    "a0.generate.guidance.deterministic_rules.v1",
    "a0.generate.guidance.legacy_rule_agreement_gepa.v1",
    "a0.generate.guidance.outcome_gepa.v1",
)
_RULE_ORDER = {
    "verify_tool_contract": 0,
    "check_tool_result": 1,
    "retry_after_failure": 2,
    "prefer_reversible_action": 3,
    "bound_tool_scope": 4,
}
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class CandidatePublicationError(ValueError):
    """A staged result or frozen publication authority is inadmissible."""


@dataclass(frozen=True, slots=True)
class RetryClassification:
    retry_eligible: bool
    terminal_work_state: str
    publication_forced_none: bool


def classify_attempt_retry(
    *,
    conclusion: str,
    reason_code: str,
    transient_reason_codes: tuple[str, ...],
    attempts_remaining: bool,
    cancellation_requested: bool,
    authorities_current: bool,
    cleanup_verified: bool,
    budget_available: bool,
) -> RetryClassification:
    """Apply the frozen attempt table plus explicit retry authorities."""

    if conclusion not in ATTEMPT_CONCLUSIONS or reason_code not in RUN_REASON_CODES:
        raise CandidatePublicationError("attempt conclusion or reason code is not admitted")
    if (
        type(transient_reason_codes) is not tuple
        or transient_reason_codes != tuple(sorted(set(transient_reason_codes)))
        or any(item not in RUN_REASON_CODES for item in transient_reason_codes)
    ):
        raise CandidatePublicationError(
            "transient_reason_codes must be an explicit sorted unique allowlist"
        )
    flags = (
        attempts_remaining,
        cancellation_requested,
        authorities_current,
        cleanup_verified,
        budget_available,
    )
    if any(type(item) is not bool for item in flags):
        raise CandidatePublicationError("retry authority flags must be strict booleans")

    terminal = (
        "cancelled"
        if conclusion == "cancelled"
        else "failed"
        if conclusion == "failed"
        else "completed"
    )
    if reason_code == "cleanup_uncertain":
        return RetryClassification(False, "failed", True)
    retryable_conclusion = conclusion in ("unavailable", "stopped", "failed")
    eligible = (
        retryable_conclusion
        and reason_code in transient_reason_codes
        and attempts_remaining
        and not cancellation_requested
        and authorities_current
        and cleanup_verified
        and budget_available
    )
    return RetryClassification(eligible, terminal, False)


def _opaque(value: Any, name: str, *, maximum: int = 512) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _OPAQUE_REF.fullmatch(value) is None:
        raise CandidatePublicationError(f"{name} must be a bounded opaque reference")
    return value


@dataclass(frozen=True, slots=True)
class ExactIdentity:
    ref: str
    digest: str

    def __post_init__(self) -> None:
        _opaque(self.ref, "identity.ref")
        try:
            validate_digest(self.digest, "identity.digest")
        except SchemaValidationError as exc:
            raise CandidatePublicationError("identity.digest is not an exact digest") from exc


@dataclass(frozen=True, slots=True)
class BoundedUsage:
    calls: int
    tokens: int
    cost_microunits: int
    wall_time_ms: int
    cases: int
    variants: int
    outputs: int
    retries: int

    def __post_init__(self) -> None:
        for name in USAGE_DIMENSIONS:
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise CandidatePublicationError(f"usage.{name} must be a non-negative integer")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BoundedUsage":
        if type(value) is not dict or set(value) != set(USAGE_DIMENSIONS):
            raise CandidatePublicationError("actual_usage must contain exactly the bounded dimensions")
        return cls(**{name: value[name] for name in USAGE_DIMENSIONS})

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in USAGE_DIMENSIONS}

    def fits_within(self, limit: "BoundedUsage") -> bool:
        return all(getattr(self, name) <= getattr(limit, name) for name in USAGE_DIMENSIONS)


@dataclass(frozen=True, slots=True)
class CandidatePolicy:
    benefit_kind: str
    benefit_bucket: str
    benefit_claim: ExactIdentity
    risk_tier: str
    lineage: ExactIdentity

    def __post_init__(self) -> None:
        if self.benefit_kind not in ("outcome", "efficiency"):
            raise CandidatePublicationError("benefit_kind is not admitted")
        _opaque(self.benefit_bucket, "benefit_bucket", maximum=128)
        if type(self.benefit_claim) is not ExactIdentity or type(self.lineage) is not ExactIdentity:
            raise CandidatePublicationError("candidate policy requires exact claim and lineage identities")
        if self.risk_tier not in ("standard", "elevated", "restricted"):
            raise CandidatePublicationError("risk_tier is not admitted")


@dataclass(frozen=True, slots=True)
class PublicationAuthorities:
    context_ref: str
    work_item: ExactIdentity
    work_attempt: ExactIdentity
    fence_token: int
    work_event_sequence: int
    engine_profile: ExactIdentity
    engine_semantic_id: str
    authority_ceiling: str
    incumbent_profile: TypedRecord
    scope_ref: str
    scope_revision: int
    worker_dependency_profile: ExactIdentity
    capability_certificate: ExactIdentity
    publication_authority: ExactIdentity
    model_use_grant: ExactIdentity | None
    budget_profile: ExactIdentity
    budget_ledger: ExactIdentity
    budget_limits: BoundedUsage
    fixture_authorities: tuple[ExactIdentity, ...]
    admitted_inputs: tuple[ExactIdentity, ...]
    guidance_rule_catalog: ExactIdentity
    renderer_contract: ExactIdentity
    key_epoch: str = "candidate-publication-v1"

    def __post_init__(self) -> None:
        _opaque(self.context_ref, "context_ref")
        _opaque(self.scope_ref, "scope_ref")
        if self.scope_ref != self.context_ref:
            raise CandidatePublicationError("scope_ref must bind the publication context")
        for name in (
            "work_item",
            "work_attempt",
            "engine_profile",
            "worker_dependency_profile",
            "capability_certificate",
            "publication_authority",
            "budget_profile",
            "budget_ledger",
            "guidance_rule_catalog",
            "renderer_contract",
        ):
            if type(getattr(self, name)) is not ExactIdentity:
                raise CandidatePublicationError(f"{name} must be an ExactIdentity")
        if self.model_use_grant is not None and type(self.model_use_grant) is not ExactIdentity:
            raise CandidatePublicationError("model_use_grant must be null or an ExactIdentity")
        if type(self.fence_token) is not int or self.fence_token <= 0:
            raise CandidatePublicationError("fence_token must be a positive integer")
        if type(self.work_event_sequence) is not int or self.work_event_sequence < 0:
            raise CandidatePublicationError("work_event_sequence must be a non-negative integer")
        if type(self.scope_revision) is not int or self.scope_revision < 0:
            raise CandidatePublicationError("scope_revision must be a non-negative integer")
        if self.engine_semantic_id not in ENGINE_SEMANTIC_IDS:
            raise CandidatePublicationError("engine_semantic_id is not admitted")
        if (
            self.engine_semantic_id != "a0.generate.guidance.deterministic_rules.v1"
            and self.model_use_grant is None
        ):
            raise CandidatePublicationError("model-backed engines require an exact Model Use Grant")
        if self.authority_ceiling not in ("artifact_only", "candidate_publication"):
            raise CandidatePublicationError("authority_ceiling is not admitted")
        if type(self.key_epoch) is not str or not self.key_epoch:
            raise CandidatePublicationError("key_epoch must be non-empty")
        if type(self.budget_limits) is not BoundedUsage:
            raise CandidatePublicationError("budget_limits must be a BoundedUsage")
        _identity_sequence(self.fixture_authorities, "fixture_authorities")
        _identity_sequence(self.admitted_inputs, "admitted_inputs", minimum=1)
        try:
            self.incumbent_profile.verify(EVIDENCE_REGISTRY)
        except (SchemaValidationError, ValueError) as exc:
            raise CandidatePublicationError("incumbent_profile is not a valid exact profile") from exc
        if self.incumbent_profile.record_kind != "activation_profile":
            raise CandidatePublicationError("incumbent_profile must be an Activation Profile")
        if self.incumbent_profile.context_ref != self.context_ref:
            raise CandidatePublicationError("incumbent_profile belongs to a different context")


def _identity_sequence(
    values: Sequence[ExactIdentity], name: str, *, minimum: int = 0
) -> None:
    if type(values) is not tuple or len(values) < minimum:
        raise CandidatePublicationError(f"{name} has too few exact identities")
    if any(type(item) is not ExactIdentity for item in values):
        raise CandidatePublicationError(f"{name} must contain only ExactIdentity values")
    refs = tuple(item.ref for item in values)
    if refs != tuple(sorted(refs)) or len(set(refs)) != len(refs):
        raise CandidatePublicationError(f"{name} must be sorted and unique")


_EMPTY_PARAMETERS = strict_object({})
_RETRY_PARAMETERS = strict_object({"max_retries": strict_integer(minimum=0, maximum=2)})


def _rule(value: Any, path: str) -> dict[str, Any]:
    outer = strict_object(
        {
            "rule_id": strict_enum(tuple(_RULE_ORDER)),
            "parameters": lambda raw, inner_path: raw,
        }
    )(value, path)
    validator = _RETRY_PARAMETERS if outer["rule_id"] == "retry_after_failure" else _EMPTY_PARAMETERS
    outer["parameters"] = validator(outer["parameters"], f"{path}.parameters")
    return outer


def _rules(value: Any, path: str) -> list[dict[str, Any]]:
    rules = strict_list(_rule, minimum=1, maximum=4)(value, path)
    ids = [item["rule_id"] for item in rules]
    if len(ids) != len(set(ids)) or ids != sorted(ids, key=_RULE_ORDER.__getitem__):
        raise SchemaValidationError(f"{path} must be unique and in catalog order")
    return rules


_USAGE_VALIDATOR = strict_object(
    {name: strict_integer(minimum=0) for name in USAGE_DIMENSIONS}
)
_STAGED_ARTIFACT_VALIDATOR = strict_object(
    {
        "artifact_type": strict_literal("structured_guidance"),
        "rules": _rules,
    }
)
_STAGED_RESULT_VALIDATOR = strict_object(
    {
        "schema": strict_literal(STAGED_RESULT_SCHEMA_ID),
        "attempt_conclusion": strict_enum(ATTEMPT_CONCLUSIONS),
        "publication_result": strict_enum(PUBLICATION_RESULTS),
        "reason_codes": strict_list(strict_enum(RUN_REASON_CODES), maximum=16),
        "actual_usage": _USAGE_VALIDATOR,
        "cleanup_verified": strict_boolean(),
        "fence_retained": strict_boolean(),
        "artifact": strict_nullable(_STAGED_ARTIFACT_VALIDATOR),
    }
)


def _link(role: str, ordinal: int, identity: ExactIdentity | TypedRecord) -> dict[str, Any]:
    if isinstance(identity, TypedRecord):
        ref, digest = identity.record_id, identity.content_digest
    else:
        ref, digest = identity.ref, identity.digest
    return {"role": role, "ordinal": ordinal, "target_id": ref, "target_digest": digest}


def _expected_links(payload: Mapping[str, Any], roles: Sequence[str]) -> list[dict[str, Any]]:
    return [
        {
            "role": role,
            "ordinal": 0,
            "target_id": payload[f"{role}_id"],
            "target_digest": payload[f"{role}_digest"],
        }
        for role in roles
    ]


def _links_bound(validator: Any, roles: Sequence[str]):
    def validate(value: Any, path: str) -> dict[str, Any]:
        payload = validator(value, path)
        if payload["links"] != _expected_links(payload, roles):
            raise SchemaValidationError(f"{path}.links do not bind the exact record inputs")
        return payload

    return validate


_ARTIFACT_VALIDATOR = _links_bound(
    strict_object(
        {
            "record_type": strict_literal("improvement_artifact"),
            "artifact_type": strict_literal("structured_guidance"),
            "artifact_slot": strict_literal("structured_guidance"),
            "payload_schema": strict_literal(STRUCTURED_GUIDANCE_SCHEMA_ID),
            "guidance_rule_catalog_id": strict_string(maximum=512),
            "guidance_rule_catalog_digest": validate_digest,
            "renderer_contract_id": strict_string(maximum=512),
            "renderer_contract_digest": validate_digest,
            "rules": _rules,
            "links": validate_links,
        }
    ),
    ("guidance_rule_catalog", "renderer_contract"),
)

def _conclusion_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object({
        "record_type": strict_literal("attempt_conclusion"),
        "work_item_ref": strict_string(maximum=512),
        "work_item_digest": validate_digest,
        "work_attempt_ref": strict_string(maximum=512),
        "work_attempt_digest": validate_digest,
        "conclusion": strict_enum(ATTEMPT_CONCLUSIONS),
        "reason_codes": strict_list(strict_enum(RUN_REASON_CODES), maximum=16),
        "cleanup_verified": strict_boolean(),
        "fence_retained": strict_boolean(),
        "fence_token": strict_integer(minimum=1),
        "links": validate_links,
    })(value, path)
    if payload["links"] != []:
        raise SchemaValidationError(f"{path}.links must be empty")
    return payload

_RUN_RECEIPT_FIELDS = strict_object({
        "record_type": strict_literal("optimization_run_receipt"),
        "work_attempt_ref": strict_string(maximum=512),
        "work_attempt_digest": validate_digest,
        "engine_profile_ref": strict_string(maximum=512),
        "engine_profile_digest": validate_digest,
        "engine_semantic_id": strict_enum(ENGINE_SEMANTIC_IDS),
        "worker_dependency_profile_ref": strict_string(maximum=512),
        "worker_dependency_profile_digest": validate_digest,
        "capability_certificate_ref": strict_string(maximum=512),
        "capability_certificate_digest": validate_digest,
        "publication_authority_ref": strict_string(maximum=512),
        "publication_authority_digest": validate_digest,
        "model_use_grant_ref": strict_nullable(strict_string(maximum=512)),
        "model_use_grant_digest": strict_nullable(validate_digest),
        "budget_profile_ref": strict_string(maximum=512),
        "budget_profile_digest": validate_digest,
        "budget_ledger_ref": strict_string(maximum=512),
        "budget_ledger_digest": validate_digest,
        "admitted_input_count": strict_integer(minimum=1),
        "fixture_authority_count": strict_integer(minimum=0),
        "attempt_conclusion_id": strict_string(maximum=512),
        "attempt_conclusion_digest": validate_digest,
        "conclusion": strict_enum(ATTEMPT_CONCLUSIONS),
        "publication_result": strict_enum(PUBLICATION_RESULTS),
        "actual_usage": _USAGE_VALIDATOR,
        "cleanup_verified": strict_boolean(),
        "fence_retained": strict_boolean(),
        "reason_codes": strict_list(strict_enum(RUN_REASON_CODES), maximum=16),
        "links": validate_links,
    })


def _run_receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = _RUN_RECEIPT_FIELDS(value, path)
    fixed = (
        ("engine_profile", "engine_profile_ref", "engine_profile_digest"),
        (
            "worker_dependency_profile",
            "worker_dependency_profile_ref",
            "worker_dependency_profile_digest",
        ),
        ("capability_certificate", "capability_certificate_ref", "capability_certificate_digest"),
        ("publication_authority", "publication_authority_ref", "publication_authority_digest"),
        ("budget_profile", "budget_profile_ref", "budget_profile_digest"),
        ("budget_ledger", "budget_ledger_ref", "budget_ledger_digest"),
        ("attempt_conclusion", "attempt_conclusion_id", "attempt_conclusion_digest"),
    )
    expected = [
        {
            "role": role,
            "ordinal": 0,
            "target_id": payload[id_field],
            "target_digest": payload[digest_field],
        }
        for role, id_field, digest_field in fixed
    ]
    model_pair = (payload["model_use_grant_ref"], payload["model_use_grant_digest"])
    if (model_pair[0] is None) != (model_pair[1] is None):
        raise SchemaValidationError(f"{path} has a partial Model Use Grant identity")
    if model_pair[0] is not None:
        expected.append(
            {
                "role": "model_use_grant",
                "ordinal": 0,
                "target_id": model_pair[0],
                "target_digest": model_pair[1],
            }
        )
    expected_prefix = len(expected)
    links = payload["links"]
    if links[:expected_prefix] != expected:
        raise SchemaValidationError(f"{path}.links do not bind exact run authorities")
    remainder = links[expected_prefix:]
    admitted_count = payload["admitted_input_count"]
    fixture_count = payload["fixture_authority_count"]
    if len(remainder) != admitted_count + fixture_count:
        raise SchemaValidationError(f"{path}.links do not cover every admitted input")
    for ordinal, link in enumerate(remainder[:admitted_count]):
        if (link["role"], link["ordinal"]) != ("admitted_input", ordinal):
            raise SchemaValidationError(f"{path}.links have an invalid admitted-input manifest")
    for ordinal, link in enumerate(remainder[admitted_count:]):
        if (link["role"], link["ordinal"]) != ("fixture_authority", ordinal):
            raise SchemaValidationError(f"{path}.links have an invalid fixture-authority manifest")
    return payload

_GENERATION_RECEIPT_FIELDS = strict_object({
        "record_type": strict_literal("artifact_generation_receipt"),
        "artifact_id": strict_string(maximum=512),
        "artifact_digest": validate_digest,
        "engine_profile_id": strict_string(maximum=512),
        "engine_profile_digest": validate_digest,
        "engine_semantic_id": strict_enum(ENGINE_SEMANTIC_IDS),
        "worker_dependency_profile_id": strict_string(maximum=512),
        "worker_dependency_profile_digest": validate_digest,
        "publication_authority_id": strict_string(maximum=512),
        "publication_authority_digest": validate_digest,
        "model_use_grant_id": strict_nullable(strict_string(maximum=512)),
        "model_use_grant_digest": strict_nullable(validate_digest),
        "budget_profile_id": strict_string(maximum=512),
        "budget_profile_digest": validate_digest,
        "optimization_run_receipt_id": strict_string(maximum=512),
        "optimization_run_receipt_digest": validate_digest,
        "admitted_input_count": strict_integer(minimum=1),
        "fixture_authority_count": strict_integer(minimum=0),
        "links": validate_links,
    })


def _generation_receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = _GENERATION_RECEIPT_FIELDS(value, path)
    roles = (
        "artifact",
        "engine_profile",
        "worker_dependency_profile",
        "publication_authority",
        "budget_profile",
        "optimization_run_receipt",
    )
    expected = _expected_links(payload, roles)
    model_pair = (payload["model_use_grant_id"], payload["model_use_grant_digest"])
    if (model_pair[0] is None) != (model_pair[1] is None):
        raise SchemaValidationError(f"{path} has a partial Model Use Grant identity")
    if model_pair[0] is not None:
        expected.append(
            {
                "role": "model_use_grant",
                "ordinal": 0,
                "target_id": model_pair[0],
                "target_digest": model_pair[1],
            }
        )
    links = payload["links"]
    if links[: len(expected)] != expected:
        raise SchemaValidationError(f"{path}.links do not bind exact generation authorities")
    remainder = links[len(expected):]
    admitted_count = payload["admitted_input_count"]
    fixture_count = payload["fixture_authority_count"]
    if len(remainder) != admitted_count + fixture_count:
        raise SchemaValidationError(f"{path}.links do not cover every generation input")
    for ordinal, link in enumerate(remainder[:admitted_count]):
        if (link["role"], link["ordinal"]) != ("admitted_input", ordinal):
            raise SchemaValidationError(f"{path}.links have an invalid admitted-input manifest")
    for ordinal, link in enumerate(remainder[admitted_count:]):
        if (link["role"], link["ordinal"]) != ("fixture_authority", ordinal):
            raise SchemaValidationError(f"{path}.links have an invalid fixture-authority manifest")
    return payload

_BENEFIT_CLAIM_VALIDATOR = strict_object(
    {
        "kind": strict_enum(("outcome", "efficiency")),
        "bucket": strict_string(maximum=128),
        "claim_ref": strict_string(maximum=512),
        "claim_digest": validate_digest,
    }
)


def _candidate_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("improvement_candidate"),
            "change_kind": strict_literal("replace_structured_guidance"),
            "artifact_slot": strict_literal("structured_guidance"),
            "artifact_id": strict_string(maximum=512),
            "artifact_digest": validate_digest,
            "incumbent_profile_id": strict_string(maximum=512),
            "incumbent_profile_digest": validate_digest,
            "successor_profile_id": strict_string(maximum=512),
            "successor_profile_digest": validate_digest,
            "activation_scope_ref": strict_string(maximum=512),
            "observed_scope_revision": strict_integer(minimum=0),
            "lineage_id": strict_string(maximum=512),
            "lineage_digest": validate_digest,
            "benefit_claim": _BENEFIT_CLAIM_VALIDATOR,
            "risk_tier": strict_enum(("standard", "elevated", "restricted")),
            "engine_semantic_id": strict_enum(ENGINE_SEMANTIC_IDS),
            "engine_profile_id": strict_string(maximum=512),
            "engine_profile_digest": validate_digest,
            "artifact_generation_receipt_id": strict_string(maximum=512),
            "artifact_generation_receipt_digest": validate_digest,
            "links": validate_links,
        }
    )(value, path)
    roles = (
        "artifact",
        "incumbent_profile",
        "successor_profile",
        "lineage",
        "engine_profile",
        "artifact_generation_receipt",
    )
    if payload["links"] != _expected_links(payload, roles):
        raise SchemaValidationError(f"{path}.links do not bind the exact candidate lineage")
    return payload


_PUBLICATION_FIELDS = strict_object({
        "record_type": strict_literal("publication_result"),
        "work_attempt_ref": strict_string(maximum=512),
        "work_attempt_digest": validate_digest,
        "result": strict_enum(PUBLICATION_RESULTS),
        "attempt_conclusion_id": strict_string(maximum=512),
        "attempt_conclusion_digest": validate_digest,
        "optimization_run_receipt_id": strict_string(maximum=512),
        "optimization_run_receipt_digest": validate_digest,
        "artifact_id": strict_nullable(strict_string(maximum=512)),
        "artifact_digest": strict_nullable(validate_digest),
        "candidate_id": strict_nullable(strict_string(maximum=512)),
        "candidate_digest": strict_nullable(validate_digest),
        "links": validate_links,
    })


def _publication_validator(value: Any, path: str) -> dict[str, Any]:
    payload = _PUBLICATION_FIELDS(value, path)
    result = payload["result"]
    artifact_pair = (payload["artifact_id"], payload["artifact_digest"])
    candidate_pair = (payload["candidate_id"], payload["candidate_digest"])
    if (artifact_pair[0] is None) != (artifact_pair[1] is None):
        raise SchemaValidationError(f"{path} has a partial artifact identity")
    if (candidate_pair[0] is None) != (candidate_pair[1] is None):
        raise SchemaValidationError(f"{path} has a partial candidate identity")
    if result == "none" and (artifact_pair[0] is not None or candidate_pair[0] is not None):
        raise SchemaValidationError(f"{path} none result cannot name an output")
    if result == "artifact_locked" and (artifact_pair[0] is None or candidate_pair[0] is not None):
        raise SchemaValidationError(f"{path} artifact_locked has invalid output identities")
    if result == "candidate_published" and (artifact_pair[0] is None or candidate_pair[0] is None):
        raise SchemaValidationError(f"{path} candidate_published requires both outputs")
    expected = _expected_links(
        payload,
        (
            "attempt_conclusion",
            "optimization_run_receipt",
            *(("artifact",) if artifact_pair[0] is not None else ()),
            *(("candidate",) if candidate_pair[0] is not None else ()),
        ),
    )
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind exact publication outputs")
    return payload


CANDIDATE_PUBLICATION_REGISTRY = SchemaRegistry(
    (
        *EVIDENCE_REGISTRY.schemas.values(),
        RecordSchema(STRUCTURED_GUIDANCE_SCHEMA_ID, "guidance_artifact", _ARTIFACT_VALIDATOR),
        RecordSchema(ATTEMPT_CONCLUSION_SCHEMA_ID, "attempt_conclusion", _conclusion_validator),
        RecordSchema(
            OPTIMIZATION_RUN_RECEIPT_SCHEMA_ID,
            "optimization_run_receipt",
            _run_receipt_validator,
        ),
        RecordSchema(
            ARTIFACT_GENERATION_RECEIPT_SCHEMA_ID,
            "artifact_generation_receipt",
            _generation_receipt_validator,
        ),
        RecordSchema(
            IMPROVEMENT_CANDIDATE_SCHEMA_ID,
            "improvement_candidate",
            _candidate_validator,
        ),
        RecordSchema(PUBLICATION_RESULT_SCHEMA_ID, "publication_result", _publication_validator),
    )
)


def _record(
    *, context_ref: str, kind: str, schema_id: str, payload: Mapping[str, Any], key_epoch: str
) -> TypedRecord:
    encoded = canonical_json(dict(payload))
    return build_typed_record(
        record_id=kind + "_" + schema_digest("record-identity", schema_id, encoded),
        context_ref=context_ref,
        record_kind=kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=key_epoch,
        registry=CANDIDATE_PUBLICATION_REGISTRY,
    )


def _validate_staged_result(staged_result: bytes) -> tuple[dict[str, Any], BoundedUsage]:
    if type(staged_result) is not bytes:
        raise CandidatePublicationError("staged_result must be one immutable bytes object")
    try:
        decoded = canonical_loads(staged_result)
        staged = _STAGED_RESULT_VALIDATOR(decoded, "staged_result")
    except (SchemaValidationError, ValueError) as exc:
        raise CandidatePublicationError("staged result is malformed, noncanonical, or unsupported") from exc
    reasons = staged["reason_codes"]
    if reasons != sorted(reasons) or len(reasons) != len(set(reasons)):
        raise CandidatePublicationError("reason_codes must be sorted and unique")
    publication = staged["publication_result"]
    artifact = staged["artifact"]
    if (publication == "none") != (artifact is None):
        raise CandidatePublicationError("publication_result does not match staged artifact presence")
    if publication != "none" and (
        staged["attempt_conclusion"] != "succeeded"
        or staged["cleanup_verified"] is not True
        or staged["fence_retained"] is not True
    ):
        raise CandidatePublicationError("publication requires a successful clean fenced attempt")
    if staged["attempt_conclusion"] == "no_candidate" and publication != "none":
        raise CandidatePublicationError("no_candidate cannot publish an artifact")
    return staged, BoundedUsage.from_mapping(staged["actual_usage"])


def plan_candidate_publication(
    staged_result: bytes,
    *,
    authorities: PublicationAuthorities,
    candidate_policy: CandidatePolicy,
) -> PublicationWriteSet:
    """Validate one staged result and return its complete append-only write set."""

    if type(authorities) is not PublicationAuthorities:
        raise CandidatePublicationError("authorities must be frozen PublicationAuthorities")
    if type(candidate_policy) is not CandidatePolicy:
        raise CandidatePublicationError("candidate_policy must be a frozen CandidatePolicy")
    staged, actual_usage = _validate_staged_result(staged_result)
    if not actual_usage.fits_within(authorities.budget_limits):
        raise CandidatePublicationError("staged usage exceeds the exact budget authority")
    if staged["publication_result"] == "candidate_published" and (
        authorities.authority_ceiling != "candidate_publication"
        or authorities.engine_semantic_id
        == "a0.generate.guidance.legacy_rule_agreement_gepa.v1"
    ):
        raise CandidatePublicationError("engine authority cannot publish a candidate")

    conclusion_payload = {
        "record_type": "attempt_conclusion",
        "work_item_ref": authorities.work_item.ref,
        "work_item_digest": authorities.work_item.digest,
        "work_attempt_ref": authorities.work_attempt.ref,
        "work_attempt_digest": authorities.work_attempt.digest,
        "conclusion": staged["attempt_conclusion"],
        "reason_codes": staged["reason_codes"],
        "cleanup_verified": staged["cleanup_verified"],
        "fence_retained": staged["fence_retained"],
        "fence_token": authorities.fence_token,
        "links": [],
    }
    conclusion = _record(
        context_ref=authorities.context_ref,
        kind="attempt_conclusion",
        schema_id=ATTEMPT_CONCLUSION_SCHEMA_ID,
        payload=conclusion_payload,
        key_epoch=authorities.key_epoch,
    )

    run_links = [
        _link("engine_profile", 0, authorities.engine_profile),
        _link("worker_dependency_profile", 0, authorities.worker_dependency_profile),
        _link("capability_certificate", 0, authorities.capability_certificate),
        _link("publication_authority", 0, authorities.publication_authority),
        _link("budget_profile", 0, authorities.budget_profile),
        _link("budget_ledger", 0, authorities.budget_ledger),
        _link("attempt_conclusion", 0, conclusion),
    ]
    if authorities.model_use_grant is not None:
        run_links.append(_link("model_use_grant", 0, authorities.model_use_grant))
    run_links.extend(
        _link("admitted_input", ordinal, item)
        for ordinal, item in enumerate(authorities.admitted_inputs)
    )
    run_links.extend(
        _link("fixture_authority", ordinal, item)
        for ordinal, item in enumerate(authorities.fixture_authorities)
    )
    run_payload = {
        "record_type": "optimization_run_receipt",
        "work_attempt_ref": authorities.work_attempt.ref,
        "work_attempt_digest": authorities.work_attempt.digest,
        "engine_profile_ref": authorities.engine_profile.ref,
        "engine_profile_digest": authorities.engine_profile.digest,
        "engine_semantic_id": authorities.engine_semantic_id,
        "worker_dependency_profile_ref": authorities.worker_dependency_profile.ref,
        "worker_dependency_profile_digest": authorities.worker_dependency_profile.digest,
        "capability_certificate_ref": authorities.capability_certificate.ref,
        "capability_certificate_digest": authorities.capability_certificate.digest,
        "publication_authority_ref": authorities.publication_authority.ref,
        "publication_authority_digest": authorities.publication_authority.digest,
        "model_use_grant_ref": (
            authorities.model_use_grant.ref if authorities.model_use_grant else None
        ),
        "model_use_grant_digest": (
            authorities.model_use_grant.digest if authorities.model_use_grant else None
        ),
        "budget_profile_ref": authorities.budget_profile.ref,
        "budget_profile_digest": authorities.budget_profile.digest,
        "budget_ledger_ref": authorities.budget_ledger.ref,
        "budget_ledger_digest": authorities.budget_ledger.digest,
        "admitted_input_count": len(authorities.admitted_inputs),
        "fixture_authority_count": len(authorities.fixture_authorities),
        "attempt_conclusion_id": conclusion.record_id,
        "attempt_conclusion_digest": conclusion.content_digest,
        "conclusion": staged["attempt_conclusion"],
        "publication_result": staged["publication_result"],
        "actual_usage": actual_usage.as_dict(),
        "cleanup_verified": staged["cleanup_verified"],
        "fence_retained": staged["fence_retained"],
        "reason_codes": staged["reason_codes"],
        "links": run_links,
    }
    run_receipt = _record(
        context_ref=authorities.context_ref,
        kind="optimization_run_receipt",
        schema_id=OPTIMIZATION_RUN_RECEIPT_SCHEMA_ID,
        payload=run_payload,
        key_epoch=authorities.key_epoch,
    )

    records: list[TypedRecord] = [conclusion, run_receipt]
    artifact: TypedRecord | None = None
    generation: TypedRecord | None = None
    successor: TypedRecord | None = None
    candidate: TypedRecord | None = None

    if staged["artifact"] is not None:
        artifact_payload = {
            "record_type": "improvement_artifact",
            "artifact_type": "structured_guidance",
            "artifact_slot": "structured_guidance",
            "payload_schema": STRUCTURED_GUIDANCE_SCHEMA_ID,
            "guidance_rule_catalog_id": authorities.guidance_rule_catalog.ref,
            "guidance_rule_catalog_digest": authorities.guidance_rule_catalog.digest,
            "renderer_contract_id": authorities.renderer_contract.ref,
            "renderer_contract_digest": authorities.renderer_contract.digest,
            "rules": staged["artifact"]["rules"],
            "links": [
                _link("guidance_rule_catalog", 0, authorities.guidance_rule_catalog),
                _link("renderer_contract", 0, authorities.renderer_contract),
            ],
        }
        artifact = _record(
            context_ref=authorities.context_ref,
            kind="guidance_artifact",
            schema_id=STRUCTURED_GUIDANCE_SCHEMA_ID,
            payload=artifact_payload,
            key_epoch=authorities.key_epoch,
        )
        generation_links = [
            _link("artifact", 0, artifact),
            _link("engine_profile", 0, authorities.engine_profile),
            _link("worker_dependency_profile", 0, authorities.worker_dependency_profile),
            _link("publication_authority", 0, authorities.publication_authority),
            _link("budget_profile", 0, authorities.budget_profile),
            _link("optimization_run_receipt", 0, run_receipt),
        ]
        if authorities.model_use_grant is not None:
            generation_links.append(
                _link("model_use_grant", 0, authorities.model_use_grant)
            )
        generation_links.extend(
            _link("admitted_input", ordinal, item)
            for ordinal, item in enumerate(authorities.admitted_inputs)
        )
        generation_links.extend(
            _link("fixture_authority", ordinal, item)
            for ordinal, item in enumerate(authorities.fixture_authorities)
        )
        generation_payload = {
            "record_type": "artifact_generation_receipt",
            "artifact_id": artifact.record_id,
            "artifact_digest": artifact.content_digest,
            "engine_profile_id": authorities.engine_profile.ref,
            "engine_profile_digest": authorities.engine_profile.digest,
            "engine_semantic_id": authorities.engine_semantic_id,
            "worker_dependency_profile_id": authorities.worker_dependency_profile.ref,
            "worker_dependency_profile_digest": authorities.worker_dependency_profile.digest,
            "publication_authority_id": authorities.publication_authority.ref,
            "publication_authority_digest": authorities.publication_authority.digest,
            "model_use_grant_id": (
                authorities.model_use_grant.ref if authorities.model_use_grant else None
            ),
            "model_use_grant_digest": (
                authorities.model_use_grant.digest if authorities.model_use_grant else None
            ),
            "budget_profile_id": authorities.budget_profile.ref,
            "budget_profile_digest": authorities.budget_profile.digest,
            "optimization_run_receipt_id": run_receipt.record_id,
            "optimization_run_receipt_digest": run_receipt.content_digest,
            "admitted_input_count": len(authorities.admitted_inputs),
            "fixture_authority_count": len(authorities.fixture_authorities),
            "links": generation_links,
        }
        generation = _record(
            context_ref=authorities.context_ref,
            kind="artifact_generation_receipt",
            schema_id=ARTIFACT_GENERATION_RECEIPT_SCHEMA_ID,
            payload=generation_payload,
            key_epoch=authorities.key_epoch,
        )
        records.extend((artifact, generation))

    if staged["publication_result"] == "candidate_published":
        assert artifact is not None and generation is not None
        successor = _successor_profile(authorities, artifact)
        candidate_payload = {
            "record_type": "improvement_candidate",
            "change_kind": "replace_structured_guidance",
            "artifact_slot": "structured_guidance",
            "artifact_id": artifact.record_id,
            "artifact_digest": artifact.content_digest,
            "incumbent_profile_id": authorities.incumbent_profile.record_id,
            "incumbent_profile_digest": authorities.incumbent_profile.content_digest,
            "successor_profile_id": successor.record_id,
            "successor_profile_digest": successor.content_digest,
            "activation_scope_ref": authorities.scope_ref,
            "observed_scope_revision": authorities.scope_revision,
            "lineage_id": candidate_policy.lineage.ref,
            "lineage_digest": candidate_policy.lineage.digest,
            "benefit_claim": {
                "kind": candidate_policy.benefit_kind,
                "bucket": candidate_policy.benefit_bucket,
                "claim_ref": candidate_policy.benefit_claim.ref,
                "claim_digest": candidate_policy.benefit_claim.digest,
            },
            "risk_tier": candidate_policy.risk_tier,
            "engine_semantic_id": authorities.engine_semantic_id,
            "engine_profile_id": authorities.engine_profile.ref,
            "engine_profile_digest": authorities.engine_profile.digest,
            "artifact_generation_receipt_id": generation.record_id,
            "artifact_generation_receipt_digest": generation.content_digest,
            "links": [
                _link("artifact", 0, artifact),
                _link("incumbent_profile", 0, authorities.incumbent_profile),
                _link("successor_profile", 0, successor),
                _link("lineage", 0, candidate_policy.lineage),
                _link("engine_profile", 0, authorities.engine_profile),
                _link("artifact_generation_receipt", 0, generation),
            ],
        }
        candidate = _record(
            context_ref=authorities.context_ref,
            kind="improvement_candidate",
            schema_id=IMPROVEMENT_CANDIDATE_SCHEMA_ID,
            payload=candidate_payload,
            key_epoch=authorities.key_epoch,
        )
        records.extend((successor, candidate))

    publication_links = [
        _link("attempt_conclusion", 0, conclusion),
        _link("optimization_run_receipt", 0, run_receipt),
    ]
    if artifact is not None:
        publication_links.append(_link("artifact", 0, artifact))
    if candidate is not None:
        publication_links.append(_link("candidate", 0, candidate))
    publication_payload = {
        "record_type": "publication_result",
        "work_attempt_ref": authorities.work_attempt.ref,
        "work_attempt_digest": authorities.work_attempt.digest,
        "result": staged["publication_result"],
        "attempt_conclusion_id": conclusion.record_id,
        "attempt_conclusion_digest": conclusion.content_digest,
        "optimization_run_receipt_id": run_receipt.record_id,
        "optimization_run_receipt_digest": run_receipt.content_digest,
        "artifact_id": artifact.record_id if artifact else None,
        "artifact_digest": artifact.content_digest if artifact else None,
        "candidate_id": candidate.record_id if candidate else None,
        "candidate_digest": candidate.content_digest if candidate else None,
        "links": publication_links,
    }
    publication = _record(
        context_ref=authorities.context_ref,
        kind="publication_result",
        schema_id=PUBLICATION_RESULT_SCHEMA_ID,
        payload=publication_payload,
        key_epoch=authorities.key_epoch,
    )
    records.append(publication)

    events = [
        _event(
            authorities,
            subject_id=authorities.work_attempt.ref,
            subject_kind="work_attempt",
            sequence=authorities.work_event_sequence,
            event_type="publication_finalized",
            payload=publication,
        )
    ]
    if artifact is not None:
        events.append(
            _event(
                authorities,
                subject_id=artifact.record_id,
                subject_kind=artifact.record_kind,
                sequence=0,
                event_type="artifact_locked",
                payload=generation,
            )
        )
    if candidate is not None:
        events.append(
            _event(
                authorities,
                subject_id=candidate.record_id,
                subject_kind=candidate.record_kind,
                sequence=0,
                event_type="candidate_published",
                payload=publication,
            )
        )
    return PublicationWriteSet(tuple(records), tuple(events))


def _successor_profile(authorities: PublicationAuthorities, artifact: TypedRecord) -> TypedRecord:
    incumbent = authorities.incumbent_profile.payload
    slots = [dict(item) for item in incumbent["slots"]]
    if [item["slot_kind"] for item in slots] != ["structured_guidance", "prompt_patch"]:
        raise CandidatePublicationError("incumbent profile does not contain the exact two slots")
    slots[0] = {
        "slot_kind": "structured_guidance",
        "artifact_id": artifact.record_id,
        "artifact_digest": artifact.content_digest,
    }
    links = [
        _link("artifact_slot:structured_guidance", 0, artifact),
        {
            "role": "artifact_slot:prompt_patch",
            "ordinal": 0,
            "target_id": slots[1]["artifact_id"],
            "target_digest": slots[1]["artifact_digest"],
        },
    ]
    payload = {"profile_type": "activation_profile", "slots": slots, "links": links}
    return _record(
        context_ref=authorities.context_ref,
        kind="activation_profile",
        schema_id=ACTIVATION_PROFILE_SCHEMA_ID,
        payload=payload,
        key_epoch=authorities.key_epoch,
    )


def _event(
    authorities: PublicationAuthorities,
    *,
    subject_id: str,
    subject_kind: str,
    sequence: int,
    event_type: str,
    payload: TypedRecord | None,
) -> DomainEvent:
    body = {
        "subject_id": subject_id,
        "subject_kind": subject_kind,
        "sequence": sequence,
        "event_type": event_type,
        "payload_record_id": payload.record_id if payload else None,
        "actor_authority_ref": authorities.publication_authority.ref,
        "fence_token": authorities.fence_token,
    }
    return DomainEvent(
        event_id="candidate_publication_event_"
        + schema_digest("domain-event", "a0.candidate-publication-event.v1", canonical_json(body)),
        **body,
    )


__all__ = [
    "ARTIFACT_GENERATION_RECEIPT_SCHEMA_ID",
    "ATTEMPT_CONCLUSION_SCHEMA_ID",
    "BoundedUsage",
    "CANDIDATE_PUBLICATION_REGISTRY",
    "CandidatePolicy",
    "CandidatePublicationError",
    "RetryClassification",
    "ENGINE_SEMANTIC_IDS",
    "ExactIdentity",
    "IMPROVEMENT_CANDIDATE_SCHEMA_ID",
    "OPTIMIZATION_RUN_RECEIPT_SCHEMA_ID",
    "PUBLICATION_RESULT_SCHEMA_ID",
    "PUBLICATION_RESULTS",
    "PublicationAuthorities",
    "STAGED_RESULT_SCHEMA_ID",
    "STRUCTURED_GUIDANCE_SCHEMA_ID",
    "classify_attempt_retry",
    "plan_candidate_publication",
]
