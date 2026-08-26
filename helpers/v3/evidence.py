"""Content-free, policy-bound evidence reduction for v3.

The reducer in this module is deliberately pure.  It validates immutable input
records and returns an append-ready Activation Disposition record; it has no
repository, activation-coordinator, provider, or Agent Zero dependency.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence

from .fixtures import (
    ASSESSMENT_PROFILE_SCHEMA_ID,
    EXECUTION_PROFILE_SCHEMA_ID,
    FIXTURE_REGISTRY,
)
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


ACTIVATION_POLICY_SCHEMA_ID = "a0.activation-policy.v1"
EVALUATION_ENVELOPE_SCHEMA_ID = "a0.evaluation-envelope.v1"
EVIDENCE_BUNDLE_SCHEMA_ID = "a0.evidence-bundle.v1"
ACTIVATION_DISPOSITION_SCHEMA_ID = "a0.activation-disposition.v1"

DISPOSITIONS = ("promotion_ready", "review_only", "rejected")
CALIBRATION_STATES = ("approved", "unapproved", "expired")
UNAVAILABILITY_CODES = (
    "calibration_unavailable",
    "coverage_unavailable",
    "dependency_unavailable",
    "grant_unavailable",
    "harness_unavailable",
    "provider_unavailable",
)
CANDIDATE_HARD_FAILURE_CODES = (
    "deterministic_regression",
    "protected_constraint_violation",
    "safety_veto",
    "schema_violation",
)
GLOBAL_REASON_CODES = (
    *UNAVAILABILITY_CODES,
    "all_requirements_satisfied",
    "authoritative_evidence_unavailable",
    "candidate_hard_failure",
    "candidate_hard_failure_unrecognized",
    "candidate_requirements_failed",
    "evidence_stale",
    "lineage_stale",
)
FAMILY_REASON_CODES = (
    *UNAVAILABILITY_CODES,
    *CANDIDATE_HARD_FAILURE_CODES,
    "candidate_hard_failure_unrecognized",
    "family_coverage_insufficient",
    "family_coverage_satisfied",
)
BUCKET_REASON_CODES = (
    *UNAVAILABILITY_CODES,
    *CANDIDATE_HARD_FAILURE_CODES,
    "bucket_coverage_insufficient",
    "bucket_policy_satisfied",
    "candidate_failure_rate_above_maximum",
    "candidate_hard_failure_unrecognized",
    "candidate_pass_rate_below_minimum",
    "noninferiority_boundary_failed",
)

_OPAQUE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class EvidenceError(ValueError):
    """Raised when immutable evidence or policy inputs are inconsistent."""


def _opaque_reference(maximum: int = 128):
    bounded = strict_string(maximum=maximum)

    def validate(value: Any, path: str) -> str:
        result = bounded(value, path)
        if _OPAQUE_REFERENCE.fullmatch(result) is None:
            raise SchemaValidationError(f"{path} must be a bounded opaque reference")
        return result

    return validate


def _sorted_unique(values: Sequence[str], *, name: str) -> tuple[str, ...]:
    result = tuple(values)
    if not result:
        raise EvidenceError(f"{name} must not be empty")
    if result != tuple(sorted(result)) or len(set(result)) != len(result):
        raise EvidenceError(f"{name} must be sorted and unique")
    return result


def _integer(value: Any, *, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise EvidenceError(f"{name} must be an integer >= {minimum}")
    return value


@dataclass(frozen=True, slots=True)
class Rational:
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        numerator = _integer(self.numerator, name="numerator")
        denominator = _integer(self.denominator, name="denominator", minimum=1)
        if numerator > denominator:
            raise EvidenceError("a policy ratio must be between zero and one")

    def as_dict(self) -> dict[str, int]:
        return {"numerator": self.numerator, "denominator": self.denominator}


@dataclass(frozen=True, slots=True)
class FamilyRequirement:
    family_ref: str
    minimum_completed_pairs: int

    def __post_init__(self) -> None:
        _opaque_reference()(self.family_ref, "family_ref")
        _integer(
            self.minimum_completed_pairs,
            name="minimum_completed_pairs",
            minimum=1,
        )


@dataclass(frozen=True, slots=True)
class BucketRule:
    bucket_ref: str
    minimum_completed_pairs: int
    minimum_candidate_pass_rate: Rational
    maximum_candidate_failure_rate: Rational
    maximum_noninferiority_gap: Rational

    def __post_init__(self) -> None:
        _opaque_reference()(self.bucket_ref, "bucket_ref")
        _integer(
            self.minimum_completed_pairs,
            name="minimum_completed_pairs",
            minimum=1,
        )
        for name in (
            "minimum_candidate_pass_rate",
            "maximum_candidate_failure_rate",
            "maximum_noninferiority_gap",
        ):
            if type(getattr(self, name)) is not Rational:
                raise EvidenceError(f"{name} must be an exact Rational")


@dataclass(frozen=True, slots=True)
class ActivationPolicyInput:
    policy_ref: str
    revision: int
    calibration_state: str
    calibration_artifact_ref: str | None
    calibration_artifact_digest: str | None
    maximum_evidence_age_seconds: int
    required_families: tuple[str, ...]
    family_requirements: tuple[FamilyRequirement, ...]
    required_buckets: tuple[str, ...]
    bucket_rules: tuple[BucketRule, ...]
    candidate_hard_failure_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _opaque_reference()(self.policy_ref, "policy_ref")
        _integer(self.revision, name="revision", minimum=1)
        if self.calibration_state not in CALIBRATION_STATES:
            raise EvidenceError("calibration_state is not admitted")
        if self.calibration_state == "approved":
            _opaque_reference()(self.calibration_artifact_ref, "calibration_artifact_ref")
            validate_digest(self.calibration_artifact_digest, "calibration_artifact_digest")
        elif self.calibration_artifact_ref is not None or self.calibration_artifact_digest is not None:
            raise EvidenceError("only approved calibration may bind a calibration artifact")
        _integer(
            self.maximum_evidence_age_seconds,
            name="maximum_evidence_age_seconds",
        )
        families = _sorted_unique(self.required_families, name="required_families")
        buckets = _sorted_unique(self.required_buckets, name="required_buckets")
        family_refs = tuple(item.family_ref for item in self.family_requirements)
        bucket_refs = tuple(item.bucket_ref for item in self.bucket_rules)
        if family_refs != families:
            raise EvidenceError("family_requirements must exactly cover required_families")
        if bucket_refs != buckets:
            raise EvidenceError("bucket_rules must exactly cover required_buckets")
        hard_failures = tuple(self.candidate_hard_failure_codes)
        if hard_failures != tuple(sorted(hard_failures)) or len(set(hard_failures)) != len(hard_failures):
            raise EvidenceError("candidate_hard_failure_codes must be sorted and unique")
        if any(item not in CANDIDATE_HARD_FAILURE_CODES for item in hard_failures):
            raise EvidenceError("candidate_hard_failure_codes contains an unknown code")


@dataclass(frozen=True, slots=True)
class FamilyEvidence:
    family_ref: str
    attempted_pairs: int
    completed_pairs: int
    unavailability_codes: tuple[str, ...]
    candidate_hard_failure_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _opaque_reference()(self.family_ref, "family_ref")
        attempted = _integer(self.attempted_pairs, name="attempted_pairs")
        completed = _integer(self.completed_pairs, name="completed_pairs")
        if completed > attempted:
            raise EvidenceError("completed_pairs cannot exceed attempted_pairs")
        _validate_codes(self.unavailability_codes, UNAVAILABILITY_CODES, "unavailability_codes")
        _validate_codes(
            self.candidate_hard_failure_codes,
            CANDIDATE_HARD_FAILURE_CODES,
            "candidate_hard_failure_codes",
        )


@dataclass(frozen=True, slots=True)
class BucketEvidence:
    family_ref: str
    bucket_ref: str
    completed_pairs: int
    candidate_passes: int
    incumbent_passes: int
    unavailability_codes: tuple[str, ...]
    candidate_hard_failure_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _opaque_reference()(self.family_ref, "family_ref")
        _opaque_reference()(self.bucket_ref, "bucket_ref")
        completed = _integer(self.completed_pairs, name="completed_pairs")
        candidate = _integer(self.candidate_passes, name="candidate_passes")
        incumbent = _integer(self.incumbent_passes, name="incumbent_passes")
        if candidate > completed or incumbent > completed:
            raise EvidenceError("pass counts cannot exceed completed_pairs")
        _validate_codes(self.unavailability_codes, UNAVAILABILITY_CODES, "unavailability_codes")
        _validate_codes(
            self.candidate_hard_failure_codes,
            CANDIDATE_HARD_FAILURE_CODES,
            "candidate_hard_failure_codes",
        )


@dataclass(frozen=True, slots=True)
class ReductionContext:
    observed_at_epoch_seconds: int
    current_scope_revision: int
    current_incumbent_profile_id: str
    current_incumbent_profile_digest: str

    def __post_init__(self) -> None:
        _integer(self.observed_at_epoch_seconds, name="observed_at_epoch_seconds")
        _integer(self.current_scope_revision, name="current_scope_revision")
        _opaque_reference(512)(self.current_incumbent_profile_id, "current_incumbent_profile_id")
        validate_digest(self.current_incumbent_profile_digest, "current_incumbent_profile_digest")


@dataclass(frozen=True, slots=True)
class ReductionResult:
    disposition: str
    evidence_stale: bool
    lineage_stale: bool
    record: TypedRecord


def _validate_codes(values: Sequence[str], admitted: Sequence[str], name: str) -> tuple[str, ...]:
    result = tuple(values)
    if result != tuple(sorted(result)) or len(set(result)) != len(result):
        raise EvidenceError(f"{name} must be sorted and unique")
    if any(item not in admitted for item in result):
        raise EvidenceError(f"{name} contains an unknown code")
    return result


_RATIONAL_VALIDATOR = strict_object(
    {
        "numerator": strict_integer(minimum=0),
        "denominator": strict_integer(minimum=1),
    }
)
_FAMILY_REQUIREMENT_VALIDATOR = strict_object(
    {
        "family_ref": _opaque_reference(),
        "minimum_completed_pairs": strict_integer(minimum=1),
    }
)
_BUCKET_RULE_VALIDATOR = strict_object(
    {
        "bucket_ref": _opaque_reference(),
        "minimum_completed_pairs": strict_integer(minimum=1),
        "minimum_candidate_pass_rate": _RATIONAL_VALIDATOR,
        "maximum_candidate_failure_rate": _RATIONAL_VALIDATOR,
        "maximum_noninferiority_gap": _RATIONAL_VALIDATOR,
    }
)


def _policy_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("activation_policy"),
            "policy_ref": _opaque_reference(),
            "revision": strict_integer(minimum=1),
            "calibration_state": strict_enum(CALIBRATION_STATES),
            "calibration_artifact_ref": strict_nullable(_opaque_reference()),
            "calibration_artifact_digest": strict_nullable(validate_digest),
            "maximum_evidence_age_seconds": strict_integer(minimum=0),
            "required_families": strict_list(_opaque_reference(), minimum=1, maximum=256),
            "family_requirements": strict_list(
                _FAMILY_REQUIREMENT_VALIDATOR, minimum=1, maximum=256
            ),
            "required_buckets": strict_list(_opaque_reference(), minimum=1, maximum=256),
            "bucket_rules": strict_list(_BUCKET_RULE_VALIDATOR, minimum=1, maximum=256),
            "candidate_hard_failure_codes": strict_list(
                strict_enum(CANDIDATE_HARD_FAILURE_CODES), maximum=len(CANDIDATE_HARD_FAILURE_CODES)
            ),
            "links": validate_links,
        }
    )(value, path)
    if payload["links"]:
        raise SchemaValidationError(f"{path}.links must be empty")
    try:
        _policy_from_payload(payload)
    except EvidenceError as exc:
        raise SchemaValidationError(str(exc)) from exc
    return payload


def _envelope_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("evaluation_envelope"),
            "frozen_at_epoch_seconds": strict_integer(minimum=0),
            "execution_profile_id": _opaque_reference(512),
            "execution_profile_digest": validate_digest,
            "assessment_profile_id": _opaque_reference(512),
            "assessment_profile_digest": validate_digest,
            "fixture_manifest_id": _opaque_reference(512),
            "fixture_manifest_digest": validate_digest,
            "activation_policy_id": _opaque_reference(512),
            "activation_policy_digest": validate_digest,
            "capability_certificate_id": _opaque_reference(512),
            "capability_certificate_digest": validate_digest,
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _payload_link(payload, "execution_profile", 0),
        _payload_link(payload, "assessment_profile", 0),
        _payload_link(payload, "fixture_manifest", 0),
        _payload_link(payload, "activation_policy", 0),
        _payload_link(payload, "capability_certificate", 0),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact evaluation envelope")
    return payload


_FAMILY_EVIDENCE_VALIDATOR = strict_object(
    {
        "family_ref": _opaque_reference(),
        "attempted_pairs": strict_integer(minimum=0),
        "completed_pairs": strict_integer(minimum=0),
        "unavailability_codes": strict_list(strict_enum(UNAVAILABILITY_CODES), maximum=16),
        "candidate_hard_failure_codes": strict_list(
            strict_enum(CANDIDATE_HARD_FAILURE_CODES), maximum=16
        ),
    }
)
_BUCKET_EVIDENCE_VALIDATOR = strict_object(
    {
        "family_ref": _opaque_reference(),
        "bucket_ref": _opaque_reference(),
        "completed_pairs": strict_integer(minimum=0),
        "candidate_passes": strict_integer(minimum=0),
        "incumbent_passes": strict_integer(minimum=0),
        "unavailability_codes": strict_list(strict_enum(UNAVAILABILITY_CODES), maximum=16),
        "candidate_hard_failure_codes": strict_list(
            strict_enum(CANDIDATE_HARD_FAILURE_CODES), maximum=16
        ),
    }
)


def _evidence_bundle_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("evidence_bundle"),
            "candidate_id": _opaque_reference(512),
            "candidate_digest": validate_digest,
            "incumbent_profile_id": _opaque_reference(512),
            "incumbent_profile_digest": validate_digest,
            "activation_scope_ref": _opaque_reference(),
            "activation_scope_revision": strict_integer(minimum=0),
            "evaluation_envelope_id": _opaque_reference(512),
            "evaluation_envelope_digest": validate_digest,
            "evidence_observed_at_epoch_seconds": strict_integer(minimum=0),
            "global_unavailability_codes": strict_list(
                strict_enum(UNAVAILABILITY_CODES), maximum=16
            ),
            "global_candidate_hard_failure_codes": strict_list(
                strict_enum(CANDIDATE_HARD_FAILURE_CODES), maximum=16
            ),
            "family_summaries": strict_list(
                _FAMILY_EVIDENCE_VALIDATOR, minimum=1, maximum=10_000
            ),
            "bucket_summaries": strict_list(
                _BUCKET_EVIDENCE_VALIDATOR, minimum=1, maximum=100_000
            ),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _payload_link(payload, "candidate", 0),
        _payload_link(payload, "incumbent_profile", 0),
        _payload_link(payload, "evaluation_envelope", 0),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact evidence inputs")
    try:
        _validate_evidence_payload(payload)
    except EvidenceError as exc:
        raise SchemaValidationError(str(exc)) from exc
    return payload


_FAMILY_REASON_VALIDATOR = strict_object(
    {
        "family_ref": _opaque_reference(),
        "reason_codes": strict_list(strict_enum(FAMILY_REASON_CODES), minimum=1, maximum=32),
    }
)
_BUCKET_REASON_VALIDATOR = strict_object(
    {
        "family_ref": _opaque_reference(),
        "bucket_ref": _opaque_reference(),
        "reason_codes": strict_list(strict_enum(BUCKET_REASON_CODES), minimum=1, maximum=32),
    }
)


def _disposition_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("activation_disposition"),
            "disposition": strict_enum(DISPOSITIONS),
            "candidate_id": _opaque_reference(512),
            "candidate_digest": validate_digest,
            "evidence_bundle_id": _opaque_reference(512),
            "evidence_bundle_digest": validate_digest,
            "activation_policy_id": _opaque_reference(512),
            "activation_policy_digest": validate_digest,
            "observed_at_epoch_seconds": strict_integer(minimum=0),
            "evidence_stale": strict_boolean(),
            "lineage_stale": strict_boolean(),
            "global_reason_codes": strict_list(
                strict_enum(GLOBAL_REASON_CODES), minimum=1, maximum=32
            ),
            "family_reasons": strict_list(_FAMILY_REASON_VALIDATOR, minimum=1, maximum=10_000),
            "bucket_reasons": strict_list(_BUCKET_REASON_VALIDATOR, minimum=1, maximum=100_000),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _payload_link(payload, "candidate", 0),
        _payload_link(payload, "evidence_bundle", 0),
        _payload_link(payload, "activation_policy", 0),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact disposition inputs")
    return payload


EVIDENCE_REGISTRY = SchemaRegistry(
    (
        *FIXTURE_REGISTRY.schemas.values(),
        RecordSchema(ACTIVATION_POLICY_SCHEMA_ID, "activation_policy", _policy_validator),
        RecordSchema(EVALUATION_ENVELOPE_SCHEMA_ID, "evaluation_envelope", _envelope_validator),
        RecordSchema(EVIDENCE_BUNDLE_SCHEMA_ID, "evidence_bundle", _evidence_bundle_validator),
        RecordSchema(
            ACTIVATION_DISPOSITION_SCHEMA_ID,
            "activation_disposition",
            _disposition_validator,
        ),
    )
)


def build_activation_policy(
    policy: ActivationPolicyInput,
    *,
    context_ref: str,
    key_epoch: str,
) -> TypedRecord:
    if type(policy) is not ActivationPolicyInput:
        raise EvidenceError("policy must be an ActivationPolicyInput")
    payload = {
        "record_type": "activation_policy",
        "policy_ref": policy.policy_ref,
        "revision": policy.revision,
        "calibration_state": policy.calibration_state,
        "calibration_artifact_ref": policy.calibration_artifact_ref,
        "calibration_artifact_digest": policy.calibration_artifact_digest,
        "maximum_evidence_age_seconds": policy.maximum_evidence_age_seconds,
        "required_families": list(policy.required_families),
        "family_requirements": [
            {
                "family_ref": item.family_ref,
                "minimum_completed_pairs": item.minimum_completed_pairs,
            }
            for item in policy.family_requirements
        ],
        "required_buckets": list(policy.required_buckets),
        "bucket_rules": [
            {
                "bucket_ref": item.bucket_ref,
                "minimum_completed_pairs": item.minimum_completed_pairs,
                "minimum_candidate_pass_rate": item.minimum_candidate_pass_rate.as_dict(),
                "maximum_candidate_failure_rate": item.maximum_candidate_failure_rate.as_dict(),
                "maximum_noninferiority_gap": item.maximum_noninferiority_gap.as_dict(),
            }
            for item in policy.bucket_rules
        ],
        "candidate_hard_failure_codes": list(policy.candidate_hard_failure_codes),
        "links": [],
    }
    return _record("activation_policy", ACTIVATION_POLICY_SCHEMA_ID, payload, context_ref, key_epoch)


def build_evaluation_envelope(
    *,
    context_ref: str,
    frozen_at_epoch_seconds: int,
    execution_profile: TypedRecord,
    assessment_profile: TypedRecord,
    fixture_manifest_id: str,
    fixture_manifest_digest: str,
    activation_policy: TypedRecord,
    capability_certificate_id: str,
    capability_certificate_digest: str,
    key_epoch: str,
) -> TypedRecord:
    _integer(frozen_at_epoch_seconds, name="frozen_at_epoch_seconds")
    _require_record(execution_profile, "execution_profile", EXECUTION_PROFILE_SCHEMA_ID, FIXTURE_REGISTRY)
    _require_record(assessment_profile, "assessment_profile", ASSESSMENT_PROFILE_SCHEMA_ID, FIXTURE_REGISTRY)
    _require_record(activation_policy, "activation_policy", ACTIVATION_POLICY_SCHEMA_ID, EVIDENCE_REGISTRY)
    _opaque_reference(512)(fixture_manifest_id, "fixture_manifest_id")
    validate_digest(fixture_manifest_digest, "fixture_manifest_digest")
    _opaque_reference(512)(capability_certificate_id, "capability_certificate_id")
    validate_digest(capability_certificate_digest, "capability_certificate_digest")
    if assessment_profile.payload["activation_policy_digest"] != activation_policy.content_digest:
        raise EvidenceError("assessment profile does not bind the exact activation policy")
    payload = {
        "record_type": "evaluation_envelope",
        "frozen_at_epoch_seconds": frozen_at_epoch_seconds,
        "execution_profile_id": execution_profile.record_id,
        "execution_profile_digest": execution_profile.content_digest,
        "assessment_profile_id": assessment_profile.record_id,
        "assessment_profile_digest": assessment_profile.content_digest,
        "fixture_manifest_id": fixture_manifest_id,
        "fixture_manifest_digest": fixture_manifest_digest,
        "activation_policy_id": activation_policy.record_id,
        "activation_policy_digest": activation_policy.content_digest,
        "capability_certificate_id": capability_certificate_id,
        "capability_certificate_digest": capability_certificate_digest,
        "links": [],
    }
    payload["links"] = [
        _payload_link(payload, "execution_profile", 0),
        _payload_link(payload, "assessment_profile", 0),
        _payload_link(payload, "fixture_manifest", 0),
        _payload_link(payload, "activation_policy", 0),
        _payload_link(payload, "capability_certificate", 0),
    ]
    return _record(
        "evaluation_envelope", EVALUATION_ENVELOPE_SCHEMA_ID, payload, context_ref, key_epoch
    )


def build_evidence_bundle(
    *,
    context_ref: str,
    candidate_id: str,
    candidate_digest: str,
    incumbent_profile_id: str,
    incumbent_profile_digest: str,
    activation_scope_ref: str,
    activation_scope_revision: int,
    evaluation_envelope: TypedRecord,
    evidence_observed_at_epoch_seconds: int,
    global_unavailability_codes: Sequence[str],
    global_candidate_hard_failure_codes: Sequence[str],
    family_summaries: Sequence[FamilyEvidence],
    bucket_summaries: Sequence[BucketEvidence],
    key_epoch: str,
) -> TypedRecord:
    _opaque_reference(512)(candidate_id, "candidate_id")
    validate_digest(candidate_digest, "candidate_digest")
    _opaque_reference(512)(incumbent_profile_id, "incumbent_profile_id")
    validate_digest(incumbent_profile_digest, "incumbent_profile_digest")
    _opaque_reference()(activation_scope_ref, "activation_scope_ref")
    _integer(activation_scope_revision, name="activation_scope_revision")
    _integer(evidence_observed_at_epoch_seconds, name="evidence_observed_at_epoch_seconds")
    _require_record(
        evaluation_envelope,
        "evaluation_envelope",
        EVALUATION_ENVELOPE_SCHEMA_ID,
        EVIDENCE_REGISTRY,
    )
    _validate_codes(global_unavailability_codes, UNAVAILABILITY_CODES, "global_unavailability_codes")
    _validate_codes(
        global_candidate_hard_failure_codes,
        CANDIDATE_HARD_FAILURE_CODES,
        "global_candidate_hard_failure_codes",
    )
    if not family_summaries or not bucket_summaries:
        raise EvidenceError("evidence bundle requires family and bucket summaries")
    if any(type(item) is not FamilyEvidence for item in family_summaries):
        raise EvidenceError("family_summaries must contain FamilyEvidence")
    if any(type(item) is not BucketEvidence for item in bucket_summaries):
        raise EvidenceError("bucket_summaries must contain BucketEvidence")
    family_values = sorted(family_summaries, key=lambda item: item.family_ref)
    bucket_values = sorted(bucket_summaries, key=lambda item: (item.family_ref, item.bucket_ref))
    payload = {
        "record_type": "evidence_bundle",
        "candidate_id": candidate_id,
        "candidate_digest": candidate_digest,
        "incumbent_profile_id": incumbent_profile_id,
        "incumbent_profile_digest": incumbent_profile_digest,
        "activation_scope_ref": activation_scope_ref,
        "activation_scope_revision": activation_scope_revision,
        "evaluation_envelope_id": evaluation_envelope.record_id,
        "evaluation_envelope_digest": evaluation_envelope.content_digest,
        "evidence_observed_at_epoch_seconds": evidence_observed_at_epoch_seconds,
        "global_unavailability_codes": list(global_unavailability_codes),
        "global_candidate_hard_failure_codes": list(global_candidate_hard_failure_codes),
        "family_summaries": [_family_evidence_payload(item) for item in family_values],
        "bucket_summaries": [_bucket_evidence_payload(item) for item in bucket_values],
        "links": [],
    }
    payload["links"] = [
        _payload_link(payload, "candidate", 0),
        _payload_link(payload, "incumbent_profile", 0),
        _payload_link(payload, "evaluation_envelope", 0),
    ]
    return _record("evidence_bundle", EVIDENCE_BUNDLE_SCHEMA_ID, payload, context_ref, key_epoch)


def reduce_evidence(
    evidence_bundle: TypedRecord,
    evaluation_envelope: TypedRecord,
    activation_policy: TypedRecord,
    *,
    context: ReductionContext,
    key_epoch: str,
) -> ReductionResult:
    """Reduce exact immutable inputs without reading or changing activation state."""

    _require_record(evidence_bundle, "evidence_bundle", EVIDENCE_BUNDLE_SCHEMA_ID, EVIDENCE_REGISTRY)
    _require_record(
        evaluation_envelope,
        "evaluation_envelope",
        EVALUATION_ENVELOPE_SCHEMA_ID,
        EVIDENCE_REGISTRY,
    )
    _require_record(activation_policy, "activation_policy", ACTIVATION_POLICY_SCHEMA_ID, EVIDENCE_REGISTRY)
    if type(context) is not ReductionContext:
        raise EvidenceError("context must be a ReductionContext")
    bundle = evidence_bundle.payload
    envelope = evaluation_envelope.payload
    if (
        bundle["evaluation_envelope_id"] != evaluation_envelope.record_id
        or bundle["evaluation_envelope_digest"] != evaluation_envelope.content_digest
    ):
        raise EvidenceError("evidence bundle does not bind the supplied evaluation envelope")
    if context.observed_at_epoch_seconds < bundle["evidence_observed_at_epoch_seconds"]:
        raise EvidenceError("reduction observation cannot predate evidence")

    policy = _policy_from_payload(activation_policy.payload)
    evidence_stale = (
        context.observed_at_epoch_seconds - bundle["evidence_observed_at_epoch_seconds"]
        > policy.maximum_evidence_age_seconds
        or envelope["activation_policy_id"] != activation_policy.record_id
        or envelope["activation_policy_digest"] != activation_policy.content_digest
    )
    lineage_stale = (
        bundle["activation_scope_revision"] != context.current_scope_revision
        or bundle["incumbent_profile_id"] != context.current_incumbent_profile_id
        or bundle["incumbent_profile_digest"] != context.current_incumbent_profile_digest
    )

    global_reasons: set[str] = set(bundle["global_unavailability_codes"])
    if policy.calibration_state != "approved":
        global_reasons.add("calibration_unavailable")
    if evidence_stale:
        global_reasons.add("evidence_stale")
    if lineage_stale:
        global_reasons.add("lineage_stale")

    family_map = {item["family_ref"]: item for item in bundle["family_summaries"]}
    bucket_map = {
        (item["family_ref"], item["bucket_ref"]): item
        for item in bundle["bucket_summaries"]
    }
    family_reasons: list[dict[str, Any]] = []
    bucket_reasons: list[dict[str, Any]] = []
    recognized_hard_failure = False
    unrecognized_hard_failure = False
    metric_failure = False
    coverage_failure = False

    recognized, unrecognized = _classify_hard_failures(
        bundle["global_candidate_hard_failure_codes"], policy.candidate_hard_failure_codes
    )
    recognized_hard_failure |= bool(recognized)
    unrecognized_hard_failure |= bool(unrecognized)

    family_requirements = {item.family_ref: item for item in policy.family_requirements}
    bucket_rules = {item.bucket_ref: item for item in policy.bucket_rules}
    for family_ref in policy.required_families:
        summary = family_map.get(family_ref)
        reasons: set[str] = set()
        if summary is None:
            reasons.add("family_coverage_insufficient")
            coverage_failure = True
        else:
            reasons.update(summary["unavailability_codes"])
            if summary["completed_pairs"] < family_requirements[family_ref].minimum_completed_pairs:
                reasons.add("family_coverage_insufficient")
                coverage_failure = True
            recognized, unrecognized = _classify_hard_failures(
                summary["candidate_hard_failure_codes"], policy.candidate_hard_failure_codes
            )
            reasons.update(recognized)
            recognized_hard_failure |= bool(recognized)
            if unrecognized:
                reasons.add("candidate_hard_failure_unrecognized")
                unrecognized_hard_failure = True
            if not reasons:
                reasons.add("family_coverage_satisfied")
        family_reasons.append({"family_ref": family_ref, "reason_codes": sorted(reasons)})

        for bucket_ref in policy.required_buckets:
            bucket = bucket_map.get((family_ref, bucket_ref))
            bucket_reason: set[str] = set()
            if bucket is None:
                bucket_reason.add("bucket_coverage_insufficient")
                coverage_failure = True
            else:
                bucket_reason.update(bucket["unavailability_codes"])
                rule = bucket_rules[bucket_ref]
                if bucket["completed_pairs"] < rule.minimum_completed_pairs:
                    bucket_reason.add("bucket_coverage_insufficient")
                    coverage_failure = True
                recognized, unrecognized = _classify_hard_failures(
                    bucket["candidate_hard_failure_codes"], policy.candidate_hard_failure_codes
                )
                bucket_reason.update(recognized)
                recognized_hard_failure |= bool(recognized)
                if unrecognized:
                    bucket_reason.add("candidate_hard_failure_unrecognized")
                    unrecognized_hard_failure = True
                if not bucket["unavailability_codes"] and bucket["completed_pairs"] >= rule.minimum_completed_pairs:
                    failures = _metric_reasons(bucket, rule)
                    bucket_reason.update(failures)
                    metric_failure |= bool(failures)
                if not bucket_reason:
                    bucket_reason.add("bucket_policy_satisfied")
            bucket_reasons.append(
                {
                    "family_ref": family_ref,
                    "bucket_ref": bucket_ref,
                    "reason_codes": sorted(bucket_reason),
                }
            )

    if coverage_failure:
        global_reasons.add("coverage_unavailable")
    if recognized_hard_failure:
        global_reasons.add("candidate_hard_failure")
    if unrecognized_hard_failure:
        global_reasons.add("candidate_hard_failure_unrecognized")

    authoritative_unavailable = bool(
        set(global_reasons) & (set(UNAVAILABILITY_CODES) | {"evidence_stale", "lineage_stale", "candidate_hard_failure_unrecognized"})
    ) or any(
        set(item["reason_codes"]) & set(UNAVAILABILITY_CODES)
        for item in family_reasons + bucket_reasons
    )
    if recognized_hard_failure:
        disposition = "rejected"
        global_reasons.add("candidate_requirements_failed")
    elif authoritative_unavailable:
        disposition = "review_only"
        global_reasons.add("authoritative_evidence_unavailable")
    elif metric_failure:
        disposition = "rejected"
        global_reasons.add("candidate_requirements_failed")
    else:
        disposition = "promotion_ready"
        global_reasons.add("all_requirements_satisfied")

    payload = {
        "record_type": "activation_disposition",
        "disposition": disposition,
        "candidate_id": bundle["candidate_id"],
        "candidate_digest": bundle["candidate_digest"],
        "evidence_bundle_id": evidence_bundle.record_id,
        "evidence_bundle_digest": evidence_bundle.content_digest,
        "activation_policy_id": activation_policy.record_id,
        "activation_policy_digest": activation_policy.content_digest,
        "observed_at_epoch_seconds": context.observed_at_epoch_seconds,
        "evidence_stale": evidence_stale,
        "lineage_stale": lineage_stale,
        "global_reason_codes": sorted(global_reasons),
        "family_reasons": family_reasons,
        "bucket_reasons": bucket_reasons,
        "links": [],
    }
    payload["links"] = [
        _payload_link(payload, "candidate", 0),
        _payload_link(payload, "evidence_bundle", 0),
        _payload_link(payload, "activation_policy", 0),
    ]
    record = _record(
        "activation_disposition",
        ACTIVATION_DISPOSITION_SCHEMA_ID,
        payload,
        evidence_bundle.context_ref or "evidence-reducer",
        key_epoch,
    )
    return ReductionResult(disposition, evidence_stale, lineage_stale, record)


def _policy_from_payload(payload: Mapping[str, Any]) -> ActivationPolicyInput:
    return ActivationPolicyInput(
        policy_ref=payload["policy_ref"],
        revision=payload["revision"],
        calibration_state=payload["calibration_state"],
        calibration_artifact_ref=payload["calibration_artifact_ref"],
        calibration_artifact_digest=payload["calibration_artifact_digest"],
        maximum_evidence_age_seconds=payload["maximum_evidence_age_seconds"],
        required_families=tuple(payload["required_families"]),
        family_requirements=tuple(
            FamilyRequirement(item["family_ref"], item["minimum_completed_pairs"])
            for item in payload["family_requirements"]
        ),
        required_buckets=tuple(payload["required_buckets"]),
        bucket_rules=tuple(
            BucketRule(
                bucket_ref=item["bucket_ref"],
                minimum_completed_pairs=item["minimum_completed_pairs"],
                minimum_candidate_pass_rate=Rational(**item["minimum_candidate_pass_rate"]),
                maximum_candidate_failure_rate=Rational(**item["maximum_candidate_failure_rate"]),
                maximum_noninferiority_gap=Rational(**item["maximum_noninferiority_gap"]),
            )
            for item in payload["bucket_rules"]
        ),
        candidate_hard_failure_codes=tuple(payload["candidate_hard_failure_codes"]),
    )


def _validate_evidence_payload(payload: Mapping[str, Any]) -> None:
    _validate_codes(payload["global_unavailability_codes"], UNAVAILABILITY_CODES, "global_unavailability_codes")
    _validate_codes(
        payload["global_candidate_hard_failure_codes"],
        CANDIDATE_HARD_FAILURE_CODES,
        "global_candidate_hard_failure_codes",
    )
    families: list[str] = []
    for item in payload["family_summaries"]:
        FamilyEvidence(
            item["family_ref"],
            item["attempted_pairs"],
            item["completed_pairs"],
            tuple(item["unavailability_codes"]),
            tuple(item["candidate_hard_failure_codes"]),
        )
        families.append(item["family_ref"])
    if families != sorted(families) or len(set(families)) != len(families):
        raise EvidenceError("family_summaries must be sorted and unique")
    buckets: list[tuple[str, str]] = []
    for item in payload["bucket_summaries"]:
        BucketEvidence(
            item["family_ref"],
            item["bucket_ref"],
            item["completed_pairs"],
            item["candidate_passes"],
            item["incumbent_passes"],
            tuple(item["unavailability_codes"]),
            tuple(item["candidate_hard_failure_codes"]),
        )
        buckets.append((item["family_ref"], item["bucket_ref"]))
    if buckets != sorted(buckets) or len(set(buckets)) != len(buckets):
        raise EvidenceError("bucket_summaries must be sorted and unique")


def _metric_reasons(bucket: Mapping[str, Any], rule: BucketRule) -> set[str]:
    completed = bucket["completed_pairs"]
    if completed == 0:
        return {"bucket_coverage_insufficient"}
    candidate = bucket["candidate_passes"]
    incumbent = bucket["incumbent_passes"]
    reasons: set[str] = set()
    minimum = rule.minimum_candidate_pass_rate
    if candidate * minimum.denominator < completed * minimum.numerator:
        reasons.add("candidate_pass_rate_below_minimum")
    maximum = rule.maximum_candidate_failure_rate
    if (completed - candidate) * maximum.denominator > completed * maximum.numerator:
        reasons.add("candidate_failure_rate_above_maximum")
    gap = rule.maximum_noninferiority_gap
    if candidate * gap.denominator + gap.numerator * completed < incumbent * gap.denominator:
        reasons.add("noninferiority_boundary_failed")
    return reasons


def _classify_hard_failures(
    observed: Sequence[str], admitted: Sequence[str]
) -> tuple[set[str], set[str]]:
    admitted_set = set(admitted)
    return ({item for item in observed if item in admitted_set}, {item for item in observed if item not in admitted_set})


def _family_evidence_payload(item: FamilyEvidence) -> dict[str, Any]:
    return {
        "family_ref": item.family_ref,
        "attempted_pairs": item.attempted_pairs,
        "completed_pairs": item.completed_pairs,
        "unavailability_codes": list(item.unavailability_codes),
        "candidate_hard_failure_codes": list(item.candidate_hard_failure_codes),
    }


def _bucket_evidence_payload(item: BucketEvidence) -> dict[str, Any]:
    return {
        "family_ref": item.family_ref,
        "bucket_ref": item.bucket_ref,
        "completed_pairs": item.completed_pairs,
        "candidate_passes": item.candidate_passes,
        "incumbent_passes": item.incumbent_passes,
        "unavailability_codes": list(item.unavailability_codes),
        "candidate_hard_failure_codes": list(item.candidate_hard_failure_codes),
    }


def _payload_link(payload: Mapping[str, Any], role: str, ordinal: int) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": payload[f"{role}_id"],
        "target_digest": payload[f"{role}_digest"],
    }


def _require_record(
    record: TypedRecord,
    kind: str,
    schema_id: str,
    registry: SchemaRegistry,
) -> None:
    if type(record) is not TypedRecord or record.record_kind != kind or record.schema_id != schema_id:
        raise EvidenceError(f"expected exact {kind} record")
    try:
        record.verify(registry)
    except SchemaValidationError as exc:
        raise EvidenceError(f"invalid {kind} record") from exc


def _record(
    kind: str,
    schema_id: str,
    payload: Mapping[str, Any],
    context_ref: str,
    key_epoch: str,
) -> TypedRecord:
    _opaque_reference()(context_ref, "context_ref")
    _opaque_reference()(key_epoch, "key_epoch")
    encoded = canonical_json(dict(payload))
    record_id = kind + "_" + schema_digest("record-identity", schema_id, encoded)
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind=kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=key_epoch,
        registry=EVIDENCE_REGISTRY,
    )


__all__ = [name for name in globals() if not name.startswith("_")]
