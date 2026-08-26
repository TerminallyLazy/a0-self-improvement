"""Durable fixed-horizon reduction of certified canary outcomes.

Exposure receipts prove assignment only.  They never prove an outcome.  This
module therefore accepts a complete, exact canary window only when every
receipt has one separately authority-ranked, content-free outcome fact.  The
approved reducer profile freezes the aggregation semantics; all decision
thresholds remain owned by the exact Canary Plan.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
from math import gcd
import re
from typing import Any, Mapping, Sequence

from .canary import (
    ACTIVATION_POLICY_SCHEMA_ID,
    CANARY_PLAN_SCHEMA_ID,
    CANARY_REGISTRY,
    CANARY_TRIAL_SCHEMA_ID,
    EXPOSURE_RECEIPT_SCHEMA_ID,
    POLICY_CALIBRATION_SCHEMA_ID,
    BucketOutcome,
    CanaryConclusionRequest,
    Rational,
)
from .canary_command_adapter import ExactRecord, SlotBinding
from .canary_conclusion_repository import (
    CANARY_CONCLUSION_REPOSITORY_REGISTRY,
    build_certified_canary_outcome_authority,
)
from .calibration_authority import (
    CALIBRATION_AUTHORITY_REGISTRY,
    CalibrationAuthorityError,
    CalibrationLifecycleFact,
    reduce_calibration_eligibility,
)
from .candidate_publication import (
    CANDIDATE_PUBLICATION_REGISTRY,
    IMPROVEMENT_CANDIDATE_SCHEMA_ID,
)
from .repository import (
    DomainEvent,
    IdempotencyConflict,
    IntegrityFailure,
    RevisionConflict,
    V3Repository,
    V3Transaction,
)
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    merge_schema_registries,
    schema_digest,
    strict_boolean,
    strict_enum,
    strict_integer,
    strict_list,
    strict_literal,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


CANARY_OUTCOME_REDUCER_PROFILE_SCHEMA_ID = "a0.canary-outcome-reducer-profile.v1"
CANARY_OUTCOME_WINDOW_SCHEMA_ID = "a0.canary-outcome-window.v1"
CANARY_OUTCOME_FACT_AUTHORITY_SCHEMA_ID = "a0.canary-outcome-fact-authority.v1"
CANARY_ATTRIBUTABLE_OUTCOME_SCHEMA_ID = "a0.canary-attributable-outcome.v1"
CANARY_OUTCOME_REDUCTION_SCHEMA_ID = "a0.canary-outcome-reduction.v1"
CANARY_OUTCOME_REDUCTION_RECEIPT_SCHEMA_ID = "a0.canary-outcome-reduction-receipt.v1"

CANARY_OUTCOME_REDUCER_PROFILE_KIND = "canary_outcome_reducer_profile"
CANARY_OUTCOME_WINDOW_KIND = "canary_outcome_window"
CANARY_OUTCOME_FACT_AUTHORITY_KIND = "canary_outcome_fact_authority"
CANARY_ATTRIBUTABLE_OUTCOME_KIND = "canary_attributable_outcome"
CANARY_OUTCOME_REDUCTION_KIND = "canary_outcome_reduction"
CANARY_OUTCOME_REDUCTION_RECEIPT_KIND = "canary_outcome_reduction_receipt"
CANARY_OUTCOME_REDUCER_AUTHORITY_REF = "system:canary-outcome-reducer:v1"

_OPAQUE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")


class CanaryOutcomeReductionError(RuntimeError):
    """The proposed reduction is incomplete or outside certified authority."""


def _opaque(value: Any, path: str) -> str:
    result = strict_string(maximum=512)(value, path)
    if _OPAQUE_PATTERN.fullmatch(result) is None:
        raise SchemaValidationError(f"{path} must be a bounded opaque reference")
    return result


def _rational(value: Any, path: str) -> dict[str, int]:
    result = strict_object(
        {"numerator": strict_integer(), "denominator": strict_integer(minimum=1)}
    )(value, path)
    if gcd(abs(result["numerator"]), result["denominator"]) != 1:
        raise SchemaValidationError(f"{path} must be in lowest terms")
    return result


_EXACT = strict_object({"record_id": _opaque, "digest": validate_digest})
_BUCKET_VALUE = strict_object(
    {
        "bucket_ref": _opaque,
        "comparable": strict_boolean(),
        "value": _rational,
    }
)
_BUCKET_REDUCTION = strict_object(
    {
        "bucket_ref": _opaque,
        "candidate_comparable_count": strict_integer(minimum=1),
        "incumbent_comparable_count": strict_integer(minimum=1),
        "comparable_count": strict_integer(minimum=1),
        "candidate_delta": _rational,
        "boundary_uncertain": strict_boolean(),
    }
)


def _exact_payload(record: TypedRecord | ExactRecord) -> dict[str, str]:
    if isinstance(record, TypedRecord):
        return {"record_id": record.record_id, "digest": record.content_digest}
    if type(record) is ExactRecord:
        return record.payload()
    raise TypeError("an exact record identity is required")


def _link(role: str, ordinal: int, exact: Mapping[str, str]) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": exact["record_id"],
        "target_digest": exact["digest"],
    }


def _profile_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "profile_type": strict_literal("fixed_horizon_canary_outcome_reducer"),
            "profile_revision": strict_integer(minimum=1),
            "approval_state": strict_literal("approved"),
            "producer": _EXACT,
            "canary_plan": _EXACT,
            "policy_calibration": _EXACT,
            "aggregation_algorithm": strict_literal("difference_of_exact_arm_means_v1"),
            "comparable_count_algorithm": strict_literal("minimum_exact_arm_count_v1"),
            "window_completion": strict_literal("exact_plan_horizon"),
            "missing_outcome_policy": strict_literal("reject"),
            "mixed_input_policy": strict_literal("reject"),
            "control_signal_policy": strict_literal("fixed_horizon_outcomes_only"),
            "hard_failure_algorithm": strict_literal("candidate_arm_count_v1"),
            "shared_failure_algorithm": strict_literal("any_exact_outcome_fact_v1"),
            "identity_drift_algorithm": strict_literal("any_exact_outcome_fact_v1"),
            "boundary_uncertainty_algorithm": strict_literal("any_exact_outcome_fact_v1"),
            "threshold_authority": strict_literal("exact_canary_plan_only"),
            "promotion_authority": strict_literal("conclusion_request_only"),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("reducer_producer", 0, payload["producer"]),
        _link("canary_plan", 0, payload["canary_plan"]),
        _link("policy_calibration", 0, payload["policy_calibration"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind reducer authority")
    return payload


def _window_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "window_type": strict_literal("fixed_horizon_canary_outcomes"),
            "window_revision": strict_integer(minimum=1),
            "trial": _EXACT,
            "canary_plan": _EXACT,
            "reducer_profile": _EXACT,
            "expected_exposure_count": strict_integer(minimum=1),
            "exposure_receipts": strict_list(_EXACT, minimum=1, maximum=100000),
            "membership_state": strict_literal("closed"),
            "contains_raw_content": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    receipts = payload["exposure_receipts"]
    refs = [item["record_id"] for item in receipts]
    if refs != sorted(refs) or len(refs) != len(set(refs)):
        raise SchemaValidationError(f"{path}.exposure_receipts must be sorted and unique")
    if payload["expected_exposure_count"] != len(receipts):
        raise SchemaValidationError(f"{path} is not a complete fixed-horizon window")
    expected = [
        _link("canary_trial", 0, payload["trial"]),
        _link("canary_plan", 0, payload["canary_plan"]),
        _link("reducer_profile", 0, payload["reducer_profile"]),
    ]
    expected.extend(
        _link("exposure_receipt", ordinal, item)
        for ordinal, item in enumerate(receipts)
    )
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind fixed window membership")
    return payload


def _outcome_authority_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "authority_type": strict_literal("canary_outcome_fact_authority"),
            "authority_revision": strict_integer(minimum=1),
            "authority_state": strict_literal("approved"),
            "authority_ceiling": strict_literal("candidate_attributable_outcome_fact_only"),
            "trial": _EXACT,
            "candidate": _EXACT,
            "producer": _EXACT,
            "reducer_profile": _EXACT,
            "canary_plan": _EXACT,
            "policy_calibration": _EXACT,
            "promotion_authority": strict_literal("reducer_input_only"),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("canary_trial", 0, payload["trial"]),
        _link("candidate", 0, payload["candidate"]),
        _link("outcome_producer", 0, payload["producer"]),
        _link("reducer_profile", 0, payload["reducer_profile"]),
        _link("canary_plan", 0, payload["canary_plan"]),
        _link("policy_calibration", 0, payload["policy_calibration"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind outcome authority")
    return payload


def _outcome_fact_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "fact_type": strict_literal("canary_attributable_outcome"),
            "trial": _EXACT,
            "canary_plan": _EXACT,
            "outcome_window": _EXACT,
            "exposure_receipt": _EXACT,
            "candidate": _EXACT,
            "selected_profile": _EXACT,
            "outcome_authority": _EXACT,
            "outcome_occurrence_ref": _opaque,
            "arm": strict_enum(("candidate", "incumbent")),
            "bucket_values": strict_list(_BUCKET_VALUE, minimum=1, maximum=256),
            "hard_failure": strict_boolean(),
            "shared_failure": strict_boolean(),
            "identity_drift": strict_boolean(),
            "boundary_uncertain": strict_boolean(),
            "authority_rank": strict_literal("certified_candidate_attribution"),
            "promotion_authority": strict_literal("reducer_input_only"),
            "contains_raw_content": strict_literal(False),
            "contains_provider_identifier": strict_literal(False),
            "contains_error_detail": strict_literal(False),
            "contains_path": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    buckets = payload["bucket_values"]
    refs = [item["bucket_ref"] for item in buckets]
    if refs != sorted(refs) or len(refs) != len(set(refs)):
        raise SchemaValidationError(f"{path}.bucket_values must be sorted and unique")
    expected = [
        _link("canary_trial", 0, payload["trial"]),
        _link("canary_plan", 0, payload["canary_plan"]),
        _link("outcome_window", 0, payload["outcome_window"]),
        _link("exposure_receipt", 0, payload["exposure_receipt"]),
        _link("candidate", 0, payload["candidate"]),
        _link("selected_profile", 0, payload["selected_profile"]),
        _link("outcome_authority", 0, payload["outcome_authority"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind attributable outcome inputs")
    return payload


def _reduction_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "reduction_type": strict_literal("fixed_horizon_canary_outcomes"),
            "request_digest": validate_digest,
            "idempotency_key_digest": validate_digest,
            "trial": _EXACT,
            "canary_plan": _EXACT,
            "activation_policy": _EXACT,
            "policy_calibration": _EXACT,
            "producer": _EXACT,
            "reducer_profile": _EXACT,
            "outcome_authority": _EXACT,
            "outcome_window": _EXACT,
            "expected_scope_revision": strict_integer(minimum=0),
            "observed_slot_revision": strict_integer(minimum=1),
            "eligible_exposure_count": strict_integer(minimum=1),
            "bucket_outcomes": strict_list(_BUCKET_REDUCTION, minimum=1, maximum=256),
            "candidate_hard_failure_count": strict_integer(minimum=0),
            "shared_failure": strict_boolean(),
            "identity_drift": strict_boolean(),
            "boundary_uncertain": strict_boolean(),
            "cancelled": strict_literal(False),
            "operator_stopped": strict_literal(False),
            "outcome_facts": strict_list(_EXACT, minimum=1, maximum=100000),
            "conclusion_record_id": _opaque,
            "aggregation_algorithm": strict_literal("difference_of_exact_arm_means_v1"),
            "threshold_authority": strict_literal("exact_canary_plan_only"),
            "promotion_authority": strict_literal("conclusion_request_only"),
            "links": validate_links,
        }
    )(value, path)
    bucket_refs = [item["bucket_ref"] for item in payload["bucket_outcomes"]]
    if bucket_refs != sorted(bucket_refs) or len(bucket_refs) != len(set(bucket_refs)):
        raise SchemaValidationError(f"{path}.bucket_outcomes must be sorted and unique")
    facts = payload["outcome_facts"]
    fact_refs = [item["record_id"] for item in facts]
    if fact_refs != sorted(fact_refs) or len(fact_refs) != len(set(fact_refs)):
        raise SchemaValidationError(f"{path}.outcome_facts must be sorted and unique")
    expected = [
        _link("canary_trial", 0, payload["trial"]),
        _link("canary_plan", 0, payload["canary_plan"]),
        _link("activation_policy", 0, payload["activation_policy"]),
        _link("policy_calibration", 0, payload["policy_calibration"]),
        _link("reducer_producer", 0, payload["producer"]),
        _link("reducer_profile", 0, payload["reducer_profile"]),
        _link("outcome_authority", 0, payload["outcome_authority"]),
        _link("outcome_window", 0, payload["outcome_window"]),
    ]
    expected.extend(
        _link("outcome_fact", ordinal, item) for ordinal, item in enumerate(facts)
    )
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact reduction")
    return payload


def _receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "receipt_type": strict_literal("canary_outcome_reduction"),
            "accepted": strict_literal(True),
            "request_digest": validate_digest,
            "idempotency_key_digest": validate_digest,
            "reduction": _EXACT,
            "certified_reducer_authority": _EXACT,
            "trial": _EXACT,
            "outcome_window": _EXACT,
            "event_sequence": strict_integer(minimum=0),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("outcome_reduction", 0, payload["reduction"]),
        _link("certified_reducer_authority", 0, payload["certified_reducer_authority"]),
        _link("canary_trial", 0, payload["trial"]),
        _link("outcome_window", 0, payload["outcome_window"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind reduction outputs")
    return payload


_LOCAL_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            CANARY_OUTCOME_REDUCER_PROFILE_SCHEMA_ID,
            CANARY_OUTCOME_REDUCER_PROFILE_KIND,
            _profile_validator,
        ),
        RecordSchema(
            CANARY_OUTCOME_WINDOW_SCHEMA_ID,
            CANARY_OUTCOME_WINDOW_KIND,
            _window_validator,
        ),
        RecordSchema(
            CANARY_OUTCOME_FACT_AUTHORITY_SCHEMA_ID,
            CANARY_OUTCOME_FACT_AUTHORITY_KIND,
            _outcome_authority_validator,
        ),
        RecordSchema(
            CANARY_ATTRIBUTABLE_OUTCOME_SCHEMA_ID,
            CANARY_ATTRIBUTABLE_OUTCOME_KIND,
            _outcome_fact_validator,
        ),
        RecordSchema(
            CANARY_OUTCOME_REDUCTION_SCHEMA_ID,
            CANARY_OUTCOME_REDUCTION_KIND,
            _reduction_validator,
        ),
        RecordSchema(
            CANARY_OUTCOME_REDUCTION_RECEIPT_SCHEMA_ID,
            CANARY_OUTCOME_REDUCTION_RECEIPT_KIND,
            _receipt_validator,
        ),
    )
)

CANARY_OUTCOME_REDUCER_REGISTRY = merge_schema_registries(
    CANARY_REGISTRY,
    CANDIDATE_PUBLICATION_REGISTRY,
    CALIBRATION_AUTHORITY_REGISTRY,
    CANARY_CONCLUSION_REPOSITORY_REGISTRY,
    _LOCAL_REGISTRY,
)


@dataclass(frozen=True, slots=True, order=True)
class CanaryBucketValue:
    bucket_ref: str
    comparable: bool
    value: Rational

    def __post_init__(self) -> None:
        _BUCKET_VALUE(self.payload(), "bucket_value")

    def payload(self) -> dict[str, Any]:
        return {
            "bucket_ref": self.bucket_ref,
            "comparable": self.comparable,
            "value": self.value.payload(),
        }


@dataclass(frozen=True, slots=True)
class CanaryOutcomeReductionRequest:
    context_ref: str
    expected_scope_revision: int
    slot: SlotBinding
    trial: ExactRecord
    canary_plan: ExactRecord
    activation_policy: ExactRecord
    policy_calibration: ExactRecord
    producer: ExactRecord
    reducer_profile: ExactRecord
    outcome_authority: ExactRecord
    outcome_window: ExactRecord
    exposure_receipts: tuple[ExactRecord, ...]
    outcome_facts: tuple[ExactRecord, ...]
    reduction_record_id: str
    certified_authority_record_id: str
    conclusion_record_id: str
    idempotency_key_digest: str
    request_digest: str
    key_epoch: str


@dataclass(frozen=True, slots=True)
class CanaryOutcomeReductionCommit:
    reduction: TypedRecord
    receipt: TypedRecord
    certified_reducer_authority: TypedRecord
    conclusion_request: CanaryConclusionRequest
    event: DomainEvent
    replayed: bool


def build_canary_outcome_reducer_profile(
    *,
    record_id: str,
    context_ref: str,
    profile_revision: int,
    producer: TypedRecord,
    canary_plan: TypedRecord,
    policy_calibration: TypedRecord,
    key_epoch: str,
) -> TypedRecord:
    payload = {
        "profile_type": "fixed_horizon_canary_outcome_reducer",
        "profile_revision": profile_revision,
        "approval_state": "approved",
        "producer": _exact_payload(producer),
        "canary_plan": _exact_payload(canary_plan),
        "policy_calibration": _exact_payload(policy_calibration),
        "aggregation_algorithm": "difference_of_exact_arm_means_v1",
        "comparable_count_algorithm": "minimum_exact_arm_count_v1",
        "window_completion": "exact_plan_horizon",
        "missing_outcome_policy": "reject",
        "mixed_input_policy": "reject",
        "control_signal_policy": "fixed_horizon_outcomes_only",
        "hard_failure_algorithm": "candidate_arm_count_v1",
        "shared_failure_algorithm": "any_exact_outcome_fact_v1",
        "identity_drift_algorithm": "any_exact_outcome_fact_v1",
        "boundary_uncertainty_algorithm": "any_exact_outcome_fact_v1",
        "threshold_authority": "exact_canary_plan_only",
        "promotion_authority": "conclusion_request_only",
        "links": [
            _link("reducer_producer", 0, _exact_payload(producer)),
            _link("canary_plan", 0, _exact_payload(canary_plan)),
            _link("policy_calibration", 0, _exact_payload(policy_calibration)),
        ],
    }
    return _record(
        record_id,
        context_ref,
        CANARY_OUTCOME_REDUCER_PROFILE_KIND,
        CANARY_OUTCOME_REDUCER_PROFILE_SCHEMA_ID,
        payload,
        key_epoch,
    )


def build_canary_outcome_window(
    *,
    record_id: str,
    context_ref: str,
    window_revision: int,
    trial: TypedRecord,
    canary_plan: TypedRecord,
    reducer_profile: TypedRecord,
    exposure_receipts: Sequence[TypedRecord],
    key_epoch: str,
) -> TypedRecord:
    receipts = tuple(exposure_receipts)
    plan_payload = canary_plan.payload
    if len(receipts) != plan_payload["horizon_exposures"]:
        raise CanaryOutcomeReductionError("window does not equal the exact plan horizon")
    identities = tuple(_exact_payload(item) for item in receipts)
    if identities != tuple(sorted(identities, key=lambda item: item["record_id"])):
        raise CanaryOutcomeReductionError("exposure receipts must be in canonical order")
    payload = {
        "window_type": "fixed_horizon_canary_outcomes",
        "window_revision": window_revision,
        "trial": _exact_payload(trial),
        "canary_plan": _exact_payload(canary_plan),
        "reducer_profile": _exact_payload(reducer_profile),
        "expected_exposure_count": plan_payload["horizon_exposures"],
        "exposure_receipts": list(identities),
        "membership_state": "closed",
        "contains_raw_content": False,
        "links": [
            _link("canary_trial", 0, _exact_payload(trial)),
            _link("canary_plan", 0, _exact_payload(canary_plan)),
            _link("reducer_profile", 0, _exact_payload(reducer_profile)),
            *(
                _link("exposure_receipt", ordinal, item)
                for ordinal, item in enumerate(identities)
            ),
        ],
    }
    return _record(
        record_id,
        context_ref,
        CANARY_OUTCOME_WINDOW_KIND,
        CANARY_OUTCOME_WINDOW_SCHEMA_ID,
        payload,
        key_epoch,
    )


def build_canary_outcome_fact_authority(
    *,
    record_id: str,
    context_ref: str,
    authority_revision: int,
    trial: TypedRecord,
    candidate: TypedRecord,
    producer: TypedRecord,
    reducer_profile: TypedRecord,
    canary_plan: TypedRecord,
    policy_calibration: TypedRecord,
    key_epoch: str,
) -> TypedRecord:
    exacts = {
        "trial": _exact_payload(trial),
        "candidate": _exact_payload(candidate),
        "producer": _exact_payload(producer),
        "reducer_profile": _exact_payload(reducer_profile),
        "canary_plan": _exact_payload(canary_plan),
        "policy_calibration": _exact_payload(policy_calibration),
    }
    payload = {
        "authority_type": "canary_outcome_fact_authority",
        "authority_revision": authority_revision,
        "authority_state": "approved",
        "authority_ceiling": "candidate_attributable_outcome_fact_only",
        **exacts,
        "promotion_authority": "reducer_input_only",
        "links": [
            _link("canary_trial", 0, exacts["trial"]),
            _link("candidate", 0, exacts["candidate"]),
            _link("outcome_producer", 0, exacts["producer"]),
            _link("reducer_profile", 0, exacts["reducer_profile"]),
            _link("canary_plan", 0, exacts["canary_plan"]),
            _link("policy_calibration", 0, exacts["policy_calibration"]),
        ],
    }
    return _record(
        record_id,
        context_ref,
        CANARY_OUTCOME_FACT_AUTHORITY_KIND,
        CANARY_OUTCOME_FACT_AUTHORITY_SCHEMA_ID,
        payload,
        key_epoch,
    )


def build_canary_attributable_outcome(
    *,
    record_id: str,
    context_ref: str,
    trial: TypedRecord,
    canary_plan: TypedRecord,
    outcome_window: TypedRecord,
    exposure_receipt: TypedRecord,
    candidate: TypedRecord,
    selected_profile: TypedRecord,
    outcome_authority: TypedRecord,
    outcome_occurrence_ref: str,
    bucket_values: Sequence[CanaryBucketValue],
    hard_failure: bool,
    shared_failure: bool,
    identity_drift: bool,
    boundary_uncertain: bool,
    key_epoch: str,
) -> TypedRecord:
    values = tuple(bucket_values)
    if values != tuple(sorted(values)) or not values:
        raise CanaryOutcomeReductionError("bucket values must be non-empty and canonical")
    exacts = {
        "trial": _exact_payload(trial),
        "canary_plan": _exact_payload(canary_plan),
        "outcome_window": _exact_payload(outcome_window),
        "exposure_receipt": _exact_payload(exposure_receipt),
        "candidate": _exact_payload(candidate),
        "selected_profile": _exact_payload(selected_profile),
        "outcome_authority": _exact_payload(outcome_authority),
    }
    arm = exposure_receipt.payload["arm"]
    payload = {
        "fact_type": "canary_attributable_outcome",
        **exacts,
        "outcome_occurrence_ref": outcome_occurrence_ref,
        "arm": arm,
        "bucket_values": [item.payload() for item in values],
        "hard_failure": hard_failure,
        "shared_failure": shared_failure,
        "identity_drift": identity_drift,
        "boundary_uncertain": boundary_uncertain,
        "authority_rank": "certified_candidate_attribution",
        "promotion_authority": "reducer_input_only",
        "contains_raw_content": False,
        "contains_provider_identifier": False,
        "contains_error_detail": False,
        "contains_path": False,
        "links": [
            _link("canary_trial", 0, exacts["trial"]),
            _link("canary_plan", 0, exacts["canary_plan"]),
            _link("outcome_window", 0, exacts["outcome_window"]),
            _link("exposure_receipt", 0, exacts["exposure_receipt"]),
            _link("candidate", 0, exacts["candidate"]),
            _link("selected_profile", 0, exacts["selected_profile"]),
            _link("outcome_authority", 0, exacts["outcome_authority"]),
        ],
    }
    return _record(
        record_id,
        context_ref,
        CANARY_ATTRIBUTABLE_OUTCOME_KIND,
        CANARY_ATTRIBUTABLE_OUTCOME_SCHEMA_ID,
        payload,
        key_epoch,
    )


def digest_canary_outcome_reduction_request(
    request: CanaryOutcomeReductionRequest,
) -> str:
    payload = {
        "context_ref": request.context_ref,
        "expected_scope_revision": request.expected_scope_revision,
        "slot": {
            "revision": request.slot.revision,
            "occupant": (
                None if request.slot.occupant is None else request.slot.occupant.payload()
            ),
        },
        "trial": request.trial.payload(),
        "canary_plan": request.canary_plan.payload(),
        "activation_policy": request.activation_policy.payload(),
        "policy_calibration": request.policy_calibration.payload(),
        "producer": request.producer.payload(),
        "reducer_profile": request.reducer_profile.payload(),
        "outcome_authority": request.outcome_authority.payload(),
        "outcome_window": request.outcome_window.payload(),
        "exposure_receipts": [item.payload() for item in request.exposure_receipts],
        "outcome_facts": [item.payload() for item in request.outcome_facts],
        "reduction_record_id": request.reduction_record_id,
        "certified_authority_record_id": request.certified_authority_record_id,
        "conclusion_record_id": request.conclusion_record_id,
        "idempotency_key_digest": request.idempotency_key_digest,
        "key_epoch": request.key_epoch,
    }
    return schema_digest(
        "canary-outcome-reduction-request",
        "a0.canary-outcome-reduction-request.v1",
        canonical_json(payload),
    )


class RepositoryCanaryOutcomeReducer:
    """Atomically certify one exact fixed-horizon outcome reduction."""

    def __init__(self, repository: V3Repository) -> None:
        if type(repository) is not V3Repository:
            raise TypeError("repository must be a V3Repository")
        self._repository = repository

    def reduce(
        self, request: CanaryOutcomeReductionRequest
    ) -> CanaryOutcomeReductionCommit:
        _validate_request(request)
        with self._repository.transaction() as transaction:
            replay = _existing_replay(transaction, request)
            if replay is not None:
                return replay
            records = _load_and_validate_inputs(transaction, request)
            conclusion_request, bucket_payloads = _reduce(records, request)
            reduction = _build_reduction(
                request, conclusion_request, bucket_payloads
            )
            transaction.insert_record(reduction)
            certified = build_certified_canary_outcome_authority(
                record_id=request.certified_authority_record_id,
                context_ref=request.context_ref,
                producer=request.producer,
                reducer_profile=request.reducer_profile,
                canary_plan=request.canary_plan,
                key_epoch=request.key_epoch,
            )
            transaction.insert_record(certified)
            sequence = transaction.next_domain_event_sequence(
                request.trial.record_id
            )
            receipt = _build_receipt(request, reduction, certified, sequence)
            transaction.insert_record(receipt)
            event = _build_event(request, receipt, sequence)
            transaction.append_event(event)
            return CanaryOutcomeReductionCommit(
                reduction,
                receipt,
                certified,
                conclusion_request,
                event,
                False,
            )


@dataclass(frozen=True, slots=True)
class _ReductionInputs:
    trial: TypedRecord
    plan: TypedRecord
    policy: TypedRecord
    calibration: TypedRecord
    producer: TypedRecord
    profile: TypedRecord
    authority: TypedRecord
    window: TypedRecord
    candidate: TypedRecord
    exposures: tuple[TypedRecord, ...]
    outcomes: tuple[TypedRecord, ...]


def _validate_request(request: CanaryOutcomeReductionRequest) -> None:
    if type(request) is not CanaryOutcomeReductionRequest:
        raise TypeError("one exact CanaryOutcomeReductionRequest is required")
    if type(request.slot) is not SlotBinding:
        raise TypeError("slot must be an exact SlotBinding")
    exact_names = (
        "trial",
        "canary_plan",
        "activation_policy",
        "policy_calibration",
        "producer",
        "reducer_profile",
        "outcome_authority",
        "outcome_window",
    )
    if any(type(getattr(request, name)) is not ExactRecord for name in exact_names):
        raise TypeError("all reduction authorities must be exact")
    if any(type(item) is not ExactRecord for item in request.exposure_receipts):
        raise TypeError("exposure receipts must be exact")
    if any(type(item) is not ExactRecord for item in request.outcome_facts):
        raise TypeError("outcome facts must be exact")
    for values, name in (
        (request.exposure_receipts, "exposure_receipts"),
        (request.outcome_facts, "outcome_facts"),
    ):
        refs = [item.record_id for item in values]
        if not refs or refs != sorted(refs) or len(refs) != len(set(refs)):
            raise CanaryOutcomeReductionError(f"{name} must be sorted, unique, and non-empty")
    for value, name in (
        (request.context_ref, "context_ref"),
        (request.reduction_record_id, "reduction_record_id"),
        (request.certified_authority_record_id, "certified_authority_record_id"),
        (request.conclusion_record_id, "conclusion_record_id"),
        (request.key_epoch, "key_epoch"),
    ):
        _opaque(value, name)
    if type(request.expected_scope_revision) is not int or request.expected_scope_revision < 0:
        raise TypeError("expected_scope_revision must be non-negative")
    validate_digest(request.idempotency_key_digest, "idempotency_key_digest")
    validate_digest(request.request_digest, "request_digest")
    if request.request_digest != digest_canary_outcome_reduction_request(request):
        raise IntegrityFailure("canary outcome reduction request digest is not exact")
    if request.slot.occupant != request.trial:
        raise RevisionConflict("reduction does not bind the active canary trial")


def _load_and_validate_inputs(
    transaction: V3Transaction, request: CanaryOutcomeReductionRequest
) -> _ReductionInputs:
    scope = transaction.get_activation_scope(request.context_ref)
    slot = transaction.get_operation_slot(request.context_ref, "canary")
    if (
        scope is None
        or scope.mode != "normal"
        or scope.scope_revision != request.expected_scope_revision
    ):
        raise RevisionConflict("canary reduction activation scope changed")
    if (
        slot is None
        or slot.operation_revision != request.slot.revision
        or slot.operation_id != request.trial.record_id
        or slot.operation_digest != request.trial.digest
    ):
        raise RevisionConflict("canary reduction slot changed")
    trial = _require_exact(
        transaction,
        request.trial,
        request.context_ref,
        CANARY_TRIAL_SCHEMA_ID,
        "canary_trial",
    )
    plan = _require_exact(
        transaction,
        request.canary_plan,
        request.context_ref,
        CANARY_PLAN_SCHEMA_ID,
        "canary_plan",
    )
    policy = _require_exact(
        transaction,
        request.activation_policy,
        request.context_ref,
        ACTIVATION_POLICY_SCHEMA_ID,
        "activation_policy",
    )
    calibration = _require_exact(
        transaction,
        request.policy_calibration,
        request.context_ref,
        POLICY_CALIBRATION_SCHEMA_ID,
        "policy_calibration",
    )
    producer = _require_exact(
        transaction, request.producer, request.context_ref, None, None
    )
    profile = _require_exact(
        transaction,
        request.reducer_profile,
        request.context_ref,
        CANARY_OUTCOME_REDUCER_PROFILE_SCHEMA_ID,
        CANARY_OUTCOME_REDUCER_PROFILE_KIND,
    )
    authority = _require_exact(
        transaction,
        request.outcome_authority,
        request.context_ref,
        CANARY_OUTCOME_FACT_AUTHORITY_SCHEMA_ID,
        CANARY_OUTCOME_FACT_AUTHORITY_KIND,
    )
    window = _require_exact(
        transaction,
        request.outcome_window,
        request.context_ref,
        CANARY_OUTCOME_WINDOW_SCHEMA_ID,
        CANARY_OUTCOME_WINDOW_KIND,
    )
    trial_payload = trial.payload
    if (
        trial_payload["canary_kind"] != "authoritative"
        or trial_payload["authority_ceiling"] != "activation_authority"
    ):
        raise IntegrityFailure("diagnostic canary has no promotion reduction authority")
    if (
        (trial_payload["plan_id"], trial_payload["plan_digest"])
        != (plan.record_id, plan.content_digest)
        or (trial_payload["policy_id"], trial_payload["policy_digest"])
        != (policy.record_id, policy.content_digest)
        or (trial_payload["calibration_id"], trial_payload["calibration_digest"])
        != (calibration.record_id, calibration.content_digest)
        or trial_payload["scope_revision"] != request.expected_scope_revision
        or (trial_payload["incumbent_profile_id"], trial_payload["incumbent_profile_digest"])
        != (scope.current_profile_id, scope.current_profile_digest)
    ):
        raise IntegrityFailure("canary trial lost an exact frozen input")
    calibration_payload = calibration.payload
    if (
        calibration_payload["status"] != "approved"
        or (calibration_payload["policy_id"], calibration_payload["policy_digest"])
        != (policy.record_id, policy.content_digest)
        or (calibration_payload["canary_plan_id"], calibration_payload["canary_plan_digest"])
        != (plan.record_id, plan.content_digest)
    ):
        raise IntegrityFailure("canary calibration does not bind policy and plan")
    _require_current_calibration(transaction, calibration)
    profile_payload = profile.payload
    if (
        profile_payload["approval_state"] != "approved"
        or profile_payload["producer"] != request.producer.payload()
        or profile_payload["canary_plan"] != request.canary_plan.payload()
        or profile_payload["policy_calibration"] != request.policy_calibration.payload()
    ):
        raise IntegrityFailure("reducer profile is stale or binds another authority")
    authority_payload = authority.payload
    expected_candidate = {
        "record_id": trial_payload["candidate_id"],
        "digest": trial_payload["candidate_digest"],
    }
    expected_authority = {
        "trial": request.trial.payload(),
        "candidate": expected_candidate,
        "producer": request.producer.payload(),
        "reducer_profile": request.reducer_profile.payload(),
        "canary_plan": request.canary_plan.payload(),
        "policy_calibration": request.policy_calibration.payload(),
    }
    if authority_payload["authority_state"] != "approved" or any(
        authority_payload[name] != value for name, value in expected_authority.items()
    ):
        raise IntegrityFailure("outcome fact authority is stale or mixed")
    candidate = _require_exact(
        transaction,
        ExactRecord(expected_candidate["record_id"], expected_candidate["digest"]),
        request.context_ref,
        IMPROVEMENT_CANDIDATE_SCHEMA_ID,
        "improvement_candidate",
    )
    window_payload = window.payload
    if (
        window_payload["trial"] != request.trial.payload()
        or window_payload["canary_plan"] != request.canary_plan.payload()
        or window_payload["reducer_profile"] != request.reducer_profile.payload()
        or window_payload["expected_exposure_count"] != plan.payload["horizon_exposures"]
        or window_payload["exposure_receipts"]
        != [item.payload() for item in request.exposure_receipts]
    ):
        raise IntegrityFailure("outcome window is mixed or incomplete")
    exposures = tuple(
        _require_exact(
            transaction,
            item,
            request.context_ref,
            EXPOSURE_RECEIPT_SCHEMA_ID,
            "canary_exposure_receipt",
        )
        for item in request.exposure_receipts
    )
    units: set[str] = set()
    envelopes: set[str] = set()
    for exposure in exposures:
        payload = exposure.payload
        if (
            (payload["trial_id"], payload["trial_digest"])
            != (trial.record_id, trial.content_digest)
            or payload["scope_revision"] != request.expected_scope_revision
            or payload["exposure_unit_ref"] in units
            or payload["envelope_ref"] in envelopes
        ):
            raise IntegrityFailure("exposure window contains mixed or duplicate authority")
        units.add(payload["exposure_unit_ref"])
        envelopes.add(payload["envelope_ref"])
    outcomes = tuple(
        _require_exact(
            transaction,
            item,
            request.context_ref,
            CANARY_ATTRIBUTABLE_OUTCOME_SCHEMA_ID,
            CANARY_ATTRIBUTABLE_OUTCOME_KIND,
        )
        for item in request.outcome_facts
    )
    if len(outcomes) != len(exposures):
        raise CanaryOutcomeReductionError("every exposure requires one certified outcome")
    exposure_by_identity = {
        (item.record_id, item.content_digest): item for item in exposures
    }
    seen: set[tuple[str, str]] = set()
    expected_buckets = [item["bucket_ref"] for item in plan.payload["buckets"]]
    candidate_payload = candidate.payload
    for outcome in outcomes:
        payload = outcome.payload
        exposure_identity = (
            payload["exposure_receipt"]["record_id"],
            payload["exposure_receipt"]["digest"],
        )
        exposure = exposure_by_identity.get(exposure_identity)
        if exposure is None or exposure_identity in seen:
            raise CanaryOutcomeReductionError("outcomes do not map one-to-one to exposures")
        seen.add(exposure_identity)
        selected_profile = payload["selected_profile"]
        expected_profile = (
            {
                "record_id": candidate_payload["successor_profile_id"],
                "digest": candidate_payload["successor_profile_digest"],
            }
            if exposure.payload["arm"] == "candidate"
            else {
                "record_id": trial_payload["incumbent_profile_id"],
                "digest": trial_payload["incumbent_profile_digest"],
            }
        )
        if (
            payload["trial"] != request.trial.payload()
            or payload["canary_plan"] != request.canary_plan.payload()
            or payload["outcome_window"] != request.outcome_window.payload()
            or payload["candidate"] != expected_candidate
            or payload["outcome_authority"] != request.outcome_authority.payload()
            or payload["arm"] != exposure.payload["arm"]
            or selected_profile != expected_profile
            or [item["bucket_ref"] for item in payload["bucket_values"]]
            != expected_buckets
        ):
            raise IntegrityFailure("outcome fact mixes profile, plan, window, or arm")
        _require_exact(
            transaction,
            ExactRecord(selected_profile["record_id"], selected_profile["digest"]),
            request.context_ref,
            None,
            "activation_profile",
        )
    if seen != set(exposure_by_identity):
        raise CanaryOutcomeReductionError("one or more exposure outcomes are missing")
    return _ReductionInputs(
        trial,
        plan,
        policy,
        calibration,
        producer,
        profile,
        authority,
        window,
        candidate,
        exposures,
        outcomes,
    )


def _reduce(
    records: _ReductionInputs, request: CanaryOutcomeReductionRequest
) -> tuple[CanaryConclusionRequest, tuple[dict[str, Any], ...]]:
    plan_buckets = [item["bucket_ref"] for item in records.plan.payload["buckets"]]
    reductions: list[dict[str, Any]] = []
    outcomes: list[BucketOutcome] = []
    for bucket_ref in plan_buckets:
        candidate_values: list[Fraction] = []
        incumbent_values: list[Fraction] = []
        uncertain = False
        for fact in records.outcomes:
            payload = fact.payload
            value = next(
                item for item in payload["bucket_values"] if item["bucket_ref"] == bucket_ref
            )
            uncertain = uncertain or payload["boundary_uncertain"]
            if not value["comparable"]:
                continue
            exact = Fraction(value["value"]["numerator"], value["value"]["denominator"])
            if payload["arm"] == "candidate":
                candidate_values.append(exact)
            else:
                incumbent_values.append(exact)
        if not candidate_values or not incumbent_values:
            raise CanaryOutcomeReductionError(
                f"bucket {bucket_ref!r} lacks an exact comparable value in both arms"
            )
        candidate_mean = sum(candidate_values, Fraction(0, 1)) / len(candidate_values)
        incumbent_mean = sum(incumbent_values, Fraction(0, 1)) / len(incumbent_values)
        delta = candidate_mean - incumbent_mean
        comparable_count = min(len(candidate_values), len(incumbent_values))
        rational = Rational(delta.numerator, delta.denominator)
        reductions.append(
            {
                "bucket_ref": bucket_ref,
                "candidate_comparable_count": len(candidate_values),
                "incumbent_comparable_count": len(incumbent_values),
                "comparable_count": comparable_count,
                "candidate_delta": rational.payload(),
                "boundary_uncertain": uncertain,
            }
        )
        outcomes.append(
            BucketOutcome(bucket_ref, comparable_count, rational, uncertain)
        )
    conclusion = CanaryConclusionRequest(
        record_id=request.conclusion_record_id,
        trial=records.trial,
        eligible_exposure_count=len(records.exposures),
        bucket_outcomes=tuple(outcomes),
        candidate_hard_failure_count=sum(
            1
            for item in records.outcomes
            if item.payload["arm"] == "candidate" and item.payload["hard_failure"]
        ),
        shared_failure=any(item.payload["shared_failure"] for item in records.outcomes),
        identity_drift=any(item.payload["identity_drift"] for item in records.outcomes),
        cancelled=False,
        boundary_uncertain=any(item["boundary_uncertain"] for item in reductions),
        operator_stopped=False,
    )
    return conclusion, tuple(reductions)


def _build_reduction(
    request: CanaryOutcomeReductionRequest,
    conclusion: CanaryConclusionRequest,
    bucket_payloads: tuple[dict[str, Any], ...],
) -> TypedRecord:
    exacts = {
        "trial": request.trial.payload(),
        "canary_plan": request.canary_plan.payload(),
        "activation_policy": request.activation_policy.payload(),
        "policy_calibration": request.policy_calibration.payload(),
        "producer": request.producer.payload(),
        "reducer_profile": request.reducer_profile.payload(),
        "outcome_authority": request.outcome_authority.payload(),
        "outcome_window": request.outcome_window.payload(),
    }
    facts = [item.payload() for item in request.outcome_facts]
    payload = {
        "reduction_type": "fixed_horizon_canary_outcomes",
        "request_digest": request.request_digest,
        "idempotency_key_digest": request.idempotency_key_digest,
        **exacts,
        "expected_scope_revision": request.expected_scope_revision,
        "observed_slot_revision": request.slot.revision,
        "eligible_exposure_count": conclusion.eligible_exposure_count,
        "bucket_outcomes": list(bucket_payloads),
        "candidate_hard_failure_count": conclusion.candidate_hard_failure_count,
        "shared_failure": conclusion.shared_failure,
        "identity_drift": conclusion.identity_drift,
        "boundary_uncertain": conclusion.boundary_uncertain,
        "cancelled": False,
        "operator_stopped": False,
        "outcome_facts": facts,
        "conclusion_record_id": conclusion.record_id,
        "aggregation_algorithm": "difference_of_exact_arm_means_v1",
        "threshold_authority": "exact_canary_plan_only",
        "promotion_authority": "conclusion_request_only",
        "links": [
            _link("canary_trial", 0, exacts["trial"]),
            _link("canary_plan", 0, exacts["canary_plan"]),
            _link("activation_policy", 0, exacts["activation_policy"]),
            _link("policy_calibration", 0, exacts["policy_calibration"]),
            _link("reducer_producer", 0, exacts["producer"]),
            _link("reducer_profile", 0, exacts["reducer_profile"]),
            _link("outcome_authority", 0, exacts["outcome_authority"]),
            _link("outcome_window", 0, exacts["outcome_window"]),
            *(
                _link("outcome_fact", ordinal, item)
                for ordinal, item in enumerate(facts)
            ),
        ],
    }
    return _record(
        request.reduction_record_id,
        request.context_ref,
        CANARY_OUTCOME_REDUCTION_KIND,
        CANARY_OUTCOME_REDUCTION_SCHEMA_ID,
        payload,
        request.key_epoch,
    )


def _receipt_id(request: CanaryOutcomeReductionRequest) -> str:
    material = canonical_json(
        {
            "context_ref": request.context_ref,
            "idempotency_key_digest": request.idempotency_key_digest,
        }
    )
    return f"canary-outcome-reduction-receipt:{sha256(material).hexdigest()}"


def _build_receipt(
    request: CanaryOutcomeReductionRequest,
    reduction: TypedRecord,
    certified: TypedRecord,
    sequence: int,
) -> TypedRecord:
    exacts = {
        "reduction": _exact_payload(reduction),
        "certified_reducer_authority": _exact_payload(certified),
        "trial": request.trial.payload(),
        "outcome_window": request.outcome_window.payload(),
    }
    return _record(
        _receipt_id(request),
        request.context_ref,
        CANARY_OUTCOME_REDUCTION_RECEIPT_KIND,
        CANARY_OUTCOME_REDUCTION_RECEIPT_SCHEMA_ID,
        {
            "receipt_type": "canary_outcome_reduction",
            "accepted": True,
            "request_digest": request.request_digest,
            "idempotency_key_digest": request.idempotency_key_digest,
            **exacts,
            "event_sequence": sequence,
            "links": [
                _link("outcome_reduction", 0, exacts["reduction"]),
                _link(
                    "certified_reducer_authority",
                    0,
                    exacts["certified_reducer_authority"],
                ),
                _link("canary_trial", 0, exacts["trial"]),
                _link("outcome_window", 0, exacts["outcome_window"]),
            ],
        },
        request.key_epoch,
    )


def _build_event(
    request: CanaryOutcomeReductionRequest, receipt: TypedRecord, sequence: int
) -> DomainEvent:
    return DomainEvent(
        event_id=f"canary-outcome-reduced-event:{sha256((request.request_digest + ':' + str(sequence)).encode()).hexdigest()}",
        subject_id=request.trial.record_id,
        subject_kind="canary_trial",
        sequence=sequence,
        event_type="canary_outcome_reduced",
        payload_record_id=receipt.record_id,
        actor_authority_ref=CANARY_OUTCOME_REDUCER_AUTHORITY_REF,
    )


def _existing_replay(
    transaction: V3Transaction, request: CanaryOutcomeReductionRequest
) -> CanaryOutcomeReductionCommit | None:
    receipt = transaction.get_record(_receipt_id(request))
    if receipt is None:
        return None
    if receipt.schema_id != CANARY_OUTCOME_REDUCTION_RECEIPT_SCHEMA_ID:
        raise IntegrityFailure("reduction idempotency identity is occupied")
    receipt.verify(CANARY_OUTCOME_REDUCER_REGISTRY)
    payload = receipt.payload
    if payload["request_digest"] != request.request_digest:
        raise IdempotencyConflict("canary outcome reduction changed for idempotency key")
    if (
        payload["idempotency_key_digest"] != request.idempotency_key_digest
        or payload["trial"] != request.trial.payload()
        or payload["outcome_window"] != request.outcome_window.payload()
    ):
        raise IntegrityFailure("durable reduction receipt differs from exact replay")
    reduction = _require_exact(
        transaction,
        ExactRecord(
            payload["reduction"]["record_id"], payload["reduction"]["digest"]
        ),
        request.context_ref,
        CANARY_OUTCOME_REDUCTION_SCHEMA_ID,
        CANARY_OUTCOME_REDUCTION_KIND,
    )
    certified = _require_exact(
        transaction,
        ExactRecord(
            payload["certified_reducer_authority"]["record_id"],
            payload["certified_reducer_authority"]["digest"],
        ),
        request.context_ref,
        None,
        "certified_canary_outcome_authority",
    )
    if (
        reduction.record_id != request.reduction_record_id
        or certified.record_id != request.certified_authority_record_id
    ):
        raise IntegrityFailure("durable reduction outputs differ from exact replay")
    event = _build_event(request, receipt, payload["event_sequence"])
    if transaction.get_domain_event(request.trial.record_id, event.sequence) != event:
        raise IntegrityFailure("durable reduction event is missing")
    conclusion = _conclusion_from_reduction(transaction, reduction)
    return CanaryOutcomeReductionCommit(
        reduction, receipt, certified, conclusion, event, True
    )


def _conclusion_from_reduction(
    transaction: V3Transaction, reduction: TypedRecord
) -> CanaryConclusionRequest:
    payload = reduction.payload
    trial_exact = payload["trial"]
    trial = _require_exact(
        transaction,
        ExactRecord(trial_exact["record_id"], trial_exact["digest"]),
        reduction.context_ref or "",
        CANARY_TRIAL_SCHEMA_ID,
        "canary_trial",
    )
    return CanaryConclusionRequest(
        record_id=payload["conclusion_record_id"],
        trial=trial,
        eligible_exposure_count=payload["eligible_exposure_count"],
        bucket_outcomes=tuple(
            BucketOutcome(
                item["bucket_ref"],
                item["comparable_count"],
                Rational(
                    item["candidate_delta"]["numerator"],
                    item["candidate_delta"]["denominator"],
                ),
                item["boundary_uncertain"],
            )
            for item in payload["bucket_outcomes"]
        ),
        candidate_hard_failure_count=payload["candidate_hard_failure_count"],
        shared_failure=payload["shared_failure"],
        identity_drift=payload["identity_drift"],
        cancelled=False,
        boundary_uncertain=payload["boundary_uncertain"],
        operator_stopped=False,
    )


def _require_exact(
    transaction: V3Transaction,
    identity: ExactRecord,
    context_ref: str,
    schema_id: str | None,
    record_kind: str | None,
) -> TypedRecord:
    record = transaction.get_record(identity.record_id)
    if (
        record is None
        or record.content_digest != identity.digest
        or record.context_ref != context_ref
        or (schema_id is not None and record.schema_id != schema_id)
        or (record_kind is not None and record.record_kind != record_kind)
    ):
        raise IntegrityFailure("canary outcome exact record binding failed")
    return record


def _require_current_calibration(
    transaction: V3Transaction, calibration: TypedRecord
) -> None:
    facts: list[CalibrationLifecycleFact] = []
    for sequence in range(transaction.next_domain_event_sequence(calibration.record_id)):
        event = transaction.get_domain_event(calibration.record_id, sequence)
        if event is None or event.payload_record_id is None:
            raise IntegrityFailure("policy calibration lifecycle is incomplete")
        receipt = transaction.get_record(event.payload_record_id)
        if receipt is None:
            raise IntegrityFailure("policy calibration lifecycle lost its receipt")
        receipt.verify(CALIBRATION_AUTHORITY_REGISTRY)
        facts.append(CalibrationLifecycleFact(receipt, event))
    try:
        eligibility = reduce_calibration_eligibility(calibration, tuple(facts))
    except CalibrationAuthorityError as exc:
        raise IntegrityFailure("policy calibration lifecycle is not authoritative") from exc
    if eligibility.state != "approved":
        raise IntegrityFailure("policy calibration is stale or withdrawn")


def _record(
    record_id: str,
    context_ref: str,
    record_kind: str,
    schema_id: str,
    payload: dict[str, Any],
    key_epoch: str,
) -> TypedRecord:
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind=record_kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=key_epoch,
        registry=CANARY_OUTCOME_REDUCER_REGISTRY,
    )


__all__ = [
    "CANARY_OUTCOME_REDUCER_PROFILE_SCHEMA_ID",
    "CANARY_OUTCOME_WINDOW_SCHEMA_ID",
    "CANARY_OUTCOME_FACT_AUTHORITY_SCHEMA_ID",
    "CANARY_ATTRIBUTABLE_OUTCOME_SCHEMA_ID",
    "CANARY_OUTCOME_REDUCTION_SCHEMA_ID",
    "CANARY_OUTCOME_REDUCTION_RECEIPT_SCHEMA_ID",
    "CANARY_OUTCOME_REDUCER_REGISTRY",
    "CANARY_OUTCOME_REDUCER_AUTHORITY_REF",
    "CanaryOutcomeReductionError",
    "CanaryBucketValue",
    "CanaryOutcomeReductionRequest",
    "CanaryOutcomeReductionCommit",
    "RepositoryCanaryOutcomeReducer",
    "build_canary_outcome_reducer_profile",
    "build_canary_outcome_window",
    "build_canary_outcome_fact_authority",
    "build_canary_attributable_outcome",
    "digest_canary_outcome_reduction_request",
]
