"""Pure, calibrated canary and activation-policy authority.

This module defines immutable v3 facts and a side-effect-free coordinator.  It
does not own SQLite transitions: callers must commit a returned plan together
with the applicable exact-revision slot/scope CAS and receipts.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
from math import gcd
from typing import Any, Iterable

from .activation import ACTIVATION_REGISTRY
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
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


ACTIVATION_POLICY_SCHEMA_ID = "a0.self-improvement.activation-policy.v1"
CANARY_PLAN_SCHEMA_ID = "a0.self-improvement.canary-plan.v1"
MONITOR_PLAN_SCHEMA_ID = "a0.self-improvement.monitor-plan.v1"
POLICY_CALIBRATION_SCHEMA_ID = "a0.self-improvement.policy-calibration.v1"
CANARY_TRIAL_SCHEMA_ID = "a0.self-improvement.canary-trial.v1"
EXPOSURE_RECEIPT_SCHEMA_ID = "a0.self-improvement.canary-exposure-receipt.v1"
CANARY_CONCLUSION_SCHEMA_ID = "a0.self-improvement.canary-conclusion.v1"
POST_PROMOTION_MONITOR_SCHEMA_ID = "a0.self-improvement.post-promotion-monitor.v1"

_REF = strict_string(maximum=512)
_RATIONAL = strict_object(
    {
        "numerator": strict_integer(),
        "denominator": strict_integer(minimum=1),
    }
)
_BUCKET_PLAN = strict_object(
    {
        "bucket_ref": strict_string(maximum=128),
        "minimum_comparable": strict_integer(minimum=1),
        "noninferiority_margin": _RATIONAL,
        "benefit_threshold": _RATIONAL,
    }
)


def _no_links(value: Any, path: str) -> list[dict[str, Any]]:
    links = validate_links(value, path)
    if links:
        raise SchemaValidationError(f"{path} must be empty")
    return links


class CanaryPolicyDenied(ValueError):
    """A stable, content-free refusal from the pure policy coordinator."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _deny(reason_code: str) -> None:
    raise CanaryPolicyDenied(reason_code)


def _validate_digest_string(value: Any, path: str) -> str:
    return validate_digest(value, path)


def _ordered_unique_buckets(value: Any, path: str) -> list[dict[str, Any]]:
    buckets = strict_list(_BUCKET_PLAN, minimum=1, maximum=256)(value, path)
    refs = [item["bucket_ref"] for item in buckets]
    if refs != sorted(refs) or len(refs) != len(set(refs)):
        raise SchemaValidationError(f"{path} must be uniquely sorted by bucket_ref")
    return buckets


def _ordered_unique_modes(value: Any, path: str) -> list[str]:
    modes = strict_list(
        strict_enum(("manual", "automatic")), minimum=1, maximum=2
    )(value, path)
    if modes != sorted(set(modes)):
        raise SchemaValidationError(f"{path} must be a uniquely sorted list")
    return modes


def _policy_payload(value: Any, path: str) -> dict[str, Any]:
    return strict_object(
        {
            "fact_type": strict_literal("activation_policy"),
            "policy_revision": strict_integer(minimum=1),
            "activation_mode": strict_enum(
                ("manual_only", "canary_required", "auto_after_canary")
            ),
            "calibration_required": strict_literal(True),
            "links": _no_links,
        }
    )(value, path)


def _canary_plan_payload(value: Any, path: str) -> dict[str, Any]:
    result = strict_object(
        {
            "fact_type": strict_literal("canary_plan"),
            "horizon_exposures": strict_integer(minimum=1),
            "expiry_seconds": strict_integer(minimum=1),
            "candidate_allocation": _RATIONAL,
            "assignment_key_commitment": _validate_digest_string,
            "hard_veto_failure_limit": strict_integer(minimum=0),
            "buckets": _ordered_unique_buckets,
            "links": _no_links,
        }
    )(value, path)
    allocation = result["candidate_allocation"]
    if not 0 < allocation["numerator"] < allocation["denominator"]:
        raise SchemaValidationError(
            f"{path}.candidate_allocation must be strictly between zero and one"
        )
    for index, bucket in enumerate(result["buckets"]):
        if bucket["noninferiority_margin"]["numerator"] < 0:
            raise SchemaValidationError(
                f"{path}.buckets[{index}].noninferiority_margin must be nonnegative"
            )
    return result


def _monitor_plan_payload(value: Any, path: str) -> dict[str, Any]:
    result = strict_object(
        {
            "fact_type": strict_literal("monitor_plan"),
            "horizon_exposures": strict_integer(minimum=1),
            "look_interval_exposures": strict_integer(minimum=1),
            "ordinary_regression_boundary": _RATIONAL,
            "hard_veto_failure_limit": strict_integer(minimum=0),
            "links": _no_links,
        }
    )(value, path)
    if result["look_interval_exposures"] > result["horizon_exposures"]:
        raise SchemaValidationError(
            f"{path}.look_interval_exposures cannot exceed the fixed horizon"
        )
    return result


def _calibration_payload(value: Any, path: str) -> dict[str, Any]:
    result = strict_object(
        {
            "fact_type": strict_literal("policy_calibration"),
            "status": strict_enum(("approved", "withdrawn")),
            "environment_ref": strict_string(maximum=128),
            "policy_id": _REF,
            "policy_digest": validate_digest,
            "policy_revision": strict_integer(minimum=1),
            "canary_plan_id": _REF,
            "canary_plan_digest": validate_digest,
            "monitor_plan_id": _REF,
            "monitor_plan_digest": validate_digest,
            "activation_authorities": _ordered_unique_modes,
            "soft_rollback_authorized": strict_boolean(),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("activation_policy", 0, result["policy_id"], result["policy_digest"]),
        _link(
            "canary_plan", 0, result["canary_plan_id"], result["canary_plan_digest"]
        ),
        _link(
            "monitor_plan", 0, result["monitor_plan_id"], result["monitor_plan_digest"]
        ),
    ]
    if result["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the calibrated inputs")
    return result


def _trial_payload(value: Any, path: str) -> dict[str, Any]:
    result = strict_object(
        {
            "fact_type": strict_literal("canary_trial"),
            "canary_kind": strict_enum(("authoritative", "diagnostic")),
            "authority_ceiling": strict_enum(
                ("activation_authority", "no_promotion_authority")
            ),
            "candidate_id": _REF,
            "candidate_digest": validate_digest,
            "incumbent_profile_id": _REF,
            "incumbent_profile_digest": validate_digest,
            "disposition_id": _REF,
            "disposition_digest": validate_digest,
            "disposition": strict_enum(("promotion_ready", "review_only")),
            "scope_revision": strict_integer(minimum=0),
            "policy_id": _REF,
            "policy_digest": validate_digest,
            "policy_revision": strict_integer(minimum=1),
            "calibration_id": strict_nullable(_REF),
            "calibration_digest": strict_nullable(validate_digest),
            "plan_id": _REF,
            "plan_digest": validate_digest,
            "environment_ref": strict_string(maximum=128),
            "authority_grant_id": _REF,
            "authority_grant_digest": validate_digest,
            "links": validate_links,
        }
    )(value, path)
    if result["canary_kind"] == "authoritative":
        if result["authority_ceiling"] != "activation_authority":
            raise SchemaValidationError(
                f"{path}.authority_ceiling is invalid for an authoritative canary"
            )
        if result["disposition"] != "promotion_ready":
            raise SchemaValidationError(
                f"{path}.disposition is invalid for an authoritative canary"
            )
        if not result["calibration_id"]:
            raise SchemaValidationError(f"{path}.calibration_id is required")
    else:
        if result["authority_ceiling"] != "no_promotion_authority":
            raise SchemaValidationError(
                f"{path}.authority_ceiling is invalid for a diagnostic canary"
            )
        if result["disposition"] != "review_only":
            raise SchemaValidationError(
                f"{path}.disposition is invalid for a diagnostic canary"
            )
    expected = [
        _link("candidate", 0, result["candidate_id"], result["candidate_digest"]),
        _link(
            "incumbent_profile",
            0,
            result["incumbent_profile_id"],
            result["incumbent_profile_digest"],
        ),
        _link(
            "activation_disposition",
            0,
            result["disposition_id"],
            result["disposition_digest"],
        ),
        _link("activation_policy", 0, result["policy_id"], result["policy_digest"]),
        _link("canary_plan", 0, result["plan_id"], result["plan_digest"]),
        _link(
            "authority_grant",
            0,
            result["authority_grant_id"],
            result["authority_grant_digest"],
        ),
    ]
    if result["calibration_id"] is not None:
        expected.append(
            _link(
                "policy_calibration",
                0,
                result["calibration_id"],
                result["calibration_digest"],
            )
        )
    if result["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact trial inputs")
    return result


def _exposure_payload(value: Any, path: str) -> dict[str, Any]:
    result = strict_object(
        {
            "fact_type": strict_literal("canary_exposure_receipt"),
            "trial_id": _REF,
            "trial_digest": validate_digest,
            "exposure_unit_ref": strict_string(maximum=128),
            "envelope_ref": strict_string(maximum=128),
            "scope_revision": strict_integer(minimum=0),
            "arm": strict_enum(("candidate", "incumbent")),
            "assignment_digest": validate_digest,
            "links": validate_links,
        }
    )(value, path)
    expected = [_link("canary_trial", 0, result["trial_id"], result["trial_digest"])]
    if result["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact trial")
    return result


def _conclusion_payload(value: Any, path: str) -> dict[str, Any]:
    result = strict_object(
        {
            "fact_type": strict_literal("canary_conclusion"),
            "trial_id": _REF,
            "trial_digest": validate_digest,
            "canary_kind": strict_enum(("authoritative", "diagnostic")),
            "authority_ceiling": strict_enum(
                ("activation_authority", "no_promotion_authority")
            ),
            "conclusion": strict_enum(
                ("passed", "failed", "inconclusive", "stopped")
            ),
            "activation_authoritative": strict_boolean(),
            "candidate_id": _REF,
            "candidate_digest": validate_digest,
            "incumbent_profile_id": _REF,
            "incumbent_profile_digest": validate_digest,
            "scope_revision": strict_integer(minimum=0),
            "policy_id": _REF,
            "policy_digest": validate_digest,
            "policy_revision": strict_integer(minimum=1),
            "calibration_id": strict_nullable(_REF),
            "calibration_digest": strict_nullable(validate_digest),
            "reason_codes": strict_list(
                strict_enum(
                    (
                        "horizon_passed",
                        "candidate_hard_failure",
                        "ordinary_boundary_failed",
                        "underpowered",
                        "shared_failure",
                        "identity_drift",
                        "cancelled",
                        "boundary_uncertain",
                        "operator_stopped",
                    )
                ),
                minimum=1,
                maximum=8,
            ),
            "links": validate_links,
        }
    )(value, path)
    authoritative = (
        result["canary_kind"] == "authoritative"
        and result["authority_ceiling"] == "activation_authority"
        and result["conclusion"] == "passed"
    )
    if result["activation_authoritative"] is not authoritative:
        raise SchemaValidationError(
            f"{path}.activation_authoritative does not match the exact conclusion"
        )
    expected = [_link("canary_trial", 0, result["trial_id"], result["trial_digest"])]
    if result["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact trial")
    return result


def _monitor_payload(value: Any, path: str) -> dict[str, Any]:
    result = strict_object(
        {
            "fact_type": strict_literal("post_promotion_monitor"),
            "candidate_id": _REF,
            "candidate_digest": validate_digest,
            "incumbent_profile_id": _REF,
            "incumbent_profile_digest": validate_digest,
            "canary_conclusion_id": _REF,
            "canary_conclusion_digest": validate_digest,
            "policy_id": _REF,
            "policy_digest": validate_digest,
            "calibration_id": _REF,
            "calibration_digest": validate_digest,
            "monitor_plan_id": _REF,
            "monitor_plan_digest": validate_digest,
            "observed_scope_revision": strict_integer(minimum=0),
            "resulting_scope_revision": strict_integer(minimum=1),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("candidate", 0, result["candidate_id"], result["candidate_digest"]),
        _link(
            "incumbent_profile",
            0,
            result["incumbent_profile_id"],
            result["incumbent_profile_digest"],
        ),
        _link(
            "canary_conclusion",
            0,
            result["canary_conclusion_id"],
            result["canary_conclusion_digest"],
        ),
        _link("activation_policy", 0, result["policy_id"], result["policy_digest"]),
        _link(
            "policy_calibration",
            0,
            result["calibration_id"],
            result["calibration_digest"],
        ),
        _link(
            "monitor_plan", 0, result["monitor_plan_id"], result["monitor_plan_digest"]
        ),
    ]
    if result["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact monitor inputs")
    return result


CANARY_REGISTRY = SchemaRegistry(
    (
        *ACTIVATION_REGISTRY.schemas.values(),
        RecordSchema(
            ACTIVATION_POLICY_SCHEMA_ID, "activation_policy", _policy_payload
        ),
        RecordSchema(CANARY_PLAN_SCHEMA_ID, "canary_plan", _canary_plan_payload),
        RecordSchema(MONITOR_PLAN_SCHEMA_ID, "monitor_plan", _monitor_plan_payload),
        RecordSchema(
            POLICY_CALIBRATION_SCHEMA_ID,
            "policy_calibration",
            _calibration_payload,
        ),
        RecordSchema(CANARY_TRIAL_SCHEMA_ID, "canary_trial", _trial_payload),
        RecordSchema(
            EXPOSURE_RECEIPT_SCHEMA_ID,
            "canary_exposure_receipt",
            _exposure_payload,
        ),
        RecordSchema(
            CANARY_CONCLUSION_SCHEMA_ID,
            "canary_conclusion",
            _conclusion_payload,
        ),
        RecordSchema(
            POST_PROMOTION_MONITOR_SCHEMA_ID,
            "post_promotion_monitor",
            _monitor_payload,
        ),
    )
)


@dataclass(frozen=True, slots=True)
class RecordIdentity:
    ref: str
    digest: str

    def __post_init__(self) -> None:
        if type(self.ref) is not str or not self.ref:
            raise ValueError("record ref must be a non-empty string")
        validate_digest(self.digest, "digest")

    @classmethod
    def of(cls, record: TypedRecord) -> "RecordIdentity":
        return cls(record.record_id, record.content_digest)


@dataclass(frozen=True, slots=True)
class Rational:
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if type(self.numerator) is not int or type(self.denominator) is not int:
            raise TypeError("rational values require exact integers")
        if self.denominator <= 0:
            raise ValueError("rational denominator must be positive")
        if gcd(abs(self.numerator), self.denominator) != 1:
            raise ValueError("rational values must be in lowest terms")

    def payload(self) -> dict[str, int]:
        return {"numerator": self.numerator, "denominator": self.denominator}


@dataclass(frozen=True, slots=True)
class BucketCalibration:
    bucket_ref: str
    minimum_comparable: int
    noninferiority_margin: Rational
    benefit_threshold: Rational

    def payload(self) -> dict[str, Any]:
        return {
            "bucket_ref": self.bucket_ref,
            "minimum_comparable": self.minimum_comparable,
            "noninferiority_margin": self.noninferiority_margin.payload(),
            "benefit_threshold": self.benefit_threshold.payload(),
        }


@dataclass(frozen=True, slots=True)
class BucketOutcome:
    bucket_ref: str
    comparable_count: int
    candidate_delta: Rational
    boundary_uncertain: bool


@dataclass(frozen=True, slots=True)
class CanaryStartRequest:
    record_id: str
    context_ref: str
    canary_kind: str
    disposition: str
    disposition_ref: RecordIdentity
    candidate: RecordIdentity
    incumbent_profile: RecordIdentity
    expected_scope_revision: int
    observed_scope_revision: int
    environment_ref: str
    policy: TypedRecord
    calibration: TypedRecord | None
    plan: TypedRecord
    authority_grant: RecordIdentity
    authority_purpose: str
    occupied_canary_ref: str | None


@dataclass(frozen=True, slots=True)
class CanaryConclusionRequest:
    record_id: str
    trial: TypedRecord
    eligible_exposure_count: int
    bucket_outcomes: tuple[BucketOutcome, ...]
    candidate_hard_failure_count: int
    shared_failure: bool
    identity_drift: bool
    cancelled: bool
    boundary_uncertain: bool
    operator_stopped: bool


@dataclass(frozen=True, slots=True)
class ActivationEligibility:
    candidate: RecordIdentity
    canary_conclusion: RecordIdentity
    policy: RecordIdentity
    calibration: RecordIdentity
    environment_ref: str
    observed_scope_revision: int
    resulting_scope_revision: int
    activation_mode: str


def _link(role: str, ordinal: int, record_id: str, digest: str) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": record_id,
        "target_digest": digest,
    }


def _record(
    *,
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
        registry=CANARY_REGISTRY,
    )


def activation_policy(
    *,
    record_id: str,
    context_ref: str,
    policy_revision: int,
    activation_mode: str,
    key_epoch: str,
) -> TypedRecord:
    return _record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="activation_policy",
        schema_id=ACTIVATION_POLICY_SCHEMA_ID,
        payload={
            "fact_type": "activation_policy",
            "policy_revision": policy_revision,
            "activation_mode": activation_mode,
            "calibration_required": True,
            "links": [],
        },
        key_epoch=key_epoch,
    )


def canary_plan(
    *,
    record_id: str,
    context_ref: str,
    horizon_exposures: int,
    expiry_seconds: int,
    candidate_allocation: Rational,
    assignment_key_commitment: str,
    hard_veto_failure_limit: int,
    buckets: Iterable[BucketCalibration],
    key_epoch: str,
) -> TypedRecord:
    bucket_payloads = sorted((item.payload() for item in buckets), key=lambda x: x["bucket_ref"])
    return _record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="canary_plan",
        schema_id=CANARY_PLAN_SCHEMA_ID,
        payload={
            "fact_type": "canary_plan",
            "horizon_exposures": horizon_exposures,
            "expiry_seconds": expiry_seconds,
            "candidate_allocation": candidate_allocation.payload(),
            "assignment_key_commitment": assignment_key_commitment,
            "hard_veto_failure_limit": hard_veto_failure_limit,
            "buckets": bucket_payloads,
            "links": [],
        },
        key_epoch=key_epoch,
    )


def monitor_plan(
    *,
    record_id: str,
    context_ref: str,
    horizon_exposures: int,
    look_interval_exposures: int,
    ordinary_regression_boundary: Rational,
    hard_veto_failure_limit: int,
    key_epoch: str,
) -> TypedRecord:
    return _record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="monitor_plan",
        schema_id=MONITOR_PLAN_SCHEMA_ID,
        payload={
            "fact_type": "monitor_plan",
            "horizon_exposures": horizon_exposures,
            "look_interval_exposures": look_interval_exposures,
            "ordinary_regression_boundary": ordinary_regression_boundary.payload(),
            "hard_veto_failure_limit": hard_veto_failure_limit,
            "links": [],
        },
        key_epoch=key_epoch,
    )


def policy_calibration(
    *,
    record_id: str,
    context_ref: str,
    status: str,
    environment_ref: str,
    policy: TypedRecord,
    canary_plan_record: TypedRecord,
    monitor_plan_record: TypedRecord,
    activation_authorities: Iterable[str],
    soft_rollback_authorized: bool,
    key_epoch: str,
) -> TypedRecord:
    policy.verify(CANARY_REGISTRY)
    canary_plan_record.verify(CANARY_REGISTRY)
    monitor_plan_record.verify(CANARY_REGISTRY)
    if policy.context_ref != context_ref or canary_plan_record.context_ref != context_ref:
        raise SchemaValidationError("calibration inputs must share the exact context")
    if monitor_plan_record.context_ref != context_ref:
        raise SchemaValidationError("calibration monitor plan must share the exact context")
    policy_payload = policy.payload
    links = [
        _link("activation_policy", 0, policy.record_id, policy.content_digest),
        _link("canary_plan", 0, canary_plan_record.record_id, canary_plan_record.content_digest),
        _link("monitor_plan", 0, monitor_plan_record.record_id, monitor_plan_record.content_digest),
    ]
    return _record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="policy_calibration",
        schema_id=POLICY_CALIBRATION_SCHEMA_ID,
        payload={
            "fact_type": "policy_calibration",
            "status": status,
            "environment_ref": environment_ref,
            "policy_id": policy.record_id,
            "policy_digest": policy.content_digest,
            "policy_revision": policy_payload["policy_revision"],
            "canary_plan_id": canary_plan_record.record_id,
            "canary_plan_digest": canary_plan_record.content_digest,
            "monitor_plan_id": monitor_plan_record.record_id,
            "monitor_plan_digest": monitor_plan_record.content_digest,
            "activation_authorities": list(activation_authorities),
            "soft_rollback_authorized": soft_rollback_authorized,
            "links": links,
        },
        key_epoch=key_epoch,
    )


class CanaryCoordinator:
    """Construct complete immutable facts after pure exact-input validation."""

    def __init__(self, *, key_epoch: str) -> None:
        if type(key_epoch) is not str or not key_epoch:
            raise ValueError("key_epoch must be a non-empty string")
        self._key_epoch = key_epoch

    def plan_start(self, request: CanaryStartRequest) -> TypedRecord:
        if request.occupied_canary_ref is not None:
            _deny("canary_slot_occupied")
        if request.expected_scope_revision != request.observed_scope_revision:
            _deny("scope_revision_conflict")
        request.policy.verify(CANARY_REGISTRY)
        request.plan.verify(CANARY_REGISTRY)
        if request.policy.context_ref != request.context_ref or request.plan.context_ref != request.context_ref:
            _deny("context_mismatch")
        policy = request.policy.payload
        calibration_id: str | None = None
        calibration_digest: str | None = None
        if request.canary_kind == "authoritative":
            if request.disposition != "promotion_ready":
                _deny("authoritative_canary_requires_promotion_ready")
            if request.authority_purpose != "authoritative_canary":
                _deny("authoritative_canary_grant_required")
            calibration = self._approved_calibration(
                request.calibration,
                environment_ref=request.environment_ref,
                policy=request.policy,
                canary_plan_record=request.plan,
            )
            calibration_id = calibration.record_id
            calibration_digest = calibration.content_digest
            ceiling = "activation_authority"
        elif request.canary_kind == "diagnostic":
            if request.disposition != "review_only":
                _deny("diagnostic_canary_requires_review_only")
            if request.authority_purpose != "diagnostic_canary":
                _deny("diagnostic_canary_grant_required")
            ceiling = "no_promotion_authority"
            if request.calibration is not None:
                calibration = self._approved_calibration(
                    request.calibration,
                    environment_ref=request.environment_ref,
                    policy=request.policy,
                    canary_plan_record=request.plan,
                )
                calibration_id = calibration.record_id
                calibration_digest = calibration.content_digest
        else:
            _deny("canary_kind_invalid")
        links = [
            _link("candidate", 0, request.candidate.ref, request.candidate.digest),
            _link(
                "incumbent_profile",
                0,
                request.incumbent_profile.ref,
                request.incumbent_profile.digest,
            ),
            _link(
                "activation_disposition",
                0,
                request.disposition_ref.ref,
                request.disposition_ref.digest,
            ),
            _link("activation_policy", 0, request.policy.record_id, request.policy.content_digest),
            _link("canary_plan", 0, request.plan.record_id, request.plan.content_digest),
            _link(
                "authority_grant",
                0,
                request.authority_grant.ref,
                request.authority_grant.digest,
            ),
        ]
        if request.calibration is not None:
            links.append(
                _link(
                    "policy_calibration",
                    0,
                    request.calibration.record_id,
                    request.calibration.content_digest,
                )
            )
        return _record(
            record_id=request.record_id,
            context_ref=request.context_ref,
            record_kind="canary_trial",
            schema_id=CANARY_TRIAL_SCHEMA_ID,
            payload={
                "fact_type": "canary_trial",
                "canary_kind": request.canary_kind,
                "authority_ceiling": ceiling,
                "candidate_id": request.candidate.ref,
                "candidate_digest": request.candidate.digest,
                "incumbent_profile_id": request.incumbent_profile.ref,
                "incumbent_profile_digest": request.incumbent_profile.digest,
                "disposition_id": request.disposition_ref.ref,
                "disposition_digest": request.disposition_ref.digest,
                "disposition": request.disposition,
                "scope_revision": request.observed_scope_revision,
                "policy_id": request.policy.record_id,
                "policy_digest": request.policy.content_digest,
                "policy_revision": policy["policy_revision"],
                "calibration_id": calibration_id,
                "calibration_digest": calibration_digest,
                "plan_id": request.plan.record_id,
                "plan_digest": request.plan.content_digest,
                "environment_ref": request.environment_ref,
                "authority_grant_id": request.authority_grant.ref,
                "authority_grant_digest": request.authority_grant.digest,
                "links": links,
            },
            key_epoch=self._key_epoch,
        )

    def plan_exposure(
        self,
        *,
        record_id: str,
        trial: TypedRecord,
        active_trial: RecordIdentity,
        observed_scope_revision: int,
        exposure_unit_ref: str,
        envelope_ref: str,
        eligible: bool,
        already_receipted: bool,
        assignment_secret: bytes,
        frozen_plan: TypedRecord,
    ) -> TypedRecord:
        trial.verify(CANARY_REGISTRY)
        frozen_plan.verify(CANARY_REGISTRY)
        trial_payload = trial.payload
        if type(eligible) is not bool or type(already_receipted) is not bool:
            _deny("exposure_eligibility_invalid")
        if active_trial != RecordIdentity.of(trial):
            _deny("canary_not_active")
        if observed_scope_revision != trial_payload["scope_revision"]:
            _deny("scope_revision_conflict")
        if not eligible:
            _deny("exposure_unit_ineligible")
        if already_receipted:
            _deny("exposure_already_receipted")
        if (
            frozen_plan.record_id != trial_payload["plan_id"]
            or frozen_plan.content_digest != trial_payload["plan_digest"]
        ):
            _deny("canary_plan_mismatch")
        if type(assignment_secret) is not bytes or not assignment_secret:
            _deny("assignment_secret_unavailable")
        committed = sha256(b"a0-canary-assignment-key\0" + assignment_secret).hexdigest()
        plan_payload = frozen_plan.payload
        if not hmac.compare_digest(committed, plan_payload["assignment_key_commitment"]):
            _deny("assignment_secret_mismatch")
        assignment = hmac.new(
            assignment_secret,
            canonical_json(
                {
                    "trial_id": trial.record_id,
                    "trial_digest": trial.content_digest,
                    "exposure_unit_ref": exposure_unit_ref,
                }
            ),
            "sha256",
        ).hexdigest()
        allocation = plan_payload["candidate_allocation"]
        arm = (
            "candidate"
            if int(assignment, 16) % allocation["denominator"] < allocation["numerator"]
            else "incumbent"
        )
        return _record(
            record_id=record_id,
            context_ref=trial.context_ref or "",
            record_kind="canary_exposure_receipt",
            schema_id=EXPOSURE_RECEIPT_SCHEMA_ID,
            payload={
                "fact_type": "canary_exposure_receipt",
                "trial_id": trial.record_id,
                "trial_digest": trial.content_digest,
                "exposure_unit_ref": exposure_unit_ref,
                "envelope_ref": envelope_ref,
                "scope_revision": observed_scope_revision,
                "arm": arm,
                "assignment_digest": assignment,
                "links": [_link("canary_trial", 0, trial.record_id, trial.content_digest)],
            },
            key_epoch=self._key_epoch,
        )

    def observation_eligible(
        self,
        *,
        trial: TypedRecord,
        receipt: TypedRecord | None,
        exposure_unit_ref: str,
        envelope_ref: str,
        arm: str,
    ) -> bool:
        if receipt is None:
            return False
        try:
            trial.verify(CANARY_REGISTRY)
            receipt.verify(CANARY_REGISTRY)
        except SchemaValidationError:
            return False
        payload = receipt.payload
        return (
            receipt.record_kind == "canary_exposure_receipt"
            and payload["trial_id"] == trial.record_id
            and payload["trial_digest"] == trial.content_digest
            and payload["exposure_unit_ref"] == exposure_unit_ref
            and payload["envelope_ref"] == envelope_ref
            and payload["arm"] == arm
        )

    def plan_conclusion(
        self, request: CanaryConclusionRequest, *, frozen_plan: TypedRecord
    ) -> TypedRecord:
        request.trial.verify(CANARY_REGISTRY)
        frozen_plan.verify(CANARY_REGISTRY)
        trial = request.trial.payload
        if (
            frozen_plan.record_id != trial["plan_id"]
            or frozen_plan.content_digest != trial["plan_digest"]
        ):
            _deny("canary_plan_mismatch")
        if any(
            type(value) is not bool
            for value in (
                request.shared_failure,
                request.identity_drift,
                request.cancelled,
                request.boundary_uncertain,
                request.operator_stopped,
            )
        ):
            _deny("conclusion_signal_invalid")
        if (
            type(request.candidate_hard_failure_count) is not int
            or request.candidate_hard_failure_count < 0
        ):
            _deny("conclusion_signal_invalid")
        plan = frozen_plan.payload
        expected = {item["bucket_ref"]: item for item in plan["buckets"]}
        observed = {item.bucket_ref: item for item in request.bucket_outcomes}
        if (
            type(request.eligible_exposure_count) is not int
            or request.eligible_exposure_count < 0
            or any(
                type(item.bucket_ref) is not str
                or not item.bucket_ref
                or type(item.comparable_count) is not int
                or item.comparable_count < 0
                or type(item.boundary_uncertain) is not bool
                for item in request.bucket_outcomes
            )
        ):
            _deny("conclusion_signal_invalid")
        if len(observed) != len(request.bucket_outcomes) or set(observed) != set(expected):
            _deny("canary_bucket_set_mismatch")
        reasons: list[str]
        if request.shared_failure:
            conclusion, reasons = "inconclusive", ["shared_failure"]
        elif request.identity_drift:
            conclusion, reasons = "inconclusive", ["identity_drift"]
        elif request.cancelled:
            conclusion, reasons = "inconclusive", ["cancelled"]
        elif request.boundary_uncertain or any(
            item.boundary_uncertain for item in request.bucket_outcomes
        ):
            conclusion, reasons = "inconclusive", ["boundary_uncertain"]
        elif request.candidate_hard_failure_count > plan["hard_veto_failure_limit"]:
            conclusion, reasons = "failed", ["candidate_hard_failure"]
        elif request.operator_stopped:
            conclusion, reasons = "stopped", ["operator_stopped"]
        elif request.eligible_exposure_count < plan["horizon_exposures"] or any(
            observed[ref].comparable_count < bucket["minimum_comparable"]
            for ref, bucket in expected.items()
        ):
            conclusion, reasons = "inconclusive", ["underpowered"]
        elif any(
            not _bucket_passes(observed[ref], bucket)
            for ref, bucket in expected.items()
        ):
            conclusion, reasons = "failed", ["ordinary_boundary_failed"]
        else:
            conclusion, reasons = "passed", ["horizon_passed"]
        authoritative = (
            trial["canary_kind"] == "authoritative"
            and trial["authority_ceiling"] == "activation_authority"
            and conclusion == "passed"
        )
        return _record(
            record_id=request.record_id,
            context_ref=request.trial.context_ref or "",
            record_kind="canary_conclusion",
            schema_id=CANARY_CONCLUSION_SCHEMA_ID,
            payload={
                "fact_type": "canary_conclusion",
                "trial_id": request.trial.record_id,
                "trial_digest": request.trial.content_digest,
                "canary_kind": trial["canary_kind"],
                "authority_ceiling": trial["authority_ceiling"],
                "conclusion": conclusion,
                "activation_authoritative": authoritative,
                "candidate_id": trial["candidate_id"],
                "candidate_digest": trial["candidate_digest"],
                "incumbent_profile_id": trial["incumbent_profile_id"],
                "incumbent_profile_digest": trial["incumbent_profile_digest"],
                "scope_revision": trial["scope_revision"],
                "policy_id": trial["policy_id"],
                "policy_digest": trial["policy_digest"],
                "policy_revision": trial["policy_revision"],
                "calibration_id": trial["calibration_id"],
                "calibration_digest": trial["calibration_digest"],
                "reason_codes": reasons,
                "links": [_link("canary_trial", 0, request.trial.record_id, request.trial.content_digest)],
            },
            key_epoch=self._key_epoch,
        )

    def activation_eligibility(
        self,
        *,
        candidate: RecordIdentity,
        conclusion: TypedRecord,
        policy: TypedRecord,
        calibration: TypedRecord | None,
        environment_ref: str,
        expected_scope_revision: int,
        observed_scope_revision: int,
        requested_authority: str,
    ) -> ActivationEligibility:
        conclusion.verify(CANARY_REGISTRY)
        payload = conclusion.payload
        if (
            type(expected_scope_revision) is not int
            or type(observed_scope_revision) is not int
            or expected_scope_revision < 0
            or observed_scope_revision < 0
        ):
            _deny("scope_revision_invalid")
        if payload["conclusion"] != "passed" or not payload["activation_authoritative"]:
            _deny("passed_authoritative_canary_required")
        if candidate.ref != payload["candidate_id"] or candidate.digest != payload["candidate_digest"]:
            _deny("candidate_mismatch")
        if expected_scope_revision != observed_scope_revision or payload["scope_revision"] != observed_scope_revision:
            _deny("scope_revision_conflict")
        approved = self._approved_calibration(
            calibration,
            environment_ref=environment_ref,
            policy=policy,
            canary_plan_record=None,
        )
        calibration_payload = approved.payload
        if (
            approved.record_id != payload["calibration_id"]
            or approved.content_digest != payload["calibration_digest"]
        ):
            _deny("calibration_mismatch")
        if requested_authority not in calibration_payload["activation_authorities"]:
            _deny("activation_authority_not_calibrated")
        mode = policy.payload["activation_mode"]
        if requested_authority == "automatic" and mode != "auto_after_canary":
            _deny("automatic_activation_disabled")
        return ActivationEligibility(
            candidate=candidate,
            canary_conclusion=RecordIdentity.of(conclusion),
            policy=RecordIdentity.of(policy),
            calibration=RecordIdentity.of(approved),
            environment_ref=environment_ref,
            observed_scope_revision=observed_scope_revision,
            resulting_scope_revision=observed_scope_revision + 1,
            activation_mode=requested_authority,
        )

    def soft_rollback_eligible(
        self,
        *,
        policy: TypedRecord,
        calibration: TypedRecord | None,
        environment_ref: str,
        expected_scope_revision: int,
        observed_scope_revision: int,
        monitor_plan_record: TypedRecord,
    ) -> bool:
        monitor_plan_record.verify(CANARY_REGISTRY)
        if (
            type(expected_scope_revision) is not int
            or type(observed_scope_revision) is not int
            or expected_scope_revision < 0
            or observed_scope_revision < 0
        ):
            _deny("scope_revision_invalid")
        if expected_scope_revision != observed_scope_revision:
            _deny("scope_revision_conflict")
        approved = self._approved_calibration(
            calibration,
            environment_ref=environment_ref,
            policy=policy,
            canary_plan_record=None,
        )
        payload = approved.payload
        if not payload["soft_rollback_authorized"]:
            _deny("soft_rollback_not_calibrated")
        if (
            payload["monitor_plan_id"] != monitor_plan_record.record_id
            or payload["monitor_plan_digest"] != monitor_plan_record.content_digest
        ):
            _deny("monitor_plan_mismatch")
        return True

    def plan_monitor_start(
        self,
        *,
        record_id: str,
        context_ref: str,
        eligibility: ActivationEligibility,
        incumbent_profile: RecordIdentity,
        conclusion: TypedRecord,
        policy: TypedRecord,
        calibration: TypedRecord,
        monitor_plan_record: TypedRecord,
    ) -> TypedRecord:
        conclusion.verify(CANARY_REGISTRY)
        policy.verify(CANARY_REGISTRY)
        calibration.verify(CANARY_REGISTRY)
        monitor_plan_record.verify(CANARY_REGISTRY)
        if RecordIdentity.of(conclusion) != eligibility.canary_conclusion:
            _deny("canary_conclusion_mismatch")
        if (
            conclusion.payload["conclusion"] != "passed"
            or not conclusion.payload["activation_authoritative"]
        ):
            _deny("passed_authoritative_canary_required")
        if eligibility.candidate != RecordIdentity(
            conclusion.payload["candidate_id"], conclusion.payload["candidate_digest"]
        ):
            _deny("candidate_mismatch")
        if eligibility.policy != RecordIdentity.of(policy):
            _deny("policy_mismatch")
        if eligibility.calibration != RecordIdentity.of(calibration):
            _deny("calibration_mismatch")
        if eligibility.environment_ref != calibration.payload["environment_ref"]:
            _deny("policy_calibration_environment_mismatch")
        if (
            eligibility.observed_scope_revision != conclusion.payload["scope_revision"]
            or eligibility.resulting_scope_revision
            != eligibility.observed_scope_revision + 1
        ):
            _deny("scope_revision_conflict")
        if any(
            record.context_ref != context_ref
            for record in (conclusion, policy, calibration, monitor_plan_record)
        ):
            _deny("context_mismatch")
        calibration_payload = calibration.payload
        if (
            calibration_payload["monitor_plan_id"] != monitor_plan_record.record_id
            or calibration_payload["monitor_plan_digest"] != monitor_plan_record.content_digest
        ):
            _deny("monitor_plan_mismatch")
        links = [
            _link("candidate", 0, eligibility.candidate.ref, eligibility.candidate.digest),
            _link("incumbent_profile", 0, incumbent_profile.ref, incumbent_profile.digest),
            _link("canary_conclusion", 0, conclusion.record_id, conclusion.content_digest),
            _link("activation_policy", 0, policy.record_id, policy.content_digest),
            _link("policy_calibration", 0, calibration.record_id, calibration.content_digest),
            _link("monitor_plan", 0, monitor_plan_record.record_id, monitor_plan_record.content_digest),
        ]
        return _record(
            record_id=record_id,
            context_ref=context_ref,
            record_kind="post_promotion_monitor",
            schema_id=POST_PROMOTION_MONITOR_SCHEMA_ID,
            payload={
                "fact_type": "post_promotion_monitor",
                "candidate_id": eligibility.candidate.ref,
                "candidate_digest": eligibility.candidate.digest,
                "incumbent_profile_id": incumbent_profile.ref,
                "incumbent_profile_digest": incumbent_profile.digest,
                "canary_conclusion_id": conclusion.record_id,
                "canary_conclusion_digest": conclusion.content_digest,
                "policy_id": policy.record_id,
                "policy_digest": policy.content_digest,
                "calibration_id": calibration.record_id,
                "calibration_digest": calibration.content_digest,
                "monitor_plan_id": monitor_plan_record.record_id,
                "monitor_plan_digest": monitor_plan_record.content_digest,
                "observed_scope_revision": eligibility.observed_scope_revision,
                "resulting_scope_revision": eligibility.resulting_scope_revision,
                "links": links,
            },
            key_epoch=self._key_epoch,
        )

    @staticmethod
    def _approved_calibration(
        calibration: TypedRecord | None,
        *,
        environment_ref: str,
        policy: TypedRecord,
        canary_plan_record: TypedRecord | None,
    ) -> TypedRecord:
        policy.verify(CANARY_REGISTRY)
        if calibration is None:
            _deny("policy_uncalibrated")
        calibration.verify(CANARY_REGISTRY)
        payload = calibration.payload
        policy_payload = policy.payload
        if payload["status"] != "approved":
            _deny("policy_calibration_not_approved")
        if calibration.context_ref != policy.context_ref:
            _deny("policy_calibration_context_mismatch")
        if payload["environment_ref"] != environment_ref:
            _deny("policy_calibration_environment_mismatch")
        if (
            payload["policy_id"] != policy.record_id
            or payload["policy_digest"] != policy.content_digest
            or payload["policy_revision"] != policy_payload["policy_revision"]
        ):
            _deny("policy_calibration_mismatch")
        if canary_plan_record is not None and (
            payload["canary_plan_id"] != canary_plan_record.record_id
            or payload["canary_plan_digest"] != canary_plan_record.content_digest
        ):
            _deny("canary_plan_not_calibrated")
        return calibration


def _compare(left: Rational, right: dict[str, int]) -> int:
    delta = left.numerator * right["denominator"] - right["numerator"] * left.denominator
    return (delta > 0) - (delta < 0)


def _bucket_passes(outcome: BucketOutcome, calibration: dict[str, Any]) -> bool:
    margin = calibration["noninferiority_margin"]
    lower_bound = {"numerator": -margin["numerator"], "denominator": margin["denominator"]}
    return _compare(outcome.candidate_delta, lower_bound) >= 0 and _compare(
        outcome.candidate_delta, calibration["benefit_threshold"]
    ) >= 0
