"""Strict, framework-agnostic admission for activation transition commands.

Framework authentication, CSRF, method, and transport checks happen before this
module is called.  The adapter binds that admitted framework identity to one
closed request schema, constructs the existing transition request types, and
projects coordinator results into a content-free response.  It performs no I/O
and owns no domain authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any, Callable, Mapping

from .activation_transition import (
    ActivationAuthorityFacts,
    ActivationRequest,
    ActivationTransitionDenied,
    ActivationTransitionResult,
    ExactRecord,
    GrantRevalidator,
    RollbackRequest,
    SafetyBypassRequest,
    SlotExpectation,
    TransitionCommand,
)
from .authority import AuthorityValidationError, digest_idempotency_key
from .canary import (
    CANARY_REGISTRY,
    POST_PROMOTION_MONITOR_SCHEMA_ID,
    ActivationEligibility,
    RecordIdentity,
)
from .repository import IdempotencyConflict, IntegrityFailure, RevisionConflict
from .schemas import (
    SchemaValidationError,
    V3SchemaError,
    build_typed_record,
    strict_enum,
    strict_integer,
    strict_list,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
)


ACTIVATE_COMMAND_SCHEMA = "a0.command.activate.v1"
ROLLBACK_COMMAND_SCHEMA = "a0.command.rollback.v1"
SAFETY_BYPASS_COMMAND_SCHEMA = "a0.command.safety-bypass.v1"
COMMAND_RESPONSE_SCHEMA = "a0.command-response.v1"

_ACTIONS = ("activate", "rollback", "safety_bypass")
_SLOT_KINDS = ("canary", "monitor", "requalification")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")

# Operator explanations are bounded catalog values, never free-form text.  The
# transition coordinator remains the authority for its receipt reason.
_OPERATOR_REASONS = {
    "activate": frozenset(("operator_requested", "canary_passed")),
    "rollback": frozenset(
        ("operator_requested", "monitor_failure", "emergency_rollback")
    ),
    "safety_bypass": frozenset(
        ("operator_requested", "emergency_safety_bypass")
    ),
}

_SUCCESS_REASONS = {
    "activate": "candidate_activated",
    "rollback": "predecessor_restored",
    "safety_bypass": "safety_bypass_applied",
}
_ACTION_STATES = {
    "activate": "activated",
    "rollback": "rolled_back",
    "safety_bypass": "safety_bypass",
}

# Only these coordinator reasons may cross the API boundary.  Unknown reasons
# and all exception messages collapse to ``internal_error``.
_DOMAIN_REASON_STATUS = {
    "authority_grant_mismatch": 422,
    "verified_grant_required": 422,
    "transition_context_mismatch": 422,
    "activation_scope_target_mismatch": 409,
    "candidate_lineage_stale": 409,
    "evidence_lineage_stale": 409,
    "canary_slot_conclusion_mismatch": 409,
    "rollback_ancestry_mismatch": 409,
    "exact_canary_slot_occupant_required": 422,
    "monitor_slot_occupied": 422,
    "requalification_slot_occupied": 422,
    "promotion_ready_disposition_required": 422,
    "passed_authoritative_canary_required": 422,
    "activation_eligibility_stale": 422,
    "monitor_plan_mismatch": 422,
    "dependency_capability_mismatch": 422,
    "fixture_authority_mismatch": 422,
    "candidate_authority_mismatch": 422,
    "capability_certificate_identity_mismatch": 422,
    "rollback_ancestry_required": 422,
    "all_null_activation_profile_required": 422,
    "dependency_capability_unavailable": 503,
}


def _safe_ref(value: Any, path: str) -> str:
    value = strict_string(maximum=512)(value, path)
    if _SAFE_REF.fullmatch(value) is None:
        raise SchemaValidationError(f"{path} is not an opaque reference")
    return value


def _short_safe_ref(value: Any, path: str) -> str:
    value = _safe_ref(value, path)
    if len(value) > 128:
        raise SchemaValidationError(f"{path} is too long")
    return value


def _json_object(value: Any, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise SchemaValidationError(f"{path} must be an object")
    return dict(value)


_EXACT = strict_object({"record_id": _safe_ref, "digest": validate_digest})
_OPTIONAL_EXACT = strict_nullable(_EXACT)
_SLOT = strict_object(
    {
        "operation_kind": strict_enum(_SLOT_KINDS),
        "revision": strict_integer(minimum=0),
        "occupant": _OPTIONAL_EXACT,
    }
)
_SLOTS = strict_list(_SLOT, minimum=3, maximum=3)
_ELIGIBILITY = strict_object(
    {
        "candidate": _EXACT,
        "canary_conclusion": _EXACT,
        "policy": _EXACT,
        "calibration": _EXACT,
        "environment_ref": _safe_ref,
        "observed_scope_revision": strict_integer(minimum=0),
        "resulting_scope_revision": strict_integer(minimum=1),
        "activation_mode": strict_enum(("manual", "automatic")),
    }
)
_AUTHORITIES = strict_object(
    {
        "dependency_profile": _EXACT,
        "capability_certificate": _EXACT,
        "fixture_manifests": strict_list(_EXACT, minimum=1, maximum=10_000),
    }
)
_MONITOR = strict_object(
    {
        "record_id": _safe_ref,
        "context_ref": _short_safe_ref,
        "record_kind": strict_literal("post_promotion_monitor"),
        "schema_id": strict_literal(POST_PROMOTION_MONITOR_SCHEMA_ID),
        "key_epoch": _safe_ref,
        "payload": _json_object,
    }
)
_COMMON = {
    "context_ref": _short_safe_ref,
    "expected_scope_revision": strict_integer(minimum=0),
    "idempotency_key": strict_string(maximum=512),
    "authority_grant_id": _short_safe_ref,
}
_ACTIVATE = strict_object(
    {
        "schema": strict_literal(ACTIVATE_COMMAND_SCHEMA),
        "action": strict_literal("activate"),
        **_COMMON,
        "operator_reason_code": strict_enum(_OPERATOR_REASONS["activate"]),
        "candidate": _EXACT,
        "disposition": _EXACT,
        "canary_conclusion": _EXACT,
        "policy": _EXACT,
        "calibration": _EXACT,
        "successor_profile": _EXACT,
        "monitor": _MONITOR,
        "eligibility": _ELIGIBILITY,
        "authorities": _AUTHORITIES,
        "slots": _SLOTS,
    }
)
_ROLLBACK = strict_object(
    {
        "schema": strict_literal(ROLLBACK_COMMAND_SCHEMA),
        "action": strict_literal("rollback"),
        **_COMMON,
        "operator_reason_code": strict_enum(_OPERATOR_REASONS["rollback"]),
        "predecessor_activation_receipt": _EXACT,
        "predecessor_profile": _EXACT,
        "slots": _SLOTS,
    }
)
_SAFETY_BYPASS = strict_object(
    {
        "schema": strict_literal(SAFETY_BYPASS_COMMAND_SCHEMA),
        "action": strict_literal("safety_bypass"),
        **_COMMON,
        "operator_reason_code": strict_enum(_OPERATOR_REASONS["safety_bypass"]),
        "null_profile": _EXACT,
        "slots": _SLOTS,
    }
)


Coordinator = Callable[..., ActivationTransitionResult]


@dataclass(frozen=True, slots=True)
class SafeCommandResponse:
    """Transport-neutral HTTP status and strict JSON-compatible body."""

    status_code: int
    body: dict[str, Any]


class SafeCommandAdapter:
    """Admit ``activate`` and ``rollback`` without acquiring new authority."""

    def __init__(
        self,
        *,
        activate_coordinator: Coordinator,
        rollback_coordinator: Coordinator,
        activate_grant_revalidator: GrantRevalidator,
        rollback_grant_revalidator: GrantRevalidator,
        safety_bypass_coordinator: Coordinator | None = None,
        safety_bypass_grant_revalidator: GrantRevalidator | None = None,
    ) -> None:
        for name, value in (
            ("activate_coordinator", activate_coordinator),
            ("rollback_coordinator", rollback_coordinator),
            ("activate_grant_revalidator", activate_grant_revalidator),
            ("rollback_grant_revalidator", rollback_grant_revalidator),
        ):
            if not callable(value):
                raise TypeError(f"{name} must be callable")
        self.activate_coordinator = activate_coordinator
        self.rollback_coordinator = rollback_coordinator
        self.activate_grant_revalidator = activate_grant_revalidator
        self.rollback_grant_revalidator = rollback_grant_revalidator
        if (safety_bypass_coordinator is None) != (
            safety_bypass_grant_revalidator is None
        ):
            raise TypeError("Safety Bypass coordinator and revalidator must be supplied together")
        if safety_bypass_coordinator is not None and not callable(
            safety_bypass_coordinator
        ):
            raise TypeError("safety_bypass_coordinator must be callable")
        if safety_bypass_grant_revalidator is not None and not callable(
            safety_bypass_grant_revalidator
        ):
            raise TypeError("safety_bypass_grant_revalidator must be callable")
        self.safety_bypass_coordinator = safety_bypass_coordinator
        self.safety_bypass_grant_revalidator = safety_bypass_grant_revalidator

    def handle(
        self,
        payload: object,
        *,
        bound_context_ref: str,
        issuer_ref: str,
        subject_ref: str,
        now: datetime,
    ) -> SafeCommandResponse:
        """Handle JSON already admitted by the framework security boundary."""

        action = _requested_action(payload)
        try:
            bound_context_ref = _short_safe_ref(bound_context_ref, "bound_context_ref")
            issuer_ref = _short_safe_ref(issuer_ref, "issuer_ref")
            subject_ref = _short_safe_ref(subject_ref, "subject_ref")
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                raise SchemaValidationError("now must be timezone-aware")
        except (SchemaValidationError, ValueError, TypeError):
            return _failure(422, action, "framework_binding_invalid")

        if type(payload) is dict:
            raw_context = payload.get("context_ref")
            if type(raw_context) is str and raw_context != bound_context_ref:
                return _failure(422, action, "context_binding_mismatch")
            raw_reason = payload.get("operator_reason_code")
            if action in _ACTIONS and type(raw_reason) is str:
                if raw_reason not in _OPERATOR_REASONS[action]:
                    return _failure(422, action, "reason_code_invalid")

        try:
            if action == "activate":
                admitted = _ACTIVATE(payload, "request")
                request = _activation_request(
                    admitted,
                    issuer_ref=issuer_ref,
                    subject_ref=subject_ref,
                    now=now,
                )
                _bind_context_and_revision(request, bound_context_ref)
                coordinator = self.activate_coordinator
                revalidator = self.activate_grant_revalidator
            elif action == "rollback":
                admitted = _ROLLBACK(payload, "request")
                request = _rollback_request(
                    admitted,
                    issuer_ref=issuer_ref,
                    subject_ref=subject_ref,
                    now=now,
                )
                _bind_context_and_revision(request, bound_context_ref)
                coordinator = self.rollback_coordinator
                revalidator = self.rollback_grant_revalidator
            elif action == "safety_bypass":
                admitted = _SAFETY_BYPASS(payload, "request")
                request = _safety_bypass_request(
                    admitted,
                    issuer_ref=issuer_ref,
                    subject_ref=subject_ref,
                    now=now,
                )
                _bind_context_and_revision(request, bound_context_ref)
                coordinator = self.safety_bypass_coordinator
                revalidator = self.safety_bypass_grant_revalidator
                if coordinator is None or revalidator is None:
                    raise SchemaValidationError("Safety Bypass authority is unavailable")
            else:
                raise SchemaValidationError("request action is not admitted")
        except (V3SchemaError, AuthorityValidationError, ValueError, TypeError):
            return _failure(400, action, "schema_invalid")

        try:
            result = coordinator(request=request, revalidate_grant=revalidator)
            return _success(action, request, result)
        except IdempotencyConflict:
            return _failure(409, action, "idempotency_conflict")
        except RevisionConflict:
            return _failure(409, action, "scope_revision_conflict")
        except ActivationTransitionDenied as exc:
            status = _DOMAIN_REASON_STATUS.get(exc.reason_code)
            if status is None:
                return _failure(503, action, "internal_error")
            return _failure(status, action, exc.reason_code)
        except (IntegrityFailure, V3SchemaError):
            return _failure(503, action, "transition_unavailable")
        except Exception:
            return _failure(503, action, "internal_error")


def adapt_command(
    payload: object,
    *,
    bound_context_ref: str,
    issuer_ref: str,
    subject_ref: str,
    now: datetime,
    activate_coordinator: Coordinator,
    rollback_coordinator: Coordinator,
    activate_grant_revalidator: GrantRevalidator,
    rollback_grant_revalidator: GrantRevalidator,
    safety_bypass_coordinator: Coordinator | None = None,
    safety_bypass_grant_revalidator: GrantRevalidator | None = None,
) -> SafeCommandResponse:
    """Functional convenience wrapper for handlers that do not retain adapters."""

    return SafeCommandAdapter(
        activate_coordinator=activate_coordinator,
        rollback_coordinator=rollback_coordinator,
        activate_grant_revalidator=activate_grant_revalidator,
        rollback_grant_revalidator=rollback_grant_revalidator,
        safety_bypass_coordinator=safety_bypass_coordinator,
        safety_bypass_grant_revalidator=safety_bypass_grant_revalidator,
    ).handle(
        payload,
        bound_context_ref=bound_context_ref,
        issuer_ref=issuer_ref,
        subject_ref=subject_ref,
        now=now,
    )


def _requested_action(payload: object) -> str | None:
    if type(payload) is dict and payload.get("action") in _ACTIONS:
        return payload["action"]
    return None


def _activation_request(
    payload: Mapping[str, Any],
    *,
    issuer_ref: str,
    subject_ref: str,
    now: datetime,
) -> ActivationRequest:
    command = _command(payload, issuer_ref=issuer_ref, subject_ref=subject_ref, now=now)
    monitor_payload = payload["monitor"]
    monitor = build_typed_record(
        record_id=monitor_payload["record_id"],
        context_ref=monitor_payload["context_ref"],
        record_kind=monitor_payload["record_kind"],
        schema_id=monitor_payload["schema_id"],
        payload=monitor_payload["payload"],
        key_epoch=monitor_payload["key_epoch"],
        registry=CANARY_REGISTRY,
    )
    eligibility = payload["eligibility"]
    authorities = payload["authorities"]
    slots = _slot_expectations(payload["slots"])
    request = ActivationRequest(
        command=command,
        candidate=_exact_record(payload["candidate"]),
        disposition=_exact_record(payload["disposition"]),
        canary_conclusion=_exact_record(payload["canary_conclusion"]),
        policy=_exact_record(payload["policy"]),
        calibration=_exact_record(payload["calibration"]),
        successor_profile=_exact_record(payload["successor_profile"]),
        monitor=monitor,
        eligibility=ActivationEligibility(
            candidate=_record_identity(eligibility["candidate"]),
            canary_conclusion=_record_identity(eligibility["canary_conclusion"]),
            policy=_record_identity(eligibility["policy"]),
            calibration=_record_identity(eligibility["calibration"]),
            environment_ref=eligibility["environment_ref"],
            observed_scope_revision=eligibility["observed_scope_revision"],
            resulting_scope_revision=eligibility["resulting_scope_revision"],
            activation_mode=eligibility["activation_mode"],
        ),
        authorities=ActivationAuthorityFacts(
            dependency_profile=_exact_record(authorities["dependency_profile"]),
            capability_certificate=_exact_record(authorities["capability_certificate"]),
            fixture_manifests=tuple(
                _exact_record(item) for item in authorities["fixture_manifests"]
            ),
        ),
        canary_slot=slots[0],
        monitor_slot=slots[1],
        requalification_slot=slots[2],
    )
    _require_activation_exactness(request)
    return request


def _rollback_request(
    payload: Mapping[str, Any],
    *,
    issuer_ref: str,
    subject_ref: str,
    now: datetime,
) -> RollbackRequest:
    return RollbackRequest(
        command=_command(payload, issuer_ref=issuer_ref, subject_ref=subject_ref, now=now),
        predecessor_activation_receipt=_exact_record(
            payload["predecessor_activation_receipt"]
        ),
        predecessor_profile=_exact_record(payload["predecessor_profile"]),
        slots=_slot_expectations(payload["slots"]),
    )


def _safety_bypass_request(
    payload: Mapping[str, Any],
    *,
    issuer_ref: str,
    subject_ref: str,
    now: datetime,
) -> SafetyBypassRequest:
    return SafetyBypassRequest(
        command=_command(payload, issuer_ref=issuer_ref, subject_ref=subject_ref, now=now),
        null_profile=_exact_record(payload["null_profile"]),
        slots=_slot_expectations(payload["slots"]),
    )


def _command(
    payload: Mapping[str, Any],
    *,
    issuer_ref: str,
    subject_ref: str,
    now: datetime,
) -> TransitionCommand:
    return TransitionCommand(
        issuer_ref=issuer_ref,
        subject_ref=subject_ref,
        context_ref=payload["context_ref"],
        target_ref=payload["context_ref"],
        expected_scope_revision=payload["expected_scope_revision"],
        idempotency_key_digest=digest_idempotency_key(payload["idempotency_key"]),
        authority_grant_id=payload["authority_grant_id"],
        now=now,
    )


def _slot_expectations(
    values: list[Mapping[str, Any]],
) -> tuple[SlotExpectation, SlotExpectation, SlotExpectation]:
    if [item["operation_kind"] for item in values] != list(_SLOT_KINDS):
        raise SchemaValidationError("request.slots must use canonical slot order")
    slots = tuple(
        SlotExpectation(
            operation_kind=item["operation_kind"],
            revision=item["revision"],
            occupant=None if item["occupant"] is None else _exact_record(item["occupant"]),
        )
        for item in values
    )
    return slots  # type: ignore[return-value]


def _exact_record(value: Mapping[str, str]) -> ExactRecord:
    return ExactRecord(value["record_id"], value["digest"])


def _record_identity(value: Mapping[str, str]) -> RecordIdentity:
    return RecordIdentity(value["record_id"], value["digest"])


def _bind_context_and_revision(
    request: ActivationRequest | RollbackRequest | SafetyBypassRequest,
    bound_context_ref: str,
) -> None:
    if request.command.context_ref != bound_context_ref:
        raise SchemaValidationError("request context is not bound to framework context")


def _require_activation_exactness(request: ActivationRequest) -> None:
    revision = request.command.expected_scope_revision
    eligibility = request.eligibility
    if (
        eligibility.observed_scope_revision != revision
        or eligibility.resulting_scope_revision != revision + 1
        or eligibility.candidate
        != RecordIdentity(request.candidate.record_id, request.candidate.digest)
        or eligibility.canary_conclusion
        != RecordIdentity(
            request.canary_conclusion.record_id, request.canary_conclusion.digest
        )
        or eligibility.policy != RecordIdentity(request.policy.record_id, request.policy.digest)
        or eligibility.calibration
        != RecordIdentity(request.calibration.record_id, request.calibration.digest)
        or request.monitor.context_ref != request.command.context_ref
    ):
        raise SchemaValidationError("activation exact bindings do not agree")
    monitor = request.monitor.payload
    if (
        monitor["candidate_id"] != request.candidate.record_id
        or monitor["candidate_digest"] != request.candidate.digest
        or monitor["canary_conclusion_id"] != request.canary_conclusion.record_id
        or monitor["canary_conclusion_digest"] != request.canary_conclusion.digest
        or monitor["policy_id"] != request.policy.record_id
        or monitor["policy_digest"] != request.policy.digest
        or monitor["calibration_id"] != request.calibration.record_id
        or monitor["calibration_digest"] != request.calibration.digest
        or monitor["observed_scope_revision"] != revision
        or monitor["resulting_scope_revision"] != revision + 1
    ):
        raise SchemaValidationError("monitor exact bindings do not agree")


def _success(
    action: str,
    request: ActivationRequest | RollbackRequest | SafetyBypassRequest,
    result: ActivationTransitionResult,
) -> SafeCommandResponse:
    if type(result) is not ActivationTransitionResult:
        raise TypeError("coordinator returned an invalid result")
    receipt = result.receipt
    payload = receipt.payload
    expected_reason = _SUCCESS_REASONS[action]
    policy = payload.get("activation_policy")
    policy_ref = None
    if action == "activate":
        if type(policy) is not dict or set(policy) != {"record_id", "digest"}:
            raise SchemaValidationError("activation receipt has no exact policy")
        policy_ref = _safe_ref(policy["record_id"], "receipt.policy_ref")
        validate_digest(policy["digest"], "receipt.policy_digest")
    elif policy is not None:
        raise SchemaValidationError("profile transition receipt unexpectedly names a policy")

    observed = payload.get("observed_revision")
    resulting = payload.get("resulting_revision")
    if (
        payload.get("action") != action
        or type(observed) is not int
        or observed != request.command.expected_scope_revision
        or type(resulting) is not int
        or resulting != observed + 1
        or payload.get("reason_codes") != [expected_reason]
        or receipt.context_ref != request.command.context_ref
        or result.scope.context_ref != request.command.context_ref
        or result.scope.scope_revision != resulting
        or result.command.action != action
        or result.command.context_ref != request.command.context_ref
        or result.command.issuer_ref != request.command.issuer_ref
        or result.command.subject_ref != request.command.subject_ref
        or result.command.idempotency_key_digest != request.command.idempotency_key_digest
        or result.command.observed_revision != observed
        or result.command.state != "accepted"
        or result.command.mutation_receipt_id != receipt.record_id
    ):
        raise SchemaValidationError("coordinator result does not match admitted command")

    return SafeCommandResponse(
        200,
        _body(
            accepted=True,
            action=action,
            receipt_ref=_safe_ref(receipt.record_id, "receipt.record_id"),
            observed_revision=observed,
            resulting_revision=resulting,
            policy_ref=policy_ref,
            action_state=_ACTION_STATES[action],
            reason_code=expected_reason,
        ),
    )


def _failure(status: int, action: str | None, reason_code: str) -> SafeCommandResponse:
    return SafeCommandResponse(
        status,
        _body(
            accepted=False,
            action=action,
            receipt_ref=None,
            observed_revision=None,
            resulting_revision=None,
            policy_ref=None,
            action_state="refused",
            reason_code=reason_code,
        ),
    )


def _body(
    *,
    accepted: bool,
    action: str | None,
    receipt_ref: str | None,
    observed_revision: int | None,
    resulting_revision: int | None,
    policy_ref: str | None,
    action_state: str,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "schema": COMMAND_RESPONSE_SCHEMA,
        "accepted": accepted,
        "action": action,
        "receipt_ref": receipt_ref,
        "observed_revision": observed_revision,
        "resulting_revision": resulting_revision,
        "policy_ref": policy_ref,
        "action_state": action_state,
        "reason_codes": [reason_code],
    }


__all__ = [
    "ACTIVATE_COMMAND_SCHEMA",
    "ROLLBACK_COMMAND_SCHEMA",
    "SAFETY_BYPASS_COMMAND_SCHEMA",
    "COMMAND_RESPONSE_SCHEMA",
    "SafeCommandAdapter",
    "SafeCommandResponse",
    "adapt_command",
]
