"""Strict framework-agnostic adapter for ``canary_start`` and ``canary_stop``.

Framework authentication, CSRF, method, and transport admission happen before
this adapter.  It decodes a closed request, resolves exact immutable planning
facts, invokes the existing pure CanaryCoordinator, and hands the plan to an
injected mutation coordinator.  It never writes a repository or claims domain
truth itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Callable, Mapping, Protocol

from .authority import (
    AuthorityAction,
    AuthorityClass,
    AuthorityDenied,
    AuthorityPurpose,
    AuthorityValidationError,
    VerifiedGrant,
    digest_idempotency_key,
)
from .canary import (
    ACTIVATION_POLICY_SCHEMA_ID,
    CANARY_CONCLUSION_SCHEMA_ID,
    CANARY_PLAN_SCHEMA_ID,
    CANARY_REGISTRY,
    CANARY_TRIAL_SCHEMA_ID,
    POLICY_CALIBRATION_SCHEMA_ID,
    BucketOutcome,
    CanaryConclusionRequest,
    CanaryCoordinator,
    CanaryPolicyDenied,
    CanaryStartRequest,
    Rational,
    RecordIdentity,
)
from .repository import (
    IdempotencyConflict,
    IdentityCollision,
    IntegrityFailure,
    OperationSlot,
    RevisionConflict,
)
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    V3SchemaError,
    build_typed_record,
    canonical_json,
    merge_schema_registries,
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


CANARY_START_COMMAND_SCHEMA = "a0.command.canary-start.v1"
CANARY_STOP_COMMAND_SCHEMA = "a0.command.canary-stop.v1"
CANARY_COMMAND_RESPONSE_SCHEMA = "a0.canary-command-response.v1"
CANARY_MUTATION_RECEIPT_SCHEMA_ID = "a0.canary-mutation-receipt.v1"
CANARY_AUTHORITY_GRANT_USE_SCHEMA_ID = "a0.canary-authority-grant-use.v1"

_ACTIONS = ("canary_start", "canary_stop")
_START_REASONS = (
    "authoritative_canary_requested",
    "diagnostic_canary_requested",
)
_STOP_REASONS = ("operator_stopped",)
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")


class CanaryCommandError(RuntimeError):
    """Stable content-free adapter or injected-coordinator failure."""


class MutationCoordinatorUnavailable(CanaryCommandError):
    pass


class CanaryCommandDenied(CanaryCommandError):
    pass


@dataclass(frozen=True, slots=True)
class ExactRecord:
    record_id: str
    digest: str

    def __post_init__(self) -> None:
        _safe_ref(self.record_id, "record_id")
        validate_digest(self.digest, "digest")

    @classmethod
    def of(cls, record: TypedRecord) -> "ExactRecord":
        return cls(record.record_id, record.content_digest)

    def payload(self) -> dict[str, str]:
        return {"record_id": self.record_id, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class SlotBinding:
    revision: int
    occupant: ExactRecord | None


@dataclass(frozen=True, slots=True)
class CanaryGrantBinding:
    action: str
    purpose: str
    authority_class: str
    issuer_ref: str
    subject_ref: str
    context_ref: str
    target_ref: str
    target_revision: int
    idempotency_key_digest: str
    session_nonce: str
    authority_grant_id: str
    now: datetime


GrantRevalidator = Callable[[CanaryGrantBinding], VerifiedGrant]


@dataclass(frozen=True, slots=True)
class CanaryMutationOperation:
    action: str
    context_ref: str
    expected_scope_revision: int
    slot: SlotBinding
    planned_fact: TypedRecord
    candidate: ExactRecord
    disposition: ExactRecord
    policy: ExactRecord
    calibration: ExactRecord | None
    canary_plan: ExactRecord
    trial: ExactRecord | None
    authority_grant_id: str
    authority_grant_use: TypedRecord
    grant_binding: CanaryGrantBinding
    issuer_ref: str
    subject_ref: str
    idempotency_key_digest: str
    request_digest: str
    operator_reason_code: str
    receipt_id: str
    key_epoch: str


@dataclass(frozen=True, slots=True)
class CanaryMutationResult:
    planned_fact: TypedRecord
    receipt: TypedRecord
    slot: OperationSlot
    verified_grant_id: str
    replayed: bool


class CanaryMutationCoordinator(Protocol):
    def get_record(self, identity: ExactRecord) -> TypedRecord | None: ...

    def commit(
        self,
        operation: CanaryMutationOperation,
        *,
        revalidate_grant: GrantRevalidator,
    ) -> CanaryMutationResult: ...


@dataclass(frozen=True, slots=True)
class SafeCanaryCommandResponse:
    status_code: int
    body: dict[str, Any]


def _safe_ref(value: Any, path: str, *, maximum: int = 512) -> str:
    value = strict_string(maximum=maximum)(value, path)
    if _SAFE_REF.fullmatch(value) is None:
        raise SchemaValidationError(f"{path} is not a bounded opaque reference")
    return value


_EXACT = strict_object({"record_id": _safe_ref, "digest": validate_digest})
_OPTIONAL_EXACT = strict_nullable(_EXACT)
_SLOT = strict_object(
    {
        "revision": strict_integer(minimum=0),
        "occupant": _OPTIONAL_EXACT,
    }
)
_DISPOSITION = strict_object(
    {
        "record": _EXACT,
        "state": strict_enum(("promotion_ready", "review_only")),
    }
)
_RATIONAL = strict_object(
    {"numerator": strict_integer(), "denominator": strict_integer(minimum=1)}
)
_BUCKET_OUTCOME = strict_object(
    {
        "bucket_ref": _safe_ref,
        "comparable_count": strict_integer(minimum=0),
        "candidate_delta": _RATIONAL,
        "boundary_uncertain": strict_boolean(),
    }
)
_SIGNALS = strict_object(
    {
        "eligible_exposure_count": strict_integer(minimum=0),
        "candidate_hard_failure_count": strict_integer(minimum=0),
        "shared_failure": strict_boolean(),
        "identity_drift": strict_boolean(),
        "cancelled": strict_boolean(),
        "boundary_uncertain": strict_boolean(),
        "operator_stopped": strict_literal(True),
        "bucket_outcomes": strict_list(_BUCKET_OUTCOME, minimum=1, maximum=256),
    }
)
_COMMON = {
    "context_ref": _safe_ref,
    "key_epoch": _safe_ref,
    "expected_scope_revision": strict_integer(minimum=0),
    "slot": _SLOT,
    "idempotency_key": strict_string(minimum=1, maximum=512),
    "authority_grant_id": _safe_ref,
    "receipt_id": _safe_ref,
}
_START = strict_object(
    {
        "schema": strict_literal(CANARY_START_COMMAND_SCHEMA),
        "action": strict_literal("canary_start"),
        **_COMMON,
        "trial_id": _safe_ref,
        "canary_kind": strict_enum(("authoritative", "diagnostic")),
        "candidate": _EXACT,
        "incumbent_profile": _EXACT,
        "disposition": _DISPOSITION,
        "policy": _EXACT,
        "calibration": _OPTIONAL_EXACT,
        "canary_plan": _EXACT,
        "environment_ref": _safe_ref,
        "operator_reason_code": strict_enum(_START_REASONS),
    }
)
_STOP = strict_object(
    {
        "schema": strict_literal(CANARY_STOP_COMMAND_SCHEMA),
        "action": strict_literal("canary_stop"),
        **_COMMON,
        "conclusion_id": _safe_ref,
        "trial": _EXACT,
        "candidate": _EXACT,
        "disposition": _DISPOSITION,
        "policy": _EXACT,
        "calibration": _OPTIONAL_EXACT,
        "canary_plan": _EXACT,
        "signals": _SIGNALS,
        "operator_reason_code": strict_enum(_STOP_REASONS),
    }
)


def _receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "receipt_type": strict_literal("canary_mutation"),
            "accepted": strict_literal(True),
            "action": strict_enum(_ACTIONS),
            "context_ref": _safe_ref,
            "planned_fact": _EXACT,
            "policy": _EXACT,
            "trial": _OPTIONAL_EXACT,
            "observed_scope_revision": strict_integer(minimum=0),
            "resulting_scope_revision": strict_integer(minimum=0),
            "observed_slot_revision": strict_integer(minimum=0),
            "resulting_slot_revision": strict_integer(minimum=1),
            "observed_slot_occupant": _OPTIONAL_EXACT,
            "resulting_slot_occupant": _OPTIONAL_EXACT,
            "authority_grant_id": _safe_ref,
            "authority_grant_use": _EXACT,
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "canary_kind": strict_enum(("authoritative", "diagnostic")),
            "authority_ceiling": strict_enum(
                ("activation_authority", "no_promotion_authority")
            ),
            "activation_authoritative": strict_boolean(),
            "result_state": strict_enum(
                ("authoritative_started", "diagnostic_started", "stopped")
            ),
            "reason_code": strict_enum(
                ("authoritative_canary_started", "diagnostic_canary_started", "canary_stopped")
            ),
            "links": validate_links,
        }
    )(value, path)
    if payload["resulting_scope_revision"] != payload["observed_scope_revision"]:
        raise SchemaValidationError(f"{path} may not mutate Activation Scope")
    if payload["resulting_slot_revision"] != payload["observed_slot_revision"] + 1:
        raise SchemaValidationError(f"{path} has a non-CAS slot revision")
    if payload["action"] == "canary_start":
        expected_state = (
            "authoritative_started"
            if payload["canary_kind"] == "authoritative"
            else "diagnostic_started"
        )
        expected_reason = (
            "authoritative_canary_started"
            if payload["canary_kind"] == "authoritative"
            else "diagnostic_canary_started"
        )
        expected_ceiling = (
            "activation_authority"
            if payload["canary_kind"] == "authoritative"
            else "no_promotion_authority"
        )
        if (
            payload["observed_slot_occupant"] is not None
            or payload["resulting_slot_occupant"] != payload["planned_fact"]
            or payload["trial"] is not None
            or payload["result_state"] != expected_state
            or payload["reason_code"] != expected_reason
            or payload["authority_ceiling"] != expected_ceiling
            or payload["activation_authoritative"] is not False
        ):
            raise SchemaValidationError(f"{path} has an invalid canary-start transition")
    else:
        if (
            payload["trial"] is None
            or payload["observed_slot_occupant"] != payload["trial"]
            or payload["resulting_slot_occupant"] is not None
            or payload["result_state"] != "stopped"
            or payload["reason_code"] != "canary_stopped"
            or payload["activation_authoritative"] is not False
        ):
            raise SchemaValidationError(f"{path} has an invalid canary-stop transition")
    links = [
        _link("planned_fact", 0, payload["planned_fact"]),
        _link("activation_policy", 0, payload["policy"]),
        _link("authority_grant_use", 0, payload["authority_grant_use"]),
    ]
    if payload["trial"] is not None:
        links.append(_link("canary_trial", 0, payload["trial"]))
    if payload["links"] != links:
        raise SchemaValidationError(f"{path}.links do not bind exact mutation facts")
    return payload


def _link(role: str, ordinal: int, exact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": exact["record_id"],
        "target_digest": exact["digest"],
    }


def _authority_timestamp(value: Any, path: str) -> str:
    if type(value) is not str:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    return value


def _no_links(value: Any, path: str) -> list[dict[str, Any]]:
    links = validate_links(value, path)
    if links:
        raise SchemaValidationError(f"{path} must be empty")
    return links


_RECEIPT_ONLY_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            CANARY_AUTHORITY_GRANT_USE_SCHEMA_ID,
            "authority_grant_use",
            strict_object(
                {
                    "record_type": strict_literal("canary_authority_grant_use"),
                    "grant_id": _safe_ref,
                    "authority_class": strict_literal(
                        AuthorityClass.OPERATOR_AUTHORITY_GRANT.value
                    ),
                    "issuer_ref": _safe_ref,
                    "subject_ref": _safe_ref,
                    "context_ref": _safe_ref,
                    "action": strict_enum(_ACTIONS),
                    "purpose": strict_enum(
                        (
                            AuthorityPurpose.OPERATOR_MUTATION.value,
                            AuthorityPurpose.DIAGNOSTIC_CANARY.value,
                        )
                    ),
                    "target_ref": _safe_ref,
                    "target_revision": strict_integer(minimum=0),
                    "issued_at": _authority_timestamp,
                    "expires_at": _authority_timestamp,
                    "idempotency_key_digest": validate_digest,
                    "session_nonce": _safe_ref,
                    "links": _no_links,
                }
            ),
        ),
        RecordSchema(
            CANARY_MUTATION_RECEIPT_SCHEMA_ID,
            "canary_mutation_receipt",
            _receipt_validator,
        ),
    )
)
CANARY_COMMAND_REGISTRY = merge_schema_registries(
    CANARY_REGISTRY, _RECEIPT_ONLY_REGISTRY
)


def build_canary_authority_grant_use(
    binding: CanaryGrantBinding,
    verified_grant: VerifiedGrant,
    *,
    key_epoch: str,
) -> TypedRecord:
    """Project one verified signed-envelope use without persisting the envelope."""

    verify_canary_grant(binding, verified_grant)
    return build_typed_record(
        record_id=verified_grant.grant_id,
        context_ref=binding.context_ref,
        record_kind="authority_grant_use",
        schema_id=CANARY_AUTHORITY_GRANT_USE_SCHEMA_ID,
        payload={
            "record_type": "canary_authority_grant_use",
            "grant_id": verified_grant.grant_id,
            "authority_class": verified_grant.authority_class,
            "issuer_ref": verified_grant.issuer_id,
            "subject_ref": verified_grant.subject_ref,
            "context_ref": verified_grant.context_ref,
            "action": verified_grant.action,
            "purpose": verified_grant.purpose,
            "target_ref": verified_grant.target_ref,
            "target_revision": verified_grant.target_revision,
            "issued_at": verified_grant.issued_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "expires_at": verified_grant.expires_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "idempotency_key_digest": verified_grant.idempotency_key_digest,
            "session_nonce": verified_grant.session_nonce,
            "links": [],
        },
        key_epoch=_safe_ref(key_epoch, "key_epoch", maximum=128),
        registry=CANARY_COMMAND_REGISTRY,
    )


def build_canary_mutation_receipt(
    operation: CanaryMutationOperation,
    *,
    resulting_slot: OperationSlot,
    verified_grant: VerifiedGrant,
) -> TypedRecord:
    """Build the append-ready receipt an injected coordinator must persist."""

    verify_canary_grant(operation.grant_binding, verified_grant)
    expected_grant_use = build_canary_authority_grant_use(
        operation.grant_binding, verified_grant, key_epoch=operation.key_epoch
    )
    if operation.authority_grant_use != expected_grant_use:
        raise CanaryCommandDenied("canary authority use differs from verified grant")
    fact = operation.planned_fact
    fact_exact = ExactRecord.of(fact)
    expected_kind = "canary_trial" if operation.action == "canary_start" else "canary_conclusion"
    if fact.record_kind != expected_kind or fact.context_ref != operation.context_ref:
        raise CanaryCommandError("planned canary fact has the wrong exact type or context")
    if (
        resulting_slot.context_ref != operation.context_ref
        or resulting_slot.operation_kind != "canary"
        or resulting_slot.operation_revision != operation.slot.revision + 1
    ):
        raise RevisionConflict("mutation coordinator returned a stale canary slot")
    trial = operation.trial.payload() if operation.trial is not None else None
    fact_payload = fact.payload
    if operation.action == "canary_start":
        expected_occupant = fact_exact
        result_state = (
            "authoritative_started"
            if fact_payload["canary_kind"] == "authoritative"
            else "diagnostic_started"
        )
        reason = (
            "authoritative_canary_started"
            if fact_payload["canary_kind"] == "authoritative"
            else "diagnostic_canary_started"
        )
        activation_authoritative = False
    else:
        expected_occupant = None
        result_state = "stopped"
        reason = "canary_stopped"
        activation_authoritative = fact_payload["activation_authoritative"]
        if activation_authoritative:
            raise CanaryCommandError("a stopped canary cannot be activation-authoritative")
    actual_occupant = (
        None
        if resulting_slot.operation_id is None
        else ExactRecord(resulting_slot.operation_id, resulting_slot.operation_digest or "")
    )
    if actual_occupant != expected_occupant:
        raise RevisionConflict("mutation coordinator returned the wrong canary occupant")
    policy_payload = operation.policy.payload()
    authority_use_payload = ExactRecord.of(operation.authority_grant_use).payload()
    links = [
        _link("planned_fact", 0, fact_exact.payload()),
        _link("activation_policy", 0, policy_payload),
        _link("authority_grant_use", 0, authority_use_payload),
    ]
    if trial is not None:
        links.append(_link("canary_trial", 0, trial))
    payload = {
        "receipt_type": "canary_mutation",
        "accepted": True,
        "action": operation.action,
        "context_ref": operation.context_ref,
        "planned_fact": fact_exact.payload(),
        "policy": policy_payload,
        "trial": trial,
        "observed_scope_revision": operation.expected_scope_revision,
        "resulting_scope_revision": operation.expected_scope_revision,
        "observed_slot_revision": operation.slot.revision,
        "resulting_slot_revision": resulting_slot.operation_revision,
        "observed_slot_occupant": (
            operation.slot.occupant.payload() if operation.slot.occupant is not None else None
        ),
        "resulting_slot_occupant": (
            actual_occupant.payload() if actual_occupant is not None else None
        ),
        "authority_grant_id": verified_grant.grant_id,
        "authority_grant_use": authority_use_payload,
        "idempotency_key_digest": operation.idempotency_key_digest,
        "request_digest": operation.request_digest,
        "canary_kind": fact_payload["canary_kind"],
        "authority_ceiling": fact_payload["authority_ceiling"],
        "activation_authoritative": activation_authoritative,
        "result_state": result_state,
        "reason_code": reason,
        "links": links,
    }
    return build_typed_record(
        record_id=operation.receipt_id,
        context_ref=operation.context_ref,
        record_kind="canary_mutation_receipt",
        schema_id=CANARY_MUTATION_RECEIPT_SCHEMA_ID,
        payload=payload,
        key_epoch=operation.key_epoch,
        registry=CANARY_COMMAND_REGISTRY,
    )


class CanaryCommandAdapter:
    """Decode and plan commands; all accepted mutation is injected."""

    def __init__(
        self,
        *,
        key_epoch: str,
        mutation_coordinator: CanaryMutationCoordinator | None,
        start_grant_revalidator: GrantRevalidator,
        stop_grant_revalidator: GrantRevalidator,
    ) -> None:
        self.key_epoch = _safe_ref(key_epoch, "key_epoch", maximum=128)
        self.mutation_coordinator = mutation_coordinator
        if not callable(start_grant_revalidator) or not callable(stop_grant_revalidator):
            raise TypeError("canary grant revalidators must be callable")
        self.start_grant_revalidator = start_grant_revalidator
        self.stop_grant_revalidator = stop_grant_revalidator
        self.planner = CanaryCoordinator(key_epoch=self.key_epoch)

    def handle(
        self,
        payload: object,
        *,
        bound_context_ref: str,
        issuer_ref: str,
        subject_ref: str,
        session_nonce: str,
        now: datetime,
    ) -> SafeCanaryCommandResponse:
        action = _requested_action(payload)
        try:
            context = _safe_ref(bound_context_ref, "bound_context_ref", maximum=128)
            issuer = _safe_ref(issuer_ref, "issuer_ref", maximum=128)
            subject = _safe_ref(subject_ref, "subject_ref", maximum=128)
            nonce = _safe_ref(session_nonce, "session_nonce", maximum=128)
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                raise SchemaValidationError("now must be timezone-aware")
        except (SchemaValidationError, TypeError, ValueError):
            return _failure(422, action, "framework_binding_invalid")
        if type(payload) is dict and type(payload.get("context_ref")) is str:
            if payload["context_ref"] != context:
                return _failure(422, action, "context_binding_mismatch")
        try:
            if action == "canary_start":
                admitted = _START(payload, "request")
            elif action == "canary_stop":
                admitted = _STOP(payload, "request")
            else:
                raise SchemaValidationError("request action is not admitted")
            _validate_syntax_relations(admitted)
        except (V3SchemaError, ValueError, TypeError):
            return _failure(400, action, "schema_invalid")
        if admitted["key_epoch"] != self.key_epoch:
            return _failure(422, action, "key_epoch_binding_mismatch")
        if self.mutation_coordinator is None:
            return _failure(503, action, "mutation_coordinator_unavailable")
        try:
            revalidator = (
                self.start_grant_revalidator
                if action == "canary_start"
                else self.stop_grant_revalidator
            )
            operation = self._plan(
                admitted,
                issuer_ref=issuer,
                subject_ref=subject,
                session_nonce=nonce,
                now=now,
                revalidate_grant=revalidator,
            )
            result = self.mutation_coordinator.commit(
                operation, revalidate_grant=revalidator
            )
            return _success(operation, result)
        except (IdempotencyConflict, IdentityCollision):
            return _failure(409, action, "idempotency_conflict")
        except RevisionConflict:
            return _failure(409, action, "canary_slot_conflict")
        except (
            CanaryPolicyDenied,
            AuthorityDenied,
            AuthorityValidationError,
            CanaryCommandDenied,
        ) as exc:
            reason = getattr(exc, "reason_code", "authority_or_policy_denied")
            return _failure(422, action, reason)
        except CanaryCommandError:
            return _failure(503, action, "canary_operation_unavailable")
        except (IntegrityFailure, V3SchemaError):
            return _failure(503, action, "canary_operation_unavailable")
        except Exception:
            return _failure(503, action, "internal_error")

    def _plan(
        self,
        payload: Mapping[str, Any],
        *,
        issuer_ref: str,
        subject_ref: str,
        session_nonce: str,
        now: datetime,
        revalidate_grant: GrantRevalidator,
    ) -> CanaryMutationOperation:
        assert self.mutation_coordinator is not None
        _validate_policy_relations(payload)
        candidate = _exact(payload["candidate"])
        disposition = _exact(payload["disposition"]["record"])
        policy_identity = _exact(payload["policy"])
        calibration_identity = _optional_exact(payload["calibration"])
        plan_identity = _exact(payload["canary_plan"])
        policy = _resolve(
            self.mutation_coordinator,
            policy_identity,
            context_ref=payload["context_ref"],
            schema_id=ACTIVATION_POLICY_SCHEMA_ID,
            record_kind="activation_policy",
        )
        plan = _resolve(
            self.mutation_coordinator,
            plan_identity,
            context_ref=payload["context_ref"],
            schema_id=CANARY_PLAN_SCHEMA_ID,
            record_kind="canary_plan",
        )
        calibration = (
            None
            if calibration_identity is None
            else _resolve(
                self.mutation_coordinator,
                calibration_identity,
                context_ref=payload["context_ref"],
                schema_id=POLICY_CALIBRATION_SCHEMA_ID,
                record_kind="policy_calibration",
            )
        )
        slot = SlotBinding(
            payload["slot"]["revision"], _optional_exact(payload["slot"]["occupant"])
        )
        request_digest = schema_digest(
            "canary-command-request",
            payload["schema"],
            canonical_json(dict(payload)),
        )
        idempotency = digest_idempotency_key(payload["idempotency_key"])
        grant_id = payload["authority_grant_id"]
        purpose = (
            AuthorityPurpose.DIAGNOSTIC_CANARY.value
            if payload["action"] == "canary_start" and payload.get("canary_kind") == "diagnostic"
            else AuthorityPurpose.OPERATOR_MUTATION.value
        )
        binding = CanaryGrantBinding(
            action=(
                AuthorityAction.CANARY_START.value
                if payload["action"] == "canary_start"
                else AuthorityAction.CANARY_STOP.value
            ),
            purpose=purpose,
            authority_class=AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,
            issuer_ref=issuer_ref,
            subject_ref=subject_ref,
            context_ref=payload["context_ref"],
            target_ref=(
                payload["trial_id"]
                if payload["action"] == "canary_start"
                else payload["trial"]["record_id"]
            ),
            target_revision=payload["expected_scope_revision"],
            idempotency_key_digest=idempotency,
            session_nonce=session_nonce,
            authority_grant_id=grant_id,
            now=now,
        )
        preverified_grant = revalidate_grant(binding)
        verify_canary_grant(binding, preverified_grant)
        authority_grant_use = build_canary_authority_grant_use(
            binding, preverified_grant, key_epoch=self.key_epoch
        )
        if payload["action"] == "canary_start":
            fact = self.planner.plan_start(
                CanaryStartRequest(
                    record_id=payload["trial_id"],
                    context_ref=payload["context_ref"],
                    canary_kind=payload["canary_kind"],
                    disposition=payload["disposition"]["state"],
                    disposition_ref=RecordIdentity(disposition.record_id, disposition.digest),
                    candidate=RecordIdentity(candidate.record_id, candidate.digest),
                    incumbent_profile=RecordIdentity(
                        payload["incumbent_profile"]["record_id"],
                        payload["incumbent_profile"]["digest"],
                    ),
                    expected_scope_revision=payload["expected_scope_revision"],
                    observed_scope_revision=payload["expected_scope_revision"],
                    environment_ref=payload["environment_ref"],
                    policy=policy,
                    calibration=calibration,
                    plan=plan,
                    authority_grant=RecordIdentity(
                        authority_grant_use.record_id,
                        authority_grant_use.content_digest,
                    ),
                    authority_purpose=(
                        "authoritative_canary"
                        if payload["canary_kind"] == "authoritative"
                        else "diagnostic_canary"
                    ),
                    occupied_canary_ref=(
                        slot.occupant.record_id if slot.occupant is not None else None
                    ),
                )
            )
            trial = None
        else:
            trial_identity = _exact(payload["trial"])
            trial_record = _resolve(
                self.mutation_coordinator,
                trial_identity,
                context_ref=payload["context_ref"],
                schema_id=CANARY_TRIAL_SCHEMA_ID,
                record_kind="canary_trial",
            )
            trial_payload = trial_record.payload
            if (
                (trial_payload["candidate_id"], trial_payload["candidate_digest"])
                != (candidate.record_id, candidate.digest)
                or (trial_payload["disposition_id"], trial_payload["disposition_digest"])
                != (disposition.record_id, disposition.digest)
                or trial_payload["disposition"] != payload["disposition"]["state"]
                or (trial_payload["policy_id"], trial_payload["policy_digest"])
                != (policy_identity.record_id, policy_identity.digest)
                or (trial_payload["plan_id"], trial_payload["plan_digest"])
                != (plan_identity.record_id, plan_identity.digest)
                or trial_payload["scope_revision"] != payload["expected_scope_revision"]
                or (trial_payload["calibration_id"], trial_payload["calibration_digest"])
                != (
                    (calibration_identity.record_id, calibration_identity.digest)
                    if calibration_identity is not None
                    else (None, None)
                )
            ):
                raise CanaryCommandDenied("canary_stop exact trial facts do not match")
            signals = payload["signals"]
            outcomes = tuple(
                BucketOutcome(
                    item["bucket_ref"],
                    item["comparable_count"],
                    Rational(
                        item["candidate_delta"]["numerator"],
                        item["candidate_delta"]["denominator"],
                    ),
                    item["boundary_uncertain"],
                )
                for item in signals["bucket_outcomes"]
            )
            fact = self.planner.plan_conclusion(
                CanaryConclusionRequest(
                    record_id=payload["conclusion_id"],
                    trial=trial_record,
                    eligible_exposure_count=signals["eligible_exposure_count"],
                    bucket_outcomes=outcomes,
                    candidate_hard_failure_count=signals["candidate_hard_failure_count"],
                    shared_failure=signals["shared_failure"],
                    identity_drift=signals["identity_drift"],
                    cancelled=signals["cancelled"],
                    boundary_uncertain=signals["boundary_uncertain"],
                    operator_stopped=signals["operator_stopped"],
                ),
                frozen_plan=plan,
            )
            trial = trial_identity
        return CanaryMutationOperation(
            action=payload["action"],
            context_ref=payload["context_ref"],
            expected_scope_revision=payload["expected_scope_revision"],
            slot=slot,
            planned_fact=fact,
            candidate=candidate,
            disposition=disposition,
            policy=policy_identity,
            calibration=calibration_identity,
            canary_plan=plan_identity,
            trial=trial,
            authority_grant_id=grant_id,
            authority_grant_use=authority_grant_use,
            grant_binding=binding,
            issuer_ref=issuer_ref,
            subject_ref=subject_ref,
            idempotency_key_digest=idempotency,
            request_digest=request_digest,
            operator_reason_code=payload["operator_reason_code"],
            receipt_id=payload["receipt_id"],
            key_epoch=self.key_epoch,
        )


def _resolve(
    coordinator: CanaryMutationCoordinator,
    identity: ExactRecord,
    *,
    context_ref: str,
    schema_id: str,
    record_kind: str,
) -> TypedRecord:
    record = coordinator.get_record(identity)
    if (
        record is None
        or record.record_id != identity.record_id
        or record.content_digest != identity.digest
        or record.context_ref != context_ref
        or record.schema_id != schema_id
        or record.record_kind != record_kind
    ):
        raise CanaryCommandDenied("exact planning fact is unavailable or incompatible")
    record.verify(CANARY_COMMAND_REGISTRY)
    return record


def _validate_syntax_relations(payload: Mapping[str, Any]) -> None:
    outcomes = payload.get("signals", {}).get("bucket_outcomes", [])
    refs = [item["bucket_ref"] for item in outcomes]
    if refs and (refs != sorted(refs) or len(refs) != len(set(refs))):
        raise SchemaValidationError("bucket outcomes must be sorted and unique")


def _validate_policy_relations(payload: Mapping[str, Any]) -> None:
    slot_occupant = payload["slot"]["occupant"]
    if payload["action"] == "canary_start":
        if slot_occupant is not None:
            raise RevisionConflict("canary_start requires an explicitly empty slot")
        expected_reason = (
            "authoritative_canary_requested"
            if payload["canary_kind"] == "authoritative"
            else "diagnostic_canary_requested"
        )
        if payload["operator_reason_code"] != expected_reason:
            raise CanaryCommandDenied("start reason does not match canary kind")
        if payload["canary_kind"] == "authoritative":
            if payload["disposition"]["state"] != "promotion_ready" or payload["calibration"] is None:
                raise CanaryCommandDenied("authoritative canary lacks promotion/calibration authority")
        elif payload["disposition"]["state"] != "review_only":
            raise CanaryCommandDenied("diagnostic canary requires review_only")
    else:
        if slot_occupant is None or slot_occupant != payload["trial"]:
            raise RevisionConflict("canary_stop must bind the exact slot trial")


def verify_canary_grant(binding: CanaryGrantBinding, grant: VerifiedGrant) -> None:
    """Require a revalidated grant to match one exact canary command binding."""

    if type(grant) is not VerifiedGrant:
        raise CanaryCommandError("mutation coordinator returned no VerifiedGrant")
    expected = {
        "authority_class": binding.authority_class,
        "issuer_id": binding.issuer_ref,
        "subject_ref": binding.subject_ref,
        "context_ref": binding.context_ref,
        "action": binding.action,
        "purpose": binding.purpose,
        "target_ref": binding.target_ref,
        "target_revision": binding.target_revision,
        "idempotency_key_digest": binding.idempotency_key_digest,
        "session_nonce": binding.session_nonce,
        "grant_id": binding.authority_grant_id,
    }
    if any(getattr(grant, name) != value for name, value in expected.items()):
        raise CanaryCommandDenied("VerifiedGrant does not match exact canary command")


def _success(
    operation: CanaryMutationOperation, result: CanaryMutationResult
) -> SafeCanaryCommandResponse:
    if type(result) is not CanaryMutationResult:
        raise CanaryCommandError("mutation coordinator returned an invalid result")
    if result.planned_fact != operation.planned_fact:
        raise CanaryCommandError("mutation coordinator changed the planned fact")
    if result.verified_grant_id != operation.authority_grant_id:
        raise CanaryCommandError("mutation coordinator used another grant")
    result.receipt.verify(CANARY_COMMAND_REGISTRY)
    receipt = result.receipt.payload
    if (
        receipt["action"] != operation.action
        or receipt["request_digest"] != operation.request_digest
        or receipt["planned_fact"] != ExactRecord.of(operation.planned_fact).payload()
        or receipt["policy"] != operation.policy.payload()
        or receipt["resulting_slot_revision"] != result.slot.operation_revision
    ):
        raise CanaryCommandError("mutation receipt does not bind the exact operation")
    return SafeCanaryCommandResponse(
        200,
        {
            "schema": CANARY_COMMAND_RESPONSE_SCHEMA,
            "accepted": True,
            "action": operation.action,
            "receipt_ref": result.receipt.record_id,
            "observed_revision": operation.expected_scope_revision,
            "resulting_revision": operation.expected_scope_revision,
            "policy_ref": operation.policy.record_id,
            "result_state": receipt["result_state"],
            "canary_kind": receipt["canary_kind"],
            "authority_ceiling": receipt["authority_ceiling"],
            "activation_authoritative": receipt["activation_authoritative"],
            "reason_codes": [receipt["reason_code"]],
            "replayed": result.replayed,
        },
    )


def _failure(status: int, action: str | None, reason: str) -> SafeCanaryCommandResponse:
    return SafeCanaryCommandResponse(
        status,
        {
            "schema": CANARY_COMMAND_RESPONSE_SCHEMA,
            "accepted": False,
            "action": action,
            "receipt_ref": None,
            "observed_revision": None,
            "resulting_revision": None,
            "policy_ref": None,
            "result_state": "refused",
            "canary_kind": None,
            "authority_ceiling": "none",
            "activation_authoritative": False,
            "reason_codes": [reason],
            "replayed": False,
        },
    )


def _requested_action(payload: object) -> str | None:
    if type(payload) is dict and payload.get("action") in _ACTIONS:
        return payload["action"]
    return None


def _exact(value: Mapping[str, str]) -> ExactRecord:
    return ExactRecord(value["record_id"], value["digest"])


def _optional_exact(value: Mapping[str, str] | None) -> ExactRecord | None:
    return None if value is None else _exact(value)


__all__ = [name for name in globals() if not name.startswith("_")]
