"""Strict, transport-neutral commands for v3 work enqueue and cancellation.

The adapter executes no worker code and owns no policy.  Callers inject a live
signed-grant revalidator and exact policy admission facts; the existing
``WorkCoordinator`` remains the only writer of work state and fences.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Callable

from .authority import (
    AuthorityError,
    VerifiedGrant,
    digest_idempotency_key,
)
from .repository import (
    IdempotencyConflict,
    IdentityCollision,
    IntegrityFailure,
)
from .schemas import (
    SchemaValidationError,
    V3SchemaError,
    canonical_json,
    schema_digest,
    strict_boolean,
    strict_enum,
    strict_integer,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
)
from .work_authority import (
    AuthorityAdmissionDenied,
    BudgetConflict,
    BudgetExceeded,
    ConditionDenied,
    DeadlineExceeded,
    LeaseIdentity,
    StaleFence,
    WorkCoordinator,
    WorkEnqueue,
    WorkAdmission,
    WorkMutationAuthority,
    WorkStateConflict,
)


OPTIMIZE_COMMAND_SCHEMA = "a0.command.optimize.v1"
WORK_CANCEL_COMMAND_SCHEMA = "a0.command.work-cancel.v1"
WORK_COMMAND_RESPONSE_SCHEMA = "a0.work-command-response.v1"

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ACTIONS = ("optimize", "work_cancel")
_REASON_CODES = ("operator_requested",)


def _safe_ref(value: object, path: str) -> str:
    admitted = strict_string(maximum=128)(value, path)
    if _SAFE_REF.fullmatch(admitted) is None:
        raise SchemaValidationError(f"{path} is not an opaque reference")
    return admitted


def _timestamp(value: object, path: str) -> datetime:
    if type(value) is not str:
        raise SchemaValidationError(f"{path} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    return parsed


_EXACT_RECORD = strict_object(
    {"record_id": _safe_ref, "digest": validate_digest}
)
_COMMON = {
    "context_ref": _safe_ref,
    "target_ref": _safe_ref,
    "expected_revision": strict_integer(minimum=0),
    "idempotency_key": strict_string(maximum=512),
    "authority_grant_id": _safe_ref,
    "policy_ref": _safe_ref,
    "operator_reason_code": strict_enum(_REASON_CODES),
}
_OPTIMIZE = strict_object(
    {
        "schema": strict_literal(OPTIMIZE_COMMAND_SCHEMA),
        "action": strict_literal("optimize"),
        **{**_COMMON, "expected_revision": strict_literal(0)},
        "work_id": _safe_ref,
        "operation_kind": _safe_ref,
        "input_record": _EXACT_RECORD,
        "budget_ledger_id": strict_nullable(_safe_ref),
        "max_attempts": strict_integer(minimum=1),
        "available_at": _timestamp,
        "deadline_at": _timestamp,
        "created_at": _timestamp,
    }
)
_LEASE_IDENTITY = strict_object(
    {
        "work_id": _safe_ref,
        "attempt_id": _safe_ref,
        "owner_id": _safe_ref,
        "fence_token": strict_integer(minimum=1),
        "process_nonce": _safe_ref,
        "process_start_identity": _safe_ref,
    }
)
_CLEANUP = strict_object(
    {
        "cleanup_confirmed": strict_boolean(),
        "process_identity_verified": strict_boolean(),
        "staging_cleanup_verified": strict_boolean(),
    }
)
_CANCEL_REQUEST = strict_object(
    {
        "schema": strict_literal(WORK_CANCEL_COMMAND_SCHEMA),
        "action": strict_literal("work_cancel"),
        **_COMMON,
        "phase": strict_literal("request"),
        "work_id": _safe_ref,
        "now": _timestamp,
    }
)
_CANCEL_COMPLETE = strict_object(
    {
        "schema": strict_literal(WORK_CANCEL_COMMAND_SCHEMA),
        "action": strict_literal("work_cancel"),
        **_COMMON,
        "phase": strict_literal("complete"),
        "work_id": _safe_ref,
        "now": _timestamp,
        "expired_identity": _LEASE_IDENTITY,
        "cleanup": _CLEANUP,
    }
)


@dataclass(frozen=True, slots=True)
class WorkPolicyFacts:
    action: str
    context_ref: str
    target_ref: str
    expected_revision: int
    policy_ref: str
    operation_kind: str | None
    input_record_id: str | None
    input_digest: str | None
    budget_ledger_id: str | None
    max_attempts: int | None
    available_at: datetime | None
    deadline_at: datetime | None
    command_at: datetime
    cancellation_phase: str | None
    cancellation_identity: LeaseIdentity | None
    cleanup_confirmed: bool | None
    process_identity_verified: bool | None
    staging_cleanup_verified: bool | None


@dataclass(frozen=True, slots=True)
class SafeWorkCommandResponse:
    status_code: int
    body: dict[str, object]


GrantRevalidator = Callable[[], VerifiedGrant]
PolicyRevalidator = Callable[[WorkPolicyFacts], bool]


class _PolicyUnavailable(RuntimeError):
    pass


class _GrantUnavailable(RuntimeError):
    pass


class SafeWorkCommandAdapter:
    """Admit optimize/work-cancel commands without executing work inline."""

    def __init__(self, coordinator: WorkCoordinator) -> None:
        if not isinstance(coordinator, WorkCoordinator):
            raise TypeError("coordinator must be a WorkCoordinator")
        self._coordinator = coordinator

    def handle(
        self,
        payload: object,
        *,
        bound_context_ref: str,
        bound_session_nonce: str,
        now: datetime,
        revalidate_grant: GrantRevalidator,
        revalidate_policy: PolicyRevalidator,
    ) -> SafeWorkCommandResponse:
        action = _requested_action(payload)
        try:
            context_ref = _safe_ref(bound_context_ref, "bound_context_ref")
            session_nonce = _safe_ref(bound_session_nonce, "bound_session_nonce")
            admitted_now = _aware_utc(now)
            if not callable(revalidate_grant) or not callable(revalidate_policy):
                raise SchemaValidationError("revalidators must be callable")
        except (V3SchemaError, TypeError, ValueError):
            return _failure(422, action, "framework_binding_invalid")

        try:
            admitted = _admit(payload)
        except (V3SchemaError, TypeError, ValueError):
            return _failure(400, action, "schema_invalid")
        action = admitted["action"]
        if (
            admitted["context_ref"] != context_ref
            or admitted["target_ref"] != admitted["work_id"]
        ):
            return _failure(422, action, "command_binding_mismatch")
        request_now = admitted.get("created_at", admitted.get("now"))
        if request_now != admitted_now:
            return _failure(422, action, "command_time_mismatch")

        facts = _policy_facts(admitted)

        def transactional_revalidator(_transaction) -> VerifiedGrant:
            try:
                if revalidate_policy(facts) is not True:
                    raise ConditionDenied("work policy denied")
            except ConditionDenied:
                raise
            except Exception as exc:
                raise _PolicyUnavailable from exc
            try:
                return revalidate_grant()
            except AuthorityError:
                raise
            except Exception as exc:
                raise _GrantUnavailable from exc

        try:
            if action == "optimize":
                return self._optimize(
                    admitted,
                    session_nonce=session_nonce,
                    admitted_now=admitted_now,
                    transactional_revalidator=transactional_revalidator,
                )
            return self._cancel(
                admitted,
                session_nonce=session_nonce,
                admitted_now=admitted_now,
                transactional_revalidator=transactional_revalidator,
            )
        except (IdempotencyConflict, IdentityCollision, WorkStateConflict, StaleFence, BudgetConflict):
            return _failure(409, action, "work_command_conflict")
        except ConditionDenied:
            return _failure(422, action, "work_policy_denied")
        except (AuthorityError, AuthorityAdmissionDenied):
            return _failure(422, action, "operator_authority_denied")
        except (DeadlineExceeded, BudgetExceeded, IntegrityFailure):
            return _failure(422, action, "work_admission_denied")
        except _PolicyUnavailable:
            return _failure(503, action, "work_policy_unavailable")
        except _GrantUnavailable:
            return _failure(503, action, "operator_authority_unavailable")
        except Exception:
            return _failure(503, action, "internal_error")

    def _optimize(
        self,
        admitted: dict[str, object],
        *,
        session_nonce: str,
        admitted_now: datetime,
        transactional_revalidator,
    ) -> SafeWorkCommandResponse:
        input_record = admitted["input_record"]
        assert type(input_record) is dict
        idempotency_digest = digest_idempotency_key(
            admitted["idempotency_key"]  # type: ignore[arg-type]
        )
        admission = self._coordinator.enqueue(
            WorkEnqueue(
                work_id=admitted["work_id"],  # type: ignore[arg-type]
                idempotency_key_digest=idempotency_digest,
                context_ref=admitted["context_ref"],  # type: ignore[arg-type]
                operation_kind=admitted["operation_kind"],  # type: ignore[arg-type]
                input_record_id=input_record["record_id"],
                input_digest=input_record["digest"],
                budget_ledger_id=admitted["budget_ledger_id"],  # type: ignore[arg-type]
                max_attempts=admitted["max_attempts"],  # type: ignore[arg-type]
                available_at=admitted["available_at"],  # type: ignore[arg-type]
                deadline_at=admitted["deadline_at"],  # type: ignore[arg-type]
                created_at=admitted["created_at"],  # type: ignore[arg-type]
            ),
            authority=_mutation_authority(
                admitted,
                phase="enqueue",
                session_nonce=session_nonce,
                admitted_now=admitted_now,
                idempotency_digest=idempotency_digest,
            ),
            authority_revalidator=transactional_revalidator,
        )
        return _success(
            200 if admission.replayed else 202,
            action="optimize",
            admission=admission,
            reason="exact_replay" if admission.replayed else "work_enqueued",
        )

    def _cancel(
        self,
        admitted: dict[str, object],
        *,
        session_nonce: str,
        admitted_now: datetime,
        transactional_revalidator,
    ) -> SafeWorkCommandResponse:
        idempotency_digest = digest_idempotency_key(
            admitted["idempotency_key"]  # type: ignore[arg-type]
        )
        authority = _mutation_authority(
            admitted,
            phase=admitted["phase"],  # type: ignore[arg-type]
            session_nonce=session_nonce,
            admitted_now=admitted_now,
            idempotency_digest=idempotency_digest,
        )
        phase = admitted["phase"]
        if phase == "request":
            admission = self._coordinator.request_cancellation(
                work_id=admitted["work_id"],  # type: ignore[arg-type]
                expected_fence=admitted["expected_revision"],  # type: ignore[arg-type]
                now=admitted["now"],  # type: ignore[arg-type]
                authority=authority,
                authority_revalidator=transactional_revalidator,
            )
            return _success(
                200
                if admission.replayed or admission.item.state == "cancelled"
                else 202,
                action="work_cancel",
                admission=admission,
                reason=(
                    "exact_replay"
                    if admission.replayed
                    else "work_cancelled"
                    if admission.item.state == "cancelled"
                    else "cancellation_requested"
                ),
            )

        identity = admitted["expired_identity"]
        cleanup = admitted["cleanup"]
        assert type(identity) is dict and type(cleanup) is dict
        if identity["work_id"] != admitted["work_id"]:
            raise WorkStateConflict("cancellation identity targets different work")
        admission = self._coordinator.complete_cancellation(
            expired_identity=LeaseIdentity(**identity),
            cancellation_fence=admitted["expected_revision"],  # type: ignore[arg-type]
            now=admitted["now"],  # type: ignore[arg-type]
            cleanup_confirmed=cleanup["cleanup_confirmed"],
            process_identity_verified=cleanup["process_identity_verified"],
            staging_cleanup_verified=cleanup["staging_cleanup_verified"],
            authority=authority,
            authority_revalidator=transactional_revalidator,
        )
        return _success(
            200,
            action="work_cancel",
            admission=admission,
            reason=(
                "exact_replay"
                if admission.replayed
                else "work_cancelled"
                if admission.item.state == "cancelled"
                else "cleanup_uncertain"
            ),
        )


def _admit(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise SchemaValidationError("request must be an object")
    if payload.get("action") == "optimize":
        return _OPTIMIZE(payload, "request")
    if payload.get("action") == "work_cancel" and payload.get("phase") == "request":
        return _CANCEL_REQUEST(payload, "request")
    if payload.get("action") == "work_cancel" and payload.get("phase") == "complete":
        return _CANCEL_COMPLETE(payload, "request")
    raise SchemaValidationError("request action or phase is not admitted")


def _requested_action(payload: object) -> str | None:
    if type(payload) is dict and payload.get("action") in _ACTIONS:
        return payload["action"]
    return None


def _policy_facts(admitted: dict[str, object]) -> WorkPolicyFacts:
    if admitted["action"] == "optimize":
        exact = admitted["input_record"]
        assert type(exact) is dict
        return WorkPolicyFacts(
            action="optimize",
            context_ref=admitted["context_ref"],  # type: ignore[arg-type]
            target_ref=admitted["target_ref"],  # type: ignore[arg-type]
            expected_revision=admitted["expected_revision"],  # type: ignore[arg-type]
            policy_ref=admitted["policy_ref"],  # type: ignore[arg-type]
            operation_kind=admitted["operation_kind"],  # type: ignore[arg-type]
            input_record_id=exact["record_id"],
            input_digest=exact["digest"],
            budget_ledger_id=admitted["budget_ledger_id"],  # type: ignore[arg-type]
            max_attempts=admitted["max_attempts"],  # type: ignore[arg-type]
            available_at=admitted["available_at"],  # type: ignore[arg-type]
            deadline_at=admitted["deadline_at"],  # type: ignore[arg-type]
            command_at=admitted["created_at"],  # type: ignore[arg-type]
            cancellation_phase=None,
            cancellation_identity=None,
            cleanup_confirmed=None,
            process_identity_verified=None,
            staging_cleanup_verified=None,
        )
    phase = admitted["phase"]
    identity = None
    cleanup = None
    if phase == "complete":
        raw_identity = admitted["expired_identity"]
        cleanup = admitted["cleanup"]
        assert type(raw_identity) is dict and type(cleanup) is dict
        identity = LeaseIdentity(**raw_identity)
    return WorkPolicyFacts(
        action="work_cancel",
        context_ref=admitted["context_ref"],  # type: ignore[arg-type]
        target_ref=admitted["target_ref"],  # type: ignore[arg-type]
        expected_revision=admitted["expected_revision"],  # type: ignore[arg-type]
        policy_ref=admitted["policy_ref"],  # type: ignore[arg-type]
        operation_kind=None,
        input_record_id=None,
        input_digest=None,
        budget_ledger_id=None,
        max_attempts=None,
        available_at=None,
        deadline_at=None,
        command_at=admitted["now"],  # type: ignore[arg-type]
        cancellation_phase=phase,  # type: ignore[arg-type]
        cancellation_identity=identity,
        cleanup_confirmed=(
            None if cleanup is None else cleanup["cleanup_confirmed"]
        ),
        process_identity_verified=(
            None if cleanup is None else cleanup["process_identity_verified"]
        ),
        staging_cleanup_verified=(
            None if cleanup is None else cleanup["staging_cleanup_verified"]
        ),
    )


def _mutation_authority(
    admitted: dict[str, object],
    *,
    phase: str,
    session_nonce: str,
    admitted_now: datetime,
    idempotency_digest: str,
) -> WorkMutationAuthority:
    return WorkMutationAuthority(
        action=admitted["action"],  # type: ignore[arg-type]
        phase=phase,  # type: ignore[arg-type]
        authority_grant_id=admitted["authority_grant_id"],  # type: ignore[arg-type]
        policy_ref=admitted["policy_ref"],  # type: ignore[arg-type]
        context_ref=admitted["context_ref"],  # type: ignore[arg-type]
        target_ref=admitted["target_ref"],  # type: ignore[arg-type]
        target_revision=admitted["expected_revision"],  # type: ignore[arg-type]
        idempotency_key_digest=idempotency_digest,
        request_digest=_request_digest(admitted),
        session_nonce=session_nonce,
        admitted_at=admitted_now,
    )


def _request_digest(admitted: dict[str, object]) -> str:
    def json_value(value: object) -> object:
        if isinstance(value, datetime):
            return _format_timestamp(value)
        if type(value) is dict:
            return {key: json_value(item) for key, item in value.items()}
        if type(value) is list:
            return [json_value(item) for item in value]
        return value

    return schema_digest(
        "work-command-request",
        admitted["schema"],  # type: ignore[arg-type]
        canonical_json(json_value(admitted)),
    )


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise SchemaValidationError("now must be timezone-aware")
    return value.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return _aware_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _success(
    status: int,
    *,
    action: str,
    admission: WorkAdmission,
    reason: str,
) -> SafeWorkCommandResponse:
    receipt_payload = admission.receipt.payload
    return SafeWorkCommandResponse(
        status,
        {
            "schema": WORK_COMMAND_RESPONSE_SCHEMA,
            "accepted": True,
            "action": action,
            "work_ref": admission.item.work_id,
            "work_state": receipt_payload["work_state"],
            "fence_revision": receipt_payload["resulting_revision"],
            "receipt_ref": admission.receipt.record_id,
            "policy_ref": receipt_payload["policy_ref"],
            "observed_revision": receipt_payload["observed_revision"],
            "resulting_revision": receipt_payload["resulting_revision"],
            "replayed": admission.replayed,
            "reason_codes": [reason],
        },
    )


def _failure(
    status: int,
    action: str | None,
    reason: str,
) -> SafeWorkCommandResponse:
    return SafeWorkCommandResponse(
        status,
        {
            "schema": WORK_COMMAND_RESPONSE_SCHEMA,
            "accepted": False,
            "action": action,
            "work_ref": None,
            "work_state": "refused",
            "fence_revision": None,
            "receipt_ref": None,
            "policy_ref": None,
            "observed_revision": None,
            "resulting_revision": None,
            "replayed": False,
            "reason_codes": [reason],
        },
    )


__all__ = [
    "OPTIMIZE_COMMAND_SCHEMA",
    "WORK_CANCEL_COMMAND_SCHEMA",
    "WORK_COMMAND_RESPONSE_SCHEMA",
    "SafeWorkCommandAdapter",
    "SafeWorkCommandResponse",
    "WorkPolicyFacts",
]
