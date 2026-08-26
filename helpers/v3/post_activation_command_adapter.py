"""Closed transport-neutral commands for monitor and requalification authority.

The adapter validates exact identities only.  It does not inspect outcome
measurements, infer a decision, choose thresholds, or mutate repository state.
Accepted commands are converted to :class:`PostActivationOperation` and handed
to the injected repository coordinator with the injected transaction-time
authority revalidator.
"""
from __future__ import annotations

import re
from typing import Protocol

from .authority import AuthorityError, digest_idempotency_key
from .command_adapter import COMMAND_RESPONSE_SCHEMA, SafeCommandResponse
from .post_activation_repository import (
    PostActivationAuthority,
    PostActivationAuthorityRevalidator,
    PostActivationCommitResult,
    PostActivationError,
    PostActivationOperation,
    RepositoryPostActivationCoordinator,
    digest_post_activation_request,
)
from .canary_command_adapter import ExactRecord, SlotBinding
from .repository import IdempotencyConflict, IntegrityFailure, RevisionConflict
from .schemas import (
    SchemaValidationError,
    V3SchemaError,
    strict_integer,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
)


MONITOR_CONCLUDE_COMMAND_SCHEMA = "a0.command.monitor-conclude.v1"
REQUALIFICATION_START_COMMAND_SCHEMA = "a0.command.requalification-start.v1"
REQUALIFICATION_CONCLUDE_COMMAND_SCHEMA = "a0.command.requalification-conclude.v1"

_ACTIONS = (
    "monitor_conclude",
    "requalification_start",
    "requalification_conclude",
)
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")


def _ref(value: object, path: str) -> str:
    admitted = strict_string(maximum=512)(value, path)
    if _SAFE_REF.fullmatch(admitted) is None:
        raise SchemaValidationError(f"{path} is not an opaque reference")
    return admitted


_EXACT = strict_object({"record_id": _ref, "digest": validate_digest})
_SLOT = strict_object(
    {
        "revision": strict_integer(minimum=0),
        "occupant": strict_nullable(_EXACT),
    }
)
_COMMON = {
    "context_ref": _ref,
    "expected_scope_revision": strict_integer(minimum=0),
    "key_epoch": _ref,
    "idempotency_key": strict_string(maximum=512),
    "authority_grant_id": _ref,
    "monitor_slot": _SLOT,
    "requalification_slot": _SLOT,
    "subject": _EXACT,
    "certified_outcome": _EXACT,
    "eligibility": _EXACT,
    "activation_policy": _EXACT,
    "policy_calibration": _EXACT,
    "conclusion_record_id": _ref,
}
_MONITOR_CONCLUDE = strict_object(
    {
        "schema": strict_literal(MONITOR_CONCLUDE_COMMAND_SCHEMA),
        "action": strict_literal("monitor_conclude"),
        **_COMMON,
        "requalification_window_id": strict_literal(None),
    }
)
_REQUALIFICATION_START = strict_object(
    {
        "schema": strict_literal(REQUALIFICATION_START_COMMAND_SCHEMA),
        "action": strict_literal("requalification_start"),
        **_COMMON,
        "requalification_window_id": _ref,
    }
)
_REQUALIFICATION_CONCLUDE = strict_object(
    {
        "schema": strict_literal(REQUALIFICATION_CONCLUDE_COMMAND_SCHEMA),
        "action": strict_literal("requalification_conclude"),
        **_COMMON,
        "requalification_window_id": strict_literal(None),
    }
)


class PostActivationMutationCoordinator(Protocol):
    def commit(
        self,
        operation: PostActivationOperation,
        *,
        revalidate_authority: PostActivationAuthorityRevalidator,
    ) -> PostActivationCommitResult: ...


class PostActivationCommandAdapter:
    """Validate closed commands and invoke durable post-activation authority."""

    def __init__(
        self,
        *,
        key_epoch: str,
        mutation_coordinator: PostActivationMutationCoordinator | None,
        authority_revalidator: PostActivationAuthorityRevalidator,
    ) -> None:
        self._key_epoch = _ref(key_epoch, "key_epoch")
        if mutation_coordinator is not None and not isinstance(
            mutation_coordinator, RepositoryPostActivationCoordinator
        ) and not callable(getattr(mutation_coordinator, "commit", None)):
            raise TypeError("post-activation coordinator must implement commit")
        if not callable(authority_revalidator):
            raise TypeError("post-activation authority revalidator must be callable")
        self._coordinator = mutation_coordinator
        self._revalidate_authority = authority_revalidator

    def handle(
        self,
        payload: object,
        *,
        bound_context_ref: str,
        actor_authority_ref: str,
        issuer_ref: str,
        subject_ref: str,
    ) -> SafeCommandResponse:
        action = _requested_action(payload)
        try:
            context = _ref(bound_context_ref, "bound_context_ref")
            authority = PostActivationAuthority(
                _ref(actor_authority_ref, "actor_authority_ref"),
                _ref(issuer_ref, "issuer_ref"),
                _ref(subject_ref, "subject_ref"),
            )
        except (V3SchemaError, TypeError, ValueError):
            return _failure(422, action, "framework_binding_invalid")
        try:
            admitted = _admit(payload, action)
        except (V3SchemaError, TypeError, ValueError):
            return _failure(400, action, "schema_invalid")
        action = admitted["action"]
        if admitted["context_ref"] != context:
            return _failure(422, action, "context_binding_mismatch")
        if admitted["key_epoch"] != self._key_epoch:
            return _failure(422, action, "key_epoch_binding_mismatch")
        if admitted["authority_grant_id"] != authority.actor_authority_ref:
            return _failure(422, action, "authority_grant_binding_mismatch")
        if self._coordinator is None:
            return _failure(503, action, "mutation_coordinator_unavailable")

        operation = _operation(admitted, authority)
        try:
            result = self._coordinator.commit(
                operation,
                revalidate_authority=self._revalidate_authority,
            )
            return _success(operation, result)
        except IdempotencyConflict:
            return _failure(409, action, "idempotency_conflict")
        except RevisionConflict:
            return _failure(409, action, "post_activation_slot_conflict")
        except (AuthorityError, PostActivationError):
            return _failure(422, action, "post_activation_authority_denied")
        except IntegrityFailure:
            return _failure(422, action, "post_activation_binding_denied")
        except V3SchemaError:
            return _failure(503, action, "post_activation_operation_unavailable")
        except Exception:
            return _failure(503, action, "internal_error")


def _admit(payload: object, action: str | None) -> dict[str, object]:
    if action == "monitor_conclude":
        return _MONITOR_CONCLUDE(payload, "request")
    if action == "requalification_start":
        return _REQUALIFICATION_START(payload, "request")
    if action == "requalification_conclude":
        return _REQUALIFICATION_CONCLUDE(payload, "request")
    raise SchemaValidationError("request action is not admitted")


def _operation(
    admitted: dict[str, object], authority: PostActivationAuthority
) -> PostActivationOperation:
    monitor_slot = admitted["monitor_slot"]
    requalification_slot = admitted["requalification_slot"]
    assert type(monitor_slot) is dict and type(requalification_slot) is dict
    operation = PostActivationOperation(
        action=admitted["action"],  # type: ignore[arg-type]
        context_ref=admitted["context_ref"],  # type: ignore[arg-type]
        expected_scope_revision=admitted["expected_scope_revision"],  # type: ignore[arg-type]
        monitor_slot=_slot(monitor_slot),
        requalification_slot=_slot(requalification_slot),
        subject=_exact(admitted["subject"]),
        certified_outcome=_exact(admitted["certified_outcome"]),
        eligibility=_exact(admitted["eligibility"]),
        policy=_exact(admitted["activation_policy"]),
        calibration=_exact(admitted["policy_calibration"]),
        authority=authority,
        conclusion_record_id=admitted["conclusion_record_id"],  # type: ignore[arg-type]
        requalification_window_id=admitted["requalification_window_id"],  # type: ignore[arg-type]
        idempotency_key_digest=digest_idempotency_key(
            admitted["idempotency_key"]  # type: ignore[arg-type]
        ),
        request_digest="0" * 64,
        key_epoch=admitted["key_epoch"],  # type: ignore[arg-type]
    )
    return PostActivationOperation(
        **{
            name: (
                digest_post_activation_request(operation)
                if name == "request_digest"
                else getattr(operation, name)
            )
            for name in operation.__dataclass_fields__
        }
    )


def _success(
    operation: PostActivationOperation, result: PostActivationCommitResult
) -> SafeCommandResponse:
    if type(result) is not PostActivationCommitResult:
        raise PostActivationError("coordinator returned an invalid result")
    receipt = result.receipt.payload
    if (
        receipt["request_digest"] != operation.request_digest
        or receipt["action"] != operation.action
        or receipt["decision"] != result.conclusion.payload["decision"]
        or receipt["observed_scope_revision"] != operation.expected_scope_revision
        or receipt["resulting_scope_revision"] != operation.expected_scope_revision
    ):
        raise PostActivationError("coordinator receipt changed the exact command")
    return SafeCommandResponse(
        200,
        {
            "schema": COMMAND_RESPONSE_SCHEMA,
            "accepted": True,
            "action": operation.action,
            "receipt_ref": result.receipt.record_id,
            "conclusion_ref": result.conclusion.record_id,
            "observed_revision": operation.expected_scope_revision,
            "resulting_revision": operation.expected_scope_revision,
            "policy_ref": operation.policy.record_id,
            "decision": receipt["decision"],
            "monitor_slot_revision": (
                0
                if result.monitor_slot is None
                else result.monitor_slot.operation_revision
            ),
            "requalification_slot_revision": (
                0
                if result.requalification_slot is None
                else result.requalification_slot.operation_revision
            ),
            "requalification_ref": (
                None
                if result.requalification_window is None
                else result.requalification_window.record_id
            ),
            "rollback_request_ref": (
                None
                if result.rollback_request is None
                else result.rollback_request.record_id
            ),
            "action_state": receipt["decision"],
            "reason_codes": ["exact_replay" if result.replayed else receipt["decision"]],
            "replayed": result.replayed,
        },
    )


def _failure(status: int, action: str | None, reason: str) -> SafeCommandResponse:
    return SafeCommandResponse(
        status,
        {
            "schema": COMMAND_RESPONSE_SCHEMA,
            "accepted": False,
            "action": action,
            "receipt_ref": None,
            "conclusion_ref": None,
            "observed_revision": None,
            "resulting_revision": None,
            "policy_ref": None,
            "decision": None,
            "monitor_slot_revision": None,
            "requalification_slot_revision": None,
            "requalification_ref": None,
            "rollback_request_ref": None,
            "action_state": "refused",
            "reason_codes": [reason],
            "replayed": False,
        },
    )


def _requested_action(payload: object) -> str | None:
    if type(payload) is dict and payload.get("action") in _ACTIONS:
        return payload["action"]
    return None


def _exact(value: object) -> ExactRecord:
    assert type(value) is dict
    return ExactRecord(value["record_id"], value["digest"])


def _slot(value: dict[str, object]) -> SlotBinding:
    occupant = value["occupant"]
    return SlotBinding(
        value["revision"],  # type: ignore[arg-type]
        None if occupant is None else _exact(occupant),
    )


__all__ = [
    "MONITOR_CONCLUDE_COMMAND_SCHEMA",
    "REQUALIFICATION_START_COMMAND_SCHEMA",
    "REQUALIFICATION_CONCLUDE_COMMAND_SCHEMA",
    "PostActivationMutationCoordinator",
    "PostActivationCommandAdapter",
]
