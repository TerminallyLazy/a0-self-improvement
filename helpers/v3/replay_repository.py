"""Repository-backed exact idempotency for paired fixture replay."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol

from .replay_adapter import (
    REPLAY_REGISTRY,
    ReplayPairRequest,
    ReplayPairResult,
    replay_binding_links,
    replay_request_digest,
    replay_result_from_receipt,
)
from .repository import (
    DomainEvent,
    IdempotencyConflict,
    IntegrityFailure,
    OperatorCommand,
    V3Repository,
    V3Transaction,
)
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    merge_schema_registries,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


REPLAY_ATTEMPT_CLAIM_SCHEMA_ID = "a0.replay-attempt-claim.v1"
REPLAY_COMMAND_ACTION = "replay_pair"
_EXACT = strict_object(
    {"record_id": strict_string(maximum=512), "digest": validate_digest}
)


class ReplayAttemptIncomplete(RuntimeError):
    """A durable claim exists but no completed receipt may be fabricated."""


class ReplayPairExecutor(Protocol):
    def run_pair(self, request: ReplayPairRequest) -> ReplayPairResult: ...


def _claim_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("replay_attempt_claim"),
            "issuer_ref": strict_string(maximum=512),
            "subject_ref": strict_string(maximum=512),
            "context_ref": strict_string(maximum=512),
            "pair_attempt_ref": strict_string(maximum=512),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "result_receipt_ref": strict_string(maximum=512),
            "retry_of": strict_nullable(_EXACT),
            "links": validate_links,
        }
    )(value, path)
    if payload["result_receipt_ref"] != _result_receipt_id(payload["request_digest"]):
        raise SchemaValidationError(f"{path}.result_receipt_ref is not deterministic")
    return payload


REPLAY_REPOSITORY_REGISTRY = merge_schema_registries(
    REPLAY_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                REPLAY_ATTEMPT_CLAIM_SCHEMA_ID,
                "replay_attempt_claim",
                _claim_validator,
            ),
        )
    ),
)


@dataclass(frozen=True, slots=True)
class DurableReplayPairResult:
    result: ReplayPairResult
    claim: TypedRecord
    command: OperatorCommand
    event: DomainEvent
    replayed: bool


class RepositoryReplayCoordinator:
    """Claim before provider dispatch, then atomically persist completion facts.

    A crash after claim but before completion remains visibly incomplete and is
    never resumed or silently re-dispatched.  A caller may create a separately
    identified whole-pair attempt; this coordinator does not certify providers.
    """

    def __init__(self, repository: V3Repository, executor: ReplayPairExecutor) -> None:
        if not isinstance(repository, V3Repository):
            raise TypeError("replay coordination requires a V3Repository")
        if not callable(getattr(executor, "run_pair", None)):
            raise TypeError("executor must implement run_pair")
        self._repository = repository
        self._executor = executor

    def run_pair(self, request: ReplayPairRequest) -> DurableReplayPairResult:
        request_digest = replay_request_digest(request)
        with self._repository.transaction() as transaction:
            prior = _existing_command(transaction, request, request_digest)
            if prior is not None:
                return _replay(transaction, request, request_digest, prior)
            claim = _build_claim(request, request_digest)
            transaction.insert_record(claim)
            admission = transaction.admit_command(
                OperatorCommand(
                    command_id=_stable_id("replay-command", request_digest),
                    issuer_ref=request.issuer_ref,
                    subject_ref=request.subject_ref,
                    context_ref=request.context_ref,
                    action=REPLAY_COMMAND_ACTION,
                    idempotency_key_digest=request.idempotency_key_digest,
                    request_digest=request_digest,
                    observed_revision=0,
                    state="accepted",
                    mutation_receipt_id=claim.record_id,
                )
            )
            if admission.replayed:
                raise IntegrityFailure("replay claim changed during one transaction")
            command = admission.command

        result = self._executor.run_pair(request)
        if (
            type(result) is not ReplayPairResult
            or result.receipt.record_id != _result_receipt_id(request_digest)
        ):
            raise IntegrityFailure("replay executor returned a different result identity")
        replay_result_from_receipt(request, result.receipt)

        with self._repository.transaction() as transaction:
            existing = _existing_command(transaction, request, request_digest)
            if existing is None or existing != command:
                raise IntegrityFailure("durable replay claim changed before completion")
            durable_claim = _require_claim(transaction, request, request_digest, existing)
            prior_receipt = transaction.get_record(_result_receipt_id(request_digest))
            if prior_receipt is not None:
                return _completed_replay(
                    transaction,
                    request,
                    request_digest,
                    durable_claim,
                    existing,
                    prior_receipt,
                )
            transaction.insert_record(result.receipt)
            event = _completion_event(durable_claim, result.receipt, request.issuer_ref)
            if transaction.next_domain_event_sequence(durable_claim.record_id) != 0:
                raise IntegrityFailure("replay claim already has an unexpected event")
            transaction.append_event(event)
        return DurableReplayPairResult(result, claim, command, event, False)


def _existing_command(
    transaction: V3Transaction,
    request: ReplayPairRequest,
    request_digest: str,
) -> OperatorCommand | None:
    command = transaction.get_operator_command(
        issuer_ref=request.issuer_ref,
        subject_ref=request.subject_ref,
        context_ref=request.context_ref,
        action=REPLAY_COMMAND_ACTION,
        idempotency_key_digest=request.idempotency_key_digest,
    )
    if command is not None and command.request_digest != request_digest:
        raise IdempotencyConflict("replay idempotency key has a different request")
    return command


def _replay(
    transaction: V3Transaction,
    request: ReplayPairRequest,
    request_digest: str,
    command: OperatorCommand,
) -> DurableReplayPairResult:
    claim = _require_claim(transaction, request, request_digest, command)
    receipt = transaction.get_record(_result_receipt_id(request_digest))
    if receipt is None:
        raise ReplayAttemptIncomplete("replay attempt is claimed without a receipt")
    return _completed_replay(
        transaction, request, request_digest, claim, command, receipt
    )


def _completed_replay(
    transaction: V3Transaction,
    request: ReplayPairRequest,
    request_digest: str,
    claim: TypedRecord,
    command: OperatorCommand,
    receipt: TypedRecord,
) -> DurableReplayPairResult:
    result = replay_result_from_receipt(request, receipt)
    event = _completion_event(claim, receipt, request.issuer_ref)
    if transaction.next_domain_event_sequence(claim.record_id) != 1:
        raise IntegrityFailure("completed replay lost its immutable completion event")
    if transaction.append_event(event) != event:
        raise IntegrityFailure("completed replay event changed")
    if command.request_digest != request_digest:
        raise IntegrityFailure("completed replay command digest changed")
    return DurableReplayPairResult(result, claim, command, event, True)


def _require_claim(
    transaction: V3Transaction,
    request: ReplayPairRequest,
    request_digest: str,
    command: OperatorCommand,
) -> TypedRecord:
    claim = transaction.get_record(command.mutation_receipt_id)
    if (
        command.state != "accepted"
        or command.observed_revision != 0
        or claim is None
        or claim.record_kind != "replay_attempt_claim"
        or claim.schema_id != REPLAY_ATTEMPT_CLAIM_SCHEMA_ID
    ):
        raise IntegrityFailure("replay command lost its exact attempt claim")
    payload = claim.payload
    if (
        claim.context_ref != request.context_ref
        or payload["issuer_ref"] != request.issuer_ref
        or payload["subject_ref"] != request.subject_ref
        or payload["context_ref"] != request.context_ref
        or payload["pair_attempt_ref"] != request.pair_attempt_ref
        or payload["idempotency_key_digest"] != request.idempotency_key_digest
        or payload["request_digest"] != request_digest
        or payload["result_receipt_ref"] != _result_receipt_id(request_digest)
        or payload["retry_of"]
        != (
            None
            if request.retry_of is None
            else {
                "record_id": request.retry_of.ref,
                "digest": request.retry_of.digest,
            }
        )
        or tuple(payload["links"]) != replay_binding_links(request)
    ):
        raise IntegrityFailure("replay attempt claim differs from the exact request")
    return claim


def _build_claim(request: ReplayPairRequest, request_digest: str) -> TypedRecord:
    payload = {
        "record_type": "replay_attempt_claim",
        "issuer_ref": request.issuer_ref,
        "subject_ref": request.subject_ref,
        "context_ref": request.context_ref,
        "pair_attempt_ref": request.pair_attempt_ref,
        "idempotency_key_digest": request.idempotency_key_digest,
        "request_digest": request_digest,
        "result_receipt_ref": _result_receipt_id(request_digest),
        "retry_of": (
            None
            if request.retry_of is None
            else {
                "record_id": request.retry_of.ref,
                "digest": request.retry_of.digest,
            }
        ),
        "links": list(replay_binding_links(request)),
    }
    return build_typed_record(
        record_id=_stable_id("replay-attempt-claim", request_digest),
        context_ref=request.context_ref,
        record_kind="replay_attempt_claim",
        schema_id=REPLAY_ATTEMPT_CLAIM_SCHEMA_ID,
        payload=payload,
        key_epoch="replay-repository-v1",
        registry=REPLAY_REPOSITORY_REGISTRY,
    )


def _completion_event(
    claim: TypedRecord, receipt: TypedRecord, issuer_ref: str
) -> DomainEvent:
    return DomainEvent(
        event_id=_stable_id("replay-completed-event", claim.payload["request_digest"]),
        subject_id=claim.record_id,
        subject_kind=claim.record_kind,
        sequence=0,
        event_type="replay_pair_completed",
        payload_record_id=receipt.record_id,
        actor_authority_ref=issuer_ref,
    )


def _result_receipt_id(request_digest: str) -> str:
    validate_digest(request_digest, "request_digest")
    return "replay_pair_receipt_" + request_digest


def _stable_id(namespace: str, request_digest: str) -> str:
    material = f"{namespace}\0{request_digest}".encode("ascii")
    return f"{namespace}:{sha256(material).hexdigest()}"


__all__ = [
    "REPLAY_ATTEMPT_CLAIM_SCHEMA_ID",
    "REPLAY_COMMAND_ACTION",
    "REPLAY_REPOSITORY_REGISTRY",
    "DurableReplayPairResult",
    "ReplayAttemptIncomplete",
    "ReplayPairExecutor",
    "RepositoryReplayCoordinator",
]
