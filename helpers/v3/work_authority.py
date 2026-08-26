"""Fenced work coordination and cumulative multi-dimensional budget authority.

Workers never receive this module or a writable repository handle.  All state
transitions run under the repository's ``BEGIN IMMEDIATE`` transaction and all
times, limits, attempt ceilings, identities, and policy checks are supplied by
the caller rather than invented here.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timezone
from hashlib import sha256
from typing import Callable, Literal, Mapping

from .artifacts import DEFAULT_REGISTRY
from .authority import AuthorityClass, AuthorityPurpose, VerifiedGrant
from .repository import (
    DomainEvent,
    IdempotencyConflict,
    IdentityCollision,
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
    strict_enum,
    strict_integer,
    strict_literal,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


WORK_MUTATION_RECEIPT_SCHEMA_ID = "a0.work-mutation-receipt.v1"
_WORK_MUTATION_RECEIPT_SCHEMA = RecordSchema(
    schema_id=WORK_MUTATION_RECEIPT_SCHEMA_ID,
    record_kind="operator_mutation_receipt",
    payload_validator=strict_object(
        {
            "receipt_type": strict_literal("work_mutation"),
            "accepted": strict_literal(True),
            "action": strict_enum(("optimize", "work_cancel")),
            "phase": strict_enum(("enqueue", "request", "complete")),
            "context_ref": strict_string(maximum=128),
            "target_ref": strict_string(maximum=128),
            "authority_grant_id": strict_string(maximum=128),
            "policy_ref": strict_string(maximum=128),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "observed_revision": strict_integer(minimum=0),
            "resulting_revision": strict_integer(minimum=0),
            "work_state": strict_enum(
                ("queued", "cancel_requested", "cancelled", "failed")
            ),
            "reason_code": strict_enum(
                (
                    "work_enqueued",
                    "cancellation_requested",
                    "work_cancelled",
                    "cleanup_uncertain",
                )
            ),
            "recorded_at": strict_string(maximum=64),
            "links": validate_links,
        }
    ),
)
WORK_AUTHORITY_REGISTRY = merge_schema_registries(
    DEFAULT_REGISTRY, SchemaRegistry((_WORK_MUTATION_RECEIPT_SCHEMA,))
)


class WorkAuthorityError(RuntimeError):
    """Base class for coordinator and budget authority refusals."""


class WorkStateConflict(WorkAuthorityError):
    pass


class StaleFence(WorkAuthorityError):
    pass


class DeadlineExceeded(WorkAuthorityError):
    pass


class ConditionDenied(WorkAuthorityError):
    pass


class AuthorityAdmissionDenied(WorkAuthorityError):
    pass


class BudgetExceeded(WorkAuthorityError):
    pass


class BudgetConflict(WorkAuthorityError):
    pass


WorkState = Literal[
    "queued",
    "leased",
    "cancel_requested",
    "recovery_required",
    "completed",
    "failed",
    "cancelled",
]


@dataclass(frozen=True, slots=True)
class WorkEnqueue:
    work_id: str
    idempotency_key_digest: str
    context_ref: str
    operation_kind: str
    input_record_id: str
    input_digest: str
    budget_ledger_id: str | None
    max_attempts: int
    available_at: datetime
    deadline_at: datetime
    created_at: datetime


@dataclass(frozen=True, slots=True)
class WorkItem:
    work_id: str
    idempotency_key_digest: str
    context_ref: str
    operation_kind: str
    input_record_id: str
    input_digest: str
    budget_ledger_id: str | None
    state: WorkState
    current_attempt_id: str | None
    attempt_count: int
    max_attempts: int
    available_at: str
    deadline_at: str
    cancel_requested_at: str | None
    recovery_required_at: str | None
    fence_token: int
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class WorkAdmission:
    item: WorkItem
    replayed: bool
    receipt: TypedRecord
    command: OperatorCommand


@dataclass(frozen=True, slots=True)
class WorkMutationAuthority:
    action: Literal["optimize", "work_cancel"]
    phase: Literal["enqueue", "request", "complete"]
    authority_grant_id: str
    policy_ref: str
    context_ref: str
    target_ref: str
    target_revision: int
    idempotency_key_digest: str
    request_digest: str
    session_nonce: str
    admitted_at: datetime


WorkMutationRevalidator = Callable[[V3Transaction], VerifiedGrant]


@dataclass(frozen=True, slots=True)
class ClaimConditions:
    inputs_valid: bool
    grants_valid: bool
    dependency_valid: bool
    budget_available: bool


@dataclass(frozen=True, slots=True)
class FinalizationConditions:
    dependency_valid: bool
    capability_valid: bool
    grant_valid: bool
    fixture_authority_valid: bool
    incumbent_valid: bool
    scope_revision_valid: bool
    budget_reconciled: bool


@dataclass(frozen=True, slots=True)
class RecoveryConditions:
    cleanup_confirmed: bool
    process_identity_verified: bool
    staging_cleanup_verified: bool
    attempts_allowed: bool
    grants_valid: bool
    dependency_valid: bool
    budget_available: bool


@dataclass(frozen=True, slots=True)
class WorkLease:
    work_id: str
    attempt_id: str
    owner_id: str
    fence_token: int
    process_nonce: str
    process_start_identity: str
    expires_at: str
    heartbeat_at: str


@dataclass(frozen=True, slots=True)
class LeaseIdentity:
    work_id: str
    attempt_id: str
    owner_id: str
    fence_token: int
    process_nonce: str
    process_start_identity: str


@dataclass(frozen=True, slots=True)
class PublicationWriteSet:
    """Complete immutable output from a pure publication planner."""

    records: tuple[TypedRecord, ...]
    events: tuple[DomainEvent, ...]


@dataclass(frozen=True, slots=True)
class BudgetLedger:
    ledger_id: str
    run_ref: str
    budget_profile_ref: str
    budget_profile_digest: str
    dimensions: Mapping[str, tuple[int, int, int, int]]


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    reservation_id: str
    ledger_id: str
    work_id: str
    attempt_id: str
    lease_owner_id: str
    fence_token: int
    amounts: Mapping[str, int]
    replayed: bool


def _text(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise SchemaValidationError(f"{name} must be a non-empty string")
    return value


def _count(value: object, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise SchemaValidationError(f"{name} must be an integer >= {minimum}")
    return value


def _utc(value: datetime, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise SchemaValidationError(f"{name} must be a timezone-aware datetime")
    converted = value.astimezone(timezone.utc)
    if converted.utcoffset() != timezone.utc.utcoffset(converted):  # pragma: no cover
        raise SchemaValidationError(f"{name} must be convertible to UTC")
    return converted


def _timestamp(value: datetime, name: str) -> str:
    return _utc(value, name).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _all_true(checks: object) -> bool:
    return all(
        type(value) is bool and value
        for value in (getattr(checks, field.name) for field in fields(checks))
    )


def _work_from_row(row: object) -> WorkItem:
    return WorkItem(**dict(row))  # type: ignore[arg-type]


def _lease_from_row(row: object) -> WorkLease:
    return WorkLease(**dict(row))  # type: ignore[arg-type]


def _load_work(transaction: V3Transaction, work_id: str) -> WorkItem:
    row = transaction._connection.execute(
        "SELECT * FROM work_items WHERE work_id = ?", (work_id,)
    ).fetchone()
    if row is None:
        raise WorkStateConflict("work item does not exist")
    return _work_from_row(row)


def _load_lease(transaction: V3Transaction, work_id: str) -> WorkLease:
    row = transaction._connection.execute(
        "SELECT * FROM work_leases WHERE work_id = ?", (work_id,)
    ).fetchone()
    if row is None:
        raise StaleFence("work lease does not exist")
    return _lease_from_row(row)


def _require_lease(lease: WorkLease, identity: LeaseIdentity) -> None:
    if (
        lease.work_id != identity.work_id
        or lease.attempt_id != identity.attempt_id
        or lease.owner_id != identity.owner_id
        or lease.fence_token != identity.fence_token
        or lease.process_nonce != identity.process_nonce
        or lease.process_start_identity != identity.process_start_identity
    ):
        raise StaleFence("attempt, owner, process identity, or fence does not match")


def _entry_id(reservation_id: str, dimension: str, kind: str) -> str:
    framed = f"a0-budget-entry-v3\0{reservation_id}\0{dimension}\0{kind}".encode()
    return f"budget-entry:{sha256(framed).hexdigest()}"


@dataclass(frozen=True, slots=True)
class _CommandReplay:
    receipt: TypedRecord
    command: OperatorCommand


def _ledger_action(authority: WorkMutationAuthority) -> str:
    return authority.action


def _validate_mutation_authority(
    authority: WorkMutationAuthority,
    *,
    action: str,
    phase: str,
    context_ref: str,
    target_ref: str,
    target_revision: int,
    idempotency_key_digest: str,
) -> None:
    if type(authority) is not WorkMutationAuthority:
        raise SchemaValidationError("work mutation authority is required")
    for value, name in (
        (authority.authority_grant_id, "authority_grant_id"),
        (authority.policy_ref, "policy_ref"),
        (authority.context_ref, "context_ref"),
        (authority.target_ref, "target_ref"),
        (authority.session_nonce, "session_nonce"),
    ):
        _text(value, name)
    validate_digest(authority.idempotency_key_digest, "idempotency_key_digest")
    validate_digest(authority.request_digest, "request_digest")
    _count(authority.target_revision, "target_revision")
    _timestamp(authority.admitted_at, "admitted_at")
    if (
        authority.action != action
        or authority.phase != phase
        or authority.context_ref != context_ref
        or authority.target_ref != target_ref
        or authority.target_revision != target_revision
        or authority.idempotency_key_digest != idempotency_key_digest
    ):
        raise AuthorityAdmissionDenied("work mutation authority binding does not match")


def _revalidate_mutation_authority(
    transaction: V3Transaction,
    authority: WorkMutationAuthority,
    revalidator: WorkMutationRevalidator,
) -> VerifiedGrant:
    try:
        grant = revalidator(transaction)
    except WorkAuthorityError:
        raise
    except Exception:
        raise
    if type(grant) is not VerifiedGrant:
        raise AuthorityAdmissionDenied("verified work authority grant is required")
    admitted_at = authority.admitted_at.astimezone(timezone.utc)
    if (
        grant.grant_id != authority.authority_grant_id
        or grant.authority_class != AuthorityClass.OPERATOR_AUTHORITY_GRANT.value
        or grant.context_ref != authority.context_ref
        or grant.action != authority.action
        or grant.purpose != AuthorityPurpose.OPERATOR_MUTATION.value
        or grant.target_ref != authority.target_ref
        or grant.target_revision != authority.target_revision
        or grant.idempotency_key_digest != authority.idempotency_key_digest
        or grant.session_nonce != authority.session_nonce
        or type(grant.issuer_id) is not str
        or not grant.issuer_id
        or type(grant.subject_ref) is not str
        or not grant.subject_ref
        or type(grant.key_epoch) is not int
        or grant.key_epoch < 0
        or grant.issued_at.tzinfo is None
        or grant.issued_at.utcoffset() is None
        or grant.expires_at.tzinfo is None
        or grant.expires_at.utcoffset() is None
        or grant.issued_at.astimezone(timezone.utc) > admitted_at
        or grant.expires_at.astimezone(timezone.utc) <= admitted_at
    ):
        raise AuthorityAdmissionDenied("verified grant does not match work mutation")
    return grant


def _load_command_replay(
    transaction: V3Transaction,
    authority: WorkMutationAuthority,
    grant: VerifiedGrant,
) -> _CommandReplay | None:
    command = transaction.get_operator_command(
        issuer_ref=grant.issuer_id,
        subject_ref=grant.subject_ref,
        context_ref=authority.context_ref,
        action=_ledger_action(authority),
        idempotency_key_digest=authority.idempotency_key_digest,
    )
    if command is None:
        return None
    if command.request_digest != authority.request_digest:
        raise IdempotencyConflict(
            "work command idempotency key was reused with a different request"
        )
    receipt = transaction.get_record(command.mutation_receipt_id)
    if receipt is None or receipt.schema_id != WORK_MUTATION_RECEIPT_SCHEMA_ID:
        raise IntegrityFailure("work command receipt is missing or has the wrong schema")
    payload = receipt.payload
    if (
        receipt.context_ref != authority.context_ref
        or payload["action"] != authority.action
        or payload["phase"] != authority.phase
        or payload["context_ref"] != authority.context_ref
        or payload["target_ref"] != authority.target_ref
        or payload["authority_grant_id"] != authority.authority_grant_id
        or payload["policy_ref"] != authority.policy_ref
        or payload["idempotency_key_digest"] != authority.idempotency_key_digest
        or payload["request_digest"] != authority.request_digest
        or payload["observed_revision"] != authority.target_revision
    ):
        raise IntegrityFailure("work command receipt does not match its command")
    return _CommandReplay(receipt, command)


def _record_work_mutation(
    transaction: V3Transaction,
    *,
    authority: WorkMutationAuthority,
    grant: VerifiedGrant,
    item: WorkItem,
    resulting_revision: int,
    reason_code: str,
    recorded_at: str,
) -> tuple[TypedRecord, OperatorCommand]:
    identity = (
        f"{grant.issuer_id}\0{grant.subject_ref}\0{authority.context_ref}\0"
        f"{_ledger_action(authority)}\0{authority.idempotency_key_digest}\0"
        f"{authority.request_digest}"
    ).encode()
    identity_digest = sha256(b"a0-work-mutation-v1\0" + identity).hexdigest()
    receipt = build_typed_record(
        record_id=f"work-mutation-receipt:{identity_digest}",
        context_ref=authority.context_ref,
        record_kind="operator_mutation_receipt",
        schema_id=WORK_MUTATION_RECEIPT_SCHEMA_ID,
        payload={
            "receipt_type": "work_mutation",
            "accepted": True,
            "action": authority.action,
            "phase": authority.phase,
            "context_ref": authority.context_ref,
            "target_ref": authority.target_ref,
            "authority_grant_id": authority.authority_grant_id,
            "policy_ref": authority.policy_ref,
            "idempotency_key_digest": authority.idempotency_key_digest,
            "request_digest": authority.request_digest,
            "observed_revision": authority.target_revision,
            "resulting_revision": resulting_revision,
            "work_state": item.state,
            "reason_code": reason_code,
            "recorded_at": recorded_at,
            "links": [],
        },
        key_epoch=f"operator-authority:{grant.key_epoch}",
        registry=WORK_AUTHORITY_REGISTRY,
    )
    transaction.insert_record(receipt)
    command = OperatorCommand(
        command_id=f"work-command:{identity_digest}",
        issuer_ref=grant.issuer_id,
        subject_ref=grant.subject_ref,
        context_ref=authority.context_ref,
        action=_ledger_action(authority),
        idempotency_key_digest=authority.idempotency_key_digest,
        request_digest=authority.request_digest,
        observed_revision=authority.target_revision,
        state="accepted",
        mutation_receipt_id=receipt.record_id,
    )
    admission = transaction.admit_command(command)
    return receipt, admission.command


class WorkCoordinator:
    """The sole writer for Work Item state, leases, and fenced publication."""

    def __init__(self, repository: V3Repository) -> None:
        self._repository = repository

    def get(self, work_id: str) -> WorkItem | None:
        row = self._repository._connection.execute(
            "SELECT * FROM work_items WHERE work_id = ?", (work_id,)
        ).fetchone()
        return None if row is None else _work_from_row(row)

    def get_lease(self, work_id: str) -> WorkLease | None:
        """Read one current lease without exposing repository internals."""

        _text(work_id, "work_id")
        row = self._repository._connection.execute(
            "SELECT * FROM work_leases WHERE work_id = ?", (work_id,)
        ).fetchone()
        return None if row is None else _lease_from_row(row)

    def enqueue(
        self,
        request: WorkEnqueue,
        *,
        authority: WorkMutationAuthority,
        authority_revalidator: WorkMutationRevalidator,
    ) -> WorkAdmission:
        for name in ("work_id", "context_ref", "operation_kind", "input_record_id"):
            _text(getattr(request, name), name)
        validate_digest(request.idempotency_key_digest, "idempotency_key_digest")
        validate_digest(request.input_digest, "input_digest")
        _count(request.max_attempts, "max_attempts", minimum=1)
        available = _timestamp(request.available_at, "available_at")
        deadline = _timestamp(request.deadline_at, "deadline_at")
        created = _timestamp(request.created_at, "created_at")
        if deadline <= available or deadline <= created:
            raise SchemaValidationError("deadline_at must be after availability and creation")
        if request.budget_ledger_id is not None:
            _text(request.budget_ledger_id, "budget_ledger_id")
        _validate_mutation_authority(
            authority,
            action="optimize",
            phase="enqueue",
            context_ref=request.context_ref,
            target_ref=request.work_id,
            target_revision=0,
            idempotency_key_digest=request.idempotency_key_digest,
        )
        if not callable(authority_revalidator):
            raise SchemaValidationError("authority_revalidator must be callable")

        with self._repository.transaction() as transaction:
            source = transaction.get_record(request.input_record_id)
            if source is None or source.content_digest != request.input_digest:
                raise IntegrityFailure("work input identity or digest mismatch")
            if request.budget_ledger_id is not None:
                ledger = transaction._connection.execute(
                    "SELECT 1 FROM budget_ledgers WHERE ledger_id = ?",
                    (request.budget_ledger_id,),
                ).fetchone()
                if ledger is None:
                    raise IntegrityFailure("work budget ledger does not exist")

            existing_work = transaction._connection.execute(
                """SELECT * FROM work_items
                   WHERE context_ref = ? AND operation_kind = ?
                     AND idempotency_key_digest = ?""",
                (
                    request.context_ref,
                    request.operation_kind,
                    request.idempotency_key_digest,
                ),
            ).fetchone()
            work_id_exists = transaction._connection.execute(
                "SELECT 1 FROM work_items WHERE work_id = ?", (request.work_id,)
            ).fetchone()
            grant = _revalidate_mutation_authority(
                transaction, authority, authority_revalidator
            )
            replay = _load_command_replay(transaction, authority, grant)
            if replay is not None:
                return WorkAdmission(
                    _load_work(transaction, request.work_id),
                    True,
                    replay.receipt,
                    replay.command,
                )
            if existing_work is not None:
                raise IdempotencyConflict(
                    "work idempotency identity exists without the admitted command"
                )
            if work_id_exists is not None:
                raise IdentityCollision("work identity was reused")
            transaction._connection.execute(
                """INSERT INTO work_items (
                     work_id, idempotency_key_digest, context_ref, operation_kind,
                     input_record_id, input_digest, budget_ledger_id, state,
                     current_attempt_id, attempt_count, max_attempts, available_at,
                     deadline_at, cancel_requested_at, recovery_required_at,
                     fence_token, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', NULL, 0, ?, ?, ?,
                             NULL, NULL, 0, ?, ?)""",
                (
                    request.work_id,
                    request.idempotency_key_digest,
                    request.context_ref,
                    request.operation_kind,
                    request.input_record_id,
                    request.input_digest,
                    request.budget_ledger_id,
                    request.max_attempts,
                    available,
                    deadline,
                    created,
                    created,
                ),
            )
            item = _load_work(transaction, request.work_id)
            receipt, command = _record_work_mutation(
                transaction,
                authority=authority,
                grant=grant,
                item=item,
                resulting_revision=0,
                reason_code="work_enqueued",
                recorded_at=created,
            )
            return WorkAdmission(item, False, receipt, command)

    def claim(
        self,
        *,
        work_id: str,
        attempt_id: str,
        owner_id: str,
        process_nonce: str,
        process_start_identity: str,
        now: datetime,
        expires_at: datetime,
        conditions: ClaimConditions,
    ) -> WorkLease:
        for name, value in (
            ("work_id", work_id),
            ("attempt_id", attempt_id),
            ("owner_id", owner_id),
            ("process_nonce", process_nonce),
            ("process_start_identity", process_start_identity),
        ):
            _text(value, name)
        if not _all_true(conditions):
            raise ConditionDenied("claim conditions are not all authoritative")
        now_text = _timestamp(now, "now")
        expiry = _timestamp(expires_at, "expires_at")
        if expiry <= now_text:
            raise SchemaValidationError("lease expiry must be after claim time")

        with self._repository.transaction() as transaction:
            item = _load_work(transaction, work_id)
            if item.state != "queued" or item.available_at > now_text:
                raise WorkStateConflict("work item is not eligible queued work")
            if item.deadline_at <= now_text:
                raise DeadlineExceeded("work deadline has passed")
            if item.attempt_count >= item.max_attempts:
                raise ConditionDenied("frozen attempt ceiling is exhausted")
            if transaction._connection.execute(
                "SELECT 1 FROM work_leases WHERE work_id = ? OR attempt_id = ?",
                (work_id, attempt_id),
            ).fetchone() is not None:
                raise WorkStateConflict("work or attempt already has a lease")
            fence = item.fence_token + 1
            transaction._connection.execute(
                """UPDATE work_items
                   SET state = 'leased', current_attempt_id = ?,
                       attempt_count = attempt_count + 1, fence_token = ?, updated_at = ?
                   WHERE work_id = ? AND state = 'queued' AND fence_token = ?""",
                (attempt_id, fence, now_text, work_id, item.fence_token),
            )
            transaction._connection.execute(
                """INSERT INTO work_leases (
                     work_id, attempt_id, owner_id, fence_token, process_nonce,
                     process_start_identity, expires_at, heartbeat_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    work_id,
                    attempt_id,
                    owner_id,
                    fence,
                    process_nonce,
                    process_start_identity,
                    expiry,
                    now_text,
                ),
            )
            return _load_lease(transaction, work_id)

    def heartbeat(
        self,
        *,
        identity: LeaseIdentity,
        now: datetime,
        new_expires_at: datetime,
    ) -> WorkLease:
        now_text = _timestamp(now, "now")
        expiry = _timestamp(new_expires_at, "new_expires_at")
        if expiry <= now_text:
            raise SchemaValidationError("renewed lease expiry must be after heartbeat")
        with self._repository.transaction() as transaction:
            item = _load_work(transaction, identity.work_id)
            lease = _load_lease(transaction, identity.work_id)
            _require_lease(lease, identity)
            if item.state != "leased" or item.fence_token != identity.fence_token:
                raise StaleFence("work item no longer admits this lease")
            if lease.expires_at <= now_text or item.deadline_at <= now_text:
                raise DeadlineExceeded("expired lease or work deadline cannot be renewed")
            if expiry <= lease.expires_at:
                raise SchemaValidationError("heartbeat must advance lease expiry")
            transaction._connection.execute(
                "UPDATE work_leases SET expires_at = ?, heartbeat_at = ? WHERE work_id = ?",
                (expiry, now_text, identity.work_id),
            )
            transaction._connection.execute(
                """INSERT INTO worker_heartbeats (
                     work_id, attempt_id, owner_id, fence_token, heartbeat_at
                   ) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(work_id) DO UPDATE SET
                     attempt_id = excluded.attempt_id,
                     owner_id = excluded.owner_id,
                     fence_token = excluded.fence_token,
                     heartbeat_at = excluded.heartbeat_at""",
                (
                    identity.work_id,
                    identity.attempt_id,
                    identity.owner_id,
                    identity.fence_token,
                    now_text,
                ),
            )
            return _load_lease(transaction, identity.work_id)

    def request_cancellation(
        self,
        *,
        work_id: str,
        expected_fence: int,
        now: datetime,
        authority: WorkMutationAuthority,
        authority_revalidator: WorkMutationRevalidator,
    ) -> WorkAdmission:
        _count(expected_fence, "expected_fence")
        now_text = _timestamp(now, "now")
        _validate_mutation_authority(
            authority,
            action="work_cancel",
            phase="request",
            context_ref=authority.context_ref,
            target_ref=work_id,
            target_revision=expected_fence,
            idempotency_key_digest=authority.idempotency_key_digest,
        )
        if not callable(authority_revalidator):
            raise SchemaValidationError("authority_revalidator must be callable")
        with self._repository.transaction() as transaction:
            item = _load_work(transaction, work_id)
            if item.context_ref != authority.context_ref:
                raise ConditionDenied("work cancellation context does not match")
            grant = _revalidate_mutation_authority(
                transaction, authority, authority_revalidator
            )
            replay = _load_command_replay(transaction, authority, grant)
            if replay is not None:
                return WorkAdmission(item, True, replay.receipt, replay.command)
            if item.state not in ("queued", "leased", "recovery_required"):
                raise WorkStateConflict("work item cannot accept cancellation")
            if item.fence_token != expected_fence:
                raise StaleFence("cancellation fence did not match")
            # Queued work has no process, lease, or staging state to clean up.
            # Advancing its fence and making it terminal in this transaction
            # avoids manufacturing a lease identity merely to cancel it.
            next_state = "cancelled" if item.state == "queued" else "cancel_requested"
            transaction._connection.execute(
                """UPDATE work_items
                   SET state = ?, cancel_requested_at = ?,
                       fence_token = fence_token + 1, updated_at = ?
                   WHERE work_id = ? AND fence_token = ?""",
                (next_state, now_text, now_text, work_id, expected_fence),
            )
            item = _load_work(transaction, work_id)
            receipt, command = _record_work_mutation(
                transaction,
                authority=authority,
                grant=grant,
                item=item,
                resulting_revision=item.fence_token,
                reason_code=(
                    "work_cancelled"
                    if item.state == "cancelled"
                    else "cancellation_requested"
                ),
                recorded_at=now_text,
            )
            return WorkAdmission(item, False, receipt, command)

    def complete_cancellation(
        self,
        *,
        expired_identity: LeaseIdentity,
        cancellation_fence: int,
        now: datetime,
        cleanup_confirmed: bool,
        process_identity_verified: bool,
        staging_cleanup_verified: bool,
        authority: WorkMutationAuthority,
        authority_revalidator: WorkMutationRevalidator,
    ) -> WorkAdmission:
        now_text = _timestamp(now, "now")
        _validate_mutation_authority(
            authority,
            action="work_cancel",
            phase="complete",
            context_ref=authority.context_ref,
            target_ref=expired_identity.work_id,
            target_revision=cancellation_fence,
            idempotency_key_digest=authority.idempotency_key_digest,
        )
        if not callable(authority_revalidator):
            raise SchemaValidationError("authority_revalidator must be callable")
        with self._repository.transaction() as transaction:
            item = _load_work(transaction, expired_identity.work_id)
            if item.context_ref != authority.context_ref:
                raise ConditionDenied("work cancellation context does not match")
            grant = _revalidate_mutation_authority(
                transaction, authority, authority_revalidator
            )
            replay = _load_command_replay(transaction, authority, grant)
            if replay is not None:
                return WorkAdmission(item, True, replay.receipt, replay.command)
            lease = _load_lease(transaction, expired_identity.work_id)
            _require_lease(lease, expired_identity)
            if item.state != "cancel_requested" or item.fence_token != cancellation_fence:
                raise StaleFence("cancellation marker or fence no longer matches")
            safe = (
                cleanup_confirmed is True
                and process_identity_verified is True
                and staging_cleanup_verified is True
            )
            terminal = "cancelled" if safe else "failed"
            transaction._connection.execute(
                "UPDATE work_items SET state = ?, updated_at = ? WHERE work_id = ?",
                (terminal, now_text, item.work_id),
            )
            if safe:
                transaction._connection.execute(
                    "DELETE FROM worker_heartbeats WHERE work_id = ?", (item.work_id,)
                )
                transaction._connection.execute(
                    "DELETE FROM work_leases WHERE work_id = ?", (item.work_id,)
                )
            item = _load_work(transaction, item.work_id)
            receipt, command = _record_work_mutation(
                transaction,
                authority=authority,
                grant=grant,
                item=item,
                resulting_revision=item.fence_token,
                reason_code=(
                    "work_cancelled"
                    if item.state == "cancelled"
                    else "cleanup_uncertain"
                ),
                recorded_at=now_text,
            )
            return WorkAdmission(item, False, receipt, command)

    def begin_expired_lease_recovery(
        self, *, identity: LeaseIdentity, now: datetime
    ) -> WorkItem:
        now_text = _timestamp(now, "now")
        with self._repository.transaction() as transaction:
            item = _load_work(transaction, identity.work_id)
            lease = _load_lease(transaction, identity.work_id)
            _require_lease(lease, identity)
            if item.state != "leased" or item.fence_token != identity.fence_token:
                raise StaleFence("lease is no longer the current fenced attempt")
            if lease.expires_at > now_text:
                raise WorkStateConflict("live lease cannot enter orphan recovery")
            transaction._connection.execute(
                """UPDATE work_items
                   SET state = 'recovery_required', recovery_required_at = ?,
                       fence_token = fence_token + 1, updated_at = ?
                   WHERE work_id = ? AND state = 'leased' AND fence_token = ?""",
                (now_text, now_text, item.work_id, identity.fence_token),
            )
            return _load_work(transaction, item.work_id)

    def complete_recovery(
        self,
        *,
        expired_identity: LeaseIdentity,
        recovery_fence: int,
        now: datetime,
        retry_available_at: datetime,
        conditions: RecoveryConditions,
    ) -> WorkItem:
        _count(recovery_fence, "recovery_fence", minimum=1)
        now_text = _timestamp(now, "now")
        available = _timestamp(retry_available_at, "retry_available_at")
        with self._repository.transaction() as transaction:
            item = _load_work(transaction, expired_identity.work_id)
            lease = _load_lease(transaction, expired_identity.work_id)
            _require_lease(lease, expired_identity)
            if item.state != "recovery_required" or item.fence_token != recovery_fence:
                raise StaleFence("recovery marker or advanced fence no longer matches")

            cleanup_safe = (
                conditions.cleanup_confirmed is True
                and conditions.process_identity_verified is True
                and conditions.staging_cleanup_verified is True
            )
            retry_safe = (
                cleanup_safe
                and conditions.attempts_allowed is True
                and conditions.grants_valid is True
                and conditions.dependency_valid is True
                and conditions.budget_available is True
                and item.attempt_count < item.max_attempts
                and item.deadline_at > now_text
            )
            if retry_safe:
                transaction._connection.execute(
                    """UPDATE work_items SET state = 'queued', current_attempt_id = NULL,
                       recovery_required_at = NULL, available_at = ?, updated_at = ?
                       WHERE work_id = ? AND fence_token = ?""",
                    (available, now_text, item.work_id, recovery_fence),
                )
            else:
                transaction._connection.execute(
                    "UPDATE work_items SET state = 'failed', updated_at = ? WHERE work_id = ?",
                    (now_text, item.work_id),
                )
            if cleanup_safe:
                transaction._connection.execute(
                    "DELETE FROM worker_heartbeats WHERE work_id = ?", (item.work_id,)
                )
                transaction._connection.execute(
                    "DELETE FROM work_leases WHERE work_id = ?", (item.work_id,)
                )
            return _load_work(transaction, item.work_id)

    def finalize(
        self,
        *,
        identity: LeaseIdentity,
        now: datetime,
        authority_revalidator: Callable[
            [V3Transaction, WorkItem, LeaseIdentity], FinalizationConditions
        ],
        publication_planner: Callable[[], PublicationWriteSet],
    ) -> WorkItem:
        """Plan without database access, then revalidate and publish atomically."""

        plan = publication_planner()
        if type(plan) is not PublicationWriteSet:
            raise SchemaValidationError("publication planner returned an invalid write set")
        now_text = _timestamp(now, "now")
        if not callable(authority_revalidator):
            raise SchemaValidationError("authority revalidator must be callable")

        with self._repository.transaction() as transaction:
            item = _load_work(transaction, identity.work_id)
            lease = _load_lease(transaction, identity.work_id)
            _require_lease(lease, identity)
            if (
                item.state != "leased"
                or item.current_attempt_id != identity.attempt_id
                or item.fence_token != identity.fence_token
            ):
                raise StaleFence("work item no longer admits fenced publication")
            if item.cancel_requested_at is not None:
                raise WorkStateConflict("cancelled work cannot publish")
            if lease.expires_at <= now_text or item.deadline_at <= now_text:
                raise DeadlineExceeded("lease or work deadline expired before publication")
            conditions = authority_revalidator(transaction, item, identity)
            if type(conditions) is not FinalizationConditions or not _all_true(conditions):
                raise ConditionDenied(
                    "transactional finalization authority was not fully revalidated"
                )
            if item.budget_ledger_id is not None:
                unsettled = transaction._connection.execute(
                    """SELECT 1 FROM budget_entries reserve
                       WHERE reserve.ledger_id = ? AND reserve.work_id = ?
                         AND reserve.attempt_id = ? AND reserve.fence_token = ?
                         AND reserve.entry_kind = 'reserve'
                         AND NOT EXISTS (
                           SELECT 1 FROM budget_entries terminal
                           WHERE terminal.reservation_id = reserve.reservation_id
                             AND terminal.dimension = reserve.dimension
                             AND terminal.entry_kind IN ('reconcile', 'unreconciled')
                         )
                       LIMIT 1""",
                    (
                        item.budget_ledger_id,
                        item.work_id,
                        identity.attempt_id,
                        identity.fence_token,
                    ),
                ).fetchone()
                unknown = transaction._connection.execute(
                    """SELECT 1 FROM budget_entries
                       WHERE ledger_id = ? AND work_id = ? AND attempt_id = ?
                         AND fence_token = ? AND entry_kind = 'unreconciled' LIMIT 1""",
                    (
                        item.budget_ledger_id,
                        item.work_id,
                        identity.attempt_id,
                        identity.fence_token,
                    ),
                ).fetchone()
                if unsettled is not None or unknown is not None:
                    raise ConditionDenied("attempt budget is not authoritatively reconciled")

            for record in plan.records:
                transaction.insert_record(record)
            for event in plan.events:
                transaction.append_event(event)
            transaction._connection.execute(
                """UPDATE work_items SET state = 'completed', updated_at = ?
                   WHERE work_id = ? AND state = 'leased' AND fence_token = ?""",
                (now_text, item.work_id, identity.fence_token),
            )
            transaction._connection.execute(
                "DELETE FROM worker_heartbeats WHERE work_id = ?", (item.work_id,)
            )
            transaction._connection.execute(
                "DELETE FROM work_leases WHERE work_id = ?", (item.work_id,)
            )
            return _load_work(transaction, item.work_id)


class BudgetBroker:
    """Cumulative reservation authority for every explicit integer dimension."""

    def __init__(self, repository: V3Repository) -> None:
        self._repository = repository

    def create_ledger(
        self,
        *,
        ledger_id: str,
        run_ref: str,
        budget_profile_ref: str,
        budget_profile_digest: str,
        dimensions: Mapping[str, int],
        created_at: datetime,
    ) -> BudgetLedger:
        for name, value in (
            ("ledger_id", ledger_id),
            ("run_ref", run_ref),
            ("budget_profile_ref", budget_profile_ref),
        ):
            _text(value, name)
        validate_digest(budget_profile_digest, "budget_profile_digest")
        created = _timestamp(created_at, "created_at")
        if type(dimensions) is not dict or not dimensions:
            raise SchemaValidationError("dimensions must be a non-empty mapping")
        limits: dict[str, int] = {}
        for dimension, limit in dimensions.items():
            limits[_text(dimension, "dimension")] = _count(limit, "limit_amount")

        with self._repository.transaction() as transaction:
            existing = transaction._connection.execute(
                "SELECT * FROM budget_ledgers WHERE ledger_id = ?", (ledger_id,)
            ).fetchone()
            if existing is not None:
                ledger = self._snapshot(transaction, ledger_id)
                if (
                    ledger.run_ref != run_ref
                    or ledger.budget_profile_ref != budget_profile_ref
                    or ledger.budget_profile_digest != budget_profile_digest
                    or {key: value[0] for key, value in ledger.dimensions.items()} != limits
                ):
                    raise BudgetConflict("budget ledger identity was reused")
                return ledger
            transaction._connection.execute(
                """INSERT INTO budget_ledgers (
                     ledger_id, run_ref, budget_profile_ref, budget_profile_digest, created_at
                   ) VALUES (?, ?, ?, ?, ?)""",
                (ledger_id, run_ref, budget_profile_ref, budget_profile_digest, created),
            )
            for dimension, limit in sorted(limits.items()):
                transaction._connection.execute(
                    """INSERT INTO budget_dimensions (
                         ledger_id, dimension, limit_amount,
                         reserved_amount, consumed_amount, unreconciled_amount
                       ) VALUES (?, ?, ?, 0, 0, 0)""",
                    (ledger_id, dimension, limit),
                )
            return self._snapshot(transaction, ledger_id)

    def snapshot(self, ledger_id: str) -> BudgetLedger:
        with self._repository.transaction() as transaction:
            return self._snapshot(transaction, ledger_id)

    def _snapshot(self, transaction: V3Transaction, ledger_id: str) -> BudgetLedger:
        row = transaction._connection.execute(
            "SELECT * FROM budget_ledgers WHERE ledger_id = ?", (ledger_id,)
        ).fetchone()
        if row is None:
            raise BudgetConflict("budget ledger does not exist")
        dimension_rows = transaction._connection.execute(
            """SELECT dimension, limit_amount, reserved_amount,
                      consumed_amount, unreconciled_amount
               FROM budget_dimensions WHERE ledger_id = ? ORDER BY dimension""",
            (ledger_id,),
        ).fetchall()
        return BudgetLedger(
            ledger_id=row["ledger_id"],
            run_ref=row["run_ref"],
            budget_profile_ref=row["budget_profile_ref"],
            budget_profile_digest=row["budget_profile_digest"],
            dimensions={
                item["dimension"]: (
                    item["limit_amount"],
                    item["reserved_amount"],
                    item["consumed_amount"],
                    item["unreconciled_amount"],
                )
                for item in dimension_rows
            },
        )

    def reserve(
        self,
        *,
        reservation_id: str,
        identity: LeaseIdentity,
        ledger_id: str,
        amounts: Mapping[str, int],
        created_at: datetime,
    ) -> BudgetReservation:
        _text(reservation_id, "reservation_id")
        created = _timestamp(created_at, "created_at")
        requested = self._validated_amounts(amounts, minimum=1)
        with self._repository.transaction() as transaction:
            lease = _load_lease(transaction, identity.work_id)
            _require_lease(lease, identity)
            item = _load_work(transaction, identity.work_id)
            if item.state != "leased" or item.fence_token != identity.fence_token:
                raise StaleFence("budget reservation lost its work fence")
            if item.budget_ledger_id != ledger_id:
                raise BudgetConflict("work item is not bound to this budget ledger")
            ledger = self._snapshot(transaction, ledger_id)
            if set(requested) != set(ledger.dimensions):
                raise BudgetConflict("reservation must cover every frozen budget dimension")

            existing = transaction._connection.execute(
                """SELECT dimension, amount, ledger_id, work_id, attempt_id,
                          lease_owner_id, fence_token
                   FROM budget_entries
                   WHERE reservation_id = ? AND entry_kind = 'reserve'
                   ORDER BY dimension""",
                (reservation_id,),
            ).fetchall()
            if existing:
                admitted = {row["dimension"]: row["amount"] for row in existing}
                exact = all(
                    row["ledger_id"] == ledger_id
                    and row["work_id"] == identity.work_id
                    and row["attempt_id"] == identity.attempt_id
                    and row["lease_owner_id"] == identity.owner_id
                    and row["fence_token"] == identity.fence_token
                    for row in existing
                )
                if admitted != requested or not exact:
                    raise IdempotencyConflict("reservation identity was reused")
                return BudgetReservation(
                    reservation_id,
                    ledger_id,
                    identity.work_id,
                    identity.attempt_id,
                    identity.owner_id,
                    identity.fence_token,
                    admitted,
                    True,
                )

            for dimension, amount in requested.items():
                limit, reserved, consumed, unreconciled = ledger.dimensions[dimension]
                if reserved + consumed + unreconciled + amount > limit:
                    raise BudgetExceeded(f"budget dimension {dimension!r} is exhausted")
            for dimension, amount in sorted(requested.items()):
                transaction._connection.execute(
                    """UPDATE budget_dimensions
                       SET reserved_amount = reserved_amount + ?
                       WHERE ledger_id = ? AND dimension = ?""",
                    (amount, ledger_id, dimension),
                )
                self._insert_entry(
                    transaction,
                    reservation_id=reservation_id,
                    ledger_id=ledger_id,
                    dimension=dimension,
                    kind="reserve",
                    amount=amount,
                    identity=identity,
                    created_at=created,
                )
            return BudgetReservation(
                reservation_id,
                ledger_id,
                identity.work_id,
                identity.attempt_id,
                identity.owner_id,
                identity.fence_token,
                requested,
                False,
            )

    def reconcile(
        self,
        *,
        reservation_id: str,
        identity: LeaseIdentity,
        actual_amounts: Mapping[str, int],
        created_at: datetime,
    ) -> BudgetLedger:
        actual = self._validated_amounts(actual_amounts, minimum=0)
        created = _timestamp(created_at, "created_at")
        with self._repository.transaction() as transaction:
            lease = _load_lease(transaction, identity.work_id)
            _require_lease(lease, identity)
            item = _load_work(transaction, identity.work_id)
            if item.state != "leased" or item.fence_token != identity.fence_token:
                raise StaleFence("budget reconciliation lost its work fence")
            rows = self._reservation_rows(transaction, reservation_id, identity)
            reserved = {row["dimension"]: row["amount"] for row in rows}
            if set(actual) != set(reserved):
                raise BudgetConflict("reconciliation must cover every reserved dimension")
            self._require_unsettled(transaction, reservation_id)
            ledger_id = rows[0]["ledger_id"]
            for dimension, amount in sorted(actual.items()):
                if amount > reserved[dimension]:
                    raise BudgetExceeded("actual use exceeds its pre-dispatch reservation")
                unused = reserved[dimension] - amount
                transaction._connection.execute(
                    """UPDATE budget_dimensions
                       SET reserved_amount = reserved_amount - ?,
                           consumed_amount = consumed_amount + ?
                       WHERE ledger_id = ? AND dimension = ?""",
                    (reserved[dimension], amount, ledger_id, dimension),
                )
                self._insert_entry(
                    transaction, reservation_id=reservation_id, ledger_id=ledger_id,
                    dimension=dimension, kind="reconcile", amount=amount,
                    identity=identity, created_at=created,
                )
                self._insert_entry(
                    transaction, reservation_id=reservation_id, ledger_id=ledger_id,
                    dimension=dimension, kind="release", amount=unused,
                    identity=identity, created_at=created,
                )
            return self._snapshot(transaction, ledger_id)

    def mark_unreconciled(
        self,
        *,
        reservation_id: str,
        expired_identity: LeaseIdentity,
        created_at: datetime,
    ) -> BudgetLedger:
        """Convert unknown crash usage into permanently blocking capacity."""

        created = _timestamp(created_at, "created_at")
        with self._repository.transaction() as transaction:
            lease = _load_lease(transaction, expired_identity.work_id)
            _require_lease(lease, expired_identity)
            if lease.expires_at > created:
                raise WorkStateConflict("live lease usage cannot be marked unreconciled")
            rows = self._reservation_rows(transaction, reservation_id, expired_identity)
            self._require_unsettled(transaction, reservation_id)
            ledger_id = rows[0]["ledger_id"]
            for row in rows:
                transaction._connection.execute(
                    """UPDATE budget_dimensions
                       SET reserved_amount = reserved_amount - ?,
                           unreconciled_amount = unreconciled_amount + ?
                       WHERE ledger_id = ? AND dimension = ?""",
                    (row["amount"], row["amount"], ledger_id, row["dimension"]),
                )
                self._insert_entry(
                    transaction, reservation_id=reservation_id, ledger_id=ledger_id,
                    dimension=row["dimension"], kind="unreconciled", amount=row["amount"],
                    identity=expired_identity, created_at=created,
                )
            return self._snapshot(transaction, ledger_id)

    @staticmethod
    def _validated_amounts(amounts: Mapping[str, int], *, minimum: int) -> dict[str, int]:
        if type(amounts) is not dict or not amounts:
            raise SchemaValidationError("amounts must be a non-empty mapping")
        return {
            _text(dimension, "dimension"): _count(amount, "amount", minimum=minimum)
            for dimension, amount in amounts.items()
        }

    @staticmethod
    def _reservation_rows(
        transaction: V3Transaction,
        reservation_id: str,
        identity: LeaseIdentity,
    ):
        rows = transaction._connection.execute(
            """SELECT * FROM budget_entries
               WHERE reservation_id = ? AND entry_kind = 'reserve'
               ORDER BY dimension""",
            (reservation_id,),
        ).fetchall()
        if not rows:
            raise BudgetConflict("budget reservation does not exist")
        if not all(
            row["work_id"] == identity.work_id
            and row["attempt_id"] == identity.attempt_id
            and row["lease_owner_id"] == identity.owner_id
            and row["fence_token"] == identity.fence_token
            for row in rows
        ):
            raise StaleFence("budget reservation is bound to another lease")
        return rows

    @staticmethod
    def _require_unsettled(transaction: V3Transaction, reservation_id: str) -> None:
        if transaction._connection.execute(
            """SELECT 1 FROM budget_entries
               WHERE reservation_id = ? AND entry_kind != 'reserve' LIMIT 1""",
            (reservation_id,),
        ).fetchone() is not None:
            raise BudgetConflict("budget reservation is already settled")

    @staticmethod
    def _insert_entry(
        transaction: V3Transaction,
        *,
        reservation_id: str,
        ledger_id: str,
        dimension: str,
        kind: str,
        amount: int,
        identity: LeaseIdentity,
        created_at: str,
    ) -> None:
        transaction._connection.execute(
            """INSERT INTO budget_entries (
                 entry_id, reservation_id, ledger_id, dimension, entry_kind, amount,
                 work_id, attempt_id, lease_owner_id, fence_token, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _entry_id(reservation_id, dimension, kind),
                reservation_id,
                ledger_id,
                dimension,
                kind,
                amount,
                identity.work_id,
                identity.attempt_id,
                identity.owner_id,
                identity.fence_token,
                created_at,
            ),
        )
