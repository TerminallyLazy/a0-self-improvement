"""Local-only, receipt-backed authority lifecycle for policy calibration.

Approval creates one immutable existing ``policy_calibration`` artifact under
an exactly rebound Policy Calibration Approval grant.  Withdrawal never edits
that artifact: it appends a typed mutation receipt and domain event.  Current
eligibility is a pure reduction of the immutable artifact and exact lifecycle
facts.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Any, Callable, Mapping, Sequence

from .authority import (
    AuthorityAction,
    AuthorityClass,
    AuthorityPurpose,
    VerifiedGrant,
)
from .canary import (
    ACTIVATION_POLICY_SCHEMA_ID,
    CANARY_PLAN_SCHEMA_ID,
    CANARY_REGISTRY,
    MONITOR_PLAN_SCHEMA_ID,
    POLICY_CALIBRATION_SCHEMA_ID,
    policy_calibration,
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


CALIBRATION_MUTATION_RECEIPT_SCHEMA_ID = "a0.policy-calibration-mutation-receipt.v1"
CALIBRATION_GRANT_TARGET_SCHEMA_ID = "a0.policy-calibration-grant-target.v1"

APPROVAL_REASON_CODES = ("calibration_approved",)
WITHDRAWAL_REASON_CODES = (
    "authority_withdrawn",
    "calibration_withdrawn",
    "environment_retired",
    "policy_superseded",
)
ALL_REASON_CODES = (*APPROVAL_REASON_CODES, *WITHDRAWAL_REASON_CODES)
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")


class CalibrationAuthorityError(RuntimeError):
    """Calibration mutation or lifecycle authority failed closed."""


@dataclass(frozen=True, slots=True)
class ExactRecord:
    record_id: str
    digest: str

    def __post_init__(self) -> None:
        _opaque(self.record_id, "record_id")
        try:
            validate_digest(self.digest, "digest")
        except SchemaValidationError as exc:
            raise CalibrationAuthorityError("exact record digest is invalid") from exc

    @classmethod
    def of(cls, record: TypedRecord) -> "ExactRecord":
        if type(record) is not TypedRecord:
            raise CalibrationAuthorityError("record identity requires a TypedRecord")
        return cls(record.record_id, record.content_digest)


@dataclass(frozen=True, slots=True)
class CalibrationApprovalRequest:
    calibration_id: str
    receipt_id: str
    context_ref: str
    expected_policy_revision: int
    environment_ref: str
    policy: ExactRecord
    canary_plan: ExactRecord
    monitor_plan: ExactRecord
    activation_authorities: tuple[str, ...]
    soft_rollback_authorized: bool
    issuer_ref: str
    subject_ref: str
    idempotency_key_digest: str
    session_nonce: str
    reason_code: str
    key_epoch: str


@dataclass(frozen=True, slots=True)
class CalibrationWithdrawalRequest:
    receipt_id: str
    context_ref: str
    expected_policy_revision: int
    environment_ref: str
    calibration: ExactRecord
    issuer_ref: str
    subject_ref: str
    idempotency_key_digest: str
    session_nonce: str
    reason_code: str
    key_epoch: str


@dataclass(frozen=True, slots=True)
class CalibrationGrantBinding:
    operation: str
    authority_class: str
    action: str
    purpose: str
    issuer_ref: str
    subject_ref: str
    context_ref: str
    target_ref: str
    target_revision: int
    idempotency_key_digest: str
    session_nonce: str
    environment_ref: str
    policy: ExactRecord
    canary_plan: ExactRecord
    monitor_plan: ExactRecord


GrantRevalidator = Callable[[CalibrationGrantBinding], VerifiedGrant]


@dataclass(frozen=True, slots=True)
class CalibrationLifecycleFact:
    receipt: TypedRecord
    event: DomainEvent


@dataclass(frozen=True, slots=True)
class CalibrationEligibility:
    state: str
    reason_codes: tuple[str, ...]
    calibration: ExactRecord


@dataclass(frozen=True, slots=True)
class CalibrationMutationResult:
    calibration: TypedRecord
    receipt: TypedRecord
    event: DomainEvent
    command: OperatorCommand
    replayed: bool


def _opaque(value: Any, name: str, *, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or _OPAQUE.fullmatch(value) is None
    ):
        raise CalibrationAuthorityError(f"{name} must be a bounded opaque reference")
    return value


def _exact_payload(value: ExactRecord) -> dict[str, str]:
    if type(value) is not ExactRecord:
        raise CalibrationAuthorityError("request contains a non-exact record identity")
    return {"record_id": value.record_id, "digest": value.digest}


def _link(role: str, ordinal: int, identity: ExactRecord) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": identity.record_id,
        "target_digest": identity.digest,
    }


_EXACT_VALIDATOR = strict_object(
    {"record_id": strict_string(maximum=512), "digest": validate_digest}
)


def _receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("policy_calibration_mutation_receipt"),
            "operation": strict_enum(("approve", "withdraw")),
            "calibration": _EXACT_VALIDATOR,
            "policy": _EXACT_VALIDATOR,
            "policy_revision": strict_integer(minimum=1),
            "environment_ref": strict_string(maximum=128),
            "canary_plan": _EXACT_VALIDATOR,
            "monitor_plan": _EXACT_VALIDATOR,
            "activation_authorities": strict_list(
                strict_enum(("automatic", "manual")), minimum=1, maximum=2
            ),
            "soft_rollback_authorized": strict_boolean(),
            "grant_id": strict_string(maximum=512),
            "issuer_ref": strict_string(maximum=512),
            "subject_ref": strict_string(maximum=512),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "reason_code": strict_enum(ALL_REASON_CODES),
            "event_sequence": strict_integer(minimum=0),
            "prior_receipt": strict_nullable(_EXACT_VALIDATOR),
            "links": validate_links,
        }
    )(value, path)
    if payload["activation_authorities"] != sorted(set(payload["activation_authorities"])):
        raise SchemaValidationError(f"{path}.activation_authorities must be sorted and unique")
    operation = payload["operation"]
    if operation == "approve":
        if (
            payload["reason_code"] not in APPROVAL_REASON_CODES
            or payload["event_sequence"] != 0
            or payload["prior_receipt"] is not None
        ):
            raise SchemaValidationError(f"{path} has an invalid approval lifecycle shape")
    elif (
        payload["reason_code"] not in WITHDRAWAL_REASON_CODES
        or payload["event_sequence"] < 1
        or payload["prior_receipt"] is None
    ):
        raise SchemaValidationError(f"{path} has an invalid withdrawal lifecycle shape")
    expected = [
        _link_from_payload("calibration", 0, payload["calibration"]),
        _link_from_payload("activation_policy", 0, payload["policy"]),
        _link_from_payload("canary_plan", 0, payload["canary_plan"]),
        _link_from_payload("monitor_plan", 0, payload["monitor_plan"]),
    ]
    if payload["prior_receipt"] is not None:
        expected.append(_link_from_payload("prior_receipt", 0, payload["prior_receipt"]))
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind exact calibration authority")
    return payload


def _link_from_payload(role: str, ordinal: int, value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": value["record_id"],
        "target_digest": value["digest"],
    }


_CALIBRATION_ONLY_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            CALIBRATION_MUTATION_RECEIPT_SCHEMA_ID,
            "policy_calibration_mutation_receipt",
            _receipt_validator,
        ),
    )
)
CALIBRATION_AUTHORITY_REGISTRY = merge_schema_registries(
    CANARY_REGISTRY, _CALIBRATION_ONLY_REGISTRY
)


def _record(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    payload: Mapping[str, Any],
) -> TypedRecord:
    return build_typed_record(
        record_id=_opaque(record_id, "receipt_id"),
        context_ref=_opaque(context_ref, "context_ref"),
        record_kind="policy_calibration_mutation_receipt",
        schema_id=CALIBRATION_MUTATION_RECEIPT_SCHEMA_ID,
        payload=payload,
        key_epoch=_opaque(key_epoch, "key_epoch", maximum=128),
        registry=CALIBRATION_AUTHORITY_REGISTRY,
    )


def _target_ref(
    *,
    operation: str,
    context_ref: str,
    environment_ref: str,
    policy: ExactRecord,
    policy_revision: int,
    canary_plan: ExactRecord,
    monitor_plan: ExactRecord,
    activation_authorities: tuple[str, ...],
    soft_rollback_authorized: bool,
    calibration_record_id: str,
    calibration: ExactRecord | None,
) -> str:
    target = {
        "operation": operation,
        "context_ref": context_ref,
        "environment_ref": environment_ref,
        "policy": _exact_payload(policy),
        "policy_revision": policy_revision,
        "canary_plan": _exact_payload(canary_plan),
        "monitor_plan": _exact_payload(monitor_plan),
        "activation_authorities": list(activation_authorities),
        "soft_rollback_authorized": soft_rollback_authorized,
        "calibration_record_id": _opaque(calibration_record_id, "calibration_record_id"),
        "calibration": _exact_payload(calibration) if calibration is not None else None,
    }
    digest = schema_digest(
        "authority-target", CALIBRATION_GRANT_TARGET_SCHEMA_ID, canonical_json(target)
    )
    return f"calibration-target:{digest}"


def _request_digest(payload: Mapping[str, Any]) -> str:
    return schema_digest(
        "operator-request", CALIBRATION_MUTATION_RECEIPT_SCHEMA_ID, canonical_json(payload)
    )


def _command_id(operation: str, request_digest: str) -> str:
    return f"policy-calibration-command:{operation}:{request_digest}"


def _event_id(operation: str, request_digest: str) -> str:
    return f"policy-calibration-event:{operation}:{request_digest}"


def _require_exact(
    transaction: V3Transaction,
    identity: ExactRecord,
    *,
    record_kind: str,
    schema_id: str,
    context_ref: str,
) -> TypedRecord:
    record = transaction.get_record(identity.record_id)
    if (
        record is None
        or record.content_digest != identity.digest
        or record.record_kind != record_kind
        or record.schema_id != schema_id
        or record.context_ref != context_ref
    ):
        raise IntegrityFailure(f"missing, cross-context, or tampered {record_kind}")
    return record


def _verified_grant(
    binding: CalibrationGrantBinding,
    callback: GrantRevalidator,
) -> VerifiedGrant:
    if not callable(callback):
        raise CalibrationAuthorityError("grant revalidator must be injected")
    grant = callback(binding)
    if type(grant) is not VerifiedGrant:
        raise CalibrationAuthorityError("grant revalidator returned no VerifiedGrant")
    expected = {
        "authority_class": AuthorityClass.POLICY_CALIBRATION_APPROVAL.value,
        "issuer_id": binding.issuer_ref,
        "subject_ref": binding.subject_ref,
        "context_ref": binding.context_ref,
        "action": AuthorityAction.POLICY_CALIBRATE.value,
        "purpose": AuthorityPurpose.POLICY_CALIBRATION.value,
        "target_ref": binding.target_ref,
        "target_revision": binding.target_revision,
        "idempotency_key_digest": binding.idempotency_key_digest,
        "session_nonce": binding.session_nonce,
    }
    if any(getattr(grant, name) != value for name, value in expected.items()):
        raise CalibrationAuthorityError("VerifiedGrant does not match exact calibration binding")
    return grant


def _existing_command(
    transaction: V3Transaction,
    *,
    issuer_ref: str,
    subject_ref: str,
    context_ref: str,
    idempotency_key_digest: str,
    request_digest: str,
) -> OperatorCommand | None:
    command = transaction.get_operator_command(
        issuer_ref=issuer_ref,
        subject_ref=subject_ref,
        context_ref=context_ref,
        action=AuthorityAction.POLICY_CALIBRATE.value,
        idempotency_key_digest=idempotency_key_digest,
    )
    if command is not None and command.request_digest != request_digest:
        raise IdempotencyConflict("idempotency key was reused with a different request")
    return command


def _lifecycle_facts(
    transaction: V3Transaction, calibration: TypedRecord
) -> tuple[CalibrationLifecycleFact, ...]:
    rows = transaction._connection.execute(
        """SELECT event_id, subject_id, subject_kind, sequence, event_type,
                  payload_record_id, actor_authority_ref, fence_token
           FROM domain_events
           WHERE subject_id = ? AND subject_kind = 'policy_calibration'
           ORDER BY sequence""",
        (calibration.record_id,),
    ).fetchall()
    facts: list[CalibrationLifecycleFact] = []
    for row in rows:
        event = DomainEvent(**dict(row))
        receipt = (
            transaction.get_record(event.payload_record_id)
            if event.payload_record_id is not None
            else None
        )
        if receipt is None:
            raise IntegrityFailure("calibration lifecycle event lost its receipt")
        facts.append(CalibrationLifecycleFact(receipt, event))
    return tuple(facts)


def _replayed_result(
    transaction: V3Transaction, command: OperatorCommand
) -> CalibrationMutationResult:
    receipt = transaction.get_record(command.mutation_receipt_id)
    if receipt is None or receipt.schema_id != CALIBRATION_MUTATION_RECEIPT_SCHEMA_ID:
        raise IntegrityFailure("calibration command lost its exact receipt")
    calibration_id = receipt.payload["calibration"]["record_id"]
    calibration = transaction.get_record(calibration_id)
    if calibration is None or calibration.content_digest != receipt.payload["calibration"]["digest"]:
        raise IntegrityFailure("calibration command lost its exact artifact")
    facts = _lifecycle_facts(transaction, calibration)
    matching = tuple(item for item in facts if item.receipt.record_id == receipt.record_id)
    if len(matching) != 1:
        raise IntegrityFailure("calibration command lost its exact lifecycle event")
    return CalibrationMutationResult(
        calibration, receipt, matching[0].event, command, True
    )


def approve_policy_calibration(
    repository: V3Repository,
    *,
    request: CalibrationApprovalRequest,
    revalidate_grant: GrantRevalidator,
) -> CalibrationMutationResult:
    """Atomically approve one exact policy/plan/environment calibration."""

    if type(repository) is not V3Repository or type(request) is not CalibrationApprovalRequest:
        raise CalibrationAuthorityError("approval requires exact repository and request inputs")
    if request.reason_code not in APPROVAL_REASON_CODES:
        raise CalibrationAuthorityError("approval reason code is not admitted")
    _validate_common_request(request)
    if request.activation_authorities != tuple(sorted(set(request.activation_authorities))):
        raise CalibrationAuthorityError("activation authorities must be sorted and unique")
    if not request.activation_authorities or any(
        item not in ("automatic", "manual") for item in request.activation_authorities
    ):
        raise CalibrationAuthorityError("activation authorities are not admitted")
    request_values = {
        "operation": "approve",
        "calibration_id": request.calibration_id,
        "receipt_id": request.receipt_id,
        "context_ref": request.context_ref,
        "expected_policy_revision": request.expected_policy_revision,
        "environment_ref": request.environment_ref,
        "policy": _exact_payload(request.policy),
        "canary_plan": _exact_payload(request.canary_plan),
        "monitor_plan": _exact_payload(request.monitor_plan),
        "activation_authorities": list(request.activation_authorities),
        "soft_rollback_authorized": request.soft_rollback_authorized,
        "issuer_ref": request.issuer_ref,
        "subject_ref": request.subject_ref,
        "idempotency_key_digest": request.idempotency_key_digest,
        "session_nonce": request.session_nonce,
        "reason_code": request.reason_code,
        "key_epoch": request.key_epoch,
    }
    digest = _request_digest(request_values)
    with repository.transaction() as transaction:
        existing = _existing_command(
            transaction,
            issuer_ref=request.issuer_ref,
            subject_ref=request.subject_ref,
            context_ref=request.context_ref,
            idempotency_key_digest=request.idempotency_key_digest,
            request_digest=digest,
        )
        if existing is not None:
            binding = _approval_binding(request)
            _verified_grant(binding, revalidate_grant)
            return _replayed_result(transaction, existing)
        policy = _require_exact(
            transaction,
            request.policy,
            record_kind="activation_policy",
            schema_id=ACTIVATION_POLICY_SCHEMA_ID,
            context_ref=request.context_ref,
        )
        canary = _require_exact(
            transaction,
            request.canary_plan,
            record_kind="canary_plan",
            schema_id=CANARY_PLAN_SCHEMA_ID,
            context_ref=request.context_ref,
        )
        monitor = _require_exact(
            transaction,
            request.monitor_plan,
            record_kind="monitor_plan",
            schema_id=MONITOR_PLAN_SCHEMA_ID,
            context_ref=request.context_ref,
        )
        if policy.payload["policy_revision"] != request.expected_policy_revision:
            raise IntegrityFailure("policy revision does not match calibration request")
        grant = _verified_grant(_approval_binding(request), revalidate_grant)
        calibration = policy_calibration(
            record_id=request.calibration_id,
            context_ref=request.context_ref,
            status="approved",
            environment_ref=request.environment_ref,
            policy=policy,
            canary_plan_record=canary,
            monitor_plan_record=monitor,
            activation_authorities=request.activation_authorities,
            soft_rollback_authorized=request.soft_rollback_authorized,
            key_epoch=request.key_epoch,
        )
        transaction.insert_record(calibration)
        receipt = _build_receipt(
            request=request,
            operation="approve",
            request_digest=digest,
            grant=grant,
            calibration=calibration,
            policy=policy,
            canary=canary,
            monitor=monitor,
            prior_receipt=None,
            event_sequence=0,
        )
        transaction.insert_record(receipt)
        event = transaction.append_event(
            DomainEvent(
                event_id=_event_id("approve", digest),
                subject_id=calibration.record_id,
                subject_kind="policy_calibration",
                sequence=0,
                event_type="policy_calibration_approved",
                payload_record_id=receipt.record_id,
                actor_authority_ref=grant.grant_id,
            )
        )
        command = OperatorCommand(
            command_id=_command_id("approve", digest),
            issuer_ref=request.issuer_ref,
            subject_ref=request.subject_ref,
            context_ref=request.context_ref,
            action=AuthorityAction.POLICY_CALIBRATE.value,
            idempotency_key_digest=request.idempotency_key_digest,
            request_digest=digest,
            observed_revision=request.expected_policy_revision,
            state="accepted",
            mutation_receipt_id=receipt.record_id,
        )
        admission = transaction.admit_command(command)
        return CalibrationMutationResult(
            calibration, receipt, event, admission.command, admission.replayed
        )


def withdraw_policy_calibration(
    repository: V3Repository,
    *,
    request: CalibrationWithdrawalRequest,
    revalidate_grant: GrantRevalidator,
) -> CalibrationMutationResult:
    """Append withdrawal authority without changing the approved artifact."""

    if type(repository) is not V3Repository or type(request) is not CalibrationWithdrawalRequest:
        raise CalibrationAuthorityError("withdrawal requires exact repository and request inputs")
    if request.reason_code not in WITHDRAWAL_REASON_CODES:
        raise CalibrationAuthorityError("withdrawal reason code is not admitted")
    _validate_common_request(request)
    request_values = {
        "operation": "withdraw",
        "receipt_id": request.receipt_id,
        "context_ref": request.context_ref,
        "expected_policy_revision": request.expected_policy_revision,
        "environment_ref": request.environment_ref,
        "calibration": _exact_payload(request.calibration),
        "issuer_ref": request.issuer_ref,
        "subject_ref": request.subject_ref,
        "idempotency_key_digest": request.idempotency_key_digest,
        "session_nonce": request.session_nonce,
        "reason_code": request.reason_code,
        "key_epoch": request.key_epoch,
    }
    digest = _request_digest(request_values)
    with repository.transaction() as transaction:
        existing = _existing_command(
            transaction,
            issuer_ref=request.issuer_ref,
            subject_ref=request.subject_ref,
            context_ref=request.context_ref,
            idempotency_key_digest=request.idempotency_key_digest,
            request_digest=digest,
        )
        if existing is not None:
            calibration = _require_exact(
                transaction,
                request.calibration,
                record_kind="policy_calibration",
                schema_id=POLICY_CALIBRATION_SCHEMA_ID,
                context_ref=request.context_ref,
            )
            binding = _withdrawal_binding(request, calibration)
            _verified_grant(binding, revalidate_grant)
            return _replayed_result(transaction, existing)
        calibration = _require_exact(
            transaction,
            request.calibration,
            record_kind="policy_calibration",
            schema_id=POLICY_CALIBRATION_SCHEMA_ID,
            context_ref=request.context_ref,
        )
        payload = calibration.payload
        if (
            payload["status"] != "approved"
            or payload["policy_revision"] != request.expected_policy_revision
            or payload["environment_ref"] != request.environment_ref
        ):
            raise IntegrityFailure("withdrawal does not bind the exact approved calibration")
        facts = _lifecycle_facts(transaction, calibration)
        eligibility = reduce_calibration_eligibility(calibration, facts)
        if eligibility.state != "approved":
            raise CalibrationAuthorityError("calibration is not currently eligible to withdraw")
        approval_receipt = facts[0].receipt
        grant = _verified_grant(_withdrawal_binding(request, calibration), revalidate_grant)
        policy = _require_exact(
            transaction,
            ExactRecord(payload["policy_id"], payload["policy_digest"]),
            record_kind="activation_policy",
            schema_id=ACTIVATION_POLICY_SCHEMA_ID,
            context_ref=request.context_ref,
        )
        canary = _require_exact(
            transaction,
            ExactRecord(payload["canary_plan_id"], payload["canary_plan_digest"]),
            record_kind="canary_plan",
            schema_id=CANARY_PLAN_SCHEMA_ID,
            context_ref=request.context_ref,
        )
        monitor = _require_exact(
            transaction,
            ExactRecord(payload["monitor_plan_id"], payload["monitor_plan_digest"]),
            record_kind="monitor_plan",
            schema_id=MONITOR_PLAN_SCHEMA_ID,
            context_ref=request.context_ref,
        )
        sequence = transaction.next_domain_event_sequence(calibration.record_id)
        receipt = _build_receipt(
            request=request,
            operation="withdraw",
            request_digest=digest,
            grant=grant,
            calibration=calibration,
            policy=policy,
            canary=canary,
            monitor=monitor,
            prior_receipt=approval_receipt,
            event_sequence=sequence,
        )
        transaction.insert_record(receipt)
        event = transaction.append_event(
            DomainEvent(
                event_id=_event_id("withdraw", digest),
                subject_id=calibration.record_id,
                subject_kind="policy_calibration",
                sequence=sequence,
                event_type="policy_calibration_withdrawn",
                payload_record_id=receipt.record_id,
                actor_authority_ref=grant.grant_id,
            )
        )
        command = OperatorCommand(
            command_id=_command_id("withdraw", digest),
            issuer_ref=request.issuer_ref,
            subject_ref=request.subject_ref,
            context_ref=request.context_ref,
            action=AuthorityAction.POLICY_CALIBRATE.value,
            idempotency_key_digest=request.idempotency_key_digest,
            request_digest=digest,
            observed_revision=request.expected_policy_revision,
            state="accepted",
            mutation_receipt_id=receipt.record_id,
        )
        admission = transaction.admit_command(command)
        return CalibrationMutationResult(
            calibration, receipt, event, admission.command, admission.replayed
        )


def reduce_calibration_eligibility(
    calibration: TypedRecord,
    facts: Sequence[CalibrationLifecycleFact],
) -> CalibrationEligibility:
    """Purely reduce immutable lifecycle facts; never mutate the calibration."""

    calibration.verify(CALIBRATION_AUTHORITY_REGISTRY)
    if (
        calibration.schema_id != POLICY_CALIBRATION_SCHEMA_ID
        or calibration.payload["status"] != "approved"
    ):
        raise CalibrationAuthorityError("eligibility requires an immutable approved calibration")
    values = tuple(facts)
    if not values or any(type(item) is not CalibrationLifecycleFact for item in values):
        raise CalibrationAuthorityError("calibration lifecycle facts are incomplete")
    expected_sequence = 0
    operations: list[str] = []
    prior_receipt: TypedRecord | None = None
    for fact in values:
        fact.receipt.verify(CALIBRATION_AUTHORITY_REGISTRY)
        payload = fact.receipt.payload
        event = fact.event
        if (
            fact.receipt.schema_id != CALIBRATION_MUTATION_RECEIPT_SCHEMA_ID
            or payload["calibration"]
            != {"record_id": calibration.record_id, "digest": calibration.content_digest}
            or event.subject_id != calibration.record_id
            or event.subject_kind != "policy_calibration"
            or event.sequence != expected_sequence
            or event.payload_record_id != fact.receipt.record_id
            or event.actor_authority_ref != payload["grant_id"]
            or event.event_type != f"policy_calibration_{'approved' if payload['operation'] == 'approve' else 'withdrawn'}"
        ):
            raise CalibrationAuthorityError("calibration lifecycle fact binding is invalid")
        if payload["operation"] == "approve":
            if expected_sequence != 0 or prior_receipt is not None:
                raise CalibrationAuthorityError("calibration approval must be the first fact")
        else:
            if prior_receipt is None or payload["prior_receipt"] != {
                "record_id": prior_receipt.record_id,
                "digest": prior_receipt.content_digest,
            }:
                raise CalibrationAuthorityError("withdrawal lost its approval ancestry")
        operations.append(payload["operation"])
        prior_receipt = fact.receipt
        expected_sequence += 1
    if operations == ["approve"]:
        return CalibrationEligibility(
            "approved", ("calibration_current",), ExactRecord.of(calibration)
        )
    if operations == ["approve", "withdraw"]:
        return CalibrationEligibility(
            "withdrawn", ("calibration_withdrawn",), ExactRecord.of(calibration)
        )
    raise CalibrationAuthorityError("calibration lifecycle has unsupported transitions")


def _validate_common_request(request: Any) -> None:
    for name in (
        "receipt_id",
        "context_ref",
        "environment_ref",
        "issuer_ref",
        "subject_ref",
        "session_nonce",
        "key_epoch",
    ):
        _opaque(getattr(request, name), name, maximum=128 if name in ("environment_ref", "key_epoch") else 512)
    if hasattr(request, "calibration_id"):
        _opaque(request.calibration_id, "calibration_id")
    if type(request.expected_policy_revision) is not int or request.expected_policy_revision < 1:
        raise CalibrationAuthorityError("expected_policy_revision must be a positive integer")
    if type(getattr(request, "soft_rollback_authorized", False)) is not bool:
        raise CalibrationAuthorityError("soft_rollback_authorized must be explicit")
    try:
        validate_digest(request.idempotency_key_digest, "idempotency_key_digest")
    except SchemaValidationError as exc:
        raise CalibrationAuthorityError("idempotency key digest is invalid") from exc


def _approval_binding(request: CalibrationApprovalRequest) -> CalibrationGrantBinding:
    target = _target_ref(
        operation="approve",
        context_ref=request.context_ref,
        environment_ref=request.environment_ref,
        policy=request.policy,
        policy_revision=request.expected_policy_revision,
        canary_plan=request.canary_plan,
        monitor_plan=request.monitor_plan,
        activation_authorities=request.activation_authorities,
        soft_rollback_authorized=request.soft_rollback_authorized,
        calibration_record_id=request.calibration_id,
        calibration=None,
    )
    return CalibrationGrantBinding(
        "approve",
        AuthorityClass.POLICY_CALIBRATION_APPROVAL.value,
        AuthorityAction.POLICY_CALIBRATE.value,
        AuthorityPurpose.POLICY_CALIBRATION.value,
        request.issuer_ref,
        request.subject_ref,
        request.context_ref,
        target,
        request.expected_policy_revision,
        request.idempotency_key_digest,
        request.session_nonce,
        request.environment_ref,
        request.policy,
        request.canary_plan,
        request.monitor_plan,
    )


def _withdrawal_binding(
    request: CalibrationWithdrawalRequest, calibration: TypedRecord
) -> CalibrationGrantBinding:
    payload = calibration.payload
    policy = ExactRecord(payload["policy_id"], payload["policy_digest"])
    canary = ExactRecord(payload["canary_plan_id"], payload["canary_plan_digest"])
    monitor = ExactRecord(payload["monitor_plan_id"], payload["monitor_plan_digest"])
    target = _target_ref(
        operation="withdraw",
        context_ref=request.context_ref,
        environment_ref=request.environment_ref,
        policy=policy,
        policy_revision=request.expected_policy_revision,
        canary_plan=canary,
        monitor_plan=monitor,
        activation_authorities=tuple(payload["activation_authorities"]),
        soft_rollback_authorized=payload["soft_rollback_authorized"],
        calibration_record_id=request.calibration.record_id,
        calibration=request.calibration,
    )
    return CalibrationGrantBinding(
        "withdraw",
        AuthorityClass.POLICY_CALIBRATION_APPROVAL.value,
        AuthorityAction.POLICY_CALIBRATE.value,
        AuthorityPurpose.POLICY_CALIBRATION.value,
        request.issuer_ref,
        request.subject_ref,
        request.context_ref,
        target,
        request.expected_policy_revision,
        request.idempotency_key_digest,
        request.session_nonce,
        request.environment_ref,
        policy,
        canary,
        monitor,
    )


def _build_receipt(
    *,
    request: CalibrationApprovalRequest | CalibrationWithdrawalRequest,
    operation: str,
    request_digest: str,
    grant: VerifiedGrant,
    calibration: TypedRecord,
    policy: TypedRecord,
    canary: TypedRecord,
    monitor: TypedRecord,
    prior_receipt: TypedRecord | None,
    event_sequence: int,
) -> TypedRecord:
    calibration_identity = ExactRecord.of(calibration)
    policy_identity = ExactRecord.of(policy)
    canary_identity = ExactRecord.of(canary)
    monitor_identity = ExactRecord.of(monitor)
    links = [
        _link("calibration", 0, calibration_identity),
        _link("activation_policy", 0, policy_identity),
        _link("canary_plan", 0, canary_identity),
        _link("monitor_plan", 0, monitor_identity),
    ]
    if prior_receipt is not None:
        links.append(_link("prior_receipt", 0, ExactRecord.of(prior_receipt)))
    calibration_payload = calibration.payload
    payload = {
        "record_type": "policy_calibration_mutation_receipt",
        "operation": operation,
        "calibration": _exact_payload(calibration_identity),
        "policy": _exact_payload(policy_identity),
        "policy_revision": calibration_payload["policy_revision"],
        "environment_ref": calibration_payload["environment_ref"],
        "canary_plan": _exact_payload(canary_identity),
        "monitor_plan": _exact_payload(monitor_identity),
        "activation_authorities": calibration_payload["activation_authorities"],
        "soft_rollback_authorized": calibration_payload["soft_rollback_authorized"],
        "grant_id": grant.grant_id,
        "issuer_ref": request.issuer_ref,
        "subject_ref": request.subject_ref,
        "idempotency_key_digest": request.idempotency_key_digest,
        "request_digest": request_digest,
        "reason_code": request.reason_code,
        "event_sequence": event_sequence,
        "prior_receipt": (
            _exact_payload(ExactRecord.of(prior_receipt))
            if prior_receipt is not None
            else None
        ),
        "links": links,
    }
    return _record(
        record_id=request.receipt_id,
        context_ref=request.context_ref,
        key_epoch=request.key_epoch,
        payload=payload,
    )


__all__ = [name for name in globals() if not name.startswith("_")]
