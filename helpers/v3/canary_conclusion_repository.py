"""Durable authority for externally reduced canary conclusions.

The certified outcome reducer owns every conclusion signal.  This module does
not inspect exposures or derive scores; it atomically revalidates the frozen
facts, asks the pure canary coordinator to materialize the conclusion, clears
the exact active slot, and persists the receipt, event, and admission identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Literal, Mapping

from .canary import (
    ACTIVATION_POLICY_SCHEMA_ID,
    CANARY_CONCLUSION_SCHEMA_ID,
    CANARY_PLAN_SCHEMA_ID,
    CANARY_REGISTRY,
    CANARY_TRIAL_SCHEMA_ID,
    POLICY_CALIBRATION_SCHEMA_ID,
    CanaryConclusionRequest,
    CanaryCoordinator,
)
from .canary_command_adapter import ExactRecord, SlotBinding
from .calibration_authority import (
    CALIBRATION_AUTHORITY_REGISTRY,
    CalibrationAuthorityError,
    CalibrationLifecycleFact,
    reduce_calibration_eligibility,
)
from .repository import (
    DomainEvent,
    IdempotencyConflict,
    IntegrityFailure,
    OperationSlot,
    OperatorCommand,
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
    schema_digest,
    strict_boolean,
    strict_enum,
    strict_integer,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


CANARY_CONCLUSION_RECEIPT_SCHEMA_ID = "a0.canary-conclusion-receipt.v1"
CANARY_CONCLUSION_AUTOMATION_TRIGGER_SCHEMA_ID = (
    "a0.canary-conclusion-automation-trigger.v1"
)
CERTIFIED_CANARY_OUTCOME_AUTHORITY_SCHEMA_ID = (
    "a0.certified-canary-outcome-authority.v1"
)
CANARY_CONCLUSION_ACTION = "canary_conclude"

_EXACT = strict_object(
    {
        "record_id": strict_string(maximum=512),
        "digest": validate_digest,
    }
)
_OPTIONAL_EXACT = strict_nullable(_EXACT)


def _receipt_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "receipt_type": strict_literal("canary_conclusion"),
            "accepted": strict_literal(True),
            "context_ref": strict_string(maximum=512),
            "conclusion": _EXACT,
            "trial": _EXACT,
            "canary_plan": _EXACT,
            "activation_policy": _EXACT,
            "policy_calibration": _OPTIONAL_EXACT,
            "certified_reducer_authority": _EXACT,
            "observed_scope_revision": strict_integer(minimum=0),
            "resulting_scope_revision": strict_integer(minimum=0),
            "observed_slot_revision": strict_integer(minimum=0),
            "resulting_slot_revision": strict_integer(minimum=1),
            "admission_kind": strict_enum(("operator", "automation")),
            "admission_ref": strict_string(maximum=512),
            "actor_authority_ref": strict_string(maximum=512),
            "issuer_ref": strict_string(maximum=512),
            "subject_ref": strict_string(maximum=512),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "canary_kind": strict_enum(("authoritative", "diagnostic")),
            "authority_ceiling": strict_enum(
                ("activation_authority", "no_promotion_authority")
            ),
            "conclusion_state": strict_enum(
                ("passed", "failed", "inconclusive", "stopped")
            ),
            "activation_authoritative": strict_boolean(),
            "event_sequence": strict_integer(minimum=0),
            "links": validate_links,
        }
    )(value, path)
    if (
        payload["resulting_scope_revision"] != payload["observed_scope_revision"]
        or payload["resulting_slot_revision"]
        != payload["observed_slot_revision"] + 1
    ):
        raise SchemaValidationError(f"{path} has a non-CAS conclusion transition")
    if (
        payload["canary_kind"] == "diagnostic"
        and payload["activation_authoritative"]
    ):
        raise SchemaValidationError(
            f"{path} gives a diagnostic canary activation authority"
        )
    expected = [
        _link("canary_conclusion", 0, payload["conclusion"]),
        _link("canary_trial", 0, payload["trial"]),
        _link("canary_plan", 0, payload["canary_plan"]),
        _link("activation_policy", 0, payload["activation_policy"]),
        _link(
            "certified_reducer_authority",
            0,
            payload["certified_reducer_authority"],
        ),
    ]
    if payload["policy_calibration"] is not None:
        expected.append(
            _link("policy_calibration", 0, payload["policy_calibration"])
        )
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind exact conclusion inputs")
    return payload


def _automation_trigger_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "trigger_type": strict_literal("canary_conclusion"),
            "action": strict_literal(CANARY_CONCLUSION_ACTION),
            "context_ref": strict_string(maximum=512),
            "authority_ref": strict_string(maximum=512),
            "issuer_ref": strict_string(maximum=512),
            "subject_ref": strict_string(maximum=512),
            "activation_policy": _EXACT,
            "policy_calibration": _EXACT,
            "mutation_receipt": _EXACT,
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("activation_policy", 0, payload["activation_policy"]),
        _link("policy_calibration", 0, payload["policy_calibration"]),
        _link("mutation_receipt", 0, payload["mutation_receipt"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind automation authority")
    return payload


def _certified_reducer_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "authority_type": strict_literal("certified_canary_outcome_authority"),
            "authority_ceiling": strict_literal("materialize_conclusion_request_only"),
            "producer": _EXACT,
            "reducer_profile": _EXACT,
            "canary_plan": _EXACT,
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("certified_producer", 0, payload["producer"]),
        _link("outcome_reducer_profile", 0, payload["reducer_profile"]),
        _link("canary_plan", 0, payload["canary_plan"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind reducer authority inputs")
    return payload


CANARY_CONCLUSION_REPOSITORY_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            CANARY_CONCLUSION_RECEIPT_SCHEMA_ID,
            "canary_conclusion_receipt",
            _receipt_payload,
        ),
        RecordSchema(
            CANARY_CONCLUSION_AUTOMATION_TRIGGER_SCHEMA_ID,
            "automation_trigger_receipt",
            _automation_trigger_payload,
        ),
        RecordSchema(
            CERTIFIED_CANARY_OUTCOME_AUTHORITY_SCHEMA_ID,
            "certified_canary_outcome_authority",
            _certified_reducer_payload,
        ),
    )
)


def build_certified_canary_outcome_authority(
    *,
    record_id: str,
    context_ref: str,
    producer: ExactRecord,
    reducer_profile: ExactRecord,
    canary_plan: ExactRecord,
    key_epoch: str,
) -> TypedRecord:
    """Bind a reducer-only authority to exact certified implementation facts."""

    exact_inputs = (producer, reducer_profile, canary_plan)
    if any(type(item) is not ExactRecord for item in exact_inputs):
        raise TypeError("certified reducer authority requires exact inputs")
    values = tuple(item.payload() for item in exact_inputs)
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="certified_canary_outcome_authority",
        schema_id=CERTIFIED_CANARY_OUTCOME_AUTHORITY_SCHEMA_ID,
        payload={
            "authority_type": "certified_canary_outcome_authority",
            "authority_ceiling": "materialize_conclusion_request_only",
            "producer": values[0],
            "reducer_profile": values[1],
            "canary_plan": values[2],
            "links": [
                _link("certified_producer", 0, values[0]),
                _link("outcome_reducer_profile", 0, values[1]),
                _link("canary_plan", 0, values[2]),
            ],
        },
        key_epoch=key_epoch,
        registry=CANARY_CONCLUSION_REPOSITORY_REGISTRY,
    )


@dataclass(frozen=True, slots=True)
class CanaryConclusionAuthority:
    admission_kind: Literal["operator", "automation"]
    actor_authority_ref: str
    issuer_ref: str
    subject_ref: str


@dataclass(frozen=True, slots=True)
class CanaryConclusionOperation:
    context_ref: str
    expected_scope_revision: int
    slot: SlotBinding
    request: CanaryConclusionRequest
    canary_plan: ExactRecord
    policy: ExactRecord
    calibration: ExactRecord | None
    certified_reducer_authority: ExactRecord
    authority: CanaryConclusionAuthority
    idempotency_key_digest: str
    request_digest: str
    key_epoch: str


CanaryConclusionAuthorityRevalidator = Callable[
    [V3Transaction, CanaryConclusionOperation], CanaryConclusionAuthority
]


@dataclass(frozen=True, slots=True)
class CanaryConclusionCommitResult:
    conclusion: TypedRecord
    receipt: TypedRecord
    slot: OperationSlot
    admission_ref: str
    replayed: bool


class RepositoryCanaryConclusionCoordinator:
    def __init__(self, repository: V3Repository, *, key_epoch: str) -> None:
        if not isinstance(repository, V3Repository):
            raise TypeError("canary conclusion coordination requires a V3Repository")
        if type(key_epoch) is not str or not key_epoch:
            raise TypeError("canary conclusion coordination requires a key epoch")
        self._repository = repository
        self._key_epoch = key_epoch
        self._planner = CanaryCoordinator(key_epoch=key_epoch)

    def commit(
        self,
        operation: CanaryConclusionOperation,
        *,
        revalidate_authority: CanaryConclusionAuthorityRevalidator,
    ) -> CanaryConclusionCommitResult:
        _validate_operation(operation)
        if operation.key_epoch != self._key_epoch:
            raise IntegrityFailure("canary conclusion key epoch changed")
        if not callable(revalidate_authority):
            raise TypeError("canary conclusion requires an authority revalidator")
        with self._repository.transaction() as transaction:
            replay = _existing_replay(transaction, operation)
            if replay is not None:
                return replay

            scope = transaction.get_activation_scope(operation.context_ref)
            if scope is None or scope.scope_revision != operation.expected_scope_revision:
                raise RevisionConflict("canary conclusion scope revision changed")
            slot = transaction.get_operation_slot(operation.context_ref, "canary")
            _require_active_slot(operation, slot)

            trial = _require_exact(
                transaction,
                ExactRecord.of(operation.request.trial),
                operation.context_ref,
                CANARY_TRIAL_SCHEMA_ID,
                "canary_trial",
            )
            if trial != operation.request.trial:
                raise IntegrityFailure("materialized conclusion request changed its trial")
            plan = _require_exact(
                transaction,
                operation.canary_plan,
                operation.context_ref,
                CANARY_PLAN_SCHEMA_ID,
                "canary_plan",
            )
            policy = _require_exact(
                transaction,
                operation.policy,
                operation.context_ref,
                ACTIVATION_POLICY_SCHEMA_ID,
                "activation_policy",
            )
            calibration = None
            if operation.calibration is not None:
                calibration = _require_exact(
                    transaction,
                    operation.calibration,
                    operation.context_ref,
                    POLICY_CALIBRATION_SCHEMA_ID,
                    "policy_calibration",
                )
                _require_current_calibration(transaction, calibration)
            reducer_authority = _require_exact(
                transaction,
                operation.certified_reducer_authority,
                operation.context_ref,
                CERTIFIED_CANARY_OUTCOME_AUTHORITY_SCHEMA_ID,
                "certified_canary_outcome_authority",
            )
            _validate_trial_bindings(operation, trial, plan, policy, calibration, scope)
            if reducer_authority.payload["canary_plan"] != operation.canary_plan.payload():
                raise IntegrityFailure("certified reducer authority binds another canary plan")

            # Last external authority check before any durable mutation.
            admitted_authority = revalidate_authority(transaction, operation)
            if admitted_authority != operation.authority:
                raise IntegrityFailure("canary conclusion authority changed in transaction")

            conclusion = self._planner.plan_conclusion(
                operation.request, frozen_plan=plan
            )
            conclusion.verify(CANARY_REGISTRY)
            transaction.insert_record(conclusion)
            resulting_slot = transaction.clear_exact_operation_slot(
                context_ref=operation.context_ref,
                operation_kind="canary",
                expected_revision=operation.slot.revision,
                expected_scope_revision=operation.expected_scope_revision,
                operation_id=trial.record_id,
                operation_digest=trial.content_digest,
            )
            event_sequence = transaction.next_domain_event_sequence(trial.record_id)
            receipt = _build_receipt(
                operation,
                conclusion,
                resulting_slot,
                event_sequence=event_sequence,
            )
            transaction.insert_record(receipt)
            event = _build_event(operation, trial, receipt, event_sequence)
            transaction.append_event(event)

            if operation.authority.admission_kind == "operator":
                admitted = transaction.admit_command(
                    _operator_command(operation, receipt)
                )
                if admitted.replayed:
                    raise IntegrityFailure(
                        "canary conclusion command changed inside one transaction"
                    )
            else:
                transaction.insert_record(
                    _build_automation_trigger(operation, receipt)
                )
            return CanaryConclusionCommitResult(
                conclusion,
                receipt,
                resulting_slot,
                receipt.payload["admission_ref"],
                False,
            )


def digest_canary_conclusion_request(operation: CanaryConclusionOperation) -> str:
    """Digest every explicit reducer signal and repository/authority binding."""

    request = operation.request
    payload = {
        "action": CANARY_CONCLUSION_ACTION,
        "context_ref": operation.context_ref,
        "expected_scope_revision": operation.expected_scope_revision,
        "slot": {
            "revision": operation.slot.revision,
            "occupant": (
                None
                if operation.slot.occupant is None
                else operation.slot.occupant.payload()
            ),
        },
        "conclusion_record_id": request.record_id,
        "trial": ExactRecord.of(request.trial).payload(),
        "eligible_exposure_count": request.eligible_exposure_count,
        "bucket_outcomes": [
            {
                "bucket_ref": item.bucket_ref,
                "comparable_count": item.comparable_count,
                "candidate_delta": {
                    "numerator": item.candidate_delta.numerator,
                    "denominator": item.candidate_delta.denominator,
                },
                "boundary_uncertain": item.boundary_uncertain,
            }
            for item in request.bucket_outcomes
        ],
        "candidate_hard_failure_count": request.candidate_hard_failure_count,
        "shared_failure": request.shared_failure,
        "identity_drift": request.identity_drift,
        "cancelled": request.cancelled,
        "boundary_uncertain": request.boundary_uncertain,
        "operator_stopped": request.operator_stopped,
        "canary_plan": operation.canary_plan.payload(),
        "policy": operation.policy.payload(),
        "calibration": (
            None if operation.calibration is None else operation.calibration.payload()
        ),
        "certified_reducer_authority": operation.certified_reducer_authority.payload(),
        "authority": {
            "admission_kind": operation.authority.admission_kind,
            "actor_authority_ref": operation.authority.actor_authority_ref,
            "issuer_ref": operation.authority.issuer_ref,
            "subject_ref": operation.authority.subject_ref,
        },
        "idempotency_key_digest": operation.idempotency_key_digest,
        "key_epoch": operation.key_epoch,
    }
    return schema_digest(
        "canary-conclusion-request",
        "a0.canary-conclusion-request.v1",
        canonical_json(payload),
    )


def _validate_operation(operation: CanaryConclusionOperation) -> None:
    if type(operation) is not CanaryConclusionOperation:
        raise TypeError("one exact CanaryConclusionOperation is required")
    if type(operation.request) is not CanaryConclusionRequest:
        raise TypeError("one materialized CanaryConclusionRequest is required")
    validate_digest(operation.idempotency_key_digest, "idempotency_key_digest")
    validate_digest(operation.request_digest, "request_digest")
    if operation.request_digest != digest_canary_conclusion_request(operation):
        raise IntegrityFailure("canary conclusion request digest is not exact")
    if (
        type(operation.expected_scope_revision) is not int
        or operation.expected_scope_revision < 0
        or type(operation.slot) is not SlotBinding
        or type(operation.authority) is not CanaryConclusionAuthority
        or type(operation.context_ref) is not str
        or not operation.context_ref
        or type(operation.key_epoch) is not str
        or not operation.key_epoch
    ):
        raise TypeError("canary conclusion operation shape is invalid")
    trial_exact = ExactRecord.of(operation.request.trial)
    if operation.slot.occupant != trial_exact:
        raise RevisionConflict("canary conclusion does not bind the active trial")
    authority = operation.authority
    if (
        authority.admission_kind not in ("operator", "automation")
        or any(
            type(value) is not str or not value
            for value in (
                authority.actor_authority_ref,
                authority.issuer_ref,
                authority.subject_ref,
            )
        )
    ):
        raise TypeError("canary conclusion admission identity is invalid")
    if operation.request.operator_stopped and authority.admission_kind != "operator":
        raise IntegrityFailure("operator-stopped conclusion requires operator admission")


def _validate_trial_bindings(
    operation: CanaryConclusionOperation,
    trial: TypedRecord,
    plan: TypedRecord,
    policy: TypedRecord,
    calibration: TypedRecord | None,
    scope,
) -> None:
    payload = trial.payload
    calibration_exact = (
        (None, None)
        if calibration is None
        else (calibration.record_id, calibration.content_digest)
    )
    if (
        (payload["plan_id"], payload["plan_digest"])
        != (plan.record_id, plan.content_digest)
        or (payload["policy_id"], payload["policy_digest"])
        != (policy.record_id, policy.content_digest)
        or (payload["calibration_id"], payload["calibration_digest"])
        != calibration_exact
        or payload["policy_revision"] != policy.payload["policy_revision"]
        or payload["scope_revision"] != operation.expected_scope_revision
        or scope.current_profile_id != payload["incumbent_profile_id"]
        or scope.current_profile_digest != payload["incumbent_profile_digest"]
    ):
        raise IntegrityFailure("active canary trial lost an exact frozen input")
    if operation.authority.admission_kind == "automation":
        if (
            calibration is None
            or payload["canary_kind"] != "authoritative"
            or policy.payload["activation_mode"] != "auto_after_canary"
            or calibration.payload["status"] != "approved"
            or calibration.payload["policy_id"] != policy.record_id
            or calibration.payload["policy_digest"] != policy.content_digest
            or calibration.payload["canary_plan_id"] != plan.record_id
            or calibration.payload["canary_plan_digest"] != plan.content_digest
            or operation.authority.actor_authority_ref != calibration.record_id
        ):
            raise IntegrityFailure("automation lacks exact calibrated canary authority")


def _require_active_slot(
    operation: CanaryConclusionOperation, current: OperationSlot | None
) -> None:
    if (
        current is None
        or current.operation_revision != operation.slot.revision
        or current.operation_id != operation.request.trial.record_id
        or current.operation_digest != operation.request.trial.content_digest
    ):
        raise RevisionConflict("active canary slot changed before conclusion")


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
        raise IntegrityFailure("canary conclusion exact record binding failed")
    return record


def _require_current_calibration(
    transaction: V3Transaction, calibration: TypedRecord
) -> None:
    facts: list[CalibrationLifecycleFact] = []
    for sequence in range(
        transaction.next_domain_event_sequence(calibration.record_id)
    ):
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
        raise IntegrityFailure("policy calibration is not currently approved")


def _receipt_id(operation: CanaryConclusionOperation) -> str:
    authority = operation.authority
    material = "\0".join(
        (
            authority.admission_kind,
            authority.issuer_ref,
            authority.subject_ref,
            operation.context_ref,
            operation.idempotency_key_digest,
        )
    ).encode()
    return f"canary-conclusion-receipt:{sha256(material).hexdigest()}"


def _admission_ref(operation: CanaryConclusionOperation) -> str:
    namespace = (
        "canary-conclusion-command"
        if operation.authority.admission_kind == "operator"
        else "canary-conclusion-automation-trigger"
    )
    return f"{namespace}:{sha256((namespace + '\0' + _receipt_id(operation)).encode()).hexdigest()}"


def _build_receipt(
    operation: CanaryConclusionOperation,
    conclusion: TypedRecord,
    slot: OperationSlot,
    *,
    event_sequence: int,
) -> TypedRecord:
    trial = ExactRecord.of(operation.request.trial).payload()
    conclusion_exact = ExactRecord.of(conclusion).payload()
    plan = operation.canary_plan.payload()
    policy = operation.policy.payload()
    calibration = (
        None if operation.calibration is None else operation.calibration.payload()
    )
    reducer = operation.certified_reducer_authority.payload()
    links = [
        _link("canary_conclusion", 0, conclusion_exact),
        _link("canary_trial", 0, trial),
        _link("canary_plan", 0, plan),
        _link("activation_policy", 0, policy),
        _link("certified_reducer_authority", 0, reducer),
    ]
    if calibration is not None:
        links.append(_link("policy_calibration", 0, calibration))
    conclusion_payload = conclusion.payload
    return build_typed_record(
        record_id=_receipt_id(operation),
        context_ref=operation.context_ref,
        record_kind="canary_conclusion_receipt",
        schema_id=CANARY_CONCLUSION_RECEIPT_SCHEMA_ID,
        payload={
            "receipt_type": "canary_conclusion",
            "accepted": True,
            "context_ref": operation.context_ref,
            "conclusion": conclusion_exact,
            "trial": trial,
            "canary_plan": plan,
            "activation_policy": policy,
            "policy_calibration": calibration,
            "certified_reducer_authority": reducer,
            "observed_scope_revision": operation.expected_scope_revision,
            "resulting_scope_revision": operation.expected_scope_revision,
            "observed_slot_revision": operation.slot.revision,
            "resulting_slot_revision": slot.operation_revision,
            "admission_kind": operation.authority.admission_kind,
            "admission_ref": _admission_ref(operation),
            "actor_authority_ref": operation.authority.actor_authority_ref,
            "issuer_ref": operation.authority.issuer_ref,
            "subject_ref": operation.authority.subject_ref,
            "idempotency_key_digest": operation.idempotency_key_digest,
            "request_digest": operation.request_digest,
            "canary_kind": conclusion_payload["canary_kind"],
            "authority_ceiling": conclusion_payload["authority_ceiling"],
            "conclusion_state": conclusion_payload["conclusion"],
            "activation_authoritative": conclusion_payload[
                "activation_authoritative"
            ],
            "event_sequence": event_sequence,
            "links": links,
        },
        key_epoch=operation.key_epoch,
        registry=CANARY_CONCLUSION_REPOSITORY_REGISTRY,
    )


def _build_event(
    operation: CanaryConclusionOperation,
    trial: TypedRecord,
    receipt: TypedRecord,
    sequence: int,
) -> DomainEvent:
    return DomainEvent(
        event_id=f"canary-conclusion-event:{sha256((operation.request_digest + ':' + str(sequence)).encode()).hexdigest()}",
        subject_id=trial.record_id,
        subject_kind="canary_trial",
        sequence=sequence,
        event_type="canary_concluded",
        payload_record_id=receipt.record_id,
        actor_authority_ref=operation.authority.actor_authority_ref,
    )


def _operator_command(
    operation: CanaryConclusionOperation, receipt: TypedRecord
) -> OperatorCommand:
    return OperatorCommand(
        command_id=_admission_ref(operation),
        issuer_ref=operation.authority.issuer_ref,
        subject_ref=operation.authority.subject_ref,
        context_ref=operation.context_ref,
        action=CANARY_CONCLUSION_ACTION,
        idempotency_key_digest=operation.idempotency_key_digest,
        request_digest=operation.request_digest,
        observed_revision=operation.expected_scope_revision,
        state="accepted",
        mutation_receipt_id=receipt.record_id,
    )


def _build_automation_trigger(
    operation: CanaryConclusionOperation, receipt: TypedRecord
) -> TypedRecord:
    if operation.calibration is None:
        raise IntegrityFailure("automation trigger has no calibration authority")
    policy = operation.policy.payload()
    calibration = operation.calibration.payload()
    receipt_exact = ExactRecord.of(receipt).payload()
    return build_typed_record(
        record_id=_admission_ref(operation),
        context_ref=operation.context_ref,
        record_kind="automation_trigger_receipt",
        schema_id=CANARY_CONCLUSION_AUTOMATION_TRIGGER_SCHEMA_ID,
        payload={
            "trigger_type": "canary_conclusion",
            "action": CANARY_CONCLUSION_ACTION,
            "context_ref": operation.context_ref,
            "authority_ref": operation.authority.actor_authority_ref,
            "issuer_ref": operation.authority.issuer_ref,
            "subject_ref": operation.authority.subject_ref,
            "activation_policy": policy,
            "policy_calibration": calibration,
            "mutation_receipt": receipt_exact,
            "idempotency_key_digest": operation.idempotency_key_digest,
            "request_digest": operation.request_digest,
            "links": [
                _link("activation_policy", 0, policy),
                _link("policy_calibration", 0, calibration),
                _link("mutation_receipt", 0, receipt_exact),
            ],
        },
        key_epoch=operation.key_epoch,
        registry=CANARY_CONCLUSION_REPOSITORY_REGISTRY,
    )


def _existing_replay(
    transaction: V3Transaction, operation: CanaryConclusionOperation
) -> CanaryConclusionCommitResult | None:
    receipt = None
    if operation.authority.admission_kind == "operator":
        command = transaction.get_operator_command(
            issuer_ref=operation.authority.issuer_ref,
            subject_ref=operation.authority.subject_ref,
            context_ref=operation.context_ref,
            action=CANARY_CONCLUSION_ACTION,
            idempotency_key_digest=operation.idempotency_key_digest,
        )
        if command is None:
            return None
        if command.request_digest != operation.request_digest:
            raise IdempotencyConflict("canary conclusion request changed for idempotency key")
        if (
            command.command_id != _admission_ref(operation)
            or command.state != "accepted"
            or command.observed_revision != operation.expected_scope_revision
            or command.mutation_receipt_id != _receipt_id(operation)
        ):
            raise IntegrityFailure("canary conclusion command differs from exact replay")
        receipt = transaction.get_record(command.mutation_receipt_id)
    else:
        receipt = transaction.get_record(_receipt_id(operation))
        if receipt is None:
            return None
        if receipt.payload.get("request_digest") != operation.request_digest:
            raise IdempotencyConflict("canary conclusion request changed for idempotency key")
    if receipt is None or receipt.schema_id != CANARY_CONCLUSION_RECEIPT_SCHEMA_ID:
        raise IntegrityFailure("canary conclusion replay lost its exact receipt")
    receipt.verify(CANARY_CONCLUSION_REPOSITORY_REGISTRY)
    payload = receipt.payload
    if (
        payload["request_digest"] != operation.request_digest
        or payload["idempotency_key_digest"] != operation.idempotency_key_digest
        or payload["trial"] != ExactRecord.of(operation.request.trial).payload()
        or payload["canary_plan"] != operation.canary_plan.payload()
        or payload["activation_policy"] != operation.policy.payload()
        or payload["policy_calibration"]
        != (None if operation.calibration is None else operation.calibration.payload())
        or payload["certified_reducer_authority"]
        != operation.certified_reducer_authority.payload()
        or payload["admission_ref"] != _admission_ref(operation)
    ):
        raise IntegrityFailure("durable canary conclusion differs from exact replay")
    conclusion = transaction.get_record(payload["conclusion"]["record_id"])
    if (
        conclusion is None
        or conclusion.content_digest != payload["conclusion"]["digest"]
    ):
        raise IntegrityFailure("canary conclusion replay lost its conclusion")
    scope = transaction.get_activation_scope(operation.context_ref)
    slot = transaction.get_operation_slot(operation.context_ref, "canary")
    if (
        scope is None
        or scope.scope_revision != payload["resulting_scope_revision"]
        or slot is None
        or slot.operation_revision != payload["resulting_slot_revision"]
        or slot.operation_id is not None
    ):
        raise RevisionConflict("canary conclusion replay state changed")
    expected_event = _build_event(
        operation, operation.request.trial, receipt, payload["event_sequence"]
    )
    if (
        transaction.get_domain_event(
            operation.request.trial.record_id, payload["event_sequence"]
        )
        != expected_event
    ):
        raise IntegrityFailure("canary conclusion replay lost its immutable event")
    if operation.authority.admission_kind == "automation":
        trigger = transaction.get_record(_admission_ref(operation))
        if trigger != _build_automation_trigger(operation, receipt):
            raise IntegrityFailure("canary conclusion replay lost automation admission")
    return CanaryConclusionCommitResult(
        conclusion, receipt, slot, payload["admission_ref"], True
    )


def _link(role: str, ordinal: int, exact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": exact["record_id"],
        "target_digest": exact["digest"],
    }


__all__ = [
    "CANARY_CONCLUSION_RECEIPT_SCHEMA_ID",
    "CANARY_CONCLUSION_AUTOMATION_TRIGGER_SCHEMA_ID",
    "CERTIFIED_CANARY_OUTCOME_AUTHORITY_SCHEMA_ID",
    "CANARY_CONCLUSION_ACTION",
    "CANARY_CONCLUSION_REPOSITORY_REGISTRY",
    "CanaryConclusionAuthority",
    "CanaryConclusionOperation",
    "CanaryConclusionAuthorityRevalidator",
    "CanaryConclusionCommitResult",
    "RepositoryCanaryConclusionCoordinator",
    "digest_canary_conclusion_request",
    "build_certified_canary_outcome_authority",
]
