"""Repository-backed atomic mutation authority for planned canary commands.

The command adapter owns syntax and pure planning.  This coordinator owns the
single SQLite transaction that turns an already-planned fact into durable
truth.  It has no cache, provider, policy defaults, or planning authority.
"""
from __future__ import annotations

from hashlib import sha256

from .canary import (
    ACTIVATION_POLICY_SCHEMA_ID,
    CANARY_CONCLUSION_SCHEMA_ID,
    CANARY_PLAN_SCHEMA_ID,
    CANARY_TRIAL_SCHEMA_ID,
    POLICY_CALIBRATION_SCHEMA_ID,
)
from .canary_command_adapter import (
    CANARY_COMMAND_REGISTRY,
    CANARY_MUTATION_RECEIPT_SCHEMA_ID,
    CanaryCommandError,
    CanaryMutationOperation,
    CanaryMutationResult,
    ExactRecord,
    GrantRevalidator,
    SlotBinding,
    build_canary_authority_grant_use,
    build_canary_mutation_receipt,
    verify_canary_grant,
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
from .schemas import TypedRecord, validate_digest


class RepositoryCanaryMutationCoordinator:
    """Commit exact canary start/stop plans through one :class:`V3Repository`."""

    def __init__(self, repository: V3Repository) -> None:
        if not isinstance(repository, V3Repository):
            raise TypeError("canary mutation coordination requires a V3Repository")
        self.repository = repository

    def get_record(self, identity: ExactRecord) -> TypedRecord | None:
        if type(identity) is not ExactRecord:
            raise TypeError("record lookup requires an exact identity")
        record = self.repository.get_record(identity.record_id)
        if record is None or record.content_digest != identity.digest:
            return None
        return record

    def commit(
        self,
        operation: CanaryMutationOperation,
        *,
        revalidate_grant: GrantRevalidator,
    ) -> CanaryMutationResult:
        if type(operation) is not CanaryMutationOperation or not callable(revalidate_grant):
            raise CanaryCommandError("repository commit requires exact operation inputs")
        _validate_operation_shape(operation)
        with self.repository.transaction() as transaction:
            existing = _existing_command(transaction, operation)
            if existing is not None:
                return _replay(transaction, operation, existing)

            scope = transaction.get_activation_scope(operation.context_ref)
            if scope is None or scope.scope_revision != operation.expected_scope_revision:
                raise RevisionConflict("activation scope revision did not match canary command")
            current_slot = transaction.get_operation_slot(operation.context_ref, "canary")
            _require_observed_slot(operation.slot, current_slot)

            policy = _require_exact(
                transaction,
                operation.policy,
                context_ref=operation.context_ref,
                record_kind="activation_policy",
                schema_id=ACTIVATION_POLICY_SCHEMA_ID,
            )
            _require_exact(
                transaction,
                operation.canary_plan,
                context_ref=operation.context_ref,
                record_kind="canary_plan",
                schema_id=CANARY_PLAN_SCHEMA_ID,
            )
            if operation.calibration is not None:
                _require_exact(
                    transaction,
                    operation.calibration,
                    context_ref=operation.context_ref,
                    record_kind="policy_calibration",
                    schema_id=POLICY_CALIBRATION_SCHEMA_ID,
                )
            _require_exact(transaction, operation.candidate, context_ref=operation.context_ref)
            _require_exact(transaction, operation.disposition, context_ref=operation.context_ref)
            trial = operation.planned_fact
            if operation.action == "canary_stop":
                assert operation.trial is not None
                trial = _require_exact(
                    transaction,
                    operation.trial,
                    context_ref=operation.context_ref,
                    record_kind="canary_trial",
                    schema_id=CANARY_TRIAL_SCHEMA_ID,
                )
            _validate_trial_bindings(operation, trial, policy)
            if (
                scope.current_profile_id != trial.payload["incumbent_profile_id"]
                or scope.current_profile_digest != trial.payload["incumbent_profile_digest"]
            ):
                raise RevisionConflict("canary command incumbent is not the current Activation Scope")

            # This is deliberately the last fallible authority check before the
            # first domain write in the transaction.
            grant = revalidate_grant(operation.grant_binding)
            verify_canary_grant(operation.grant_binding, grant)
            authority_grant_use = build_canary_authority_grant_use(
                operation.grant_binding,
                grant,
                key_epoch=operation.key_epoch,
            )
            if authority_grant_use != operation.authority_grant_use:
                raise CanaryCommandError(
                    "transactional grant differs from preverified canary authority"
                )

            transaction.insert_record(authority_grant_use)
            operation.planned_fact.verify(CANARY_COMMAND_REGISTRY)
            _require_link_targets(transaction, operation.planned_fact)
            transaction.insert_record(operation.planned_fact)
            if operation.action == "canary_start":
                resulting_slot = transaction.claim_empty_operation_slot(
                    context_ref=operation.context_ref,
                    operation_kind="canary",
                    expected_revision=operation.slot.revision,
                    expected_scope_revision=operation.expected_scope_revision,
                    operation_id=operation.planned_fact.record_id,
                    operation_digest=operation.planned_fact.content_digest,
                )
            else:
                assert operation.trial is not None
                resulting_slot = transaction.clear_exact_operation_slot(
                    context_ref=operation.context_ref,
                    operation_kind="canary",
                    expected_revision=operation.slot.revision,
                    expected_scope_revision=operation.expected_scope_revision,
                    operation_id=operation.trial.record_id,
                    operation_digest=operation.trial.digest,
                )

            receipt = build_canary_mutation_receipt(
                operation,
                resulting_slot=resulting_slot,
                verified_grant=grant,
            )
            transaction.insert_record(receipt)
            subject = ExactRecord.of(operation.planned_fact)
            subject_kind = operation.planned_fact.record_kind
            if operation.action == "canary_stop":
                assert operation.trial is not None
                subject = operation.trial
                subject_kind = "canary_trial"
            transaction.append_event(
                DomainEvent(
                    event_id=_stable_id("canary-event", operation.action, operation.request_digest),
                    subject_id=subject.record_id,
                    subject_kind=subject_kind,
                    sequence=transaction.next_domain_event_sequence(subject.record_id),
                    event_type=(
                        "canary_started"
                        if operation.action == "canary_start"
                        else "canary_stopped"
                    ),
                    payload_record_id=receipt.record_id,
                    actor_authority_ref=grant.grant_id,
                )
            )
            admission = transaction.admit_command(
                OperatorCommand(
                    command_id=_stable_id(
                        "canary-operator-command", operation.action, operation.request_digest
                    ),
                    issuer_ref=operation.issuer_ref,
                    subject_ref=operation.subject_ref,
                    context_ref=operation.context_ref,
                    action=operation.action,
                    idempotency_key_digest=operation.idempotency_key_digest,
                    request_digest=operation.request_digest,
                    observed_revision=operation.expected_scope_revision,
                    state="accepted",
                    mutation_receipt_id=receipt.record_id,
                )
            )
            if admission.replayed:  # protected by the in-transaction preflight
                raise IntegrityFailure("canary command admission changed during one transaction")
            return CanaryMutationResult(
                operation.planned_fact,
                receipt,
                resulting_slot,
                grant.grant_id,
                False,
            )


def _stable_id(namespace: str, action: str, request_digest: str) -> str:
    material = f"{namespace}\0{action}\0{request_digest}".encode("utf-8")
    return f"{namespace}:{sha256(material).hexdigest()}"


def _validate_operation_shape(operation: CanaryMutationOperation) -> None:
    if operation.action not in ("canary_start", "canary_stop"):
        raise CanaryCommandError("canary mutation action is not admitted")
    validate_digest(operation.idempotency_key_digest, "idempotency_key_digest")
    validate_digest(operation.request_digest, "request_digest")
    binding = operation.grant_binding
    expected_action = "canary_start" if operation.action == "canary_start" else "canary_stop"
    expected_target = (
        operation.planned_fact.record_id
        if operation.action == "canary_start"
        else operation.trial.record_id if operation.trial is not None else ""
    )
    if (
        binding.action != expected_action
        or binding.context_ref != operation.context_ref
        or binding.issuer_ref != operation.issuer_ref
        or binding.subject_ref != operation.subject_ref
        or binding.target_revision != operation.expected_scope_revision
        or binding.target_ref != expected_target
        or binding.idempotency_key_digest != operation.idempotency_key_digest
        or binding.authority_grant_id != operation.authority_grant_id
        or operation.authority_grant_use.record_id != operation.authority_grant_id
    ):
        raise CanaryCommandError("canary grant binding differs from the mutation operation")
    expected_schema = (
        CANARY_TRIAL_SCHEMA_ID
        if operation.action == "canary_start"
        else CANARY_CONCLUSION_SCHEMA_ID
    )
    expected_kind = "canary_trial" if operation.action == "canary_start" else "canary_conclusion"
    if (
        operation.planned_fact.schema_id != expected_schema
        or operation.planned_fact.record_kind != expected_kind
        or operation.planned_fact.context_ref != operation.context_ref
    ):
        raise CanaryCommandError("planned canary fact has the wrong exact type or context")
    if operation.action == "canary_start":
        if operation.trial is not None or operation.slot.occupant is not None:
            raise RevisionConflict("canary start requires an exactly empty observed slot")
    elif operation.trial is None or operation.slot.occupant != operation.trial:
        raise RevisionConflict("canary stop requires the exact observed trial occupant")


def _existing_command(
    transaction: V3Transaction, operation: CanaryMutationOperation
) -> OperatorCommand | None:
    existing = transaction.get_operator_command(
        issuer_ref=operation.issuer_ref,
        subject_ref=operation.subject_ref,
        context_ref=operation.context_ref,
        action=operation.action,
        idempotency_key_digest=operation.idempotency_key_digest,
    )
    if existing is not None and existing.request_digest != operation.request_digest:
        raise IdempotencyConflict("idempotency key was reused with a different request")
    return existing


def _require_exact(
    transaction: V3Transaction,
    identity: ExactRecord,
    *,
    context_ref: str,
    record_kind: str | None = None,
    schema_id: str | None = None,
) -> TypedRecord:
    record = transaction.get_record(identity.record_id)
    if (
        record is None
        or record.content_digest != identity.digest
        or record.context_ref != context_ref
        or (record_kind is not None and record.record_kind != record_kind)
        or (schema_id is not None and record.schema_id != schema_id)
    ):
        raise IntegrityFailure("canary command exact record binding failed")
    return record


def _require_link_targets(transaction: V3Transaction, record: TypedRecord) -> None:
    for link in record.links:
        target = transaction.get_record(link.target_id)
        if target is None or target.content_digest != link.target_digest:
            raise IntegrityFailure("planned canary fact has a missing or changed exact input")


def _require_observed_slot(expected: SlotBinding, current: OperationSlot | None) -> None:
    revision = 0 if current is None else current.operation_revision
    occupant = None
    if current is not None and current.operation_id is not None:
        occupant = ExactRecord(current.operation_id, current.operation_digest or "")
    if expected.revision != revision or expected.occupant != occupant:
        raise RevisionConflict("canary slot revision or occupant did not match")


def _validate_trial_bindings(
    operation: CanaryMutationOperation, trial: TypedRecord, policy: TypedRecord
) -> None:
    payload = trial.payload
    calibration = (
        (operation.calibration.record_id, operation.calibration.digest)
        if operation.calibration is not None
        else (None, None)
    )
    if (
        (payload["candidate_id"], payload["candidate_digest"])
        != (operation.candidate.record_id, operation.candidate.digest)
        or (payload["disposition_id"], payload["disposition_digest"])
        != (operation.disposition.record_id, operation.disposition.digest)
        or (payload["policy_id"], payload["policy_digest"])
        != (operation.policy.record_id, operation.policy.digest)
        or (payload["plan_id"], payload["plan_digest"])
        != (operation.canary_plan.record_id, operation.canary_plan.digest)
        or (payload["calibration_id"], payload["calibration_digest"]) != calibration
        or payload["scope_revision"] != operation.expected_scope_revision
        or payload["policy_revision"] != policy.payload["policy_revision"]
    ):
        raise IntegrityFailure("planned canary fact lost an exact admitted input")


def _replay(
    transaction: V3Transaction,
    operation: CanaryMutationOperation,
    command: OperatorCommand,
) -> CanaryMutationResult:
    if (
        command.state != "accepted"
        or command.observed_revision != operation.expected_scope_revision
        or command.mutation_receipt_id != operation.receipt_id
    ):
        raise IntegrityFailure("durable canary command does not match its exact request")
    receipt = transaction.get_record(command.mutation_receipt_id)
    if receipt is None or receipt.schema_id != CANARY_MUTATION_RECEIPT_SCHEMA_ID:
        raise IntegrityFailure("durable canary command lost its exact receipt")
    receipt.verify(CANARY_COMMAND_REGISTRY)
    payload = receipt.payload
    expected_trial = operation.trial.payload() if operation.trial is not None else None
    if (
        payload["action"] != operation.action
        or payload["context_ref"] != operation.context_ref
        or payload["request_digest"] != operation.request_digest
        or payload["idempotency_key_digest"] != operation.idempotency_key_digest
        or payload["planned_fact"] != ExactRecord.of(operation.planned_fact).payload()
        or payload["policy"] != operation.policy.payload()
        or payload["trial"] != expected_trial
        or payload["observed_scope_revision"] != operation.expected_scope_revision
        or payload["observed_slot_revision"] != operation.slot.revision
        or payload["observed_slot_occupant"]
        != (operation.slot.occupant.payload() if operation.slot.occupant is not None else None)
        or payload["authority_grant_id"] != operation.authority_grant_id
        or payload["authority_grant_use"]
        != ExactRecord.of(operation.authority_grant_use).payload()
    ):
        raise IntegrityFailure("durable canary receipt differs from the exact replay")
    fact = transaction.get_record(operation.planned_fact.record_id)
    if fact != operation.planned_fact:
        raise IntegrityFailure("durable canary replay lost its exact planned fact")
    authority_grant_use = transaction.get_record(operation.authority_grant_use.record_id)
    if authority_grant_use != operation.authority_grant_use:
        raise IntegrityFailure("durable canary replay lost its authority use record")
    scope = transaction.get_activation_scope(operation.context_ref)
    if scope is None or scope.scope_revision != payload["resulting_scope_revision"]:
        raise RevisionConflict("activation scope changed before exact canary replay")
    slot = transaction.get_operation_slot(operation.context_ref, "canary")
    if slot is None:
        raise IntegrityFailure("durable canary replay lost its slot transition")
    occupant = (
        None
        if slot.operation_id is None
        else {"record_id": slot.operation_id, "digest": slot.operation_digest}
    )
    if (
        slot.operation_revision != payload["resulting_slot_revision"]
        or occupant != payload["resulting_slot_occupant"]
    ):
        raise RevisionConflict("canary slot changed before exact command replay")
    return CanaryMutationResult(
        operation.planned_fact,
        receipt,
        slot,
        payload["authority_grant_id"],
        True,
    )
