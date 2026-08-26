"""Durable monitor and requalification authority after profile activation.

All decisions arrive as exact certified outcome and eligibility records.  This
module performs no scoring and has no thresholds.  It atomically concludes an
active monitor, starts or concludes requalification with exact slot CAS, and
admits one immutable operator command.

The existing rollback coordinator opens its own repository transaction, so it
cannot be safely composed here.  A rollback-required conclusion therefore
clears the exact active slot and emits a typed, authority-bounded rollback
request while leaving the Activation Scope unchanged.  No profile is silently
mutated and a later rollback still requires the normal activation authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Literal, Mapping

from .artifacts import ACTIVATION_PROFILE_SCHEMA_ID
from .canary import (
    ACTIVATION_POLICY_SCHEMA_ID,
    POLICY_CALIBRATION_SCHEMA_ID,
    POST_PROMOTION_MONITOR_SCHEMA_ID,
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


CERTIFIED_POST_ACTIVATION_OUTCOME_SCHEMA_ID = (
    "a0.certified-post-activation-outcome.v1"
)
POST_ACTIVATION_ELIGIBILITY_SCHEMA_ID = "a0.post-activation-eligibility.v1"
POST_ACTIVATION_CONCLUSION_SCHEMA_ID = "a0.post-activation-conclusion.v1"
REQUALIFICATION_WINDOW_SCHEMA_ID = "a0.evidence-requalification-window.v1"
ROLLBACK_AUTHORITY_REQUEST_SCHEMA_ID = "a0.rollback-authority-request.v1"
POST_ACTIVATION_RECEIPT_SCHEMA_ID = "a0.post-activation-mutation-receipt.v1"

POST_ACTIVATION_ACTIONS = (
    "monitor_conclude",
    "requalification_start",
    "requalification_conclude",
)
POST_ACTIVATION_DECISIONS = ("retain", "requalify", "rollback_required")

_EXACT = strict_object(
    {"record_id": strict_string(maximum=512), "digest": validate_digest}
)
_OPTIONAL_EXACT = strict_nullable(_EXACT)
_SLOT = strict_object(
    {
        "operation_kind": strict_enum(("monitor", "requalification")),
        "observed_revision": strict_integer(minimum=0),
        "resulting_revision": strict_integer(minimum=0),
        "observed_occupant": _OPTIONAL_EXACT,
        "resulting_occupant": _OPTIONAL_EXACT,
    }
)


class PostActivationError(RuntimeError):
    """An exact post-activation authority or lifecycle condition failed."""


def _outcome_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "outcome_type": strict_literal("certified_post_activation_outcome"),
            "authority_ceiling": strict_literal("materialize_conclusion_only"),
            "subject": _EXACT,
            "producer": _EXACT,
            "reducer_profile": _EXACT,
            "measurement_bundle": _EXACT,
            "decision": strict_enum(POST_ACTIVATION_DECISIONS),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("subject", 0, payload["subject"]),
        _link("certified_producer", 0, payload["producer"]),
        _link("reducer_profile", 0, payload["reducer_profile"]),
        _link("measurement_bundle", 0, payload["measurement_bundle"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind certified outcome")
    return payload


def _eligibility_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "eligibility_type": strict_literal("post_activation_eligibility"),
            "action": strict_enum(POST_ACTIVATION_ACTIONS),
            "eligible": strict_literal(True),
            "decision": strict_enum(POST_ACTIVATION_DECISIONS),
            "scope_revision": strict_integer(minimum=0),
            "active_profile": _EXACT,
            "subject": _EXACT,
            "certified_outcome": _EXACT,
            "activation_policy": _EXACT,
            "policy_calibration": _EXACT,
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("active_profile", 0, payload["active_profile"]),
        _link("subject", 0, payload["subject"]),
        _link("certified_outcome", 0, payload["certified_outcome"]),
        _link("activation_policy", 0, payload["activation_policy"]),
        _link("policy_calibration", 0, payload["policy_calibration"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind eligibility inputs")
    return payload


def _conclusion_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "conclusion_type": strict_enum(("monitor", "requalification")),
            "decision": strict_enum(POST_ACTIVATION_DECISIONS),
            "subject": _EXACT,
            "certified_outcome": _EXACT,
            "eligibility": _EXACT,
            "observed_scope_revision": strict_integer(minimum=0),
            "resulting_scope_revision": strict_integer(minimum=0),
            "profile_mutation": strict_literal("none"),
            "links": validate_links,
        }
    )(value, path)
    if payload["resulting_scope_revision"] != payload["observed_scope_revision"]:
        raise SchemaValidationError(f"{path} cannot mutate Activation Scope")
    expected = [
        _link("subject", 0, payload["subject"]),
        _link("certified_outcome", 0, payload["certified_outcome"]),
        _link("eligibility", 0, payload["eligibility"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind conclusion inputs")
    return payload


def _window_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "fact_type": strict_literal("evidence_requalification_window"),
            "monitor": _EXACT,
            "monitor_conclusion": _EXACT,
            "certified_outcome": _EXACT,
            "eligibility": _EXACT,
            "active_profile": _EXACT,
            "activation_policy": _EXACT,
            "policy_calibration": _EXACT,
            "scope_revision": strict_integer(minimum=0),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("monitor", 0, payload["monitor"]),
        _link("monitor_conclusion", 0, payload["monitor_conclusion"]),
        _link("certified_outcome", 0, payload["certified_outcome"]),
        _link("eligibility", 0, payload["eligibility"]),
        _link("active_profile", 0, payload["active_profile"]),
        _link("activation_policy", 0, payload["activation_policy"]),
        _link("policy_calibration", 0, payload["policy_calibration"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind requalification")
    return payload


def _rollback_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "request_type": strict_literal("rollback_authority_request"),
            "authority_ceiling": strict_literal("request_only"),
            "conclusion": _EXACT,
            "active_profile": _EXACT,
            "observed_scope_revision": strict_integer(minimum=0),
            "profile_mutation": strict_literal("none"),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("conclusion", 0, payload["conclusion"]),
        _link("active_profile", 0, payload["active_profile"]),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind rollback request")
    return payload


def _receipt_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "receipt_type": strict_literal("post_activation_mutation"),
            "accepted": strict_literal(True),
            "action": strict_enum(POST_ACTIVATION_ACTIONS),
            "decision": strict_enum(POST_ACTIVATION_DECISIONS),
            "context_ref": strict_string(maximum=512),
            "conclusion": _EXACT,
            "subject": _EXACT,
            "certified_outcome": _EXACT,
            "eligibility": _EXACT,
            "activation_policy": _EXACT,
            "policy_calibration": _EXACT,
            "requalification_window": _OPTIONAL_EXACT,
            "rollback_request": _OPTIONAL_EXACT,
            "observed_scope_revision": strict_integer(minimum=0),
            "resulting_scope_revision": strict_integer(minimum=0),
            "monitor_slot": _SLOT,
            "requalification_slot": _SLOT,
            "actor_authority_ref": strict_string(maximum=512),
            "issuer_ref": strict_string(maximum=512),
            "subject_ref": strict_string(maximum=512),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "event_sequence": strict_integer(minimum=0),
            "links": validate_links,
        }
    )(value, path)
    if payload["resulting_scope_revision"] != payload["observed_scope_revision"]:
        raise SchemaValidationError(f"{path} silently mutates Activation Scope")
    monitor = payload["monitor_slot"]
    requalification = payload["requalification_slot"]
    if monitor["operation_kind"] != "monitor" or requalification[
        "operation_kind"
    ] != "requalification":
        raise SchemaValidationError(f"{path} has noncanonical slots")
    action = payload["action"]
    if action in ("monitor_conclude", "requalification_start"):
        if not _cleared(monitor):
            raise SchemaValidationError(f"{path} does not clear exact monitor")
    elif not _unchanged_empty(monitor):
        raise SchemaValidationError(f"{path} changed monitor during conclusion")
    if action == "requalification_start":
        if (
            payload["decision"] != "requalify"
            or payload["requalification_window"] is None
            or not _claimed(requalification, payload["requalification_window"])
        ):
            raise SchemaValidationError(f"{path} has invalid requalification start")
    elif action == "requalification_conclude":
        if not _cleared(requalification):
            raise SchemaValidationError(f"{path} does not conclude requalification")
    elif not _unchanged_empty(requalification):
        raise SchemaValidationError(f"{path} changed requalification during monitor retain")
    rollback = payload["rollback_request"]
    if (payload["decision"] == "rollback_required") != (rollback is not None):
        raise SchemaValidationError(f"{path} rollback decision/request differ")
    expected = [
        _link("conclusion", 0, payload["conclusion"]),
        _link("subject", 0, payload["subject"]),
        _link("certified_outcome", 0, payload["certified_outcome"]),
        _link("eligibility", 0, payload["eligibility"]),
        _link("activation_policy", 0, payload["activation_policy"]),
        _link("policy_calibration", 0, payload["policy_calibration"]),
    ]
    for role, item in (
        ("requalification_window", payload["requalification_window"]),
        ("rollback_request", rollback),
    ):
        if item is not None:
            expected.append(_link(role, 0, item))
    for name, slot in (("monitor", monitor), ("requalification", requalification)):
        if slot["observed_occupant"] is not None:
            expected.append(_link(f"observed_slot:{name}", 0, slot["observed_occupant"]))
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind mutation authority")
    return payload


POST_ACTIVATION_REPOSITORY_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            CERTIFIED_POST_ACTIVATION_OUTCOME_SCHEMA_ID,
            "certified_post_activation_outcome",
            _outcome_payload,
        ),
        RecordSchema(
            POST_ACTIVATION_ELIGIBILITY_SCHEMA_ID,
            "post_activation_eligibility",
            _eligibility_payload,
        ),
        RecordSchema(
            POST_ACTIVATION_CONCLUSION_SCHEMA_ID,
            "post_activation_conclusion",
            _conclusion_payload,
        ),
        RecordSchema(
            REQUALIFICATION_WINDOW_SCHEMA_ID,
            "evidence_requalification_window",
            _window_payload,
        ),
        RecordSchema(
            ROLLBACK_AUTHORITY_REQUEST_SCHEMA_ID,
            "rollback_authority_request",
            _rollback_payload,
        ),
        RecordSchema(
            POST_ACTIVATION_RECEIPT_SCHEMA_ID,
            "post_activation_mutation_receipt",
            _receipt_payload,
        ),
    )
)


@dataclass(frozen=True, slots=True)
class PostActivationAuthority:
    actor_authority_ref: str
    issuer_ref: str
    subject_ref: str


@dataclass(frozen=True, slots=True)
class PostActivationOperation:
    action: Literal[
        "monitor_conclude", "requalification_start", "requalification_conclude"
    ]
    context_ref: str
    expected_scope_revision: int
    monitor_slot: SlotBinding
    requalification_slot: SlotBinding
    subject: ExactRecord
    certified_outcome: ExactRecord
    eligibility: ExactRecord
    policy: ExactRecord
    calibration: ExactRecord
    authority: PostActivationAuthority
    conclusion_record_id: str
    requalification_window_id: str | None
    idempotency_key_digest: str
    request_digest: str
    key_epoch: str


PostActivationAuthorityRevalidator = Callable[
    [V3Transaction, PostActivationOperation], PostActivationAuthority
]


@dataclass(frozen=True, slots=True)
class PostActivationCommitResult:
    conclusion: TypedRecord
    receipt: TypedRecord
    monitor_slot: OperationSlot | None
    requalification_slot: OperationSlot | None
    requalification_window: TypedRecord | None
    rollback_request: TypedRecord | None
    command: OperatorCommand
    replayed: bool


def build_certified_post_activation_outcome(
    *,
    record_id: str,
    context_ref: str,
    subject: ExactRecord,
    producer: ExactRecord,
    reducer_profile: ExactRecord,
    measurement_bundle: ExactRecord,
    decision: str,
    key_epoch: str,
) -> TypedRecord:
    values = tuple(
        item.payload()
        for item in (subject, producer, reducer_profile, measurement_bundle)
    )
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="certified_post_activation_outcome",
        schema_id=CERTIFIED_POST_ACTIVATION_OUTCOME_SCHEMA_ID,
        payload={
            "outcome_type": "certified_post_activation_outcome",
            "authority_ceiling": "materialize_conclusion_only",
            "subject": values[0],
            "producer": values[1],
            "reducer_profile": values[2],
            "measurement_bundle": values[3],
            "decision": decision,
            "links": [
                _link("subject", 0, values[0]),
                _link("certified_producer", 0, values[1]),
                _link("reducer_profile", 0, values[2]),
                _link("measurement_bundle", 0, values[3]),
            ],
        },
        key_epoch=key_epoch,
        registry=POST_ACTIVATION_REPOSITORY_REGISTRY,
    )


def build_post_activation_eligibility(
    *,
    record_id: str,
    context_ref: str,
    action: str,
    decision: str,
    scope_revision: int,
    active_profile: ExactRecord,
    subject: ExactRecord,
    certified_outcome: ExactRecord,
    policy: ExactRecord,
    calibration: ExactRecord,
    key_epoch: str,
) -> TypedRecord:
    inputs = tuple(
        item.payload()
        for item in (
            active_profile,
            subject,
            certified_outcome,
            policy,
            calibration,
        )
    )
    roles = (
        "active_profile",
        "subject",
        "certified_outcome",
        "activation_policy",
        "policy_calibration",
    )
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="post_activation_eligibility",
        schema_id=POST_ACTIVATION_ELIGIBILITY_SCHEMA_ID,
        payload={
            "eligibility_type": "post_activation_eligibility",
            "action": action,
            "eligible": True,
            "decision": decision,
            "scope_revision": scope_revision,
            "active_profile": inputs[0],
            "subject": inputs[1],
            "certified_outcome": inputs[2],
            "activation_policy": inputs[3],
            "policy_calibration": inputs[4],
            "links": [
                _link(role, 0, item) for role, item in zip(roles, inputs, strict=True)
            ],
        },
        key_epoch=key_epoch,
        registry=POST_ACTIVATION_REPOSITORY_REGISTRY,
    )


class RepositoryPostActivationCoordinator:
    def __init__(self, repository: V3Repository, *, key_epoch: str) -> None:
        if not isinstance(repository, V3Repository) or not key_epoch:
            raise TypeError("post-activation coordination requires repository and key epoch")
        self._repository = repository
        self._key_epoch = key_epoch

    def commit(
        self,
        operation: PostActivationOperation,
        *,
        revalidate_authority: PostActivationAuthorityRevalidator,
    ) -> PostActivationCommitResult:
        _validate_operation(operation)
        if operation.key_epoch != self._key_epoch:
            raise IntegrityFailure("post-activation key epoch changed")
        if not callable(revalidate_authority):
            raise TypeError("post-activation authority revalidator is required")
        with self._repository.transaction() as transaction:
            replay = _existing_replay(transaction, operation)
            if replay is not None:
                return replay
            scope = transaction.get_activation_scope(operation.context_ref)
            if scope is None or scope.scope_revision != operation.expected_scope_revision:
                raise RevisionConflict("post-activation scope revision changed")
            monitor_slot = transaction.get_operation_slot(operation.context_ref, "monitor")
            requalification_slot = transaction.get_operation_slot(
                operation.context_ref, "requalification"
            )
            _require_slot(operation.monitor_slot, monitor_slot, "monitor")
            _require_slot(
                operation.requalification_slot,
                requalification_slot,
                "requalification",
            )
            expected_kind = (
                "post_promotion_monitor"
                if operation.action != "requalification_conclude"
                else "evidence_requalification_window"
            )
            expected_schema = (
                POST_PROMOTION_MONITOR_SCHEMA_ID
                if operation.action != "requalification_conclude"
                else REQUALIFICATION_WINDOW_SCHEMA_ID
            )
            subject = _require_exact(
                transaction,
                operation.subject,
                operation.context_ref,
                expected_schema,
                expected_kind,
            )
            outcome = _require_exact(
                transaction,
                operation.certified_outcome,
                operation.context_ref,
                CERTIFIED_POST_ACTIVATION_OUTCOME_SCHEMA_ID,
                "certified_post_activation_outcome",
            )
            eligibility = _require_exact(
                transaction,
                operation.eligibility,
                operation.context_ref,
                POST_ACTIVATION_ELIGIBILITY_SCHEMA_ID,
                "post_activation_eligibility",
            )
            policy = _require_exact(
                transaction,
                operation.policy,
                operation.context_ref,
                ACTIVATION_POLICY_SCHEMA_ID,
                "activation_policy",
            )
            calibration = _require_exact(
                transaction,
                operation.calibration,
                operation.context_ref,
                POLICY_CALIBRATION_SCHEMA_ID,
                "policy_calibration",
            )
            _require_current_calibration(transaction, calibration)
            _validate_bindings(
                operation, scope, subject, outcome, eligibility, policy, calibration
            )
            admitted = revalidate_authority(transaction, operation)
            if admitted != operation.authority:
                raise IntegrityFailure("post-activation authority changed in transaction")

            conclusion = _build_conclusion(operation, outcome, eligibility)
            transaction.insert_record(conclusion)
            window = None
            if operation.action == "requalification_start":
                window = _build_window(operation, conclusion, scope)
                transaction.insert_record(window)
            rollback_request = None
            if outcome.payload["decision"] == "rollback_required":
                rollback_request = _build_rollback_request(
                    operation, conclusion, scope.current_profile_id, scope.current_profile_digest
                )
                transaction.insert_record(rollback_request)

            if operation.action in ("monitor_conclude", "requalification_start"):
                assert operation.monitor_slot.occupant is not None
                monitor_slot = transaction.clear_exact_operation_slot(
                    context_ref=operation.context_ref,
                    operation_kind="monitor",
                    expected_revision=operation.monitor_slot.revision,
                    expected_scope_revision=operation.expected_scope_revision,
                    operation_id=operation.monitor_slot.occupant.record_id,
                    operation_digest=operation.monitor_slot.occupant.digest,
                )
            if operation.action == "requalification_start":
                assert window is not None
                requalification_slot = transaction.claim_empty_operation_slot(
                    context_ref=operation.context_ref,
                    operation_kind="requalification",
                    expected_revision=operation.requalification_slot.revision,
                    expected_scope_revision=operation.expected_scope_revision,
                    operation_id=window.record_id,
                    operation_digest=window.content_digest,
                )
            elif operation.action == "requalification_conclude":
                assert operation.requalification_slot.occupant is not None
                requalification_slot = transaction.clear_exact_operation_slot(
                    context_ref=operation.context_ref,
                    operation_kind="requalification",
                    expected_revision=operation.requalification_slot.revision,
                    expected_scope_revision=operation.expected_scope_revision,
                    operation_id=operation.requalification_slot.occupant.record_id,
                    operation_digest=operation.requalification_slot.occupant.digest,
                )
            sequence = transaction.next_domain_event_sequence(subject.record_id)
            receipt = _build_receipt(
                operation,
                conclusion,
                outcome,
                eligibility,
                monitor_slot,
                requalification_slot,
                window,
                rollback_request,
                sequence,
            )
            transaction.insert_record(receipt)
            transaction.append_event(_build_event(operation, subject, receipt, sequence))
            command = transaction.admit_command(_build_command(operation, receipt))
            if command.replayed:
                raise IntegrityFailure("post-activation command changed in transaction")
            return PostActivationCommitResult(
                conclusion,
                receipt,
                monitor_slot,
                requalification_slot,
                window,
                rollback_request,
                command.command,
                False,
            )


def digest_post_activation_request(operation: PostActivationOperation) -> str:
    payload = {
        "action": operation.action,
        "context_ref": operation.context_ref,
        "expected_scope_revision": operation.expected_scope_revision,
        "monitor_slot": _slot_binding(operation.monitor_slot),
        "requalification_slot": _slot_binding(operation.requalification_slot),
        "subject": operation.subject.payload(),
        "certified_outcome": operation.certified_outcome.payload(),
        "eligibility": operation.eligibility.payload(),
        "policy": operation.policy.payload(),
        "calibration": operation.calibration.payload(),
        "authority": {
            "actor_authority_ref": operation.authority.actor_authority_ref,
            "issuer_ref": operation.authority.issuer_ref,
            "subject_ref": operation.authority.subject_ref,
        },
        "conclusion_record_id": operation.conclusion_record_id,
        "requalification_window_id": operation.requalification_window_id,
        "idempotency_key_digest": operation.idempotency_key_digest,
        "key_epoch": operation.key_epoch,
    }
    return schema_digest(
        "post-activation-request",
        "a0.post-activation-request.v1",
        canonical_json(payload),
    )


def _validate_operation(operation: PostActivationOperation) -> None:
    if type(operation) is not PostActivationOperation:
        raise TypeError("one exact PostActivationOperation is required")
    if operation.action not in POST_ACTIVATION_ACTIONS:
        raise TypeError("post-activation action is not admitted")
    validate_digest(operation.idempotency_key_digest, "idempotency_key_digest")
    validate_digest(operation.request_digest, "request_digest")
    if operation.request_digest != digest_post_activation_request(operation):
        raise IntegrityFailure("post-activation request digest is not exact")
    if operation.action == "requalification_start":
        if operation.requalification_window_id is None:
            raise TypeError("requalification start requires an exact window identity")
    elif operation.requalification_window_id is not None:
        raise TypeError("only requalification start may create a window")
    for value in (
        operation.context_ref,
        operation.conclusion_record_id,
        operation.key_epoch,
        operation.authority.actor_authority_ref,
        operation.authority.issuer_ref,
        operation.authority.subject_ref,
    ):
        if type(value) is not str or not value:
            raise TypeError("post-activation identities must be non-empty")


def _validate_bindings(operation, scope, subject, outcome, eligibility, policy, calibration):
    subject_exact = ExactRecord.of(subject).payload()
    outcome_exact = ExactRecord.of(outcome).payload()
    policy_exact = ExactRecord.of(policy).payload()
    calibration_exact = ExactRecord.of(calibration).payload()
    active = {"record_id": scope.current_profile_id, "digest": scope.current_profile_digest}
    ep = eligibility.payload
    if (
        outcome.payload["subject"] != subject_exact
        or ep["action"] != operation.action
        or ep["decision"] != outcome.payload["decision"]
        or ep["scope_revision"] != operation.expected_scope_revision
        or ep["active_profile"] != active
        or ep["subject"] != subject_exact
        or ep["certified_outcome"] != outcome_exact
        or ep["activation_policy"] != policy_exact
        or ep["policy_calibration"] != calibration_exact
    ):
        raise IntegrityFailure("post-activation certified facts are not exact")
    if (
        calibration.payload["status"] != "approved"
        or calibration.payload["policy_id"] != policy.record_id
        or calibration.payload["policy_digest"] != policy.content_digest
        or calibration.payload["policy_revision"] != policy.payload["policy_revision"]
    ):
        raise IntegrityFailure("post-activation calibration does not bind policy")
    if subject.record_kind == "post_promotion_monitor":
        sp = subject.payload
        if (
            (sp["policy_id"], sp["policy_digest"])
            != (policy.record_id, policy.content_digest)
            or (sp["calibration_id"], sp["calibration_digest"])
            != (calibration.record_id, calibration.content_digest)
            or sp["resulting_scope_revision"] != operation.expected_scope_revision
        ):
            raise IntegrityFailure("active monitor lost exact activation inputs")
    else:
        sp = subject.payload
        if (
            sp["active_profile"] != active
            or sp["activation_policy"] != policy_exact
            or sp["policy_calibration"] != calibration_exact
            or sp["scope_revision"] != operation.expected_scope_revision
        ):
            raise IntegrityFailure("requalification window lost exact inputs")
    decision = outcome.payload["decision"]
    if operation.action == "requalification_start" and decision != "requalify":
        raise IntegrityFailure("requalification start requires explicit requalify outcome")
    if operation.action != "requalification_start" and decision == "requalify":
        raise IntegrityFailure("requalify outcome requires requalification start")


def _require_current_calibration(transaction: V3Transaction, calibration: TypedRecord) -> None:
    facts: list[CalibrationLifecycleFact] = []
    for sequence in range(transaction.next_domain_event_sequence(calibration.record_id)):
        event = transaction.get_domain_event(calibration.record_id, sequence)
        if event is None or event.payload_record_id is None:
            raise IntegrityFailure("policy calibration lifecycle is incomplete")
        receipt = transaction.get_record(event.payload_record_id)
        if receipt is None:
            raise IntegrityFailure("policy calibration lifecycle lost its receipt")
        receipt.verify(CALIBRATION_AUTHORITY_REGISTRY)
        facts.append(CalibrationLifecycleFact(receipt, event))
    try:
        current = reduce_calibration_eligibility(calibration, tuple(facts))
    except CalibrationAuthorityError as exc:
        raise IntegrityFailure("policy calibration lifecycle is not authoritative") from exc
    if current.state != "approved":
        raise IntegrityFailure("policy calibration is not currently approved")


def _build_conclusion(operation, outcome, eligibility):
    subject = operation.subject.payload()
    outcome_exact = ExactRecord.of(outcome).payload()
    eligibility_exact = ExactRecord.of(eligibility).payload()
    return build_typed_record(
        record_id=operation.conclusion_record_id,
        context_ref=operation.context_ref,
        record_kind="post_activation_conclusion",
        schema_id=POST_ACTIVATION_CONCLUSION_SCHEMA_ID,
        payload={
            "conclusion_type": "requalification" if operation.action == "requalification_conclude" else "monitor",
            "decision": outcome.payload["decision"],
            "subject": subject,
            "certified_outcome": outcome_exact,
            "eligibility": eligibility_exact,
            "observed_scope_revision": operation.expected_scope_revision,
            "resulting_scope_revision": operation.expected_scope_revision,
            "profile_mutation": "none",
            "links": [
                _link("subject", 0, subject),
                _link("certified_outcome", 0, outcome_exact),
                _link("eligibility", 0, eligibility_exact),
            ],
        },
        key_epoch=operation.key_epoch,
        registry=POST_ACTIVATION_REPOSITORY_REGISTRY,
    )


def _build_window(operation, conclusion, scope):
    values = {
        "monitor": operation.subject.payload(),
        "monitor_conclusion": ExactRecord.of(conclusion).payload(),
        "certified_outcome": operation.certified_outcome.payload(),
        "eligibility": operation.eligibility.payload(),
        "active_profile": {"record_id": scope.current_profile_id, "digest": scope.current_profile_digest},
        "activation_policy": operation.policy.payload(),
        "policy_calibration": operation.calibration.payload(),
    }
    return build_typed_record(
        record_id=operation.requalification_window_id,
        context_ref=operation.context_ref,
        record_kind="evidence_requalification_window",
        schema_id=REQUALIFICATION_WINDOW_SCHEMA_ID,
        payload={
            "fact_type": "evidence_requalification_window",
            **values,
            "scope_revision": operation.expected_scope_revision,
            "links": [_link(role, 0, value) for role, value in values.items()],
        },
        key_epoch=operation.key_epoch,
        registry=POST_ACTIVATION_REPOSITORY_REGISTRY,
    )


def _build_rollback_request(operation, conclusion, profile_id, profile_digest):
    conclusion_exact = ExactRecord.of(conclusion).payload()
    profile = {"record_id": profile_id, "digest": profile_digest}
    return build_typed_record(
        record_id=_stable_id("rollback-authority-request", operation.request_digest),
        context_ref=operation.context_ref,
        record_kind="rollback_authority_request",
        schema_id=ROLLBACK_AUTHORITY_REQUEST_SCHEMA_ID,
        payload={
            "request_type": "rollback_authority_request",
            "authority_ceiling": "request_only",
            "conclusion": conclusion_exact,
            "active_profile": profile,
            "observed_scope_revision": operation.expected_scope_revision,
            "profile_mutation": "none",
            "links": [
                _link("conclusion", 0, conclusion_exact),
                _link("active_profile", 0, profile),
            ],
        },
        key_epoch=operation.key_epoch,
        registry=POST_ACTIVATION_REPOSITORY_REGISTRY,
    )


def _build_receipt(operation, conclusion, outcome, eligibility, monitor, requalification, window, rollback, sequence):
    monitor_transition = _slot_transition("monitor", operation.monitor_slot, monitor)
    requalification_transition = _slot_transition(
        "requalification", operation.requalification_slot, requalification
    )
    exacts = {
        "conclusion": ExactRecord.of(conclusion).payload(),
        "subject": operation.subject.payload(),
        "certified_outcome": ExactRecord.of(outcome).payload(),
        "eligibility": ExactRecord.of(eligibility).payload(),
        "activation_policy": operation.policy.payload(),
        "policy_calibration": operation.calibration.payload(),
        "requalification_window": None if window is None else ExactRecord.of(window).payload(),
        "rollback_request": None if rollback is None else ExactRecord.of(rollback).payload(),
    }
    links = [
        _link(role, 0, exacts[role])
        for role in ("conclusion", "subject", "certified_outcome", "eligibility", "activation_policy", "policy_calibration")
    ]
    for role in ("requalification_window", "rollback_request"):
        if exacts[role] is not None:
            links.append(_link(role, 0, exacts[role]))
    for name, transition in (("monitor", monitor_transition), ("requalification", requalification_transition)):
        if transition["observed_occupant"] is not None:
            links.append(_link(f"observed_slot:{name}", 0, transition["observed_occupant"]))
    return build_typed_record(
        record_id=_receipt_id(operation),
        context_ref=operation.context_ref,
        record_kind="post_activation_mutation_receipt",
        schema_id=POST_ACTIVATION_RECEIPT_SCHEMA_ID,
        payload={
            "receipt_type": "post_activation_mutation",
            "accepted": True,
            "action": operation.action,
            "decision": outcome.payload["decision"],
            "context_ref": operation.context_ref,
            **exacts,
            "observed_scope_revision": operation.expected_scope_revision,
            "resulting_scope_revision": operation.expected_scope_revision,
            "monitor_slot": monitor_transition,
            "requalification_slot": requalification_transition,
            "actor_authority_ref": operation.authority.actor_authority_ref,
            "issuer_ref": operation.authority.issuer_ref,
            "subject_ref": operation.authority.subject_ref,
            "idempotency_key_digest": operation.idempotency_key_digest,
            "request_digest": operation.request_digest,
            "event_sequence": sequence,
            "links": links,
        },
        key_epoch=operation.key_epoch,
        registry=POST_ACTIVATION_REPOSITORY_REGISTRY,
    )


def _build_event(operation, subject, receipt, sequence):
    return DomainEvent(
        event_id=_stable_id("post-activation-event", operation.request_digest),
        subject_id=subject.record_id,
        subject_kind=subject.record_kind,
        sequence=sequence,
        event_type=operation.action,
        payload_record_id=receipt.record_id,
        actor_authority_ref=operation.authority.actor_authority_ref,
    )


def _build_command(operation, receipt):
    return OperatorCommand(
        command_id=_stable_id("post-activation-command", operation.request_digest),
        issuer_ref=operation.authority.issuer_ref,
        subject_ref=operation.authority.subject_ref,
        context_ref=operation.context_ref,
        action=operation.action,
        idempotency_key_digest=operation.idempotency_key_digest,
        request_digest=operation.request_digest,
        observed_revision=operation.expected_scope_revision,
        state="accepted",
        mutation_receipt_id=receipt.record_id,
    )


def _existing_replay(transaction, operation):
    command = transaction.get_operator_command(
        issuer_ref=operation.authority.issuer_ref,
        subject_ref=operation.authority.subject_ref,
        context_ref=operation.context_ref,
        action=operation.action,
        idempotency_key_digest=operation.idempotency_key_digest,
    )
    if command is None:
        return None
    if command.request_digest != operation.request_digest:
        raise IdempotencyConflict("post-activation request changed for idempotency key")
    receipt = transaction.get_record(command.mutation_receipt_id)
    if receipt is None or receipt.schema_id != POST_ACTIVATION_RECEIPT_SCHEMA_ID:
        raise IntegrityFailure("post-activation replay lost its exact receipt")
    receipt.verify(POST_ACTIVATION_REPOSITORY_REGISTRY)
    payload = receipt.payload
    if (
        payload["request_digest"] != operation.request_digest
        or payload["action"] != operation.action
        or payload["subject"] != operation.subject.payload()
        or payload["certified_outcome"] != operation.certified_outcome.payload()
        or payload["eligibility"] != operation.eligibility.payload()
    ):
        raise IntegrityFailure("post-activation replay differs from exact request")
    conclusion = _load_exact(transaction, payload["conclusion"])
    window = None if payload["requalification_window"] is None else _load_exact(transaction, payload["requalification_window"])
    rollback = None if payload["rollback_request"] is None else _load_exact(transaction, payload["rollback_request"])
    monitor = transaction.get_operation_slot(operation.context_ref, "monitor")
    requalification = transaction.get_operation_slot(operation.context_ref, "requalification")
    _require_resulting_slot(payload["monitor_slot"], monitor)
    _require_resulting_slot(payload["requalification_slot"], requalification)
    scope = transaction.get_activation_scope(operation.context_ref)
    if scope is None or scope.scope_revision != payload["resulting_scope_revision"]:
        raise RevisionConflict("Activation Scope changed before post-activation replay")
    event = _build_event(operation, _load_exact(transaction, payload["subject"]), receipt, payload["event_sequence"])
    if transaction.get_domain_event(payload["subject"]["record_id"], payload["event_sequence"]) != event:
        raise IntegrityFailure("post-activation replay lost its event")
    return PostActivationCommitResult(conclusion, receipt, monitor, requalification, window, rollback, command, True)


def _require_exact(transaction, exact, context_ref, schema_id, record_kind):
    record = transaction.get_record(exact.record_id)
    if (
        record is None
        or record.content_digest != exact.digest
        or record.context_ref != context_ref
        or record.schema_id != schema_id
        or record.record_kind != record_kind
    ):
        raise IntegrityFailure("post-activation exact record binding failed")
    return record


def _load_exact(transaction, exact):
    record = transaction.get_record(exact["record_id"])
    if record is None or record.content_digest != exact["digest"]:
        raise IntegrityFailure("post-activation replay lost an exact record")
    return record


def _require_slot(expected, actual, kind):
    revision = 0 if actual is None else actual.operation_revision
    occupant = None if actual is None or actual.operation_id is None else ExactRecord(actual.operation_id, actual.operation_digest or "")
    if expected.revision != revision or expected.occupant != occupant:
        raise RevisionConflict(f"{kind} slot revision or occupant changed")


def _require_resulting_slot(expected, actual):
    revision = 0 if actual is None else actual.operation_revision
    occupant = None if actual is None or actual.operation_id is None else {"record_id": actual.operation_id, "digest": actual.operation_digest}
    if revision != expected["resulting_revision"] or occupant != expected["resulting_occupant"]:
        raise RevisionConflict("post-activation replay slot changed")


def _slot_binding(slot):
    return {"revision": slot.revision, "occupant": None if slot.occupant is None else slot.occupant.payload()}


def _slot_transition(operation_kind, observed, resulting):
    return {
        "operation_kind": operation_kind,
        "observed_revision": observed.revision,
        "resulting_revision": 0 if resulting is None else resulting.operation_revision,
        "observed_occupant": None if observed.occupant is None else observed.occupant.payload(),
        "resulting_occupant": None if resulting is None or resulting.operation_id is None else {"record_id": resulting.operation_id, "digest": resulting.operation_digest},
    }


def _cleared(slot):
    return slot["observed_occupant"] is not None and slot["resulting_occupant"] is None and slot["resulting_revision"] == slot["observed_revision"] + 1


def _claimed(slot, exact):
    return slot["observed_occupant"] is None and slot["resulting_occupant"] == exact and slot["resulting_revision"] == slot["observed_revision"] + 1


def _unchanged_empty(slot):
    return slot["observed_occupant"] is None and slot["resulting_occupant"] is None and slot["resulting_revision"] == slot["observed_revision"]


def _receipt_id(operation):
    material = "\0".join((operation.authority.issuer_ref, operation.authority.subject_ref, operation.context_ref, operation.action, operation.idempotency_key_digest))
    return f"post-activation-receipt:{sha256(material.encode()).hexdigest()}"


def _stable_id(namespace, request_digest):
    return f"{namespace}:{sha256((namespace + chr(0) + request_digest).encode()).hexdigest()}"


def _link(role: str, ordinal: int, exact: Mapping[str, Any]) -> dict[str, Any]:
    return {"role": role, "ordinal": ordinal, "target_id": exact["record_id"], "target_digest": exact["digest"]}


__all__ = [
    "CERTIFIED_POST_ACTIVATION_OUTCOME_SCHEMA_ID",
    "POST_ACTIVATION_ELIGIBILITY_SCHEMA_ID",
    "POST_ACTIVATION_CONCLUSION_SCHEMA_ID",
    "REQUALIFICATION_WINDOW_SCHEMA_ID",
    "ROLLBACK_AUTHORITY_REQUEST_SCHEMA_ID",
    "POST_ACTIVATION_RECEIPT_SCHEMA_ID",
    "POST_ACTIVATION_REPOSITORY_REGISTRY",
    "PostActivationError",
    "PostActivationAuthority",
    "PostActivationOperation",
    "PostActivationAuthorityRevalidator",
    "PostActivationCommitResult",
    "RepositoryPostActivationCoordinator",
    "build_certified_post_activation_outcome",
    "build_post_activation_eligibility",
    "digest_post_activation_request",
]
