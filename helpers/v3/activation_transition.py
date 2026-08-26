"""Durable, exact-revision activation, rollback, and Safety Bypass authority.

The coordinator owns one SQLite transaction.  It accepts immutable facts, asks
the local authority boundary to revalidate the exact grant *inside* that
transaction, and never accepts caller-supplied eligibility booleans.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from .artifacts import (
    NULL_GUIDANCE_RECORD_ID,
    NULL_PROMPT_PATCH_RECORD_ID,
)
from .authority import AuthorityClass, AuthorityPurpose, VerifiedGrant
from .canary import (
    ActivationEligibility,
    CANARY_REGISTRY,
    RecordIdentity,
)
from .candidate_publication import CANDIDATE_PUBLICATION_REGISTRY
from .model_routes import MODEL_ROUTE_REGISTRY
from .repository import (
    ActivationScope,
    DomainEvent,
    IntegrityFailure,
    IdempotencyConflict,
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
    merge_schema_registries,
    schema_digest,
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


ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID = "a0.activation-transition-receipt.v1"
_ACTIONS = ("activate", "rollback", "safety_bypass")
_SLOT_KINDS = ("canary", "monitor", "requalification")
_CAPABILITY_KINDS = (
    "worker_dependency_capability_certificate",
    "provider_capability_certificate",
    "replay_capability_certificate",
)


class ActivationTransitionDenied(RuntimeError):
    """Stable fail-closed denial from the transition authority."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _deny(reason_code: str) -> None:
    raise ActivationTransitionDenied(reason_code)


@dataclass(frozen=True, slots=True)
class ExactRecord:
    record_id: str
    digest: str

    def __post_init__(self) -> None:
        if type(self.record_id) is not str or not self.record_id:
            raise ValueError("record_id must be non-empty")
        validate_digest(self.digest, "digest")

    @classmethod
    def of(cls, record: TypedRecord) -> "ExactRecord":
        return cls(record.record_id, record.content_digest)


@dataclass(frozen=True, slots=True)
class SlotExpectation:
    operation_kind: str
    revision: int
    occupant: ExactRecord | None

    def __post_init__(self) -> None:
        if self.operation_kind not in _SLOT_KINDS:
            raise ValueError("operation_kind is not admitted")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("slot revision must be a non-negative integer")
        if self.occupant is not None and type(self.occupant) is not ExactRecord:
            raise ValueError("slot occupant must be an ExactRecord or null")


@dataclass(frozen=True, slots=True)
class ActivationAuthorityFacts:
    dependency_profile: ExactRecord
    capability_certificate: ExactRecord
    fixture_manifests: tuple[ExactRecord, ...]

    def __post_init__(self) -> None:
        if type(self.dependency_profile) is not ExactRecord:
            raise ValueError("dependency_profile must be exact")
        if type(self.capability_certificate) is not ExactRecord:
            raise ValueError("capability_certificate must be exact")
        if type(self.fixture_manifests) is not tuple or not self.fixture_manifests:
            raise ValueError("at least one exact fixture manifest is required")
        if any(type(item) is not ExactRecord for item in self.fixture_manifests):
            raise ValueError("fixture_manifests must contain exact records")
        refs = tuple(item.record_id for item in self.fixture_manifests)
        if refs != tuple(sorted(set(refs))):
            raise ValueError("fixture_manifests must be sorted and unique")


@dataclass(frozen=True, slots=True)
class TransitionCommand:
    issuer_ref: str
    subject_ref: str
    context_ref: str
    target_ref: str
    expected_scope_revision: int
    idempotency_key_digest: str
    authority_grant_id: str
    now: datetime

    def __post_init__(self) -> None:
        for name in (
            "issuer_ref",
            "subject_ref",
            "context_ref",
            "target_ref",
            "authority_grant_id",
        ):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if type(self.expected_scope_revision) is not int or self.expected_scope_revision < 0:
            raise ValueError("expected_scope_revision must be non-negative")
        validate_digest(self.idempotency_key_digest, "idempotency_key_digest")
        if not isinstance(self.now, datetime) or self.now.tzinfo is None:
            raise ValueError("now must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ActivationRequest:
    command: TransitionCommand
    candidate: ExactRecord
    disposition: ExactRecord
    canary_conclusion: ExactRecord
    policy: ExactRecord
    calibration: ExactRecord
    successor_profile: ExactRecord
    monitor: TypedRecord
    eligibility: ActivationEligibility
    authorities: ActivationAuthorityFacts
    canary_slot: SlotExpectation
    monitor_slot: SlotExpectation
    requalification_slot: SlotExpectation


@dataclass(frozen=True, slots=True)
class RollbackRequest:
    command: TransitionCommand
    predecessor_activation_receipt: ExactRecord
    predecessor_profile: ExactRecord
    slots: tuple[SlotExpectation, SlotExpectation, SlotExpectation]


@dataclass(frozen=True, slots=True)
class SafetyBypassRequest:
    command: TransitionCommand
    null_profile: ExactRecord
    slots: tuple[SlotExpectation, SlotExpectation, SlotExpectation]


@dataclass(frozen=True, slots=True)
class ActivationTransitionResult:
    scope: ActivationScope
    receipt: TypedRecord
    command: OperatorCommand
    slots: tuple[OperationSlot | None, OperationSlot | None, OperationSlot | None]
    replayed: bool


GrantRevalidator = Callable[[V3Transaction], VerifiedGrant]


_EXACT = strict_object(
    {"record_id": strict_string(maximum=512), "digest": validate_digest}
)
_OPTIONAL_EXACT = strict_nullable(_EXACT)
_SLOT_TRANSITION = strict_object(
    {
        "operation_kind": strict_enum(_SLOT_KINDS),
        "observed_revision": strict_integer(minimum=0),
        "resulting_revision": strict_integer(minimum=0),
        "observed_occupant": _OPTIONAL_EXACT,
        "resulting_occupant": _OPTIONAL_EXACT,
        "reason_code": strict_enum(
            (
                "canary_concluded_for_activation",
                "monitor_started",
                "unchanged_empty",
                "rollback_stopped",
                "safety_bypass_stopped",
            )
        ),
    }
)


def _receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "receipt_type": strict_literal("activation_transition"),
            "accepted": strict_literal(True),
            "action": strict_enum(_ACTIONS),
            "context_ref": strict_string(maximum=128),
            "target_ref": strict_string(maximum=128),
            "observed_revision": strict_integer(minimum=0),
            "resulting_revision": strict_integer(minimum=1),
            "mode": strict_enum(("normal", "safety_bypass")),
            "from_profile": _EXACT,
            "to_profile": _EXACT,
            "candidate": _OPTIONAL_EXACT,
            "canary_conclusion": _OPTIONAL_EXACT,
            "activation_disposition": _OPTIONAL_EXACT,
            "activation_policy": _OPTIONAL_EXACT,
            "policy_calibration": _OPTIONAL_EXACT,
            "monitor": _OPTIONAL_EXACT,
            "ancestry_receipt": _OPTIONAL_EXACT,
            "dependency_profile": _OPTIONAL_EXACT,
            "capability_certificate": _OPTIONAL_EXACT,
            "fixture_manifests": strict_list(_EXACT, maximum=10_000),
            "slot_transitions": strict_list(_SLOT_TRANSITION, minimum=3, maximum=3),
            "authority_grant_id": strict_string(maximum=128),
            "issuer_ref": strict_string(maximum=128),
            "subject_ref": strict_string(maximum=128),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "reason_codes": strict_list(
                strict_enum(("candidate_activated", "predecessor_restored", "safety_bypass_applied")),
                minimum=1,
                maximum=1,
            ),
            "links": validate_links,
        }
    )(value, path)
    action = payload["action"]
    if payload["resulting_revision"] != payload["observed_revision"] + 1:
        raise SchemaValidationError(f"{path}.resulting_revision must advance exactly once")
    if [item["operation_kind"] for item in payload["slot_transitions"]] != list(_SLOT_KINDS):
        raise SchemaValidationError(f"{path}.slot_transitions must use canonical slot order")
    activated_fields = (
        "candidate",
        "canary_conclusion",
        "activation_disposition",
        "activation_policy",
        "policy_calibration",
        "monitor",
        "dependency_profile",
        "capability_certificate",
    )
    if action == "activate":
        if any(payload[name] is None for name in activated_fields):
            raise SchemaValidationError(f"{path} activation is missing exact authorities")
        if not payload["fixture_manifests"]:
            raise SchemaValidationError(f"{path} activation requires fixture authority")
        if payload["ancestry_receipt"] is not None or payload["mode"] != "normal":
            raise SchemaValidationError(f"{path} activation ancestry or mode is invalid")
        if payload["reason_codes"] != ["candidate_activated"]:
            raise SchemaValidationError(f"{path} activation reason is invalid")
    else:
        if any(payload[name] is not None for name in activated_fields):
            raise SchemaValidationError(f"{path} non-activation contains candidate authorities")
        if payload["fixture_manifests"]:
            raise SchemaValidationError(f"{path} non-activation cannot bind fixtures")
        if action == "rollback":
            if payload["ancestry_receipt"] is None or payload["mode"] != "normal":
                raise SchemaValidationError(f"{path} rollback ancestry or mode is invalid")
            if payload["reason_codes"] != ["predecessor_restored"]:
                raise SchemaValidationError(f"{path} rollback reason is invalid")
        elif (
            payload["ancestry_receipt"] is not None
            or payload["mode"] != "safety_bypass"
            or payload["reason_codes"] != ["safety_bypass_applied"]
        ):
            raise SchemaValidationError(f"{path} Safety Bypass receipt is invalid")

    canary, monitor, requalification = payload["slot_transitions"]
    if action == "activate":
        if not (
            canary["observed_occupant"] is not None
            and canary["resulting_occupant"] is None
            and canary["resulting_revision"] == canary["observed_revision"] + 1
            and canary["reason_code"] == "canary_concluded_for_activation"
            and monitor["observed_occupant"] is None
            and monitor["resulting_occupant"] == payload["monitor"]
            and monitor["resulting_revision"] == monitor["observed_revision"] + 1
            and monitor["reason_code"] == "monitor_started"
            and requalification["observed_occupant"] is None
            and requalification["resulting_occupant"] is None
            and requalification["resulting_revision"] == requalification["observed_revision"]
            and requalification["reason_code"] == "unchanged_empty"
        ):
            raise SchemaValidationError(f"{path} activation slot transitions are invalid")
    else:
        stopped_reason = (
            "rollback_stopped" if action == "rollback" else "safety_bypass_stopped"
        )
        for slot in payload["slot_transitions"]:
            if slot["observed_occupant"] is None:
                valid = (
                    slot["resulting_occupant"] is None
                    and slot["resulting_revision"] == slot["observed_revision"]
                    and slot["reason_code"] == "unchanged_empty"
                )
            else:
                valid = (
                    slot["resulting_occupant"] is None
                    and slot["resulting_revision"] == slot["observed_revision"] + 1
                    and slot["reason_code"] == stopped_reason
                )
            if not valid:
                raise SchemaValidationError(f"{path} stopped slot transition is invalid")

    expected: list[dict[str, Any]] = []
    for role, field in (
        ("from_profile", "from_profile"),
        ("to_profile", "to_profile"),
        ("candidate", "candidate"),
        ("canary_conclusion", "canary_conclusion"),
        ("activation_disposition", "activation_disposition"),
        ("activation_policy", "activation_policy"),
        ("policy_calibration", "policy_calibration"),
        ("monitor", "monitor"),
        ("ancestry_receipt", "ancestry_receipt"),
        ("dependency_profile", "dependency_profile"),
        ("capability_certificate", "capability_certificate"),
    ):
        item = payload[field]
        if item is not None:
            expected.append(_link(role, 0, item))
    expected.extend(
        _link("fixture_manifest", index, item)
        for index, item in enumerate(payload["fixture_manifests"])
    )
    expected.extend(
        _link(f"stopped_slot:{item['operation_kind']}", 0, item["observed_occupant"])
        for item in payload["slot_transitions"]
        if item["observed_occupant"] is not None
        and not (
            action == "activate"
            and item["operation_kind"] == "monitor"
            and item["observed_occupant"] == payload["monitor"]
        )
    )
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact transition facts")
    return payload


_TRANSITION_ONLY_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID,
            "activation_transition_receipt",
            _receipt_validator,
        ),
    )
)
ACTIVATION_TRANSITION_REGISTRY = merge_schema_registries(
    CANDIDATE_PUBLICATION_REGISTRY,
    CANARY_REGISTRY,
    MODEL_ROUTE_REGISTRY,
    _TRANSITION_ONLY_REGISTRY,
)


def activate_candidate(
    repository: V3Repository,
    *,
    request: ActivationRequest,
    revalidate_grant: GrantRevalidator,
) -> ActivationTransitionResult:
    """Activate one exact published successor and start its exact monitor."""

    command = request.command
    expected_slots = _canonical_slots(
        (request.canary_slot, request.monitor_slot, request.requalification_slot)
    )
    request_payload = {
        "action": "activate",
        "command": _command_payload(command),
        "candidate": _exact_payload(request.candidate),
        "disposition": _exact_payload(request.disposition),
        "canary_conclusion": _exact_payload(request.canary_conclusion),
        "policy": _exact_payload(request.policy),
        "calibration": _exact_payload(request.calibration),
        "successor_profile": _exact_payload(request.successor_profile),
        "monitor": _exact_payload(ExactRecord.of(request.monitor)),
        "eligibility": _eligibility_payload(request.eligibility),
        "authorities": _authority_payload(request.authorities),
        "slots": [_slot_payload(item) for item in expected_slots],
    }
    request_digest = _request_digest(request_payload)
    with repository.transaction() as transaction:
        grant = _verified_grant(
            transaction, command, "activate", revalidate_grant
        )
        replay = _existing_command_replay(
            transaction, command, "activate", request_digest, grant
        )
        if replay is not None:
            return replay
        scope = _require_scope(transaction, command)
        records = _validate_activation_records(transaction, request, scope)
        current_slots = _require_slots(transaction, command.context_ref, expected_slots)
        canary_slot, monitor_slot, requalification_slot = current_slots
        if canary_slot is None or canary_slot.operation_id is None:
            _deny("exact_canary_slot_occupant_required")
        if monitor_slot is not None and monitor_slot.operation_id is not None:
            _deny("monitor_slot_occupied")
        if requalification_slot is not None and requalification_slot.operation_id is not None:
            _deny("requalification_slot_occupied")
        conclusion = records["conclusion"]
        if (
            canary_slot.operation_id != conclusion.payload["trial_id"]
            or canary_slot.operation_digest != conclusion.payload["trial_digest"]
        ):
            _deny("canary_slot_conclusion_mismatch")

        transaction.insert_record(request.monitor)
        resulting_slots = (
            _cleared_transition(request.canary_slot, "canary_concluded_for_activation"),
            _claimed_transition(
                request.monitor_slot,
                ExactRecord.of(request.monitor),
                "monitor_started",
            ),
            _unchanged_transition(request.requalification_slot),
        )
        receipt = _build_receipt(
            action="activate",
            command=command,
            request_digest=request_digest,
            grant=grant,
            from_profile=ExactRecord(scope.current_profile_id, scope.current_profile_digest),
            to_profile=request.successor_profile,
            candidate=request.candidate,
            conclusion=request.canary_conclusion,
            disposition=request.disposition,
            policy=request.policy,
            calibration=request.calibration,
            monitor=ExactRecord.of(request.monitor),
            ancestry=None,
            authorities=request.authorities,
            slot_transitions=resulting_slots,
            mode="normal",
            reason="candidate_activated",
        )
        receipt = transaction.insert_record(receipt).record
        admission = transaction.admit_command(
            _operator_command(command, "activate", request_digest, grant, receipt)
        )
        if admission.replayed:
            return _replayed_result(
                transaction, command, receipt, admission.command, resulting_slots
            )

        cleared = transaction.clear_exact_operation_slot(
            context_ref=command.context_ref,
            operation_kind="canary",
            expected_revision=request.canary_slot.revision,
            expected_scope_revision=command.expected_scope_revision,
            operation_id=canary_slot.operation_id,
            operation_digest=canary_slot.operation_digest or "",
        )
        scope = transaction.compare_and_swap_activation_scope(
            context_ref=command.context_ref,
            expected_revision=command.expected_scope_revision,
            profile_id=request.successor_profile.record_id,
            profile_digest=request.successor_profile.digest,
            mode="normal",
        )
        claimed = transaction.claim_empty_operation_slot(
            context_ref=command.context_ref,
            operation_kind="monitor",
            expected_revision=request.monitor_slot.revision,
            expected_scope_revision=scope.scope_revision,
            operation_id=request.monitor.record_id,
            operation_digest=request.monitor.content_digest,
        )
        transaction.append_event(
            DomainEvent(
                event_id=_identity("canary-slot-cleared", request_digest),
                subject_id=canary_slot.operation_id,
                subject_kind="canary_trial",
                sequence=transaction.next_domain_event_sequence(canary_slot.operation_id),
                event_type="canary_slot_cleared_for_activation",
                payload_record_id=receipt.record_id,
                actor_authority_ref=grant.grant_id,
            )
        )
        transaction.append_event(
            DomainEvent(
                event_id=_identity("monitor-started", request_digest),
                subject_id=request.monitor.record_id,
                subject_kind="post_promotion_monitor",
                sequence=0,
                event_type="post_promotion_monitor_started",
                payload_record_id=receipt.record_id,
                actor_authority_ref=grant.grant_id,
            )
        )
        return ActivationTransitionResult(
            scope, receipt, admission.command, (cleared, claimed, requalification_slot), False
        )


def rollback_to_predecessor(
    repository: V3Repository,
    *,
    request: RollbackRequest,
    revalidate_grant: GrantRevalidator,
) -> ActivationTransitionResult:
    """Restore only the exact predecessor recorded by the current activation."""

    return _profile_transition(
        repository,
        action="rollback",
        command=request.command,
        target_profile=request.predecessor_profile,
        ancestry=request.predecessor_activation_receipt,
        slots=request.slots,
        revalidate_grant=revalidate_grant,
    )


def apply_safety_bypass(
    repository: V3Repository,
    *,
    request: SafetyBypassRequest,
    revalidate_grant: GrantRevalidator,
) -> ActivationTransitionResult:
    """Select an exact all-Null profile and stop every occupied operation slot."""

    return _profile_transition(
        repository,
        action="safety_bypass",
        command=request.command,
        target_profile=request.null_profile,
        ancestry=None,
        slots=request.slots,
        revalidate_grant=revalidate_grant,
    )


def _profile_transition(
    repository: V3Repository,
    *,
    action: str,
    command: TransitionCommand,
    target_profile: ExactRecord,
    ancestry: ExactRecord | None,
    slots: Iterable[SlotExpectation],
    revalidate_grant: GrantRevalidator,
) -> ActivationTransitionResult:
    expected_slots = _canonical_slots(slots)
    request_payload = {
        "action": action,
        "command": _command_payload(command),
        "target_profile": _exact_payload(target_profile),
        "ancestry": None if ancestry is None else _exact_payload(ancestry),
        "slots": [_slot_payload(item) for item in expected_slots],
    }
    request_digest = _request_digest(request_payload)
    with repository.transaction() as transaction:
        grant = _verified_grant(transaction, command, action, revalidate_grant)
        replay = _existing_command_replay(
            transaction, command, action, request_digest, grant
        )
        if replay is not None:
            return replay
        scope = _require_scope(transaction, command)
        target = _require_exact(transaction, target_profile, "activation_profile")
        if action == "rollback":
            if ancestry is None:
                _deny("rollback_ancestry_required")
            ancestry_record = _require_exact(
                transaction, ancestry, "activation_transition_receipt"
            )
            payload = ancestry_record.payload
            if (
                payload["action"] != "activate"
                or payload["to_profile"]
                != {"record_id": scope.current_profile_id, "digest": scope.current_profile_digest}
                or payload["from_profile"] != _exact_payload(target_profile)
                or payload["resulting_revision"] != scope.scope_revision
            ):
                _deny("rollback_ancestry_mismatch")
            mode, reason = "normal", "predecessor_restored"
        else:
            _require_all_null_profile(transaction, target)
            mode, reason = "safety_bypass", "safety_bypass_applied"

        current_slots = _require_slots(transaction, command.context_ref, expected_slots)
        transition_reason = (
            "rollback_stopped" if action == "rollback" else "safety_bypass_stopped"
        )
        resulting_slots = tuple(
            _unchanged_transition(expected)
            if expected.occupant is None
            else _cleared_transition(expected, transition_reason)
            for expected in expected_slots
        )
        receipt = _build_receipt(
            action=action,
            command=command,
            request_digest=request_digest,
            grant=grant,
            from_profile=ExactRecord(scope.current_profile_id, scope.current_profile_digest),
            to_profile=target_profile,
            candidate=None,
            conclusion=None,
            disposition=None,
            policy=None,
            calibration=None,
            monitor=None,
            ancestry=ancestry,
            authorities=None,
            slot_transitions=resulting_slots,
            mode=mode,
            reason=reason,
        )
        receipt = transaction.insert_record(receipt).record
        admission = transaction.admit_command(
            _operator_command(command, action, request_digest, grant, receipt)
        )
        if admission.replayed:
            return _replayed_result(
                transaction, command, receipt, admission.command, resulting_slots
            )

        cleared_slots: list[OperationSlot | None] = []
        for expected, current in zip(expected_slots, current_slots, strict=True):
            if expected.occupant is None:
                cleared_slots.append(current)
                continue
            assert current is not None and current.operation_id is not None
            cleared = transaction.clear_exact_operation_slot(
                context_ref=command.context_ref,
                operation_kind=expected.operation_kind,  # type: ignore[arg-type]
                expected_revision=expected.revision,
                expected_scope_revision=command.expected_scope_revision,
                operation_id=current.operation_id,
                operation_digest=current.operation_digest or "",
            )
            cleared_slots.append(cleared)
            transaction.append_event(
                DomainEvent(
                    event_id=_identity(f"{action}-{expected.operation_kind}-stopped", request_digest),
                    subject_id=current.operation_id,
                    subject_kind={
                        "canary": "canary_trial",
                        "monitor": "post_promotion_monitor",
                        "requalification": "evidence_requalification_window",
                    }[expected.operation_kind],
                    sequence=transaction.next_domain_event_sequence(current.operation_id),
                    event_type=f"{expected.operation_kind}_stopped_for_{action}",
                    payload_record_id=receipt.record_id,
                    actor_authority_ref=grant.grant_id,
                )
            )
        scope = transaction.compare_and_swap_activation_scope(
            context_ref=command.context_ref,
            expected_revision=command.expected_scope_revision,
            profile_id=target_profile.record_id,
            profile_digest=target_profile.digest,
            mode=mode,  # type: ignore[arg-type]
        )
        return ActivationTransitionResult(
            scope,
            receipt,
            admission.command,
            tuple(cleared_slots),  # type: ignore[arg-type]
            False,
        )


def _validate_activation_records(
    transaction: V3Transaction,
    request: ActivationRequest,
    scope: ActivationScope,
) -> dict[str, TypedRecord]:
    candidate = _require_exact(transaction, request.candidate, "improvement_candidate")
    disposition = _require_exact(transaction, request.disposition, "activation_disposition")
    conclusion = _require_exact(transaction, request.canary_conclusion, "canary_conclusion")
    policy = _require_exact(transaction, request.policy, "activation_policy")
    calibration = _require_exact(transaction, request.calibration, "policy_calibration")
    successor = _require_exact(transaction, request.successor_profile, "activation_profile")
    for record in (candidate, disposition, conclusion, policy, calibration, successor, request.monitor):
        if record.context_ref != request.command.context_ref:
            _deny("transition_context_mismatch")
    cp = candidate.payload
    if (
        cp["incumbent_profile_id"] != scope.current_profile_id
        or cp["incumbent_profile_digest"] != scope.current_profile_digest
        or cp["observed_scope_revision"] != scope.scope_revision
        or cp["activation_scope_ref"] != request.command.target_ref
        or cp["successor_profile_id"] != successor.record_id
        or cp["successor_profile_digest"] != successor.content_digest
    ):
        _deny("candidate_lineage_stale")
    dp = disposition.payload
    if (
        dp["disposition"] != "promotion_ready"
        or dp["evidence_stale"]
        or dp["lineage_stale"]
        or dp["candidate_id"] != candidate.record_id
        or dp["candidate_digest"] != candidate.content_digest
    ):
        _deny("promotion_ready_disposition_required")
    evidence_bundle = _require_linked(
        transaction,
        dp["evidence_bundle_id"],
        dp["evidence_bundle_digest"],
        "evidence_bundle",
    )
    ep = evidence_bundle.payload
    if (
        ep["candidate_id"] != candidate.record_id
        or ep["candidate_digest"] != candidate.content_digest
        or ep["incumbent_profile_id"] != scope.current_profile_id
        or ep["incumbent_profile_digest"] != scope.current_profile_digest
        or ep["activation_scope_ref"] != request.command.target_ref
        or ep["activation_scope_revision"] != scope.scope_revision
    ):
        _deny("evidence_lineage_stale")
    evidence_policy = _require_linked(
        transaction,
        dp["activation_policy_id"],
        dp["activation_policy_digest"],
        "activation_policy",
    )
    envelope = _require_linked(
        transaction,
        ep["evaluation_envelope_id"],
        ep["evaluation_envelope_digest"],
        "evaluation_envelope",
    )

    cpayload = conclusion.payload
    if (
        cpayload["conclusion"] != "passed"
        or not cpayload["activation_authoritative"]
        or cpayload["candidate_id"] != candidate.record_id
        or cpayload["candidate_digest"] != candidate.content_digest
        or cpayload["incumbent_profile_id"] != scope.current_profile_id
        or cpayload["incumbent_profile_digest"] != scope.current_profile_digest
        or cpayload["scope_revision"] != scope.scope_revision
        or cpayload["policy_id"] != policy.record_id
        or cpayload["policy_digest"] != policy.content_digest
        or cpayload["calibration_id"] != calibration.record_id
        or cpayload["calibration_digest"] != calibration.content_digest
    ):
        _deny("passed_authoritative_canary_required")
    cal = calibration.payload
    eligibility = request.eligibility
    if (
        eligibility.candidate != RecordIdentity.of(candidate)
        or eligibility.canary_conclusion != RecordIdentity.of(conclusion)
        or eligibility.policy != RecordIdentity.of(policy)
        or eligibility.calibration != RecordIdentity.of(calibration)
        or eligibility.observed_scope_revision != scope.scope_revision
        or eligibility.resulting_scope_revision != scope.scope_revision + 1
        or cal["status"] != "approved"
        or cal["environment_ref"] != eligibility.environment_ref
        or cal["policy_id"] != policy.record_id
        or cal["policy_digest"] != policy.content_digest
        or eligibility.activation_mode not in cal["activation_authorities"]
    ):
        _deny("activation_eligibility_stale")
    monitor = request.monitor
    monitor.verify(CANARY_REGISTRY)
    mp = monitor.payload
    if (
        monitor.record_kind != "post_promotion_monitor"
        or mp["candidate_id"] != candidate.record_id
        or mp["candidate_digest"] != candidate.content_digest
        or mp["incumbent_profile_id"] != scope.current_profile_id
        or mp["incumbent_profile_digest"] != scope.current_profile_digest
        or mp["canary_conclusion_id"] != conclusion.record_id
        or mp["canary_conclusion_digest"] != conclusion.content_digest
        or mp["policy_id"] != policy.record_id
        or mp["policy_digest"] != policy.content_digest
        or mp["calibration_id"] != calibration.record_id
        or mp["calibration_digest"] != calibration.content_digest
        or mp["monitor_plan_id"] != cal["monitor_plan_id"]
        or mp["monitor_plan_digest"] != cal["monitor_plan_digest"]
        or mp["observed_scope_revision"] != scope.scope_revision
        or mp["resulting_scope_revision"] != scope.scope_revision + 1
    ):
        _deny("monitor_plan_mismatch")

    dependency = _require_exact(
        transaction, request.authorities.dependency_profile, "worker_dependency_profile"
    )
    capability = _require_exact_one_of(
        transaction, request.authorities.capability_certificate, _CAPABILITY_KINDS
    )
    if capability.record_kind == "worker_dependency_capability_certificate" and (
        capability.payload.get("dependency_profile_ref") != dependency.record_id
        or capability.payload.get("dependency_profile_digest") != dependency.content_digest
        or capability.payload.get("observed_lock_digest") != dependency.payload.get("lock_digest")
    ):
        _deny("dependency_capability_mismatch")
    if (
        capability.payload.get("dependency_profile_ref") != dependency.record_id
        or capability.payload.get("dependency_profile_digest") != dependency.content_digest
    ):
        _deny("dependency_capability_mismatch")
    now = request.command.now.astimezone(timezone.utc)
    try:
        expires = datetime.strptime(
            capability.payload["expires_at"], "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        _deny("dependency_capability_mismatch")
    if expires <= now or capability.payload.get("state") == "unavailable":
        _deny("dependency_capability_unavailable")
    if capability.record_kind == "worker_dependency_capability_certificate" and any(
            item["state"] != "ready" for item in capability.payload["probe_states"]
    ):
        _deny("dependency_capability_unavailable")
    fixtures = tuple(
        _require_exact(transaction, item, "fixture_manifest")
        for item in request.authorities.fixture_manifests
    )
    envelope_fixture = (
        envelope.payload["fixture_manifest_id"],
        envelope.payload["fixture_manifest_digest"],
    )
    if envelope_fixture not in {
        (item.record_id, item.content_digest) for item in fixtures
    }:
        _deny("fixture_authority_mismatch")
    generation = _require_linked(
        transaction,
        cp["artifact_generation_receipt_id"],
        cp["artifact_generation_receipt_digest"],
        "artifact_generation_receipt",
    )
    run = _require_linked(
        transaction,
        generation.payload["optimization_run_receipt_id"],
        generation.payload["optimization_run_receipt_digest"],
        "optimization_run_receipt",
    )
    run_payload = run.payload
    if (
        run_payload["worker_dependency_profile_ref"] != dependency.record_id
        or run_payload["worker_dependency_profile_digest"] != dependency.content_digest
        or run_payload["capability_certificate_ref"] != capability.record_id
        or run_payload["capability_certificate_digest"] != capability.content_digest
    ):
        _deny("candidate_authority_mismatch")
    run_fixtures = {
        (item.target_id, item.target_digest)
        for item in run.links
        if item.role == "fixture_authority"
    }
    if run_fixtures != {(item.record_id, item.content_digest) for item in fixtures}:
        _deny("fixture_authority_mismatch")
    return {
        "candidate": candidate,
        "disposition": disposition,
        "conclusion": conclusion,
        "policy": policy,
        "calibration": calibration,
        "successor": successor,
        "evidence_policy": evidence_policy,
    }


def _verified_grant(
    transaction: V3Transaction,
    command: TransitionCommand,
    action: str,
    revalidate_grant: GrantRevalidator,
) -> VerifiedGrant:
    grant = revalidate_grant(transaction)
    if type(grant) is not VerifiedGrant:
        _deny("verified_grant_required")
    now = command.now.astimezone(timezone.utc)
    if grant.issued_at.tzinfo is None or grant.expires_at.tzinfo is None:
        _deny("authority_grant_mismatch")
    if (
        grant.grant_id != command.authority_grant_id
        or grant.authority_class != AuthorityClass.OPERATOR_AUTHORITY_GRANT.value
        or grant.issuer_id != command.issuer_ref
        or grant.subject_ref != command.subject_ref
        or grant.context_ref != command.context_ref
        or grant.action != action
        or grant.purpose != AuthorityPurpose.OPERATOR_MUTATION.value
        or grant.target_ref != command.target_ref
        or grant.target_revision != command.expected_scope_revision
        or grant.idempotency_key_digest != command.idempotency_key_digest
        or grant.issued_at.astimezone(timezone.utc) > now
        or grant.expires_at.astimezone(timezone.utc) <= now
    ):
        _deny("authority_grant_mismatch")
    return grant


def _existing_command_replay(
    transaction: V3Transaction,
    command: TransitionCommand,
    action: str,
    request_digest: str,
    grant: VerifiedGrant,
) -> ActivationTransitionResult | None:
    existing = transaction.get_operator_command(
        issuer_ref=grant.issuer_id,
        subject_ref=grant.subject_ref,
        context_ref=command.context_ref,
        action=action,
        idempotency_key_digest=command.idempotency_key_digest,
    )
    if existing is None:
        return None
    if existing.request_digest != request_digest:
        raise IdempotencyConflict("idempotency key was reused with a different request")
    receipt = transaction.get_record(existing.mutation_receipt_id)
    if (
        receipt is None
        or receipt.record_kind != "activation_transition_receipt"
        or receipt.schema_id != ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID
        or receipt.payload["request_digest"] != request_digest
    ):
        raise IntegrityFailure("command ledger points to an invalid activation receipt")
    return _replayed_result(
        transaction,
        command,
        receipt,
        existing,
        tuple(receipt.payload["slot_transitions"]),
    )


def _require_scope(transaction: V3Transaction, command: TransitionCommand) -> ActivationScope:
    scope = transaction.get_activation_scope(command.context_ref)
    if scope is None or scope.scope_revision != command.expected_scope_revision:
        raise RevisionConflict("activation scope revision did not match")
    if command.target_ref != command.context_ref:
        _deny("activation_scope_target_mismatch")
    return scope


def _require_exact(
    transaction: V3Transaction, identity: ExactRecord, kind: str
) -> TypedRecord:
    record = transaction.get_record(identity.record_id)
    if record is None or record.content_digest != identity.digest or record.record_kind != kind:
        _deny(f"{kind}_identity_mismatch")
    return record


def _require_exact_one_of(
    transaction: V3Transaction, identity: ExactRecord, kinds: tuple[str, ...]
) -> TypedRecord:
    record = transaction.get_record(identity.record_id)
    if record is None or record.content_digest != identity.digest or record.record_kind not in kinds:
        _deny("capability_certificate_identity_mismatch")
    return record


def _require_linked(
    transaction: V3Transaction, record_id: str, digest: str, kind: str
) -> TypedRecord:
    return _require_exact(transaction, ExactRecord(record_id, digest), kind)


def _require_all_null_profile(transaction: V3Transaction, profile: TypedRecord) -> None:
    slots = profile.payload["slots"]
    if (
        slots[0]["slot_kind"] != "structured_guidance"
        or slots[0]["artifact_id"] != NULL_GUIDANCE_RECORD_ID
        or slots[1]["slot_kind"] != "prompt_patch"
        or slots[1]["artifact_id"] != NULL_PROMPT_PATCH_RECORD_ID
    ):
        _deny("all_null_activation_profile_required")
    for slot in slots:
        artifact = transaction.get_record(slot["artifact_id"])
        if artifact is None or artifact.content_digest != slot["artifact_digest"]:
            _deny("all_null_activation_profile_required")


def _canonical_slots(values: Iterable[SlotExpectation]) -> tuple[SlotExpectation, ...]:
    slots = tuple(values)
    if len(slots) != 3 or tuple(item.operation_kind for item in slots) != _SLOT_KINDS:
        raise ValueError("slots must be canary, monitor, requalification in canonical order")
    return slots


def _require_slots(
    transaction: V3Transaction,
    context_ref: str,
    expectations: tuple[SlotExpectation, ...],
) -> tuple[OperationSlot | None, ...]:
    current: list[OperationSlot | None] = []
    for expected in expectations:
        slot = transaction.get_operation_slot(context_ref, expected.operation_kind)  # type: ignore[arg-type]
        actual_revision = 0 if slot is None else slot.operation_revision
        actual_occupant = (
            None
            if slot is None or slot.operation_id is None
            else ExactRecord(slot.operation_id, slot.operation_digest or "")
        )
        if actual_revision != expected.revision or actual_occupant != expected.occupant:
            raise RevisionConflict(f"{expected.operation_kind} slot expectation is stale")
        current.append(slot)
    return tuple(current)


def _build_receipt(
    *,
    action: str,
    command: TransitionCommand,
    request_digest: str,
    grant: VerifiedGrant,
    from_profile: ExactRecord,
    to_profile: ExactRecord,
    candidate: ExactRecord | None,
    conclusion: ExactRecord | None,
    disposition: ExactRecord | None,
    policy: ExactRecord | None,
    calibration: ExactRecord | None,
    monitor: ExactRecord | None,
    ancestry: ExactRecord | None,
    authorities: ActivationAuthorityFacts | None,
    slot_transitions: tuple[dict[str, Any], ...],
    mode: str,
    reason: str,
) -> TypedRecord:
    fixtures = () if authorities is None else authorities.fixture_manifests
    payload: dict[str, Any] = {
        "receipt_type": "activation_transition",
        "accepted": True,
        "action": action,
        "context_ref": command.context_ref,
        "target_ref": command.target_ref,
        "observed_revision": command.expected_scope_revision,
        "resulting_revision": command.expected_scope_revision + 1,
        "mode": mode,
        "from_profile": _exact_payload(from_profile),
        "to_profile": _exact_payload(to_profile),
        "candidate": _optional_exact(candidate),
        "canary_conclusion": _optional_exact(conclusion),
        "activation_disposition": _optional_exact(disposition),
        "activation_policy": _optional_exact(policy),
        "policy_calibration": _optional_exact(calibration),
        "monitor": _optional_exact(monitor),
        "ancestry_receipt": _optional_exact(ancestry),
        "dependency_profile": _optional_exact(
            None if authorities is None else authorities.dependency_profile
        ),
        "capability_certificate": _optional_exact(
            None if authorities is None else authorities.capability_certificate
        ),
        "fixture_manifests": [_exact_payload(item) for item in fixtures],
        "slot_transitions": list(slot_transitions),
        "authority_grant_id": grant.grant_id,
        "issuer_ref": grant.issuer_id,
        "subject_ref": grant.subject_ref,
        "idempotency_key_digest": command.idempotency_key_digest,
        "request_digest": request_digest,
        "reason_codes": [reason],
        "links": [],
    }
    for role, field in (
        ("from_profile", "from_profile"),
        ("to_profile", "to_profile"),
        ("candidate", "candidate"),
        ("canary_conclusion", "canary_conclusion"),
        ("activation_disposition", "activation_disposition"),
        ("activation_policy", "activation_policy"),
        ("policy_calibration", "policy_calibration"),
        ("monitor", "monitor"),
        ("ancestry_receipt", "ancestry_receipt"),
        ("dependency_profile", "dependency_profile"),
        ("capability_certificate", "capability_certificate"),
    ):
        if payload[field] is not None:
            payload["links"].append(_link(role, 0, payload[field]))
    payload["links"].extend(
        _link("fixture_manifest", index, item)
        for index, item in enumerate(payload["fixture_manifests"])
    )
    payload["links"].extend(
        _link(f"stopped_slot:{item['operation_kind']}", 0, item["observed_occupant"])
        for item in slot_transitions
        if item["observed_occupant"] is not None
    )
    return build_typed_record(
        record_id=_identity(f"{action}-receipt", request_digest),
        context_ref=command.context_ref,
        record_kind="activation_transition_receipt",
        schema_id=ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID,
        payload=payload,
        key_epoch="activation-transition-v1",
        registry=ACTIVATION_TRANSITION_REGISTRY,
    )


def _operator_command(
    command: TransitionCommand,
    action: str,
    request_digest: str,
    grant: VerifiedGrant,
    receipt: TypedRecord,
) -> OperatorCommand:
    return OperatorCommand(
        command_id=_identity(f"{action}-command", request_digest),
        issuer_ref=grant.issuer_id,
        subject_ref=grant.subject_ref,
        context_ref=command.context_ref,
        action=action,
        idempotency_key_digest=command.idempotency_key_digest,
        request_digest=request_digest,
        observed_revision=command.expected_scope_revision,
        state="accepted",
        mutation_receipt_id=receipt.record_id,
    )


def _replayed_result(
    transaction: V3Transaction,
    command: TransitionCommand,
    receipt: TypedRecord,
    admitted: OperatorCommand,
    resulting_slots: tuple[dict[str, Any], ...],
) -> ActivationTransitionResult:
    scope = transaction.get_activation_scope(command.context_ref)
    payload = receipt.payload
    if (
        scope is None
        or scope.scope_revision != payload["resulting_revision"]
        or scope.current_profile_id != payload["to_profile"]["record_id"]
        or scope.current_profile_digest != payload["to_profile"]["digest"]
        or scope.mode != payload["mode"]
    ):
        raise IntegrityFailure("replayed transition does not match activation scope")
    slots: list[OperationSlot | None] = []
    for expected in resulting_slots:
        slot = transaction.get_operation_slot(command.context_ref, expected["operation_kind"])
        revision = 0 if slot is None else slot.operation_revision
        occupant = (
            None
            if slot is None or slot.operation_id is None
            else {"record_id": slot.operation_id, "digest": slot.operation_digest}
        )
        if revision != expected["resulting_revision"] or occupant != expected["resulting_occupant"]:
            raise IntegrityFailure("replayed transition does not match operation slots")
        slots.append(slot)
    return ActivationTransitionResult(
        scope, receipt, admitted, tuple(slots), True  # type: ignore[arg-type]
    )


def _request_digest(payload: Mapping[str, Any]) -> str:
    return schema_digest(
        "activation-transition-request",
        "a0.activation-transition-request.v1",
        canonical_json(dict(payload)),
    )


def _identity(purpose: str, request_digest: str) -> str:
    return purpose + "_" + schema_digest(
        "activation-transition-identity", purpose, request_digest.encode("ascii")
    )


def _exact_payload(identity: ExactRecord) -> dict[str, str]:
    return {"record_id": identity.record_id, "digest": identity.digest}


def _optional_exact(identity: ExactRecord | None) -> dict[str, str] | None:
    return None if identity is None else _exact_payload(identity)


def _link(role: str, ordinal: int, identity: Mapping[str, str]) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": identity["record_id"],
        "target_digest": identity["digest"],
    }


def _slot_payload(slot: SlotExpectation) -> dict[str, Any]:
    return {
        "operation_kind": slot.operation_kind,
        "revision": slot.revision,
        "occupant": _optional_exact(slot.occupant),
    }


def _command_payload(command: TransitionCommand) -> dict[str, Any]:
    return {
        "issuer_ref": command.issuer_ref,
        "subject_ref": command.subject_ref,
        "context_ref": command.context_ref,
        "target_ref": command.target_ref,
        "expected_scope_revision": command.expected_scope_revision,
        "idempotency_key_digest": command.idempotency_key_digest,
        "authority_grant_id": command.authority_grant_id,
    }


def _eligibility_payload(value: ActivationEligibility) -> dict[str, Any]:
    return {
        "candidate": {"record_id": value.candidate.ref, "digest": value.candidate.digest},
        "canary_conclusion": {
            "record_id": value.canary_conclusion.ref,
            "digest": value.canary_conclusion.digest,
        },
        "policy": {"record_id": value.policy.ref, "digest": value.policy.digest},
        "calibration": {
            "record_id": value.calibration.ref,
            "digest": value.calibration.digest,
        },
        "environment_ref": value.environment_ref,
        "observed_scope_revision": value.observed_scope_revision,
        "resulting_scope_revision": value.resulting_scope_revision,
        "activation_mode": value.activation_mode,
    }


def _authority_payload(value: ActivationAuthorityFacts) -> dict[str, Any]:
    return {
        "dependency_profile": _exact_payload(value.dependency_profile),
        "capability_certificate": _exact_payload(value.capability_certificate),
        "fixture_manifests": [_exact_payload(item) for item in value.fixture_manifests],
    }


def _transition(
    slot: SlotExpectation,
    *,
    resulting_revision: int,
    resulting_occupant: ExactRecord | None,
    reason: str,
) -> dict[str, Any]:
    return {
        "operation_kind": slot.operation_kind,
        "observed_revision": slot.revision,
        "resulting_revision": resulting_revision,
        "observed_occupant": _optional_exact(slot.occupant),
        "resulting_occupant": _optional_exact(resulting_occupant),
        "reason_code": reason,
    }


def _cleared_transition(slot: SlotExpectation, reason: str) -> dict[str, Any]:
    if slot.occupant is None:
        raise ValueError("cannot clear an empty slot")
    return _transition(
        slot, resulting_revision=slot.revision + 1, resulting_occupant=None, reason=reason
    )


def _claimed_transition(
    slot: SlotExpectation, occupant: ExactRecord, reason: str
) -> dict[str, Any]:
    if slot.occupant is not None:
        raise ValueError("cannot claim an occupied slot")
    return _transition(
        slot,
        resulting_revision=slot.revision + 1,
        resulting_occupant=occupant,
        reason=reason,
    )


def _unchanged_transition(slot: SlotExpectation) -> dict[str, Any]:
    if slot.occupant is not None:
        raise ValueError("unchanged slot must be empty")
    return _transition(
        slot,
        resulting_revision=slot.revision,
        resulting_occupant=None,
        reason="unchanged_empty",
    )
