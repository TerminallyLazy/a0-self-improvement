"""Read-only canary routing and post-outcome exposure persistence.

Prompt-time selection is pure and never stores an exposure.  The assignment
key is supplied by the local runtime caller, checked against the frozen Canary
Plan commitment, and never returned.  Only after the matching loop outcome can
one transaction append the exposure receipt, neutral runtime observation, and
content-free canary observation.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Protocol

from .artifacts import ACTIVATION_PROFILE_SCHEMA_ID
from .canary import (
    CANARY_PLAN_SCHEMA_ID,
    CANARY_REGISTRY,
    CANARY_TRIAL_SCHEMA_ID,
    CanaryCoordinator,
    RecordIdentity,
)
from .candidate_publication import (
    CANDIDATE_PUBLICATION_REGISTRY,
    IMPROVEMENT_CANDIDATE_SCHEMA_ID,
)
from .observation import (
    OBSERVATION_REGISTRY,
    RUNTIME_OBSERVER_AUTHORITY_REF,
    RuntimeObservationRequest,
    record_runtime_observation_in_transaction,
)
from .repository import ActivationScope, DomainEvent, OperationSlot, V3Repository
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
    strict_literal,
    strict_object,
    validate_digest,
    validate_links,
)


CANARY_ASSIGNMENT_KEY_ENV = "DSPY_RLM_CANARY_ASSIGNMENT_KEY"
CANARY_SELECTION_LOOP_KEY = "dspy_rlm_v3_canary_selection"
CANARY_RUNTIME_OBSERVATION_SCHEMA_ID = "a0.canary-runtime-observation.v1"
CANARY_RUNTIME_OBSERVATION_KIND = "canary_runtime_observation"
_KEY_EPOCH = "canary-runtime-v1"
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class CanaryRuntimeError(RuntimeError):
    """A runtime canary binding was not exact enough to use."""


class CanaryRuntimeReader(Protocol):
    def get_activation_scope(self, context_ref: str) -> ActivationScope | None: ...

    def get_operation_slot(
        self, context_ref: str, operation_kind: str
    ) -> OperationSlot | None: ...

    def get_record(self, record_id: str) -> TypedRecord | None: ...


def _opaque(value: Any, path: str) -> str:
    if type(value) is not str or _OPAQUE.fullmatch(value) is None:
        raise SchemaValidationError(f"{path} must be a content-free opaque reference")
    return value


def _observation_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "fact_type": strict_literal(CANARY_RUNTIME_OBSERVATION_KIND),
            "context_ref": _opaque,
            "trial_id": _opaque,
            "trial_digest": validate_digest,
            "exposure_receipt_id": _opaque,
            "exposure_receipt_digest": validate_digest,
            "runtime_observation_id": _opaque,
            "runtime_observation_digest": validate_digest,
            "exposure_unit_ref": _opaque,
            "envelope_ref": _opaque,
            "outcome_occurrence_ref": _opaque,
            "arm": strict_enum(("candidate", "incumbent")),
            "selected_profile_id": _opaque,
            "selected_profile_digest": validate_digest,
            "scope_revision": strict_integer(minimum=0),
            "assignment_digest": validate_digest,
            "outcome_code": strict_literal("message_loop_end_observed"),
            "outcome_authority": strict_literal("exposure_only"),
            "promotion_authority": strict_literal("none"),
            "objective_bucket_state": strict_literal("unbound"),
            "contains_raw_content": strict_literal(False),
            "contains_provider_identifier": strict_literal(False),
            "contains_error_detail": strict_literal(False),
            "contains_path": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("canary_trial", 0, payload["trial_id"], payload["trial_digest"]),
        _link(
            "exposure_receipt",
            0,
            payload["exposure_receipt_id"],
            payload["exposure_receipt_digest"],
        ),
        _link(
            "runtime_observation",
            0,
            payload["runtime_observation_id"],
            payload["runtime_observation_digest"],
        ),
        _link(
            "selected_profile",
            0,
            payload["selected_profile_id"],
            payload["selected_profile_digest"],
        ),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact exposure")
    return payload


CANARY_RUNTIME_REGISTRY = merge_schema_registries(
    CANARY_REGISTRY,
    CANDIDATE_PUBLICATION_REGISTRY,
    OBSERVATION_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                CANARY_RUNTIME_OBSERVATION_SCHEMA_ID,
                CANARY_RUNTIME_OBSERVATION_KIND,
                _observation_validator,
            ),
        )
    ),
)


@dataclass(frozen=True, slots=True)
class ExposureIdentity:
    context_ref: str
    exposure_unit_ref: str
    envelope_ref: str


@dataclass(frozen=True, slots=True)
class CanaryRuntimeSelection:
    context_ref: str
    exposure_unit_ref: str
    envelope_ref: str
    trial_id: str
    trial_digest: str
    plan_id: str
    plan_digest: str
    candidate_id: str
    candidate_digest: str
    incumbent_profile_id: str
    incumbent_profile_digest: str
    successor_profile_id: str
    successor_profile_digest: str
    selected_profile_id: str
    selected_profile_digest: str
    scope_revision: int
    slot_revision: int
    arm: str
    assignment_digest: str
    exposure_receipt: TypedRecord


@dataclass(frozen=True, slots=True)
class CanaryRuntimeCommit:
    exposure_receipt: TypedRecord
    runtime_observation: TypedRecord
    canary_observation: TypedRecord
    replayed: bool


def exposure_identity(
    *, context_ref: str, message_ref: str, loop_iteration: int
) -> ExposureIdentity:
    """Derive the stable pre/post identity from pinned Agent Zero loop facts."""

    try:
        _opaque(context_ref, "context_ref")
        _opaque(message_ref, "message_ref")
    except SchemaValidationError as exc:
        raise CanaryRuntimeError(str(exc)) from exc
    if type(loop_iteration) is not int or loop_iteration < 0:
        raise CanaryRuntimeError("loop_iteration must be a non-negative integer")
    digest = schema_digest(
        "canary-runtime-exposure-identity",
        CANARY_RUNTIME_OBSERVATION_SCHEMA_ID,
        canonical_json(
            {
                "context_ref": context_ref,
                "message_ref": message_ref,
                "loop_iteration": loop_iteration,
            }
        ),
    )
    return ExposureIdentity(
        context_ref=context_ref,
        exposure_unit_ref=f"canary-exposure:{digest}",
        envelope_ref=f"canary-envelope:{digest}",
    )


def select_canary_runtime(
    reader: CanaryRuntimeReader,
    *,
    identity: ExposureIdentity,
    assignment_secret: bytes | None,
    now: datetime,
) -> CanaryRuntimeSelection | None:
    """Select one arm from exact read-only authority, otherwise return incumbent."""

    if type(identity) is not ExposureIdentity:
        raise TypeError("identity must be an ExposureIdentity")
    if type(assignment_secret) is not bytes or not assignment_secret:
        return None
    if not isinstance(now, datetime) or now.tzinfo is None:
        return None
    try:
        scope = reader.get_activation_scope(identity.context_ref)
        slot = reader.get_operation_slot(identity.context_ref, "canary")
        if (
            scope is None
            or scope.mode != "normal"
            or slot is None
            or slot.operation_id is None
            or slot.operation_digest is None
        ):
            return None
        trial = _exact_record(
            reader,
            slot.operation_id,
            slot.operation_digest,
            context_ref=identity.context_ref,
            record_kind="canary_trial",
            schema_id=CANARY_TRIAL_SCHEMA_ID,
        )
        trial.verify(CANARY_REGISTRY)
        trial_payload = trial.payload
        if (
            trial_payload["scope_revision"] != scope.scope_revision
            or trial_payload["incumbent_profile_id"] != scope.current_profile_id
            or trial_payload["incumbent_profile_digest"] != scope.current_profile_digest
        ):
            return None
        plan = _exact_record(
            reader,
            trial_payload["plan_id"],
            trial_payload["plan_digest"],
            context_ref=identity.context_ref,
            record_kind="canary_plan",
            schema_id=CANARY_PLAN_SCHEMA_ID,
        )
        plan.verify(CANARY_REGISTRY)
        started = _slot_timestamp(slot.updated_at)
        reference = now.astimezone(timezone.utc)
        if reference < started or reference >= started + timedelta(
            seconds=plan.payload["expiry_seconds"]
        ):
            return None
        candidate = _exact_record(
            reader,
            trial_payload["candidate_id"],
            trial_payload["candidate_digest"],
            context_ref=identity.context_ref,
            record_kind="improvement_candidate",
            schema_id=IMPROVEMENT_CANDIDATE_SCHEMA_ID,
        )
        candidate.verify(CANDIDATE_PUBLICATION_REGISTRY)
        candidate_payload = candidate.payload
        if (
            candidate_payload["incumbent_profile_id"] != scope.current_profile_id
            or candidate_payload["incumbent_profile_digest"]
            != scope.current_profile_digest
            or candidate_payload["observed_scope_revision"] != scope.scope_revision
        ):
            return None
        successor = _exact_record(
            reader,
            candidate_payload["successor_profile_id"],
            candidate_payload["successor_profile_digest"],
            context_ref=identity.context_ref,
            record_kind="activation_profile",
            schema_id=ACTIVATION_PROFILE_SCHEMA_ID,
        )
        incumbent = _exact_record(
            reader,
            scope.current_profile_id,
            scope.current_profile_digest,
            context_ref=identity.context_ref,
            record_kind="activation_profile",
            schema_id=ACTIVATION_PROFILE_SCHEMA_ID,
        )
        receipt_id = _stable_id(
            "canary-exposure-receipt",
            identity.context_ref,
            identity.exposure_unit_ref,
        )
        planned = CanaryCoordinator(key_epoch=trial.key_epoch).plan_exposure(
            record_id=receipt_id,
            trial=trial,
            active_trial=RecordIdentity.of(trial),
            observed_scope_revision=scope.scope_revision,
            exposure_unit_ref=identity.exposure_unit_ref,
            envelope_ref=identity.envelope_ref,
            eligible=True,
            already_receipted=False,
            assignment_secret=assignment_secret,
            frozen_plan=plan,
        )
        existing = reader.get_record(receipt_id)
        if existing is not None and existing != planned:
            return None
        receipt = planned if existing is None else existing
        receipt_payload = receipt.payload
        selected = successor if receipt_payload["arm"] == "candidate" else incumbent
        return CanaryRuntimeSelection(
            context_ref=identity.context_ref,
            exposure_unit_ref=identity.exposure_unit_ref,
            envelope_ref=identity.envelope_ref,
            trial_id=trial.record_id,
            trial_digest=trial.content_digest,
            plan_id=plan.record_id,
            plan_digest=plan.content_digest,
            candidate_id=candidate.record_id,
            candidate_digest=candidate.content_digest,
            incumbent_profile_id=incumbent.record_id,
            incumbent_profile_digest=incumbent.content_digest,
            successor_profile_id=successor.record_id,
            successor_profile_digest=successor.content_digest,
            selected_profile_id=selected.record_id,
            selected_profile_digest=selected.content_digest,
            scope_revision=scope.scope_revision,
            slot_revision=slot.operation_revision,
            arm=receipt_payload["arm"],
            assignment_digest=receipt_payload["assignment_digest"],
            exposure_receipt=receipt,
        )
    except Exception:
        return None


def commit_canary_runtime_observation(
    repository: V3Repository,
    *,
    selection: CanaryRuntimeSelection,
    outcome_request: RuntimeObservationRequest,
    assignment_secret: bytes,
    now: datetime,
) -> CanaryRuntimeCommit:
    """Revalidate selection and append receipt plus observation atomically."""

    if type(repository) is not V3Repository:
        raise TypeError("repository must be a V3Repository")
    if type(selection) is not CanaryRuntimeSelection:
        raise TypeError("selection must be a CanaryRuntimeSelection")
    if (
        type(outcome_request) is not RuntimeObservationRequest
        or outcome_request.observation_kind != "message_loop_end"
        or outcome_request.context_ref != selection.context_ref
    ):
        raise CanaryRuntimeError("outcome request does not match the canary selection")
    identity = ExposureIdentity(
        selection.context_ref,
        selection.exposure_unit_ref,
        selection.envelope_ref,
    )
    with repository.transaction() as transaction:
        current = select_canary_runtime(
            transaction,
            identity=identity,
            assignment_secret=assignment_secret,
            now=now,
        )
        if current != selection:
            raise CanaryRuntimeError("canary authority changed before outcome commit")
        runtime = record_runtime_observation_in_transaction(transaction, outcome_request)
        if runtime is None:
            raise CanaryRuntimeError("runtime observation authority is unavailable")
        receipt_insert = transaction.insert_record(selection.exposure_receipt)
        receipt_event = DomainEvent(
            event_id=_stable_id(
                "canary-exposure-event",
                selection.context_ref,
                selection.exposure_unit_ref,
            ),
            subject_id=selection.exposure_receipt.record_id,
            subject_kind=selection.exposure_receipt.record_kind,
            sequence=0,
            event_type="canary_exposure_recorded",
            payload_record_id=selection.exposure_receipt.record_id,
            actor_authority_ref=RUNTIME_OBSERVER_AUTHORITY_REF,
        )
        transaction.append_event(receipt_event)
        observation = _build_canary_observation(selection, runtime.record)
        observation_insert = transaction.insert_record(observation)
        transaction.append_event(
            DomainEvent(
                event_id=_stable_id(
                    "canary-runtime-observation-event",
                    selection.context_ref,
                    selection.exposure_unit_ref,
                ),
                subject_id=observation.record_id,
                subject_kind=observation.record_kind,
                sequence=0,
                event_type="canary_runtime_observed",
                payload_record_id=observation.record_id,
                actor_authority_ref=RUNTIME_OBSERVER_AUTHORITY_REF,
            )
        )
        if receipt_insert.inserted != observation_insert.inserted:
            raise CanaryRuntimeError("partial canary replay state is not admissible")
        return CanaryRuntimeCommit(
            receipt_insert.record,
            runtime.record,
            observation_insert.record,
            not observation_insert.inserted,
        )


def _build_canary_observation(
    selection: CanaryRuntimeSelection, runtime_observation: TypedRecord
) -> TypedRecord:
    record_id = _stable_id(
        "canary-runtime-observation",
        selection.context_ref,
        selection.exposure_unit_ref,
    )
    payload = {
        "fact_type": CANARY_RUNTIME_OBSERVATION_KIND,
        "context_ref": selection.context_ref,
        "trial_id": selection.trial_id,
        "trial_digest": selection.trial_digest,
        "exposure_receipt_id": selection.exposure_receipt.record_id,
        "exposure_receipt_digest": selection.exposure_receipt.content_digest,
        "runtime_observation_id": runtime_observation.record_id,
        "runtime_observation_digest": runtime_observation.content_digest,
        "exposure_unit_ref": selection.exposure_unit_ref,
        "envelope_ref": selection.envelope_ref,
        "outcome_occurrence_ref": runtime_observation.payload["occurrence_ref"],
        "arm": selection.arm,
        "selected_profile_id": selection.selected_profile_id,
        "selected_profile_digest": selection.selected_profile_digest,
        "scope_revision": selection.scope_revision,
        "assignment_digest": selection.assignment_digest,
        "outcome_code": "message_loop_end_observed",
        "outcome_authority": "exposure_only",
        "promotion_authority": "none",
        "objective_bucket_state": "unbound",
        "contains_raw_content": False,
        "contains_provider_identifier": False,
        "contains_error_detail": False,
        "contains_path": False,
        "links": [
            _link("canary_trial", 0, selection.trial_id, selection.trial_digest),
            _link(
                "exposure_receipt",
                0,
                selection.exposure_receipt.record_id,
                selection.exposure_receipt.content_digest,
            ),
            _link(
                "runtime_observation",
                0,
                runtime_observation.record_id,
                runtime_observation.content_digest,
            ),
            _link(
                "selected_profile",
                0,
                selection.selected_profile_id,
                selection.selected_profile_digest,
            ),
        ],
    }
    return build_typed_record(
        record_id=record_id,
        context_ref=selection.context_ref,
        record_kind=CANARY_RUNTIME_OBSERVATION_KIND,
        schema_id=CANARY_RUNTIME_OBSERVATION_SCHEMA_ID,
        payload=payload,
        key_epoch=_KEY_EPOCH,
        registry=CANARY_RUNTIME_REGISTRY,
    )


def _exact_record(
    reader: CanaryRuntimeReader,
    record_id: str,
    digest: str,
    *,
    context_ref: str,
    record_kind: str,
    schema_id: str,
) -> TypedRecord:
    record = reader.get_record(record_id)
    if (
        record is None
        or record.content_digest != digest
        or record.context_ref != context_ref
        or record.record_kind != record_kind
        or record.schema_id != schema_id
    ):
        raise CanaryRuntimeError("exact canary runtime record is unavailable")
    return record


def _slot_timestamp(value: str) -> datetime:
    if type(value) is not str:
        raise CanaryRuntimeError("canary slot timestamp is unavailable")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise CanaryRuntimeError("canary slot timestamp is invalid") from exc
    return parsed


def _stable_id(namespace: str, context_ref: str, occurrence_ref: str) -> str:
    digest = schema_digest(
        namespace,
        CANARY_RUNTIME_OBSERVATION_SCHEMA_ID,
        canonical_json(
            {"context_ref": context_ref, "occurrence_ref": occurrence_ref}
        ),
    )
    return f"{namespace}:{digest}"


def _link(role: str, ordinal: int, target_id: str, digest: str) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": target_id,
        "target_digest": digest,
    }


__all__ = [
    "CANARY_ASSIGNMENT_KEY_ENV",
    "CANARY_RUNTIME_OBSERVATION_KIND",
    "CANARY_RUNTIME_OBSERVATION_SCHEMA_ID",
    "CANARY_RUNTIME_REGISTRY",
    "CANARY_SELECTION_LOOP_KEY",
    "CanaryRuntimeCommit",
    "CanaryRuntimeError",
    "CanaryRuntimeSelection",
    "ExposureIdentity",
    "commit_canary_runtime_observation",
    "exposure_identity",
    "select_canary_runtime",
]
