"""Content-free, append-only facts from certified Agent Zero runtime hooks.

The observer deliberately records only facts supplied by the pinned hook
contracts.  It does not inspect or hash prompts, tool arguments, tool results,
provider metadata, or exception text.  The Activation Scope link is explicitly
the scope observed inside the commit transaction; it is not a claim about which
profile produced an earlier response.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .artifacts import DEFAULT_REGISTRY
from .repository import DomainEvent, V3Repository, V3Transaction
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


RUNTIME_OBSERVATION_SCHEMA_ID = "a0.runtime-observation-fact.v1"
RUNTIME_OBSERVATION_KIND = "runtime_observation_fact"
RUNTIME_OBSERVER_AUTHORITY_REF = "system:agent-zero-runtime-observer:v1"
RUNTIME_OBSERVATION_KEY_EPOCH = "runtime-observation-v1"

OBSERVATION_KINDS = ("message_loop_end", "tool_execute_after")
OUTCOME_CODES = (
    "message_loop_end_observed",
    "tool_returned_continuing",
    "tool_returned_terminal",
)
_OUTCOMES_BY_KIND = {
    "message_loop_end": frozenset(("message_loop_end_observed",)),
    "tool_execute_after": frozenset(
        ("tool_returned_continuing", "tool_returned_terminal")
    ),
}
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class RuntimeObservationError(RuntimeError):
    """The hook fact was not safe or exact enough to persist."""


def _opaque(value: Any, path: str) -> str:
    if type(value) is not str or _OPAQUE.fullmatch(value) is None:
        raise SchemaValidationError(f"{path} must be a content-free opaque reference")
    return value


def _validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal(RUNTIME_OBSERVATION_KIND),
            "observation_kind": strict_enum(OBSERVATION_KINDS),
            "outcome_code": strict_enum(OUTCOME_CODES),
            "context_ref": _opaque,
            "occurrence_ref": _opaque,
            "loop_iteration": strict_integer(minimum=-1),
            "observed_profile_ref": _opaque,
            "observed_profile_digest": validate_digest,
            "observed_scope_revision": strict_integer(minimum=0),
            "observed_activation_mode": strict_enum(("normal", "safety_bypass")),
            "profile_binding_semantics": strict_literal(
                "activation_scope_at_observation_commit"
            ),
            "objective_bucket_state": strict_literal("unbound"),
            "runtime_mode": strict_literal("ordinary"),
            "authority_ceiling": strict_literal("runtime_observation_only"),
            "promotion_authority": strict_literal("none"),
            "contains_raw_content": strict_literal(False),
            "contains_quarantine_content": strict_literal(False),
            "contains_certification_holdout": strict_literal(False),
            "contains_provider_identifier": strict_literal(False),
            "contains_error_detail": strict_literal(False),
            "contains_path": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    if payload["outcome_code"] not in _OUTCOMES_BY_KIND[payload["observation_kind"]]:
        raise SchemaValidationError(f"{path}.outcome_code does not match its hook")
    expected = [
        {
            "role": "observed_activation_profile",
            "ordinal": 0,
            "target_id": payload["observed_profile_ref"],
            "target_digest": payload["observed_profile_digest"],
        }
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(
            f"{path}.links do not bind the exact observed Activation Profile"
        )
    return payload


OBSERVATION_REGISTRY = merge_schema_registries(
    DEFAULT_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                RUNTIME_OBSERVATION_SCHEMA_ID,
                RUNTIME_OBSERVATION_KIND,
                _validator,
            ),
        )
    ),
)


@dataclass(frozen=True, slots=True)
class RuntimeObservationRequest:
    context_ref: str
    occurrence_ref: str
    observation_kind: str
    outcome_code: str
    loop_iteration: int

    def __post_init__(self) -> None:
        try:
            _opaque(self.context_ref, "context_ref")
            _opaque(self.occurrence_ref, "occurrence_ref")
        except SchemaValidationError as exc:
            raise RuntimeObservationError(str(exc)) from exc
        if self.observation_kind not in OBSERVATION_KINDS:
            raise RuntimeObservationError("observation kind is not admitted")
        if self.outcome_code not in _OUTCOMES_BY_KIND[self.observation_kind]:
            raise RuntimeObservationError("outcome code does not match its hook")
        if type(self.loop_iteration) is not int or self.loop_iteration < -1:
            raise RuntimeObservationError("loop iteration is not a certified integer")


@dataclass(frozen=True, slots=True)
class RuntimeObservationCommit:
    record: TypedRecord
    event: DomainEvent
    replayed: bool


def record_runtime_observation(
    repository: V3Repository,
    request: RuntimeObservationRequest,
) -> RuntimeObservationCommit | None:
    """Atomically append one fact and event, or return ``None`` without Genesis.

    Record identity is derived only from context, hook, and occurrence.  An
    exact post-crash retry equivalence-inserts; reuse of the occurrence with a
    changed outcome, iteration, or observed scope collides before either row is
    written.
    """

    if type(repository) is not V3Repository:
        raise TypeError("repository must be a V3Repository")
    if type(request) is not RuntimeObservationRequest:
        raise TypeError("request must be a RuntimeObservationRequest")
    with repository.transaction() as transaction:
        return record_runtime_observation_in_transaction(transaction, request)


def record_runtime_observation_in_transaction(
    transaction: V3Transaction,
    request: RuntimeObservationRequest,
) -> RuntimeObservationCommit | None:
    """Append one observation inside a coordinator-owned transaction."""

    if type(transaction) is not V3Transaction:
        raise TypeError("transaction must be a V3Transaction")
    if type(request) is not RuntimeObservationRequest:
        raise TypeError("request must be a RuntimeObservationRequest")
    scope = transaction.get_activation_scope(request.context_ref)
    if scope is None:
        return None
    identity_payload = {
        "context_ref": request.context_ref,
        "observation_kind": request.observation_kind,
        "occurrence_ref": request.occurrence_ref,
    }
    identity_digest = schema_digest(
        "runtime-observation-identity",
        RUNTIME_OBSERVATION_SCHEMA_ID,
        canonical_json(identity_payload),
    )
    record_id = f"runtime-observation:{identity_digest}"
    payload = {
        "record_type": RUNTIME_OBSERVATION_KIND,
        "observation_kind": request.observation_kind,
        "outcome_code": request.outcome_code,
        "context_ref": request.context_ref,
        "occurrence_ref": request.occurrence_ref,
        "loop_iteration": request.loop_iteration,
        "observed_profile_ref": scope.current_profile_id,
        "observed_profile_digest": scope.current_profile_digest,
        "observed_scope_revision": scope.scope_revision,
        "observed_activation_mode": scope.mode,
        "profile_binding_semantics": "activation_scope_at_observation_commit",
        "objective_bucket_state": "unbound",
        "runtime_mode": "ordinary",
        "authority_ceiling": "runtime_observation_only",
        "promotion_authority": "none",
        "contains_raw_content": False,
        "contains_quarantine_content": False,
        "contains_certification_holdout": False,
        "contains_provider_identifier": False,
        "contains_error_detail": False,
        "contains_path": False,
        "links": [
            {
                "role": "observed_activation_profile",
                "ordinal": 0,
                "target_id": scope.current_profile_id,
                "target_digest": scope.current_profile_digest,
            }
        ],
    }
    record = build_typed_record(
        record_id=record_id,
        context_ref=request.context_ref,
        record_kind=RUNTIME_OBSERVATION_KIND,
        schema_id=RUNTIME_OBSERVATION_SCHEMA_ID,
        payload=payload,
        key_epoch=RUNTIME_OBSERVATION_KEY_EPOCH,
        registry=OBSERVATION_REGISTRY,
    )
    inserted = transaction.insert_record(record)
    event = DomainEvent(
        event_id=f"runtime-observation-event:{identity_digest}",
        subject_id=record.record_id,
        subject_kind=record.record_kind,
        sequence=0,
        event_type="runtime_observation_recorded",
        payload_record_id=record.record_id,
        actor_authority_ref=RUNTIME_OBSERVER_AUTHORITY_REF,
    )
    admitted_event = transaction.append_event(event)
    return RuntimeObservationCommit(inserted.record, admitted_event, not inserted.inserted)


__all__ = [
    "OBSERVATION_KINDS",
    "OBSERVATION_REGISTRY",
    "OUTCOME_CODES",
    "RUNTIME_OBSERVATION_KIND",
    "RUNTIME_OBSERVATION_SCHEMA_ID",
    "RuntimeObservationCommit",
    "RuntimeObservationError",
    "RuntimeObservationRequest",
    "record_runtime_observation",
    "record_runtime_observation_in_transaction",
]
