"""Explicit authority bridge from runtime observations to analysis facts.

Runtime hook facts deliberately carry no objective-bucket or promotion
authority.  This module adds neither by inference: one immutable policy must
name every admitted source code, its exact bucket, the current profile, the
analysis window, the evidence authority, and the output key epoch.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Any, Mapping, Sequence

from .canary_runtime import (
    CANARY_RUNTIME_OBSERVATION_KIND,
    CANARY_RUNTIME_REGISTRY,
)
from .deterministic_analysis import (
    DETERMINISTIC_ANALYSIS_REGISTRY,
    OBJECTIVE_BUCKETS,
    ExactIdentity,
    build_observation_fact,
)
from .observation import (
    RUNTIME_OBSERVATION_KIND,
    RUNTIME_OBSERVATION_SCHEMA_ID,
)
from .repository import DomainEvent, IntegrityFailure, V3Repository, V3Transaction
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


ANALYSIS_WINDOW_SCHEMA_ID = "a0.observation-analysis-window.v1"
EVIDENCE_AUTHORITY_SCHEMA_ID = "a0.observation-evidence-authority.v1"
OBSERVATION_BRIDGE_POLICY_SCHEMA_ID = "a0.observation-bridge-policy.v1"
CERTIFIED_CANARY_OUTCOME_SCHEMA_ID = "a0.certified-canary-outcome.v1"
OBSERVATION_BRIDGE_RECEIPT_SCHEMA_ID = "a0.observation-bridge-receipt.v1"

ANALYSIS_WINDOW_KIND = "observation_analysis_window"
EVIDENCE_AUTHORITY_KIND = "observation_evidence_authority"
OBSERVATION_BRIDGE_POLICY_KIND = "observation_bridge_policy"
CERTIFIED_CANARY_OUTCOME_KIND = "certified_canary_outcome"
OBSERVATION_BRIDGE_RECEIPT_KIND = "observation_bridge_receipt"
OBSERVATION_BRIDGE_AUTHORITY_REF = "system:observation-bridge-coordinator:v1"

_SOURCE_KINDS = ("runtime_observation", "certified_canary_outcome")
_CANARY_OBSERVATION_KIND = "canary_runtime_observation"
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")


class ObservationBridgeError(RuntimeError):
    """An exact bridge input is unavailable or outside explicit authority."""


class ObservationBridgeConflict(ObservationBridgeError):
    """One idempotency identity was reused with a changed request."""


class CanaryOutcomeAuthorityRequired(ObservationBridgeError):
    """An exposure-only canary observation lacks certified outcome authority."""


def _opaque(value: Any, path: str, *, maximum: int = 512) -> str:
    result = strict_string(maximum=maximum)(value, path)
    if _OPAQUE.fullmatch(result) is None:
        raise SchemaValidationError(f"{path} must be a bounded opaque reference")
    return result


_EXACT = strict_object({"record_id": _opaque, "digest": validate_digest})
_OPTIONAL_EXACT = strict_nullable(_EXACT)
_MAPPING = strict_object(
    {
        "source_kind": strict_enum(_SOURCE_KINDS),
        "observation_kind": _opaque,
        "outcome_code": _opaque,
        "objective_bucket": strict_enum(OBJECTIVE_BUCKETS),
    }
)
_INPUT = strict_object(
    {
        "observation": _EXACT,
        "certified_outcome_authority": _OPTIONAL_EXACT,
    }
)


def _identity_payload(identity: ExactIdentity) -> dict[str, str]:
    return {"record_id": identity.ref, "digest": identity.digest}


def _identity_from_payload(value: Mapping[str, str]) -> ExactIdentity:
    return ExactIdentity(value["record_id"], value["digest"])


def _link(role: str, ordinal: int, identity: ExactIdentity | TypedRecord) -> dict[str, Any]:
    if isinstance(identity, TypedRecord):
        target_id, target_digest = identity.record_id, identity.content_digest
    else:
        target_id, target_digest = identity.ref, identity.digest
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": target_id,
        "target_digest": target_digest,
    }


def _window_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal(ANALYSIS_WINDOW_KIND),
            "window_revision": strict_integer(minimum=0),
            "membership_authority": strict_literal("explicit_bridge_request_only"),
            "contains_raw_content": strict_literal(False),
            "contains_quarantine_content": strict_literal(False),
            "contains_certification_holdout": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    if payload["links"]:
        raise SchemaValidationError(f"{path}.links must be empty")
    return payload


def _evidence_authority_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal(EVIDENCE_AUTHORITY_KIND),
            "authority_revision": strict_integer(minimum=0),
            "authority_state": strict_literal("approved"),
            "authority_ceiling": strict_literal("analysis_input_only"),
            "promotion_authority": strict_literal("none"),
            "contains_raw_content": strict_literal(False),
            "contains_quarantine_content": strict_literal(False),
            "contains_certification_holdout": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    if payload["links"]:
        raise SchemaValidationError(f"{path}.links must be empty")
    return payload


def _policy_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal(OBSERVATION_BRIDGE_POLICY_KIND),
            "policy_revision": strict_integer(minimum=0),
            "current_profile": _EXACT,
            "analysis_window": _EXACT,
            "evidence_authority": _EXACT,
            "output_key_epoch": _opaque,
            "mappings": strict_list(_MAPPING, minimum=1, maximum=64),
            "canary_admission": strict_literal("certified_outcome_authority_required"),
            "semantic_authority": strict_literal("explicit_mapping_only"),
            "promotion_authority": strict_literal("none"),
            "links": validate_links,
        }
    )(value, path)
    mappings = payload["mappings"]
    keys = [
        (item["source_kind"], item["observation_kind"], item["outcome_code"])
        for item in mappings
    ]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise SchemaValidationError(f"{path}.mappings must be sorted and unique")
    for item in mappings:
        if (
            item["source_kind"] == "runtime_observation"
            and item["observation_kind"] not in ("message_loop_end", "tool_execute_after")
        ) or (
            item["source_kind"] == "certified_canary_outcome"
            and item["observation_kind"] != _CANARY_OBSERVATION_KIND
        ):
            raise SchemaValidationError(f"{path}.mappings contains an invalid source shape")
    expected = [
        _link("current_profile", 0, _identity_from_payload(payload["current_profile"])),
        _link("analysis_window", 0, _identity_from_payload(payload["analysis_window"])),
        _link("evidence_authority", 0, _identity_from_payload(payload["evidence_authority"])),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind exact bridge authorities")
    return payload


def _certified_canary_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal(CERTIFIED_CANARY_OUTCOME_KIND),
            "canary_observation": _EXACT,
            "certified_outcome_code": _opaque,
            "source_profile": _EXACT,
            "current_profile": _EXACT,
            "observed_scope_revision": strict_integer(minimum=0),
            "analysis_window": _EXACT,
            "evidence_authority": _EXACT,
            "authority_class": strict_literal("certified_canary_outcome"),
            "authority_ceiling": strict_literal("analysis_input_only"),
            "promotion_authority": strict_literal("none"),
            "contains_raw_content": strict_literal(False),
            "contains_provider_identifier": strict_literal(False),
            "contains_error_detail": strict_literal(False),
            "contains_path": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    if payload["certified_outcome_code"] == "message_loop_end_observed":
        raise SchemaValidationError(
            f"{path}.certified_outcome_code cannot relabel an exposure occurrence"
        )
    expected = [
        _link("canary_observation", 0, _identity_from_payload(payload["canary_observation"])),
        _link("source_profile", 0, _identity_from_payload(payload["source_profile"])),
        _link("current_profile", 0, _identity_from_payload(payload["current_profile"])),
        _link("analysis_window", 0, _identity_from_payload(payload["analysis_window"])),
        _link("evidence_authority", 0, _identity_from_payload(payload["evidence_authority"])),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind exact certified outcome inputs")
    return payload


def _receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal(OBSERVATION_BRIDGE_RECEIPT_KIND),
            "request_digest": validate_digest,
            "idempotency_key_digest": validate_digest,
            "policy": _EXACT,
            "policy_revision": strict_integer(minimum=0),
            "current_profile": _EXACT,
            "observed_scope_revision": strict_integer(minimum=0),
            "analysis_window": _EXACT,
            "evidence_authority": _EXACT,
            "output_key_epoch": _opaque,
            "inputs": strict_list(_INPUT, minimum=1, maximum=1024),
            "facts": strict_list(_EXACT, minimum=1, maximum=1024),
            "admission_state": strict_literal("admitted"),
            "semantic_authority": strict_literal("explicit_policy_mapping"),
            "promotion_authority": strict_literal("none"),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("bridge_policy", 0, _identity_from_payload(payload["policy"])),
        _link("current_profile", 0, _identity_from_payload(payload["current_profile"])),
        _link("analysis_window", 0, _identity_from_payload(payload["analysis_window"])),
        _link("evidence_authority", 0, _identity_from_payload(payload["evidence_authority"])),
    ]
    for ordinal, item in enumerate(payload["inputs"]):
        expected.append(
            _link("runtime_input", ordinal, _identity_from_payload(item["observation"]))
        )
        authority = item["certified_outcome_authority"]
        if authority is not None:
            expected.append(
                _link("certified_outcome_authority", ordinal, _identity_from_payload(authority))
            )
    expected.extend(
        _link("analysis_fact", ordinal, _identity_from_payload(item))
        for ordinal, item in enumerate(payload["facts"])
    )
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact bridge write set")
    return payload


_LOCAL_REGISTRY = SchemaRegistry(
    (
        RecordSchema(ANALYSIS_WINDOW_SCHEMA_ID, ANALYSIS_WINDOW_KIND, _window_validator),
        RecordSchema(
            EVIDENCE_AUTHORITY_SCHEMA_ID,
            EVIDENCE_AUTHORITY_KIND,
            _evidence_authority_validator,
        ),
        RecordSchema(
            OBSERVATION_BRIDGE_POLICY_SCHEMA_ID,
            OBSERVATION_BRIDGE_POLICY_KIND,
            _policy_validator,
        ),
        RecordSchema(
            CERTIFIED_CANARY_OUTCOME_SCHEMA_ID,
            CERTIFIED_CANARY_OUTCOME_KIND,
            _certified_canary_validator,
        ),
        RecordSchema(
            OBSERVATION_BRIDGE_RECEIPT_SCHEMA_ID,
            OBSERVATION_BRIDGE_RECEIPT_KIND,
            _receipt_validator,
        ),
    )
)

OBSERVATION_BRIDGE_REGISTRY = merge_schema_registries(
    CANARY_RUNTIME_REGISTRY,
    DETERMINISTIC_ANALYSIS_REGISTRY,
    _LOCAL_REGISTRY,
)


@dataclass(frozen=True, slots=True, order=True)
class OutcomeMapping:
    source_kind: str
    observation_kind: str
    outcome_code: str
    objective_bucket: str

    def __post_init__(self) -> None:
        _MAPPING(self.as_payload(), "mapping")

    def as_payload(self) -> dict[str, str]:
        return {
            "source_kind": self.source_kind,
            "observation_kind": self.observation_kind,
            "outcome_code": self.outcome_code,
            "objective_bucket": self.objective_bucket,
        }


@dataclass(frozen=True, slots=True)
class BridgeInput:
    observation: ExactIdentity
    certified_outcome_authority: ExactIdentity | None = None

    def __post_init__(self) -> None:
        if type(self.observation) is not ExactIdentity:
            raise TypeError("observation must be exact")
        if self.certified_outcome_authority is not None and type(
            self.certified_outcome_authority
        ) is not ExactIdentity:
            raise TypeError("certified_outcome_authority must be exact")

    def as_payload(self) -> dict[str, object]:
        return {
            "observation": _identity_payload(self.observation),
            "certified_outcome_authority": (
                None
                if self.certified_outcome_authority is None
                else _identity_payload(self.certified_outcome_authority)
            ),
        }


@dataclass(frozen=True, slots=True)
class ObservationBridgeRequest:
    context_ref: str
    idempotency_key: str
    policy: ExactIdentity
    current_profile: ExactIdentity
    analysis_window: ExactIdentity
    evidence_authority: ExactIdentity
    output_key_epoch: str
    inputs: tuple[BridgeInput, ...]

    def __post_init__(self) -> None:
        _opaque(self.context_ref, "context_ref")
        if type(self.idempotency_key) is not str or not 1 <= len(self.idempotency_key) <= 512:
            raise ObservationBridgeError("idempotency_key must be explicit and bounded")
        for name in (
            "policy",
            "current_profile",
            "analysis_window",
            "evidence_authority",
        ):
            if type(getattr(self, name)) is not ExactIdentity:
                raise TypeError(f"{name} must be exact")
        _opaque(self.output_key_epoch, "output_key_epoch")
        if type(self.inputs) is not tuple or not self.inputs:
            raise ObservationBridgeError("inputs must be a non-empty frozen tuple")
        if any(type(item) is not BridgeInput for item in self.inputs):
            raise TypeError("inputs must contain BridgeInput values")
        refs = [item.observation.ref for item in self.inputs]
        if refs != sorted(refs) or len(refs) != len(set(refs)):
            raise ObservationBridgeError("inputs must be sorted and unique by observation")


@dataclass(frozen=True, slots=True)
class ObservationBridgeCommit:
    receipt: TypedRecord
    facts: tuple[TypedRecord, ...]
    event: DomainEvent
    replayed: bool


def build_analysis_window(
    *, record_id: str, context_ref: str, window_revision: int, key_epoch: str
) -> TypedRecord:
    payload = {
        "record_type": ANALYSIS_WINDOW_KIND,
        "window_revision": window_revision,
        "membership_authority": "explicit_bridge_request_only",
        "contains_raw_content": False,
        "contains_quarantine_content": False,
        "contains_certification_holdout": False,
        "links": [],
    }
    return _record(record_id, context_ref, ANALYSIS_WINDOW_KIND, ANALYSIS_WINDOW_SCHEMA_ID, payload, key_epoch)


def build_evidence_authority(
    *, record_id: str, context_ref: str, authority_revision: int, key_epoch: str
) -> TypedRecord:
    payload = {
        "record_type": EVIDENCE_AUTHORITY_KIND,
        "authority_revision": authority_revision,
        "authority_state": "approved",
        "authority_ceiling": "analysis_input_only",
        "promotion_authority": "none",
        "contains_raw_content": False,
        "contains_quarantine_content": False,
        "contains_certification_holdout": False,
        "links": [],
    }
    return _record(
        record_id,
        context_ref,
        EVIDENCE_AUTHORITY_KIND,
        EVIDENCE_AUTHORITY_SCHEMA_ID,
        payload,
        key_epoch,
    )


def build_observation_bridge_policy(
    *,
    record_id: str,
    context_ref: str,
    policy_revision: int,
    current_profile: TypedRecord,
    analysis_window: TypedRecord,
    evidence_authority: TypedRecord,
    mappings: Sequence[OutcomeMapping],
    output_key_epoch: str,
) -> TypedRecord:
    _require_supplied_record(current_profile, context_ref, "activation_profile", None)
    _require_supplied_record(
        analysis_window, context_ref, ANALYSIS_WINDOW_KIND, ANALYSIS_WINDOW_SCHEMA_ID
    )
    _require_supplied_record(
        evidence_authority,
        context_ref,
        EVIDENCE_AUTHORITY_KIND,
        EVIDENCE_AUTHORITY_SCHEMA_ID,
    )
    items = tuple(mappings)
    if not items or any(type(item) is not OutcomeMapping for item in items):
        raise ObservationBridgeError("mappings must contain explicit OutcomeMapping values")
    if items != tuple(sorted(items)):
        raise ObservationBridgeError("mappings must be in canonical order")
    payload = {
        "record_type": OBSERVATION_BRIDGE_POLICY_KIND,
        "policy_revision": policy_revision,
        "current_profile": _identity_payload(ExactIdentity(current_profile.record_id, current_profile.content_digest)),
        "analysis_window": _identity_payload(ExactIdentity(analysis_window.record_id, analysis_window.content_digest)),
        "evidence_authority": _identity_payload(ExactIdentity(evidence_authority.record_id, evidence_authority.content_digest)),
        "output_key_epoch": output_key_epoch,
        "mappings": [item.as_payload() for item in items],
        "canary_admission": "certified_outcome_authority_required",
        "semantic_authority": "explicit_mapping_only",
        "promotion_authority": "none",
        "links": [
            _link("current_profile", 0, current_profile),
            _link("analysis_window", 0, analysis_window),
            _link("evidence_authority", 0, evidence_authority),
        ],
    }
    return _record(
        record_id,
        context_ref,
        OBSERVATION_BRIDGE_POLICY_KIND,
        OBSERVATION_BRIDGE_POLICY_SCHEMA_ID,
        payload,
        output_key_epoch,
    )


def build_certified_canary_outcome(
    *,
    record_id: str,
    context_ref: str,
    canary_observation: TypedRecord,
    certified_outcome_code: str,
    source_profile: TypedRecord,
    current_profile: TypedRecord,
    observed_scope_revision: int,
    analysis_window: TypedRecord,
    evidence_authority: TypedRecord,
    key_epoch: str,
) -> TypedRecord:
    _require_supplied_record(
        canary_observation,
        context_ref,
        CANARY_RUNTIME_OBSERVATION_KIND,
        None,
        CANARY_RUNTIME_REGISTRY,
    )
    for record in (source_profile, current_profile):
        _require_supplied_record(record, context_ref, "activation_profile", None)
    _require_supplied_record(
        analysis_window, context_ref, ANALYSIS_WINDOW_KIND, ANALYSIS_WINDOW_SCHEMA_ID
    )
    _require_supplied_record(
        evidence_authority,
        context_ref,
        EVIDENCE_AUTHORITY_KIND,
        EVIDENCE_AUTHORITY_SCHEMA_ID,
    )
    payload = {
        "record_type": CERTIFIED_CANARY_OUTCOME_KIND,
        "canary_observation": _identity_payload(ExactIdentity(canary_observation.record_id, canary_observation.content_digest)),
        "certified_outcome_code": certified_outcome_code,
        "source_profile": _identity_payload(ExactIdentity(source_profile.record_id, source_profile.content_digest)),
        "current_profile": _identity_payload(ExactIdentity(current_profile.record_id, current_profile.content_digest)),
        "observed_scope_revision": observed_scope_revision,
        "analysis_window": _identity_payload(ExactIdentity(analysis_window.record_id, analysis_window.content_digest)),
        "evidence_authority": _identity_payload(ExactIdentity(evidence_authority.record_id, evidence_authority.content_digest)),
        "authority_class": "certified_canary_outcome",
        "authority_ceiling": "analysis_input_only",
        "promotion_authority": "none",
        "contains_raw_content": False,
        "contains_provider_identifier": False,
        "contains_error_detail": False,
        "contains_path": False,
        "links": [
            _link("canary_observation", 0, canary_observation),
            _link("source_profile", 0, source_profile),
            _link("current_profile", 0, current_profile),
            _link("analysis_window", 0, analysis_window),
            _link("evidence_authority", 0, evidence_authority),
        ],
    }
    return _record(
        record_id,
        context_ref,
        CERTIFIED_CANARY_OUTCOME_KIND,
        CERTIFIED_CANARY_OUTCOME_SCHEMA_ID,
        payload,
        key_epoch,
    )


def bridge_runtime_observations(
    repository: V3Repository, request: ObservationBridgeRequest
) -> ObservationBridgeCommit:
    """Admit exact observations and append deterministic facts atomically."""

    if type(repository) is not V3Repository:
        raise TypeError("repository must be a V3Repository")
    if type(request) is not ObservationBridgeRequest:
        raise TypeError("request must be an ObservationBridgeRequest")
    request_digest = _request_digest(request)
    key_digest = _idempotency_digest(request.idempotency_key)
    receipt_identity = canonical_json(
        {"context_ref": request.context_ref, "idempotency_key_digest": key_digest}
    )
    receipt_id = (
        "observation-bridge-receipt:"
        + schema_digest(
            "observation-bridge-id",
            OBSERVATION_BRIDGE_RECEIPT_SCHEMA_ID,
            receipt_identity,
        )
    )
    with repository.transaction() as transaction:
        existing = transaction.get_record(receipt_id)
        if existing is not None:
            return _replay(transaction, request, existing, request_digest)

        policy = _exact_record(
            transaction,
            request.policy,
            context_ref=request.context_ref,
            record_kind=OBSERVATION_BRIDGE_POLICY_KIND,
            schema_id=OBSERVATION_BRIDGE_POLICY_SCHEMA_ID,
        )
        profile = _exact_record(
            transaction,
            request.current_profile,
            context_ref=request.context_ref,
            record_kind="activation_profile",
        )
        window = _exact_record(
            transaction,
            request.analysis_window,
            context_ref=request.context_ref,
            record_kind=ANALYSIS_WINDOW_KIND,
            schema_id=ANALYSIS_WINDOW_SCHEMA_ID,
        )
        evidence = _exact_record(
            transaction,
            request.evidence_authority,
            context_ref=request.context_ref,
            record_kind=EVIDENCE_AUTHORITY_KIND,
            schema_id=EVIDENCE_AUTHORITY_SCHEMA_ID,
        )
        scope = transaction.get_activation_scope(request.context_ref)
        if (
            scope is None
            or scope.mode != "normal"
            or (scope.current_profile_id, scope.current_profile_digest)
            != (profile.record_id, profile.content_digest)
        ):
            raise ObservationBridgeError("current Activation Profile authority is unavailable")
        _require_policy_bindings(policy, request, scope.scope_revision)
        mappings = {
            (item["source_kind"], item["observation_kind"], item["outcome_code"]): item[
                "objective_bucket"
            ]
            for item in policy.payload["mappings"]
        }

        aggregates: dict[tuple[str, str, str, str], int] = {}
        for item in request.inputs:
            source, outcome_code, bucket = _admit_input(
                transaction,
                item,
                request=request,
                scope_revision=scope.scope_revision,
                mappings=mappings,
            )
            key = (bucket, outcome_code, source.ref, source.digest)
            aggregates[key] = aggregates.get(key, 0) + 1

        facts: list[TypedRecord] = []
        for (bucket, outcome_code, source_ref, source_digest), occurrences in sorted(
            aggregates.items()
        ):
            fact = build_observation_fact(
                context_ref=request.context_ref,
                key_epoch=request.output_key_epoch,
                bucket_ref=bucket,
                outcome_code=outcome_code,
                occurrences=occurrences,
                source_profile=ExactIdentity(source_ref, source_digest),
                window=request.analysis_window,
                evidence=request.evidence_authority,
                contains_raw_content=False,
                contains_quarantine_content=False,
                contains_certification_holdout=False,
            )
            facts.append(transaction.insert_record(fact).record)

        receipt = _build_receipt(
            receipt_id=receipt_id,
            request=request,
            request_digest=request_digest,
            key_digest=key_digest,
            policy=policy,
            scope_revision=scope.scope_revision,
            facts=tuple(facts),
        )
        admitted_receipt = transaction.insert_record(receipt).record
        event = DomainEvent(
            event_id=f"observation-bridge-event:{admitted_receipt.record_id.split(':', 1)[-1]}",
            subject_id=admitted_receipt.record_id,
            subject_kind=admitted_receipt.record_kind,
            sequence=0,
            event_type="observation_bridge_admitted",
            payload_record_id=admitted_receipt.record_id,
            actor_authority_ref=OBSERVATION_BRIDGE_AUTHORITY_REF,
        )
        admitted_event = transaction.append_event(event)
        return ObservationBridgeCommit(admitted_receipt, tuple(facts), admitted_event, False)


def _admit_input(
    transaction: V3Transaction,
    item: BridgeInput,
    *,
    request: ObservationBridgeRequest,
    scope_revision: int,
    mappings: Mapping[tuple[str, str, str], str],
) -> tuple[ExactIdentity, str, str]:
    observation = transaction.get_record(item.observation.ref)
    if observation is None or observation.content_digest != item.observation.digest:
        raise ObservationBridgeError("exact runtime observation is unavailable")
    if observation.context_ref != request.context_ref:
        raise ObservationBridgeError("runtime observation belongs to another context")

    if observation.record_kind == RUNTIME_OBSERVATION_KIND:
        if item.certified_outcome_authority is not None:
            raise ObservationBridgeError("ordinary runtime input cannot borrow canary authority")
        observation.verify(OBSERVATION_BRIDGE_REGISTRY)
        payload = observation.payload
        if (
            observation.schema_id != RUNTIME_OBSERVATION_SCHEMA_ID
            or payload["promotion_authority"] != "none"
            or payload["authority_ceiling"] != "runtime_observation_only"
            or payload["objective_bucket_state"] != "unbound"
            or payload["contains_raw_content"]
            or payload["contains_quarantine_content"]
            or payload["contains_certification_holdout"]
            or payload["contains_provider_identifier"]
            or payload["contains_error_detail"]
            or payload["contains_path"]
            or payload["observed_profile_ref"] != request.current_profile.ref
            or payload["observed_profile_digest"] != request.current_profile.digest
            or payload["observed_scope_revision"] != scope_revision
        ):
            raise ObservationBridgeError("runtime observation lost content-safe current authority")
        mapping_key = (
            "runtime_observation",
            payload["observation_kind"],
            payload["outcome_code"],
        )
        bucket = mappings.get(mapping_key)
        if bucket is None:
            raise ObservationBridgeError("runtime outcome has no explicit bucket mapping")
        return request.current_profile, payload["outcome_code"], bucket

    if observation.record_kind != CANARY_RUNTIME_OBSERVATION_KIND:
        raise ObservationBridgeError("input is not an admitted runtime observation")
    if item.certified_outcome_authority is None:
        raise CanaryOutcomeAuthorityRequired(
            "exposure-only canary observation requires certified outcome authority"
        )
    observation.verify(OBSERVATION_BRIDGE_REGISTRY)
    op = observation.payload
    if (
        op["outcome_authority"] != "exposure_only"
        or op["promotion_authority"] != "none"
        or op["objective_bucket_state"] != "unbound"
        or op["outcome_code"] != "message_loop_end_observed"
    ):
        raise ObservationBridgeError("canary input is not an exact exposure-only observation")
    runtime = _exact_record(
        transaction,
        ExactIdentity(op["runtime_observation_id"], op["runtime_observation_digest"]),
        context_ref=request.context_ref,
        record_kind=RUNTIME_OBSERVATION_KIND,
        schema_id=RUNTIME_OBSERVATION_SCHEMA_ID,
    )
    rp = runtime.payload
    if (
        rp["observed_profile_ref"] != request.current_profile.ref
        or rp["observed_profile_digest"] != request.current_profile.digest
        or rp["observed_scope_revision"] != scope_revision
    ):
        raise ObservationBridgeError("canary runtime occurrence is stale")
    source = _exact_record(
        transaction,
        ExactIdentity(op["selected_profile_id"], op["selected_profile_digest"]),
        context_ref=request.context_ref,
        record_kind="activation_profile",
    )
    authority = _exact_record(
        transaction,
        item.certified_outcome_authority,
        context_ref=request.context_ref,
        record_kind=CERTIFIED_CANARY_OUTCOME_KIND,
        schema_id=CERTIFIED_CANARY_OUTCOME_SCHEMA_ID,
    )
    ap = authority.payload
    if (
        ap["canary_observation"] != _identity_payload(item.observation)
        or ap["source_profile"]
        != _identity_payload(ExactIdentity(source.record_id, source.content_digest))
        or ap["current_profile"] != _identity_payload(request.current_profile)
        or ap["observed_scope_revision"] != scope_revision
        or ap["analysis_window"] != _identity_payload(request.analysis_window)
        or ap["evidence_authority"] != _identity_payload(request.evidence_authority)
        or authority.key_epoch != request.output_key_epoch
    ):
        raise ObservationBridgeError("certified canary outcome authority is not exact")
    outcome_code = ap["certified_outcome_code"]
    bucket = mappings.get(
        ("certified_canary_outcome", _CANARY_OBSERVATION_KIND, outcome_code)
    )
    if bucket is None:
        raise ObservationBridgeError("certified canary outcome has no explicit bucket mapping")
    return ExactIdentity(source.record_id, source.content_digest), outcome_code, bucket


def _require_policy_bindings(
    policy: TypedRecord, request: ObservationBridgeRequest, scope_revision: int
) -> None:
    payload = policy.payload
    if (
        payload["current_profile"] != _identity_payload(request.current_profile)
        or payload["analysis_window"] != _identity_payload(request.analysis_window)
        or payload["evidence_authority"] != _identity_payload(request.evidence_authority)
        or payload["output_key_epoch"] != request.output_key_epoch
        or policy.key_epoch != request.output_key_epoch
        or payload["promotion_authority"] != "none"
        or type(scope_revision) is not int
    ):
        raise ObservationBridgeError("bridge policy does not bind exact request authority")


def _exact_record(
    transaction: V3Transaction,
    identity: ExactIdentity,
    *,
    context_ref: str,
    record_kind: str,
    schema_id: str | None = None,
) -> TypedRecord:
    record = transaction.get_record(identity.ref)
    if (
        record is None
        or record.content_digest != identity.digest
        or record.context_ref != context_ref
        or record.record_kind != record_kind
        or (schema_id is not None and record.schema_id != schema_id)
    ):
        raise ObservationBridgeError(f"exact {record_kind} is unavailable")
    record.verify(OBSERVATION_BRIDGE_REGISTRY)
    return record


def _require_supplied_record(
    record: TypedRecord,
    context_ref: str,
    record_kind: str,
    schema_id: str | None,
    registry: SchemaRegistry = OBSERVATION_BRIDGE_REGISTRY,
) -> None:
    if type(record) is not TypedRecord:
        raise TypeError(f"{record_kind} must be a TypedRecord")
    record.verify(registry)
    if (
        record.context_ref != context_ref
        or record.record_kind != record_kind
        or (schema_id is not None and record.schema_id != schema_id)
    ):
        raise ObservationBridgeError(f"{record_kind} is not exact for this context")


def _record(
    record_id: str,
    context_ref: str,
    record_kind: str,
    schema_id: str,
    payload: Mapping[str, Any],
    key_epoch: str,
) -> TypedRecord:
    _opaque(record_id, "record_id")
    _opaque(context_ref, "context_ref")
    _opaque(key_epoch, "key_epoch")
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind=record_kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=key_epoch,
        registry=OBSERVATION_BRIDGE_REGISTRY,
    )


def _request_payload(request: ObservationBridgeRequest) -> dict[str, Any]:
    return {
        "context_ref": request.context_ref,
        "idempotency_key_digest": _idempotency_digest(request.idempotency_key),
        "policy": _identity_payload(request.policy),
        "current_profile": _identity_payload(request.current_profile),
        "analysis_window": _identity_payload(request.analysis_window),
        "evidence_authority": _identity_payload(request.evidence_authority),
        "output_key_epoch": request.output_key_epoch,
        "inputs": [item.as_payload() for item in request.inputs],
    }


def _request_digest(request: ObservationBridgeRequest) -> str:
    return schema_digest(
        "observation-bridge-request",
        OBSERVATION_BRIDGE_RECEIPT_SCHEMA_ID,
        canonical_json(_request_payload(request)),
    )


def _idempotency_digest(value: str) -> str:
    return sha256(b"a0-observation-bridge-key\0" + value.encode("utf-8")).hexdigest()


def _build_receipt(
    *,
    receipt_id: str,
    request: ObservationBridgeRequest,
    request_digest: str,
    key_digest: str,
    policy: TypedRecord,
    scope_revision: int,
    facts: tuple[TypedRecord, ...],
) -> TypedRecord:
    inputs = [item.as_payload() for item in request.inputs]
    fact_refs = [
        _identity_payload(ExactIdentity(item.record_id, item.content_digest)) for item in facts
    ]
    links = [
        _link("bridge_policy", 0, request.policy),
        _link("current_profile", 0, request.current_profile),
        _link("analysis_window", 0, request.analysis_window),
        _link("evidence_authority", 0, request.evidence_authority),
    ]
    for ordinal, item in enumerate(request.inputs):
        links.append(_link("runtime_input", ordinal, item.observation))
        if item.certified_outcome_authority is not None:
            links.append(
                _link(
                    "certified_outcome_authority",
                    ordinal,
                    item.certified_outcome_authority,
                )
            )
    links.extend(_link("analysis_fact", ordinal, fact) for ordinal, fact in enumerate(facts))
    payload = {
        "record_type": OBSERVATION_BRIDGE_RECEIPT_KIND,
        "request_digest": request_digest,
        "idempotency_key_digest": key_digest,
        "policy": _identity_payload(request.policy),
        "policy_revision": policy.payload["policy_revision"],
        "current_profile": _identity_payload(request.current_profile),
        "observed_scope_revision": scope_revision,
        "analysis_window": _identity_payload(request.analysis_window),
        "evidence_authority": _identity_payload(request.evidence_authority),
        "output_key_epoch": request.output_key_epoch,
        "inputs": inputs,
        "facts": fact_refs,
        "admission_state": "admitted",
        "semantic_authority": "explicit_policy_mapping",
        "promotion_authority": "none",
        "links": links,
    }
    return _record(
        receipt_id,
        request.context_ref,
        OBSERVATION_BRIDGE_RECEIPT_KIND,
        OBSERVATION_BRIDGE_RECEIPT_SCHEMA_ID,
        payload,
        request.output_key_epoch,
    )


def _replay(
    transaction: V3Transaction,
    request: ObservationBridgeRequest,
    receipt: TypedRecord,
    request_digest: str,
) -> ObservationBridgeCommit:
    if (
        receipt.context_ref != request.context_ref
        or receipt.record_kind != OBSERVATION_BRIDGE_RECEIPT_KIND
        or receipt.schema_id != OBSERVATION_BRIDGE_RECEIPT_SCHEMA_ID
    ):
        raise IntegrityFailure("bridge receipt identity resolved to another record")
    receipt.verify(OBSERVATION_BRIDGE_REGISTRY)
    if receipt.payload["request_digest"] != request_digest:
        raise ObservationBridgeConflict(
            "idempotency key was reused with a different bridge request"
        )
    facts = tuple(
        _exact_record(
            transaction,
            _identity_from_payload(item),
            context_ref=request.context_ref,
            record_kind="analysis_observation_fact",
        )
        for item in receipt.payload["facts"]
    )
    event = transaction.get_domain_event(receipt.record_id, 0)
    expected = DomainEvent(
        event_id=f"observation-bridge-event:{receipt.record_id.split(':', 1)[-1]}",
        subject_id=receipt.record_id,
        subject_kind=receipt.record_kind,
        sequence=0,
        event_type="observation_bridge_admitted",
        payload_record_id=receipt.record_id,
        actor_authority_ref=OBSERVATION_BRIDGE_AUTHORITY_REF,
    )
    if event != expected:
        raise IntegrityFailure("bridge receipt event is missing or changed")
    return ObservationBridgeCommit(receipt, facts, expected, True)


__all__ = [
    "ANALYSIS_WINDOW_KIND",
    "ANALYSIS_WINDOW_SCHEMA_ID",
    "CERTIFIED_CANARY_OUTCOME_KIND",
    "CERTIFIED_CANARY_OUTCOME_SCHEMA_ID",
    "EVIDENCE_AUTHORITY_KIND",
    "EVIDENCE_AUTHORITY_SCHEMA_ID",
    "OBSERVATION_BRIDGE_POLICY_KIND",
    "OBSERVATION_BRIDGE_POLICY_SCHEMA_ID",
    "OBSERVATION_BRIDGE_RECEIPT_KIND",
    "OBSERVATION_BRIDGE_RECEIPT_SCHEMA_ID",
    "OBSERVATION_BRIDGE_REGISTRY",
    "BridgeInput",
    "CanaryOutcomeAuthorityRequired",
    "ObservationBridgeCommit",
    "ObservationBridgeConflict",
    "ObservationBridgeError",
    "ObservationBridgeRequest",
    "OutcomeMapping",
    "bridge_runtime_observations",
    "build_analysis_window",
    "build_certified_canary_outcome",
    "build_evidence_authority",
    "build_observation_bridge_policy",
]
