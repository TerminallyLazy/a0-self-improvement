"""Append-only, annotation-only Feedback Evidence authority."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from .authority import AuthorityAction, AuthorityClass, AuthorityPurpose, VerifiedGrant
from .evidence import EVIDENCE_REGISTRY
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
    strict_enum,
    strict_list,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


FEEDBACK_ASSESSMENT_SCHEMA_ID = "a0.feedback-assessment.v1"
FEEDBACK_MUTATION_RECEIPT_SCHEMA_ID = "a0.feedback-mutation-receipt.v1"
FEEDBACK_REASON_CATALOG_ID = "a0.feedback-reason-catalog.v1"

ASSESSMENT_KINDS = ("helpfulness", "correctness", "safety", "completeness")
ASSESSMENT_STATES = ("pass", "fail", "unavailable", "not_applicable")
FEEDBACK_OPERATIONS = ("assess", "correct", "withdraw")
FEEDBACK_REASON_CODES = (
    "complete",
    "correct",
    "evidence_unavailable",
    "helpful",
    "incomplete",
    "incorrect",
    "insufficient_context",
    "not_applicable",
    "not_helpful",
    "safe",
    "unsafe",
    "withdrawn",
)

_ACTION = AuthorityAction.FEEDBACK_SUBMIT.value
_PURPOSE = AuthorityPurpose.OPERATOR_MUTATION.value
_AUTHORITY_CLASS = AuthorityClass.OPERATOR_AUTHORITY_GRANT.value
_OUTCOME_EVIDENCE_KINDS = frozenset({"outcome_evidence", "evidence_bundle"})
_REASONS_BY_STATE = {
    ("helpfulness", "pass"): frozenset({"helpful"}),
    ("helpfulness", "fail"): frozenset({"not_helpful"}),
    ("correctness", "pass"): frozenset({"correct"}),
    ("correctness", "fail"): frozenset({"incorrect"}),
    ("safety", "pass"): frozenset({"safe"}),
    ("safety", "fail"): frozenset({"unsafe"}),
    ("completeness", "pass"): frozenset({"complete"}),
    ("completeness", "fail"): frozenset({"incomplete"}),
}
for _kind in ASSESSMENT_KINDS:
    _REASONS_BY_STATE[(_kind, "unavailable")] = frozenset(
        {"evidence_unavailable", "insufficient_context", "withdrawn"}
    )
    _REASONS_BY_STATE[(_kind, "not_applicable")] = frozenset({"not_applicable"})


class FeedbackDenied(RuntimeError):
    """Stable fail-closed feedback admission error."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _deny(reason_code: str) -> None:
    raise FeedbackDenied(reason_code)


def _timestamp(value: Any, path: str) -> str:
    if type(value) is not str:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    return value


_EXACT = strict_object(
    {"record_id": strict_string(maximum=512), "digest": validate_digest}
)
_OPTIONAL_EXACT = strict_nullable(_EXACT)
_REASONS = strict_list(
    strict_enum(FEEDBACK_REASON_CODES), minimum=1, maximum=4
)


def _assessment_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("feedback_assessment"),
            "operation": strict_enum(FEEDBACK_OPERATIONS),
            "context_ref": strict_string(maximum=128),
            "subject_ref": strict_string(maximum=128),
            "outcome_evidence": _EXACT,
            "activation_profile": _EXACT,
            "assessment_kind": strict_enum(ASSESSMENT_KINDS),
            "state": strict_enum(ASSESSMENT_STATES),
            "reason_catalog_id": strict_literal(FEEDBACK_REASON_CATALOG_ID),
            "reason_codes": _REASONS,
            "prior_assessment": _OPTIONAL_EXACT,
            "authority_grant_id": strict_string(maximum=128),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "recorded_at": _timestamp,
            "links": validate_links,
        }
    )(value, path)
    if payload["reason_codes"] != sorted(set(payload["reason_codes"])):
        raise SchemaValidationError(f"{path}.reason_codes must be sorted and unique")
    admitted_reasons = _REASONS_BY_STATE[
        (payload["assessment_kind"], payload["state"])
    ]
    if not set(payload["reason_codes"]) <= admitted_reasons:
        raise SchemaValidationError(f"{path}.reason_codes do not match the assessment")
    prior = payload["prior_assessment"]
    if payload["operation"] == "assess" and prior is not None:
        raise SchemaValidationError(f"{path}.prior_assessment must be null")
    if payload["operation"] != "assess" and prior is None:
        raise SchemaValidationError(f"{path}.prior_assessment is required")
    if payload["operation"] == "withdraw" and (
        payload["state"] != "unavailable" or payload["reason_codes"] != ["withdrawn"]
    ):
        raise SchemaValidationError(f"{path} withdrawal must use unavailable/withdrawn")
    expected = [
        _link("outcome_evidence", 0, payload["outcome_evidence"]),
        _link("activation_profile", 0, payload["activation_profile"]),
    ]
    if prior is not None:
        expected.append(_link("prior_assessment", 0, prior))
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind exact feedback inputs")
    return payload


def _receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "receipt_type": strict_literal("feedback_mutation"),
            "accepted": strict_literal(True),
            "action": strict_literal(_ACTION),
            "operation": strict_enum(FEEDBACK_OPERATIONS),
            "context_ref": strict_string(maximum=128),
            "subject_ref": strict_string(maximum=128),
            "assessment": _EXACT,
            "outcome_evidence": _EXACT,
            "activation_profile": _EXACT,
            "prior_assessment": _OPTIONAL_EXACT,
            "authority_grant_id": strict_string(maximum=128),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "reason_code": strict_enum(
                ("feedback_recorded", "feedback_corrected", "feedback_withdrawn")
            ),
            "recorded_at": _timestamp,
            "links": validate_links,
        }
    )(value, path)
    expected = [
        _link("assessment", 0, payload["assessment"]),
        _link("outcome_evidence", 0, payload["outcome_evidence"]),
        _link("activation_profile", 0, payload["activation_profile"]),
    ]
    if payload["prior_assessment"] is not None:
        expected.append(_link("prior_assessment", 0, payload["prior_assessment"]))
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the feedback mutation")
    expected_reason = {
        "assess": "feedback_recorded",
        "correct": "feedback_corrected",
        "withdraw": "feedback_withdrawn",
    }[payload["operation"]]
    if payload["reason_code"] != expected_reason:
        raise SchemaValidationError(f"{path}.reason_code does not match the operation")
    return payload


FEEDBACK_REGISTRY = merge_schema_registries(
    EVIDENCE_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                FEEDBACK_ASSESSMENT_SCHEMA_ID,
                "feedback_assessment",
                _assessment_validator,
            ),
            RecordSchema(
                FEEDBACK_MUTATION_RECEIPT_SCHEMA_ID,
                "feedback_mutation_receipt",
                _receipt_validator,
            ),
        )
    ),
)


@dataclass(frozen=True, slots=True)
class ExactFeedbackRecord:
    record_id: str
    digest: str

    def __post_init__(self) -> None:
        if type(self.record_id) is not str or not self.record_id:
            raise ValueError("record_id must be non-empty")
        validate_digest(self.digest, "digest")

    @classmethod
    def of(cls, record: TypedRecord) -> "ExactFeedbackRecord":
        return cls(record.record_id, record.content_digest)


@dataclass(frozen=True, slots=True)
class FeedbackRequest:
    issuer_ref: str
    subject_ref: str
    context_ref: str
    outcome_evidence: ExactFeedbackRecord
    activation_profile: ExactFeedbackRecord
    assessment_kind: str
    state: str
    reason_codes: tuple[str, ...]
    operation: str
    prior_assessment: ExactFeedbackRecord | None
    authority_grant_id: str
    idempotency_key_digest: str
    now: datetime

    def __post_init__(self) -> None:
        for name in ("issuer_ref", "subject_ref", "context_ref", "authority_grant_id"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if type(self.outcome_evidence) is not ExactFeedbackRecord:
            raise ValueError("outcome_evidence must be exact")
        if type(self.activation_profile) is not ExactFeedbackRecord:
            raise ValueError("activation_profile must be exact")
        if self.assessment_kind not in ASSESSMENT_KINDS:
            raise ValueError("assessment_kind is not admitted")
        if self.state not in ASSESSMENT_STATES:
            raise ValueError("state is not admitted")
        if self.operation not in FEEDBACK_OPERATIONS:
            raise ValueError("operation is not admitted")
        if self.prior_assessment is not None and type(self.prior_assessment) is not ExactFeedbackRecord:
            raise ValueError("prior_assessment must be exact or null")
        if type(self.reason_codes) is not tuple:
            raise ValueError("reason_codes must be a tuple")
        if not isinstance(self.now, datetime) or self.now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        validate_digest(self.idempotency_key_digest, "idempotency_key_digest")


@dataclass(frozen=True, slots=True)
class FeedbackMutationResult:
    assessment: TypedRecord
    receipt: TypedRecord
    command: OperatorCommand
    event: DomainEvent
    replayed: bool


@dataclass(frozen=True, slots=True)
class FeedbackReduction:
    outcome_evidence_ref: str
    activation_profile_ref: str
    active_counts: tuple[tuple[str, str, int], ...]
    conflict_kinds: tuple[str, ...]
    authority_ceiling: str = "annotation_only"
    deterministic_outcome_unchanged: bool = True
    deterministic_rejection_override: bool = False


GrantRevalidator = Callable[[V3Transaction], VerifiedGrant]


def record_feedback(
    repository: V3Repository,
    request: FeedbackRequest,
    *,
    revalidate_grant: GrantRevalidator,
) -> FeedbackMutationResult:
    """Atomically append one assessment, receipt, command, and domain event."""

    if type(request) is not FeedbackRequest:
        raise TypeError("request must be a FeedbackRequest")
    if not callable(revalidate_grant):
        raise TypeError("revalidate_grant must be callable")
    request_payload = _request_payload(request)
    request_digest = schema_digest(
        "feedback-request", "a0.feedback-request.v1", canonical_json(request_payload)
    )
    with repository.transaction() as transaction:
        evidence = _require_exact(
            transaction, request.outcome_evidence, _OUTCOME_EVIDENCE_KINDS
        )
        profile = _require_exact(
            transaction, request.activation_profile, frozenset({"activation_profile"})
        )
        if evidence.context_ref != request.context_ref:
            _deny("outcome_evidence_context_mismatch")
        if profile.context_ref != request.context_ref:
            _deny("activation_profile_context_mismatch")
        prior = _require_prior(transaction, request)
        grant = _verified_grant(transaction, request, revalidate_grant)
        replay = _existing_replay(transaction, request, request_digest, grant)
        if replay is not None:
            return replay

        assessment = _build_assessment(request, request_digest, grant, prior)
        transaction.insert_record(assessment)
        receipt = _build_receipt(request, request_digest, grant, assessment, prior)
        transaction.insert_record(receipt)
        command = _operator_command(request, request_digest, grant, receipt)
        admitted = transaction.admit_command(command)
        if admitted.replayed:
            raise IntegrityFailure("new feedback record collided with an existing command")
        event = DomainEvent(
            event_id=_identity("feedback-event", request_digest),
            subject_id=assessment.record_id,
            subject_kind=assessment.record_kind,
            sequence=0,
            event_type={
                "assess": "feedback_assessed",
                "correct": "feedback_corrected",
                "withdraw": "feedback_withdrawn",
            }[request.operation],
            payload_record_id=receipt.record_id,
            actor_authority_ref=grant.grant_id,
        )
        transaction.append_event(event)
        return FeedbackMutationResult(assessment, receipt, admitted.command, event, False)


def reduce_feedback(
    assessments: Iterable[TypedRecord],
    *,
    outcome_evidence: ExactFeedbackRecord,
    activation_profile: ExactFeedbackRecord,
) -> FeedbackReduction:
    """Reduce active annotations without producing or changing outcome authority."""

    records = tuple(assessments)
    by_id: dict[str, TypedRecord] = {}
    for record in records:
        record.verify(FEEDBACK_REGISTRY)
        if record.record_kind != "feedback_assessment":
            raise SchemaValidationError("reduction accepts feedback assessments only")
        payload = record.payload
        if record.context_ref != payload["context_ref"]:
            raise SchemaValidationError("feedback record context is inconsistent")
        if payload["outcome_evidence"] != _exact_payload(outcome_evidence):
            raise SchemaValidationError("feedback references different outcome evidence")
        if payload["activation_profile"] != _exact_payload(activation_profile):
            raise SchemaValidationError("feedback references different activation profile")
        if record.record_id in by_id:
            raise SchemaValidationError("feedback identity is duplicated")
        by_id[record.record_id] = record
    referenced: set[str] = set()
    for record in records:
        prior = record.payload["prior_assessment"]
        if prior is None:
            continue
        prior_record = by_id.get(prior["record_id"])
        if prior_record is None or prior_record.content_digest != prior["digest"]:
            raise SchemaValidationError("feedback lineage is incomplete")
        if (
            prior_record.payload["subject_ref"] != record.payload["subject_ref"]
            or prior_record.payload["assessment_kind"]
            != record.payload["assessment_kind"]
        ):
            raise SchemaValidationError("feedback lineage authority is inconsistent")
        referenced.add(prior["record_id"])
    leaves = [record for record in records if record.record_id not in referenced]
    count_map: dict[tuple[str, str], int] = {}
    states_by_kind: dict[str, set[str]] = {}
    for record in leaves:
        payload = record.payload
        key = (payload["assessment_kind"], payload["state"])
        count_map[key] = count_map.get(key, 0) + 1
        states_by_kind.setdefault(payload["assessment_kind"], set()).add(payload["state"])
    counts = tuple((kind, state, count_map[(kind, state)]) for kind, state in sorted(count_map))
    conflicts = tuple(sorted(kind for kind, states in states_by_kind.items() if len(states) > 1))
    return FeedbackReduction(
        outcome_evidence.record_id,
        activation_profile.record_id,
        counts,
        conflicts,
    )


def _require_exact(
    transaction: V3Transaction,
    identity: ExactFeedbackRecord,
    kinds: frozenset[str],
) -> TypedRecord:
    record = transaction.get_record(identity.record_id)
    if (
        record is None
        or record.content_digest != identity.digest
        or record.record_kind not in kinds
    ):
        _deny("exact_target_missing")
    return record


def _require_prior(
    transaction: V3Transaction, request: FeedbackRequest
) -> TypedRecord | None:
    prior_identity = request.prior_assessment
    if request.operation == "assess":
        if prior_identity is not None:
            _deny("initial_assessment_cannot_reference_prior")
        return None
    if prior_identity is None:
        _deny("prior_assessment_required")
    prior = _require_exact(
        transaction, prior_identity, frozenset({"feedback_assessment"})
    )
    payload = prior.payload
    if (
        prior.schema_id != FEEDBACK_ASSESSMENT_SCHEMA_ID
        or prior.context_ref != request.context_ref
        or payload["subject_ref"] != request.subject_ref
        or payload["outcome_evidence"] != _exact_payload(request.outcome_evidence)
        or payload["activation_profile"] != _exact_payload(request.activation_profile)
        or payload["assessment_kind"] != request.assessment_kind
    ):
        _deny("prior_assessment_mismatch")
    if payload["operation"] == "withdraw":
        _deny("withdrawn_assessment_is_terminal")
    return prior


def _verified_grant(
    transaction: V3Transaction,
    request: FeedbackRequest,
    revalidate_grant: GrantRevalidator,
) -> VerifiedGrant:
    grant = revalidate_grant(transaction)
    if type(grant) is not VerifiedGrant:
        _deny("verified_grant_required")
    now = request.now.astimezone(timezone.utc)
    if grant.issued_at.tzinfo is None or grant.expires_at.tzinfo is None:
        _deny("authority_grant_mismatch")
    if (
        grant.grant_id != request.authority_grant_id
        or grant.authority_class != _AUTHORITY_CLASS
        or grant.issuer_id != request.issuer_ref
        or grant.subject_ref != request.subject_ref
        or grant.context_ref != request.context_ref
        or grant.action != _ACTION
        or grant.purpose != _PURPOSE
        or grant.target_ref != request.outcome_evidence.record_id
        or grant.target_revision != 0
        or grant.idempotency_key_digest != request.idempotency_key_digest
        or grant.issued_at.astimezone(timezone.utc) > now
        or grant.expires_at.astimezone(timezone.utc) <= now
    ):
        _deny("authority_grant_mismatch")
    return grant


def _existing_replay(
    transaction: V3Transaction,
    request: FeedbackRequest,
    request_digest: str,
    grant: VerifiedGrant,
) -> FeedbackMutationResult | None:
    existing = transaction.get_operator_command(
        issuer_ref=grant.issuer_id,
        subject_ref=grant.subject_ref,
        context_ref=request.context_ref,
        action=_ACTION,
        idempotency_key_digest=request.idempotency_key_digest,
    )
    if existing is None:
        return None
    if existing.request_digest != request_digest:
        raise IdempotencyConflict("idempotency key was reused with a different request")
    receipt = transaction.get_record(existing.mutation_receipt_id)
    if (
        receipt is None
        or receipt.record_kind != "feedback_mutation_receipt"
        or receipt.schema_id != FEEDBACK_MUTATION_RECEIPT_SCHEMA_ID
        or receipt.payload["request_digest"] != request_digest
    ):
        raise IntegrityFailure("command ledger points to an invalid feedback receipt")
    assessment_identity = receipt.payload["assessment"]
    assessment = transaction.get_record(assessment_identity["record_id"])
    if assessment is None or assessment.content_digest != assessment_identity["digest"]:
        raise IntegrityFailure("feedback receipt assessment is missing")
    event = DomainEvent(
        event_id=_identity("feedback-event", request_digest),
        subject_id=assessment.record_id,
        subject_kind=assessment.record_kind,
        sequence=0,
        event_type={
            "assess": "feedback_assessed",
            "correct": "feedback_corrected",
            "withdraw": "feedback_withdrawn",
        }[request.operation],
        payload_record_id=receipt.record_id,
        actor_authority_ref=grant.grant_id,
    )
    return FeedbackMutationResult(assessment, receipt, existing, event, True)


def _build_assessment(
    request: FeedbackRequest,
    request_digest: str,
    grant: VerifiedGrant,
    prior: TypedRecord | None,
) -> TypedRecord:
    payload: dict[str, Any] = {
        "record_type": "feedback_assessment",
        "operation": request.operation,
        "context_ref": request.context_ref,
        "subject_ref": grant.subject_ref,
        "outcome_evidence": _exact_payload(request.outcome_evidence),
        "activation_profile": _exact_payload(request.activation_profile),
        "assessment_kind": request.assessment_kind,
        "state": request.state,
        "reason_catalog_id": FEEDBACK_REASON_CATALOG_ID,
        "reason_codes": list(request.reason_codes),
        "prior_assessment": None if prior is None else _record_exact(prior),
        "authority_grant_id": grant.grant_id,
        "idempotency_key_digest": request.idempotency_key_digest,
        "request_digest": request_digest,
        "recorded_at": _canonical_timestamp(request.now),
        "links": [],
    }
    payload["links"] = [
        _link("outcome_evidence", 0, payload["outcome_evidence"]),
        _link("activation_profile", 0, payload["activation_profile"]),
    ]
    if payload["prior_assessment"] is not None:
        payload["links"].append(
            _link("prior_assessment", 0, payload["prior_assessment"])
        )
    return build_typed_record(
        record_id=_identity("feedback-assessment", request_digest),
        context_ref=request.context_ref,
        record_kind="feedback_assessment",
        schema_id=FEEDBACK_ASSESSMENT_SCHEMA_ID,
        payload=payload,
        key_epoch="feedback-v1",
        registry=FEEDBACK_REGISTRY,
    )


def _build_receipt(
    request: FeedbackRequest,
    request_digest: str,
    grant: VerifiedGrant,
    assessment: TypedRecord,
    prior: TypedRecord | None,
) -> TypedRecord:
    payload: dict[str, Any] = {
        "receipt_type": "feedback_mutation",
        "accepted": True,
        "action": _ACTION,
        "operation": request.operation,
        "context_ref": request.context_ref,
        "subject_ref": grant.subject_ref,
        "assessment": _record_exact(assessment),
        "outcome_evidence": _exact_payload(request.outcome_evidence),
        "activation_profile": _exact_payload(request.activation_profile),
        "prior_assessment": None if prior is None else _record_exact(prior),
        "authority_grant_id": grant.grant_id,
        "idempotency_key_digest": request.idempotency_key_digest,
        "request_digest": request_digest,
        "reason_code": {
            "assess": "feedback_recorded",
            "correct": "feedback_corrected",
            "withdraw": "feedback_withdrawn",
        }[request.operation],
        "recorded_at": _canonical_timestamp(request.now),
        "links": [],
    }
    payload["links"] = [
        _link("assessment", 0, payload["assessment"]),
        _link("outcome_evidence", 0, payload["outcome_evidence"]),
        _link("activation_profile", 0, payload["activation_profile"]),
    ]
    if payload["prior_assessment"] is not None:
        payload["links"].append(
            _link("prior_assessment", 0, payload["prior_assessment"])
        )
    return build_typed_record(
        record_id=_identity("feedback-receipt", request_digest),
        context_ref=request.context_ref,
        record_kind="feedback_mutation_receipt",
        schema_id=FEEDBACK_MUTATION_RECEIPT_SCHEMA_ID,
        payload=payload,
        key_epoch="feedback-v1",
        registry=FEEDBACK_REGISTRY,
    )


def _operator_command(
    request: FeedbackRequest,
    request_digest: str,
    grant: VerifiedGrant,
    receipt: TypedRecord,
) -> OperatorCommand:
    return OperatorCommand(
        command_id=_identity("feedback-command", request_digest),
        issuer_ref=grant.issuer_id,
        subject_ref=grant.subject_ref,
        context_ref=request.context_ref,
        action=_ACTION,
        idempotency_key_digest=request.idempotency_key_digest,
        request_digest=request_digest,
        observed_revision=0,
        state="accepted",
        mutation_receipt_id=receipt.record_id,
    )


def _request_payload(request: FeedbackRequest) -> dict[str, Any]:
    return {
        "issuer_ref": request.issuer_ref,
        "subject_ref": request.subject_ref,
        "context_ref": request.context_ref,
        "outcome_evidence": _exact_payload(request.outcome_evidence),
        "activation_profile": _exact_payload(request.activation_profile),
        "assessment_kind": request.assessment_kind,
        "state": request.state,
        "reason_catalog_id": FEEDBACK_REASON_CATALOG_ID,
        "reason_codes": list(request.reason_codes),
        "operation": request.operation,
        "prior_assessment": (
            None
            if request.prior_assessment is None
            else _exact_payload(request.prior_assessment)
        ),
        "authority_grant_id": request.authority_grant_id,
        "idempotency_key_digest": request.idempotency_key_digest,
    }


def _canonical_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identity(purpose: str, request_digest: str) -> str:
    return purpose + "_" + schema_digest(
        "feedback-identity", purpose, request_digest.encode("ascii")
    )


def _exact_payload(identity: ExactFeedbackRecord) -> dict[str, str]:
    return {"record_id": identity.record_id, "digest": identity.digest}


def _record_exact(record: TypedRecord) -> dict[str, str]:
    return {"record_id": record.record_id, "digest": record.content_digest}


def _link(role: str, ordinal: int, identity: Mapping[str, str]) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": identity["record_id"],
        "target_digest": identity["digest"],
    }


__all__ = [
    "ASSESSMENT_KINDS",
    "ASSESSMENT_STATES",
    "FEEDBACK_ASSESSMENT_SCHEMA_ID",
    "FEEDBACK_MUTATION_RECEIPT_SCHEMA_ID",
    "FEEDBACK_REASON_CATALOG_ID",
    "FEEDBACK_REASON_CODES",
    "FEEDBACK_REGISTRY",
    "ExactFeedbackRecord",
    "FeedbackDenied",
    "FeedbackMutationResult",
    "FeedbackReduction",
    "FeedbackRequest",
    "record_feedback",
    "reduce_feedback",
]
