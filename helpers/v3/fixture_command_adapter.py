"""Strict, framework-agnostic fixture command admission.

The adapter owns no fixture authority and persists no command data.  Fixture
content crosses this module only as transient bytes returned by an injected
content provider; responses contain opaque record identities only.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any, Callable, Mapping, Protocol

from .authority import AuthorityDenied, AuthorityValidationError, digest_idempotency_key
from .command_adapter import COMMAND_RESPONSE_SCHEMA, SafeCommandResponse
from .fixtures import (
    ORIGINS,
    ContentAccessAuthority,
    FixtureAdmission,
    FixtureDraft,
    FixtureError,
    FixtureIneligible,
    FixtureReview,
    FixtureValidationError,
    FixtureWithdrawal,
    GrantAuthority,
    QuarantineReleaseBinding,
)
from .repository import DomainEvent, IdempotencyConflict, RevisionConflict
from .schemas import (
    SchemaValidationError,
    TypedRecord,
    V3SchemaError,
    canonical_json,
    canonical_loads,
    schema_digest,
    strict_boolean,
    strict_enum,
    strict_integer,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
)


FIXTURE_DRAFT_COMMAND_SCHEMA = "a0.command.fixture-draft.v1"
FIXTURE_REVIEW_COMMAND_SCHEMA = "a0.command.fixture-review.v1"
FIXTURE_ADMIT_COMMAND_SCHEMA = "a0.command.fixture-admit.v1"
FIXTURE_WITHDRAW_COMMAND_SCHEMA = "a0.command.fixture-withdraw.v1"

_ACTIONS = ("fixture_draft", "fixture_review", "fixture_admit", "fixture_withdraw")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
_REASONS = {
    "fixture_draft": "fixture_authoring_requested",
    "fixture_review": "fixture_review_requested",
    "fixture_admit": "fixture_admission_requested",
    "fixture_withdraw": "fixture_withdrawal_requested",
}
_SUCCESS_REASONS = {
    "fixture_draft": "fixture_drafted",
    "fixture_review": "fixture_reviewed",
    "fixture_admit": "fixture_admitted",
    "fixture_withdraw": "fixture_withdrawn",
}
_ACTION_STATES = {
    "fixture_draft": "drafted",
    "fixture_review": "reviewed",
    "fixture_admit": "admitted",
    "fixture_withdraw": "withdrawn",
}
_PURPOSES = {
    "fixture_draft": "fixture_authoring",
    "fixture_review": "fixture_review",
    "fixture_admit": "fixture_replay",
    "fixture_withdraw": "fixture_replay",
}


class FixtureCommandConflict(RuntimeError):
    """An exact fixture target or adapter idempotency binding is stale."""


class FixtureLedgerUnavailable(RuntimeError):
    """The durable command-equivalence and persistence seam is unavailable."""


def _safe_ref(value: Any, path: str) -> str:
    result = strict_string(maximum=512)(value, path)
    if _SAFE_REF.fullmatch(result) is None:
        raise SchemaValidationError(f"{path} is not an opaque reference")
    return result


def _short_ref(value: Any, path: str) -> str:
    result = _safe_ref(value, path)
    if len(result) > 128:
        raise SchemaValidationError(f"{path} is too long")
    return result


_EXACT = strict_object({"record_id": _safe_ref, "digest": validate_digest})
_RELEASE = strict_object(
    {"receipt_ref": _short_ref, "receipt_digest": validate_digest}
)
_COMMON = {
    "context_ref": _short_ref,
    "target_revision": strict_integer(minimum=0),
    "idempotency_key": strict_string(maximum=512),
    "fixture_grant_id": _short_ref,
}
_DRAFT = strict_object(
    {
        "schema": strict_literal(FIXTURE_DRAFT_COMMAND_SCHEMA),
        "action": strict_literal("fixture_draft"),
        **_COMMON,
        "operator_reason_code": strict_literal(_REASONS["fixture_draft"]),
        "target_ref": _short_ref,
        "content_session_id": _short_ref,
        "content_handle": _short_ref,
        "family_ref": _short_ref,
        "source_lineage_digest": validate_digest,
        "author_ref": _short_ref,
        "origin_class": strict_enum(ORIGINS),
        "source_attestation_digest": validate_digest,
        "protected": strict_boolean(),
        "quarantine_release": strict_nullable(_RELEASE),
    }
)
_REVIEW = strict_object(
    {
        "schema": strict_literal(FIXTURE_REVIEW_COMMAND_SCHEMA),
        "action": strict_literal("fixture_review"),
        **_COMMON,
        "operator_reason_code": strict_literal(_REASONS["fixture_review"]),
        "target": _EXACT,
        "content_session_id": _short_ref,
        "reviewer_ref": _short_ref,
    }
)
_ADMIT = strict_object(
    {
        "schema": strict_literal(FIXTURE_ADMIT_COMMAND_SCHEMA),
        "action": strict_literal("fixture_admit"),
        **_COMMON,
        "operator_reason_code": strict_literal(_REASONS["fixture_admit"]),
        "target": _EXACT,
        "review": _EXACT,
    }
)
_WITHDRAW = strict_object(
    {
        "schema": strict_literal(FIXTURE_WITHDRAW_COMMAND_SCHEMA),
        "action": strict_literal("fixture_withdraw"),
        **_COMMON,
        "operator_reason_code": strict_literal(_REASONS["fixture_withdraw"]),
        "target": _EXACT,
    }
)
_VALIDATORS = {
    "fixture_draft": _DRAFT,
    "fixture_review": _REVIEW,
    "fixture_admit": _ADMIT,
    "fixture_withdraw": _WITHDRAW,
}


@dataclass(frozen=True, slots=True)
class ExactFixtureRecord:
    record_id: str
    digest: str


@dataclass(frozen=True, slots=True)
class FixtureAuthorityBinding:
    authority_ref: str
    authority_class: str
    issuer_ref: str
    subject_ref: str
    context_ref: str
    action: str
    purpose: str
    target_ref: str
    target_revision: int
    idempotency_key_digest: str
    now: datetime


@dataclass(frozen=True, slots=True)
class FixtureCommandAdmission:
    issuer_ref: str
    subject_ref: str
    context_ref: str
    action: str
    target_ref: str
    target_digest: str | None
    target_revision: int
    idempotency_key_digest: str
    request_digest: str


@dataclass(frozen=True, slots=True)
class FixtureAcceptedMutation:
    """Append-ready domain facts returned inside the ledger transaction."""

    domain_result_ref: str
    records: tuple[TypedRecord, ...]
    events: tuple[DomainEvent, ...]


@dataclass(frozen=True, slots=True)
class FixtureLedgerResult:
    """Durable accepted command result, including lost-ack replay."""

    admission: FixtureCommandAdmission
    mutation_receipt_ref: str
    replayed: bool


class FixtureCoordinator(Protocol):
    def create_draft(self, **kwargs: Any) -> FixtureDraft: ...
    def review(self, *args: Any, **kwargs: Any) -> FixtureReview: ...
    def admit(self, *args: Any, **kwargs: Any) -> FixtureAdmission: ...
    def withdraw(self, *args: Any, **kwargs: Any) -> FixtureWithdrawal: ...


class FixtureCommandLedger(Protocol):
    """Owning repository transaction and durable idempotency boundary.

    ``execute`` must look up the exact command identity and compare
    ``request_digest`` before invoking ``executor``.  An equivalent prior
    command returns its durable result without invoking the executor; a changed
    request raises :class:`IdempotencyConflict`.  For a new request, the seam
    invokes the executor under its owning repository transaction and atomically
    persists every returned fixture record/event plus its command mutation
    receipt before returning.  The adapter has no persistence authority.
    """

    def execute(
        self,
        admission: FixtureCommandAdmission,
        executor: Callable[[], FixtureAcceptedMutation],
    ) -> FixtureLedgerResult: ...


ContentProvider = Callable[[str, str], bytes]
AuthorityRevalidator = Callable[[FixtureAuthorityBinding], GrantAuthority]
DraftResolver = Callable[[ExactFixtureRecord], FixtureDraft | None]
ReviewResolver = Callable[[ExactFixtureRecord], FixtureReview | None]


class FixtureCommandAdapter:
    """Admit fixture mutations without receiving raw fixture content."""

    def __init__(
        self,
        *,
        coordinator: FixtureCoordinator,
        ledger: FixtureCommandLedger,
        content_provider: ContentProvider,
        draft_resolver: DraftResolver,
        review_resolver: ReviewResolver,
        fixture_grant_revalidator: AuthorityRevalidator,
        content_session_revalidator: AuthorityRevalidator,
    ) -> None:
        for name, value in (
            ("ledger.execute", getattr(ledger, "execute", None)),
            ("content_provider", content_provider),
            ("draft_resolver", draft_resolver),
            ("review_resolver", review_resolver),
            ("fixture_grant_revalidator", fixture_grant_revalidator),
            ("content_session_revalidator", content_session_revalidator),
        ):
            if not callable(value):
                raise TypeError(f"{name} must be callable")
        for name in ("create_draft", "review", "admit", "withdraw"):
            if not callable(getattr(coordinator, name, None)):
                raise TypeError(f"coordinator.{name} must be callable")
        self._coordinator = coordinator
        self._ledger = ledger
        self._content_provider = content_provider
        self._draft_resolver = draft_resolver
        self._review_resolver = review_resolver
        self._fixture_grant_revalidator = fixture_grant_revalidator
        self._content_session_revalidator = content_session_revalidator

    def handle(
        self,
        payload: object,
        *,
        bound_context_ref: str,
        issuer_ref: str,
        subject_ref: str,
        now: datetime,
    ) -> SafeCommandResponse:
        action = _requested_action(payload)
        try:
            context_ref = _short_ref(bound_context_ref, "bound_context_ref")
            issuer = _short_ref(issuer_ref, "issuer_ref")
            subject = _short_ref(subject_ref, "subject_ref")
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                raise SchemaValidationError("now must be timezone-aware")
        except (SchemaValidationError, TypeError, ValueError):
            return _failure(422, action, "framework_binding_invalid")

        if type(payload) is dict and type(payload.get("context_ref")) is str:
            if payload["context_ref"] != context_ref:
                return _failure(422, action, "context_binding_mismatch")
        if type(payload) is dict and action in _REASONS:
            raw_reason = payload.get("operator_reason_code")
            if type(raw_reason) is str and raw_reason != _REASONS[action]:
                return _failure(422, action, "reason_code_invalid")
        try:
            if action not in _VALIDATORS:
                raise SchemaValidationError("request action is not admitted")
            admitted = _VALIDATORS[action](payload, "request")
            idempotency_digest = digest_idempotency_key(admitted["idempotency_key"])
            request_digest = _request_fingerprint(admitted, idempotency_digest)
        except (V3SchemaError, AuthorityValidationError, TypeError, ValueError):
            return _failure(400, action, "schema_invalid")
        try:
            self._require_subject_binding(admitted, subject)
            self._require_release_binding(admitted)
        except SchemaValidationError:
            return _failure(422, action, "fixture_policy_denied")

        try:
            target = (
                {"record_id": admitted["target_ref"], "digest": None}
                if action == "fixture_draft"
                else admitted["target"]
            )
            admission = FixtureCommandAdmission(
                issuer_ref=issuer,
                subject_ref=subject,
                context_ref=context_ref,
                action=action,
                target_ref=target["record_id"],
                target_digest=target["digest"],
                target_revision=admitted["target_revision"],
                idempotency_key_digest=idempotency_digest,
                request_digest=request_digest,
            )
            ledger_result = self._ledger.execute(
                admission,
                lambda: self._execute(
                    action,
                    admitted,
                    issuer_ref=issuer,
                    subject_ref=subject,
                    context_ref=context_ref,
                    idempotency_digest=idempotency_digest,
                    now=now,
                ),
            )
            if (
                type(ledger_result) is not FixtureLedgerResult
                or ledger_result.admission != admission
                or type(ledger_result.mutation_receipt_ref) is not str
                or _SAFE_REF.fullmatch(ledger_result.mutation_receipt_ref) is None
                or type(ledger_result.replayed) is not bool
            ):
                raise FixtureLedgerUnavailable("ledger returned an invalid durable result")
            return _success(
                action,
                ledger_result.mutation_receipt_ref,
                admission.target_revision,
            )
        except FixtureLedgerUnavailable:
            return _failure(503, action, "fixture_ledger_unavailable")
        except (FixtureCommandConflict, IdempotencyConflict, RevisionConflict) as exc:
            reason = (
                "idempotency_conflict"
                if isinstance(exc, IdempotencyConflict)
                else "fixture_revision_conflict"
            )
            return _failure(409, action, reason)
        except (AuthorityDenied, AuthorityValidationError):
            return _failure(422, action, "fixture_authority_denied")
        except FixtureIneligible:
            return _failure(409, action, "fixture_state_conflict")
        except FixtureValidationError:
            return _failure(422, action, "fixture_policy_denied")
        except V3SchemaError:
            return _failure(422, action, "fixture_content_invalid")
        except FixtureError:
            return _failure(503, action, "fixture_unavailable")
        except Exception:
            return _failure(503, action, "internal_error")

    def _execute(
        self,
        action: str,
        payload: Mapping[str, Any],
        *,
        issuer_ref: str,
        subject_ref: str,
        context_ref: str,
        idempotency_digest: str,
        now: datetime,
    ) -> FixtureAcceptedMutation:
        if action == "fixture_draft":
            target_ref = payload["target_ref"]
            revision = payload["target_revision"]
        else:
            target_ref = payload["target"]["record_id"]
            revision = payload["target_revision"]
        fixture_grant = self._authority(
            payload["fixture_grant_id"],
            "fixture_use_grant",
            action,
            target_ref,
            revision,
            issuer_ref,
            subject_ref,
            context_ref,
            idempotency_digest,
            now,
            self._fixture_grant_revalidator,
        )
        if action == "fixture_draft":
            content_session = self._content_authority(
                payload,
                action,
                target_ref,
                revision,
                issuer_ref,
                subject_ref,
                context_ref,
                idempotency_digest,
                now,
            )
            try:
                content_bytes = self._content_provider(
                    payload["content_session_id"], payload["content_handle"]
                )
            except Exception as exc:
                raise FixtureError("content provider unavailable") from exc
            if type(content_bytes) is not bytes:
                raise SchemaValidationError("content provider must return bytes")
            content = canonical_loads(content_bytes)
            if type(content) is not dict:
                raise SchemaValidationError("fixture content must be a canonical object")
            release = payload["quarantine_release"]
            result = self._coordinator.create_draft(
                fixture_ref=target_ref,
                revision=revision,
                family_ref=payload["family_ref"],
                source_lineage_digest=payload["source_lineage_digest"],
                author_ref=payload["author_ref"],
                origin_class=payload["origin_class"],
                source_attestation_digest=payload["source_attestation_digest"],
                protected=payload["protected"],
                content=content,
                authority=ContentAccessAuthority(fixture_grant, content_session),
                now=now,
                quarantine_release=(
                    None
                    if release is None
                    else QuarantineReleaseBinding(
                        release["receipt_ref"], release["receipt_digest"]
                    )
                ),
            )
            self._validate_draft(result, target_ref, revision)
            receipt_ref = result.record.record_id
            records = (result.family, *result.authority_uses, result.record)
            events: tuple[DomainEvent, ...] = ()
        elif action == "fixture_review":
            draft = self._draft(payload["target"], revision)
            content_session = self._content_authority(
                payload,
                action,
                target_ref,
                revision,
                issuer_ref,
                subject_ref,
                context_ref,
                idempotency_digest,
                now,
            )
            result = self._coordinator.review(
                draft,
                reviewer_ref=payload["reviewer_ref"],
                authority=ContentAccessAuthority(fixture_grant, content_session),
                now=now,
            )
            self._validate_review(result, draft, payload["reviewer_ref"])
            receipt_ref = result.record.record_id
            records = (*result.authority_uses, result.record)
            events = ()
        elif action == "fixture_admit":
            draft = self._draft(payload["target"], revision)
            review = self._review(payload["review"], draft)
            result = self._coordinator.admit(
                draft, review, fixture_use=fixture_grant, now=now
            )
            self._validate_admission(result, draft, review)
            receipt_ref = result.receipt.record_id
            records = (result.fixture_use, result.receipt, result.eligibility)
            events = (result.event,)
        else:
            draft = self._draft(payload["target"], revision)
            result = self._coordinator.withdraw(
                draft, fixture_use=fixture_grant, now=now
            )
            self._validate_withdrawal(result, draft)
            receipt_ref = result.eligibility.record_id
            records = (result.eligibility,)
            events = (result.event,)
        return FixtureAcceptedMutation(receipt_ref, tuple(records), tuple(events))

    def _content_authority(
        self,
        payload: Mapping[str, Any],
        action: str,
        target_ref: str,
        revision: int,
        issuer_ref: str,
        subject_ref: str,
        context_ref: str,
        idempotency_digest: str,
        now: datetime,
    ) -> GrantAuthority:
        return self._authority(
            payload["content_session_id"],
            "operator_content_session",
            action,
            target_ref,
            revision,
            issuer_ref,
            subject_ref,
            context_ref,
            idempotency_digest,
            now,
            self._content_session_revalidator,
        )

    @staticmethod
    def _authority(
        authority_ref: str,
        authority_class: str,
        action: str,
        target_ref: str,
        revision: int,
        issuer_ref: str,
        subject_ref: str,
        context_ref: str,
        idempotency_digest: str,
        now: datetime,
        revalidator: AuthorityRevalidator,
    ) -> GrantAuthority:
        binding = FixtureAuthorityBinding(
            authority_ref,
            authority_class,
            issuer_ref,
            subject_ref,
            context_ref,
            action,
            _PURPOSES[action],
            target_ref,
            revision,
            idempotency_digest,
            now,
        )
        authority = revalidator(binding)
        if type(authority) is not GrantAuthority:
            raise AuthorityValidationError("revalidator did not return GrantAuthority")
        expectation = authority.expectation
        expected = {
            "authority_class": authority_class,
            "issuer_id": issuer_ref,
            "subject_ref": subject_ref,
            "context_ref": context_ref,
            "action": action,
            "purpose": _PURPOSES[action],
            "target_ref": target_ref,
            "target_revision": revision,
            "idempotency_key_digest": idempotency_digest,
        }
        if any(getattr(expectation, field) != value for field, value in expected.items()):
            raise AuthorityDenied("authority expectation does not match command")
        envelope_payload = authority.envelope.get("payload")
        if not isinstance(envelope_payload, Mapping) or envelope_payload.get("grant_id") != authority_ref:
            raise AuthorityDenied("authority identity does not match command")
        return authority

    def _draft(self, exact: Mapping[str, str], revision: int) -> FixtureDraft:
        identity = ExactFixtureRecord(exact["record_id"], exact["digest"])
        draft = self._draft_resolver(identity)
        if (
            type(draft) is not FixtureDraft
            or draft.record.record_id != identity.record_id
            or draft.record.content_digest != identity.digest
            or draft.record.payload["revision"] != revision
        ):
            raise FixtureCommandConflict("fixture draft identity or revision is stale")
        return draft

    def _review(self, exact: Mapping[str, str], draft: FixtureDraft) -> FixtureReview:
        identity = ExactFixtureRecord(exact["record_id"], exact["digest"])
        review = self._review_resolver(identity)
        if (
            type(review) is not FixtureReview
            or review.record.record_id != identity.record_id
            or review.record.content_digest != identity.digest
            or review.record.payload["draft_id"] != draft.record.record_id
            or review.record.payload["draft_digest"] != draft.record.content_digest
        ):
            raise FixtureCommandConflict("fixture review identity is stale")
        return review

    @staticmethod
    def _validate_draft(result: FixtureDraft, fixture_ref: str, revision: int) -> None:
        if (
            type(result) is not FixtureDraft
            or result.record.payload["fixture_ref"] != fixture_ref
            or result.record.payload["revision"] != revision
        ):
            raise FixtureValidationError("coordinator returned an invalid fixture draft")

    @staticmethod
    def _validate_review(result: FixtureReview, draft: FixtureDraft, reviewer_ref: str) -> None:
        if (
            type(result) is not FixtureReview
            or result.record.payload["draft_id"] != draft.record.record_id
            or result.record.payload["draft_digest"] != draft.record.content_digest
            or result.record.payload["reviewer_ref"] != reviewer_ref
        ):
            raise FixtureValidationError("coordinator returned an invalid fixture review")

    @staticmethod
    def _validate_admission(
        result: FixtureAdmission, draft: FixtureDraft, review: FixtureReview
    ) -> None:
        if (
            type(result) is not FixtureAdmission
            or result.receipt.payload["draft_id"] != draft.record.record_id
            or result.receipt.payload["draft_digest"] != draft.record.content_digest
            or result.receipt.payload["review_id"] != review.record.record_id
            or result.receipt.payload["review_digest"] != review.record.content_digest
            or result.eligibility.payload["state"] != "admitted"
        ):
            raise FixtureValidationError("coordinator returned an invalid admission")

    @staticmethod
    def _validate_withdrawal(result: FixtureWithdrawal, draft: FixtureDraft) -> None:
        if (
            type(result) is not FixtureWithdrawal
            or result.eligibility.payload["fixture_id"] != draft.record.record_id
            or result.eligibility.payload["fixture_digest"] != draft.record.content_digest
            or result.eligibility.payload["state"] != "withdrawn"
        ):
            raise FixtureValidationError("coordinator returned an invalid withdrawal")

    @staticmethod
    def _require_subject_binding(payload: Mapping[str, Any], subject_ref: str) -> None:
        if payload["action"] == "fixture_draft" and payload["author_ref"] != subject_ref:
            raise SchemaValidationError("draft author must match framework subject")
        if payload["action"] == "fixture_review" and payload["reviewer_ref"] != subject_ref:
            raise SchemaValidationError("reviewer must match framework subject")

    @staticmethod
    def _require_release_binding(payload: Mapping[str, Any]) -> None:
        if payload["action"] != "fixture_draft":
            return
        release = payload["quarantine_release"]
        if (payload["origin_class"] == "quarantine_release") != (release is not None):
            raise SchemaValidationError("quarantine release origin requires exact receipt")


def _requested_action(payload: object) -> str | None:
    if type(payload) is dict and payload.get("action") in _ACTIONS:
        return payload["action"]
    return None


def _request_fingerprint(payload: Mapping[str, Any], idempotency_digest: str) -> str:
    safe = dict(payload)
    safe["idempotency_key"] = idempotency_digest
    return schema_digest(
        "fixture-command-request", "a0.fixture-command-request.v1", canonical_json(safe)
    )


def _success(action: str, receipt_ref: str, revision: int) -> SafeCommandResponse:
    return SafeCommandResponse(
        200,
        _body(
            accepted=True,
            action=action,
            receipt_ref=_safe_ref(receipt_ref, "receipt_ref"),
            observed_revision=revision,
            resulting_revision=revision,
            action_state=_ACTION_STATES[action],
            reason_code=_SUCCESS_REASONS[action],
        ),
    )


def _failure(status: int, action: str | None, reason_code: str) -> SafeCommandResponse:
    return SafeCommandResponse(
        status,
        _body(
            accepted=False,
            action=action,
            receipt_ref=None,
            observed_revision=None,
            resulting_revision=None,
            action_state="refused",
            reason_code=reason_code,
        ),
    )


def _body(
    *,
    accepted: bool,
    action: str | None,
    receipt_ref: str | None,
    observed_revision: int | None,
    resulting_revision: int | None,
    action_state: str,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "schema": COMMAND_RESPONSE_SCHEMA,
        "accepted": accepted,
        "action": action,
        "receipt_ref": receipt_ref,
        "observed_revision": observed_revision,
        "resulting_revision": resulting_revision,
        "policy_ref": None,
        "action_state": action_state,
        "reason_codes": [reason_code],
    }


__all__ = [
    "FIXTURE_ADMIT_COMMAND_SCHEMA",
    "FIXTURE_DRAFT_COMMAND_SCHEMA",
    "FIXTURE_REVIEW_COMMAND_SCHEMA",
    "FIXTURE_WITHDRAW_COMMAND_SCHEMA",
    "ExactFixtureRecord",
    "FixtureAcceptedMutation",
    "FixtureAuthorityBinding",
    "FixtureCommandAdapter",
    "FixtureCommandAdmission",
    "FixtureCommandConflict",
    "FixtureCommandLedger",
    "FixtureLedgerResult",
    "FixtureLedgerUnavailable",
]
