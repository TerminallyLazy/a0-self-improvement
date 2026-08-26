"""Closed transport-neutral admission for ``feedback_submit``."""
from __future__ import annotations

from datetime import datetime
import re
from typing import Callable

from .authority import AuthorityError, VerifiedGrant, digest_idempotency_key
from .command_adapter import COMMAND_RESPONSE_SCHEMA, SafeCommandResponse
from .feedback import (
    ASSESSMENT_KINDS,
    ASSESSMENT_STATES,
    FEEDBACK_OPERATIONS,
    FEEDBACK_REASON_CODES,
    ExactFeedbackRecord,
    FeedbackDenied,
    FeedbackRequest,
    record_feedback,
)
from .repository import IdempotencyConflict, IntegrityFailure, V3Repository, V3Transaction
from .schemas import (
    SchemaValidationError,
    V3SchemaError,
    strict_enum,
    strict_integer,
    strict_list,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
)


FEEDBACK_SUBMIT_COMMAND_SCHEMA = "a0.command.feedback-submit.v1"
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")


def _ref(value: object, path: str) -> str:
    admitted = strict_string(maximum=512)(value, path)
    if _SAFE_REF.fullmatch(admitted) is None:
        raise SchemaValidationError(f"{path} is not an opaque reference")
    return admitted


_EXACT = strict_object({"record_id": _ref, "digest": validate_digest})
_COMMAND = strict_object(
    {
        "schema": strict_literal(FEEDBACK_SUBMIT_COMMAND_SCHEMA),
        "action": strict_literal("feedback_submit"),
        "context_ref": _ref,
        "target_ref": _ref,
        "expected_revision": strict_literal(0),
        "idempotency_key": strict_string(maximum=512),
        "authority_grant_id": _ref,
        "operator_reason_code": strict_literal("feedback_requested"),
        "outcome_evidence": _EXACT,
        "activation_profile": _EXACT,
        "assessment_kind": strict_enum(ASSESSMENT_KINDS),
        "state": strict_enum(ASSESSMENT_STATES),
        "reason_codes": strict_list(
            strict_enum(FEEDBACK_REASON_CODES), minimum=1, maximum=4
        ),
        "operation": strict_enum(FEEDBACK_OPERATIONS),
        "prior_assessment": strict_nullable(_EXACT),
    }
)


GrantRevalidator = Callable[[V3Transaction], VerifiedGrant]


class FeedbackCommandAdapter:
    def __init__(self, repository: V3Repository) -> None:
        if not isinstance(repository, V3Repository):
            raise TypeError("feedback adapter requires a V3Repository")
        self._repository = repository

    def handle(
        self,
        payload: object,
        *,
        bound_context_ref: str,
        issuer_ref: str,
        subject_ref: str,
        now: datetime,
        revalidate_grant: GrantRevalidator,
    ) -> SafeCommandResponse:
        try:
            command = _COMMAND(payload, "request")
        except (V3SchemaError, TypeError, ValueError):
            return _failure(400, "schema_invalid")
        if (
            command["context_ref"] != bound_context_ref
            or command["target_ref"] != command["outcome_evidence"]["record_id"]
        ):
            return _failure(422, "feedback_binding_mismatch")
        if not callable(revalidate_grant):
            return _failure(503, "feedback_unavailable")
        try:
            prior = command["prior_assessment"]
            result = record_feedback(
                self._repository,
                FeedbackRequest(
                    issuer_ref=issuer_ref,
                    subject_ref=subject_ref,
                    context_ref=bound_context_ref,
                    outcome_evidence=ExactFeedbackRecord(**command["outcome_evidence"]),
                    activation_profile=ExactFeedbackRecord(**command["activation_profile"]),
                    assessment_kind=command["assessment_kind"],
                    state=command["state"],
                    reason_codes=tuple(command["reason_codes"]),
                    operation=command["operation"],
                    prior_assessment=(
                        None if prior is None else ExactFeedbackRecord(**prior)
                    ),
                    authority_grant_id=command["authority_grant_id"],
                    idempotency_key_digest=digest_idempotency_key(
                        command["idempotency_key"]
                    ),
                    now=now,
                ),
                revalidate_grant=revalidate_grant,
            )
            return SafeCommandResponse(
                200,
                {
                    "schema": COMMAND_RESPONSE_SCHEMA,
                    "accepted": True,
                    "action": "feedback_submit",
                    "receipt_ref": result.receipt.record_id,
                    "observed_revision": 0,
                    "resulting_revision": 0,
                    "policy_ref": None,
                    "action_state": result.receipt.payload["reason_code"],
                    "reason_codes": [
                        "exact_replay"
                        if result.replayed
                        else result.receipt.payload["reason_code"]
                    ],
                },
            )
        except IdempotencyConflict:
            return _failure(409, "idempotency_conflict")
        except (FeedbackDenied, AuthorityError):
            return _failure(422, "feedback_authority_or_policy_denied")
        except (IntegrityFailure, V3SchemaError):
            return _failure(503, "feedback_unavailable")
        except Exception:
            return _failure(503, "internal_error")


def _failure(status: int, reason: str) -> SafeCommandResponse:
    return SafeCommandResponse(
        status,
        {
            "schema": COMMAND_RESPONSE_SCHEMA,
            "accepted": False,
            "action": "feedback_submit",
            "receipt_ref": None,
            "observed_revision": None,
            "resulting_revision": None,
            "policy_ref": None,
            "action_state": "refused",
            "reason_codes": [reason],
        },
    )


__all__ = ["FEEDBACK_SUBMIT_COMMAND_SCHEMA", "FeedbackCommandAdapter"]
