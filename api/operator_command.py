"""Signed, session-bound HTTP seam for the initial v3 operator commands.

Agent Zero owns authentication, CSRF, method, and transport admission.  This
handler adds strict plugin admission, verifies an explicitly issued local grant,
opens only the runtime-authoritative writable generation, and delegates all
mutation authority to the activation coordinator.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, MutableMapping
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from typing import Any, Protocol

from agent import AgentContext
from flask import session
from helpers.api import ApiHandler, Request, Response

from usr.plugins.dspy_rlm.api.authority_challenge import CHALLENGE_SESSION_KEY
from usr.plugins.dspy_rlm.helpers import paths as plugin_paths
from usr.plugins.dspy_rlm.helpers.v3.activation_transition import (
    activate_candidate,
    apply_safety_bypass,
    rollback_to_predecessor,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import (
    AuthorityDenied,
    AuthorityClass,
    AuthorityPurpose,
    GrantExpectation,
    VerifiedGrant,
    digest_idempotency_key,
)
from usr.plugins.dspy_rlm.helpers.v3.authority_service import (
    AuthorityServiceError,
    LocalGrantVerifier,
    RevocationFileLedger,
)
from usr.plugins.dspy_rlm.helpers.v3.command_adapter import (
    COMMAND_RESPONSE_SCHEMA,
    SafeCommandAdapter,
    SafeCommandResponse,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_command_adapter import CanaryCommandAdapter
from usr.plugins.dspy_rlm.helpers.v3.canary_repository import (
    RepositoryCanaryMutationCoordinator,
)
from usr.plugins.dspy_rlm.helpers.v3.feedback_command_adapter import (
    FeedbackCommandAdapter,
)
from usr.plugins.dspy_rlm.helpers.v3.fixture_command_adapter import (
    FixtureAuthorityBinding,
    FixtureLedgerUnavailable,
)
from usr.plugins.dspy_rlm.helpers.v3.fixture_runtime_service import (
    build_fixture_runtime_adapter,
)
from usr.plugins.dspy_rlm.helpers.v3.fixtures import GrantAuthority
from usr.plugins.dspy_rlm.helpers.v3.post_activation_command_adapter import (
    PostActivationCommandAdapter,
)
from usr.plugins.dspy_rlm.helpers.v3.post_activation_repository import (
    PostActivationAuthority,
    RepositoryPostActivationCoordinator,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import StoreNotFoundError, V3Repository
from usr.plugins.dspy_rlm.helpers.v3.store_authority import StoreAuthorityCorrupt
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_repository
from usr.plugins.dspy_rlm.helpers.v3.work_authority import WorkCoordinator
from usr.plugins.dspy_rlm.helpers.v3.work_command_adapter import SafeWorkCommandAdapter


_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ACTIONS = frozenset(
    {
        "optimize",
        "work_cancel",
        "canary_start",
        "canary_stop",
        "activate",
        "rollback",
        "safety_bypass",
        "monitor_conclude",
        "requalification_start",
        "requalification_conclude",
        "feedback_submit",
        "fixture_draft",
        "fixture_review",
        "fixture_admit",
        "fixture_withdraw",
    }
)
_FIXTURE_ACTIONS = frozenset(
    {"fixture_draft", "fixture_review", "fixture_admit", "fixture_withdraw"}
)
_POST_ACTIVATION_ACTIONS = frozenset(
    {"monitor_conclude", "requalification_start", "requalification_conclude"}
)
_OUTER_FIELDS = frozenset(
    {"context_id", "target_ref", "authority_envelope", "command"}
)


class GrantVerifier(Protocol):
    def authorize(
        self,
        envelope: Mapping[str, Any],
        expectation: GrantExpectation,
        *,
        now: datetime,
    ) -> VerifiedGrant: ...


RepositoryOpener = Callable[[], AbstractContextManager[V3Repository]]
Clock = Callable[[], datetime]
CommandDispatcher = Callable[..., SafeCommandResponse]


def _safe_ref(value: object) -> str | None:
    return value if type(value) is str and _SAFE_REF.fullmatch(value) else None


def _aware_utc(clock: Clock) -> datetime:
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("clock must return an aware datetime")
    return now.astimezone(timezone.utc)


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("timestamp is required")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    return parsed.replace(tzinfo=timezone.utc)


def _failure(status: int, reason_code: str, *, action: str | None = None) -> SafeCommandResponse:
    return SafeCommandResponse(
        status,
        {
            "schema": COMMAND_RESPONSE_SCHEMA,
            "accepted": False,
            "action": action if action in _ACTIONS else None,
            "receipt_ref": None,
            "observed_revision": None,
            "resulting_revision": None,
            "policy_ref": None,
            "action_state": "refused",
            "reason_codes": [reason_code],
        },
    )


def _transport(response: SafeCommandResponse) -> dict[str, Any] | Response:
    if response.status_code == 200:
        return response.body
    return Response(
        json.dumps(
            response.body,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        status=response.status_code,
        mimetype="application/json",
    )


def _session_nonce(
    session_state: MutableMapping[str, Any], context_ref: str
) -> str | None:
    challenge = session_state.get(CHALLENGE_SESSION_KEY)
    if type(challenge) is not dict or set(challenge) != {"context_ref", "session_nonce"}:
        return None
    if challenge.get("context_ref") != context_ref:
        return None
    return _safe_ref(challenge.get("session_nonce"))


def _command_binding(command: Mapping[str, Any], context_ref: str) -> tuple[str, int, str, str, str]:
    action = command.get("action")
    if action not in _ACTIONS or command.get("context_ref") != context_ref:
        raise ValueError("command action or context is not admitted")
    if action in {"activate", "rollback", "safety_bypass"} | _POST_ACTIVATION_ACTIONS:
        target_ref = context_ref
        revision = command.get("expected_scope_revision")
    elif action in {"optimize", "work_cancel", "feedback_submit"}:
        target_ref = command.get("target_ref")
        revision = command.get("expected_revision")
    elif action == "canary_start":
        target_ref = command.get("trial_id")
        revision = command.get("expected_scope_revision")
    elif action == "canary_stop":
        trial = command.get("trial")
        target_ref = trial.get("record_id") if type(trial) is dict else None
        revision = command.get("expected_scope_revision")
    elif action == "fixture_draft":
        target_ref = command.get("target_ref")
        revision = command.get("target_revision")
    else:
        target = command.get("target")
        target_ref = target.get("record_id") if type(target) is dict else None
        revision = command.get("target_revision")
    target = _safe_ref(target_ref)
    if target is None or type(revision) is not int or revision < 0:
        raise ValueError("command target binding is invalid")
    if action == "feedback_submit" and revision != 0:
        raise ValueError("feedback target revision must be zero")
    grant_field = "fixture_grant_id" if action in _FIXTURE_ACTIONS else "authority_grant_id"
    grant_id = _safe_ref(command.get(grant_field))
    if grant_id is None:
        raise ValueError("command authority identity is invalid")
    authority_class = (
        AuthorityClass.FIXTURE_USE_GRANT.value
        if action in _FIXTURE_ACTIONS
        else AuthorityClass.OPERATOR_AUTHORITY_GRANT.value
    )
    if action == "canary_start" and command.get("canary_kind") == "diagnostic":
        purpose = AuthorityPurpose.DIAGNOSTIC_CANARY.value
    elif action == "fixture_draft":
        purpose = AuthorityPurpose.FIXTURE_AUTHORING.value
    elif action == "fixture_review":
        purpose = AuthorityPurpose.FIXTURE_REVIEW.value
    elif action in {"fixture_admit", "fixture_withdraw"}:
        purpose = AuthorityPurpose.FIXTURE_REPLAY.value
    else:
        purpose = AuthorityPurpose.OPERATOR_MUTATION.value
    return target, revision, grant_id, authority_class, purpose


def _expectation(
    *,
    envelope: Mapping[str, Any],
    command: Mapping[str, Any],
    context_ref: str,
    target_ref: str,
    session_nonce: str,
) -> GrantExpectation:
    payload = envelope.get("payload")
    if type(payload) is not dict:
        raise ValueError("signed payload is required")
    action = command.get("action")
    bound_target, revision, grant_id, authority_class, purpose = _command_binding(
        command, context_ref
    )
    if bound_target != target_ref:
        raise ValueError("outer target is not the exact command target")
    idempotency_key = command.get("idempotency_key")
    if type(idempotency_key) is not str or not idempotency_key or len(idempotency_key) > 512:
        raise ValueError("idempotency key is invalid")
    if payload.get("grant_id") != grant_id:
        raise ValueError("authority identity is not bound")
    issuer_ref = _safe_ref(payload.get("issuer_id"))
    subject_ref = _safe_ref(payload.get("subject_ref"))
    if issuer_ref is None or subject_ref is None:
        raise ValueError("signed authority identity is invalid")
    return GrantExpectation(
        authority_class=authority_class,
        issuer_id=issuer_ref,
        subject_ref=subject_ref,
        context_ref=context_ref,
        action=action,
        purpose=purpose,
        target_ref=target_ref,
        target_revision=revision,
        expires_at=_parse_timestamp(payload.get("expires_at")),
        idempotency_key_digest=digest_idempotency_key(idempotency_key),
        session_nonce=session_nonce,
    )


def execute_operator_command(
    input: object,
    *,
    bound_context_ref: str,
    session_state: MutableMapping[str, Any],
    verifier: GrantVerifier,
    repository_opener: RepositoryOpener,
    clock: Clock = lambda: datetime.now(timezone.utc),
    command_dispatcher: CommandDispatcher | None = None,
) -> SafeCommandResponse:
    """Perform plugin admission and delegate one exact command to a coordinator."""

    action: str | None = None
    try:
        if type(input) is not dict or set(input) != _OUTER_FIELDS:
            return _failure(400, "schema_invalid")
        context_id = _safe_ref(input.get("context_id"))
        target_ref = _safe_ref(input.get("target_ref"))
        command = input.get("command")
        envelope = input.get("authority_envelope")
        if (
            context_id != bound_context_ref
            or target_ref is None
            or type(command) is not dict
            or type(envelope) is not dict
        ):
            return _failure(400, "schema_invalid")
        action = command.get("action") if command.get("action") in _ACTIONS else None
        bound_target, _revision, _grant_id, _authority_class, _purpose = (
            _command_binding(command, bound_context_ref)
        )
        if target_ref != bound_target:
            return _failure(422, "operator_authority_denied", action=action)
        nonce = _session_nonce(session_state, bound_context_ref)
        if nonce is None:
            return _failure(422, "authority_challenge_required", action=action)
        expectation = _expectation(
            envelope=envelope,
            command=command,
            context_ref=bound_context_ref,
            target_ref=target_ref,
            session_nonce=nonce,
        )
        now = _aware_utc(clock)
    except Exception:
        return _failure(400, "schema_invalid", action=action)

    try:
        verified = verifier.authorize(envelope, expectation, now=now)
        if type(verified) is not VerifiedGrant:
            return _failure(422, "operator_authority_denied", action=action)
    except Exception:
        return _failure(422, "operator_authority_denied", action=action)

    try:
        with repository_opener() as repository:
            def revalidate_grant(_transaction: object) -> VerifiedGrant:
                # LocalGrantVerifier reloads the signed revocation ledger on
                # every call.  The coordinator invokes this inside its final
                # transaction, closing the pre-check/use race.
                return verifier.authorize(
                    envelope,
                    expectation,
                    now=_aware_utc(clock),
                )

            def revalidate_fixture_grant(
                binding: FixtureAuthorityBinding,
            ) -> GrantAuthority:
                if type(binding) is not FixtureAuthorityBinding:
                    raise AuthorityDenied("fixture authority binding is invalid")
                exact = {
                    "authority_ref": verified.grant_id,
                    "authority_class": expectation.authority_class,
                    "issuer_ref": expectation.issuer_id,
                    "subject_ref": expectation.subject_ref,
                    "context_ref": expectation.context_ref,
                    "action": expectation.action,
                    "purpose": expectation.purpose,
                    "target_ref": expectation.target_ref,
                    "target_revision": expectation.target_revision,
                    "idempotency_key_digest": expectation.idempotency_key_digest,
                }
                if any(getattr(binding, field) != value for field, value in exact.items()):
                    raise AuthorityDenied("fixture authority binding changed")
                refreshed = verifier.authorize(envelope, expectation, now=binding.now)
                if type(refreshed) is not VerifiedGrant or refreshed.grant_id != verified.grant_id:
                    raise AuthorityDenied("fixture authority revalidation changed")
                return GrantAuthority(envelope, expectation)

            # The signed envelope is deliberately absent from this closed
            # adapter call; only the strict command payload crosses the seam.
            dispatcher = command_dispatcher or _dispatch_command
            return dispatcher(
                repository=repository,
                command=command,
                bound_context_ref=bound_context_ref,
                verified_grant=verified,
                session_nonce=nonce,
                now=now,
                revalidate_grant=revalidate_grant,
                fixture_grant_revalidator=revalidate_fixture_grant,
            )
    except (StoreNotFoundError, StoreAuthorityCorrupt, AuthorityServiceError):
        return _failure(503, "operator_command_unavailable", action=action)
    except Exception:
        return _failure(503, "internal_error", action=action)


def _dispatch_command(
    command: Mapping[str, Any],
    *,
    repository: V3Repository,
    bound_context_ref: str,
    verified_grant: VerifiedGrant,
    session_nonce: str,
    now: datetime,
    revalidate_grant: Callable[[object], VerifiedGrant],
    fixture_grant_revalidator: Callable[[FixtureAuthorityBinding], GrantAuthority],
) -> SafeCommandResponse:
    action = command.get("action")
    if action in {"activate", "rollback", "safety_bypass"}:
        adapter = SafeCommandAdapter(
            activate_coordinator=lambda *, request, revalidate_grant: activate_candidate(
                repository, request=request, revalidate_grant=revalidate_grant
            ),
            rollback_coordinator=lambda *, request, revalidate_grant: rollback_to_predecessor(
                repository, request=request, revalidate_grant=revalidate_grant
            ),
            safety_bypass_coordinator=lambda *, request, revalidate_grant: apply_safety_bypass(
                repository, request=request, revalidate_grant=revalidate_grant
            ),
            activate_grant_revalidator=revalidate_grant,
            rollback_grant_revalidator=revalidate_grant,
            safety_bypass_grant_revalidator=revalidate_grant,
        )
        return adapter.handle(
            command,
            bound_context_ref=bound_context_ref,
            issuer_ref=verified_grant.issuer_id,
            subject_ref=verified_grant.subject_ref,
            now=now,
        )
    if action in {"optimize", "work_cancel"}:
        def policy_revalidator(facts: object) -> bool:
            policy_ref = getattr(facts, "policy_ref", None)
            policy = repository.get_record(policy_ref) if type(policy_ref) is str else None
            return bool(
                policy is not None
                and policy.context_ref == bound_context_ref
                and policy.record_kind == "activation_policy"
            )

        return SafeWorkCommandAdapter(WorkCoordinator(repository)).handle(
            command,
            bound_context_ref=bound_context_ref,
            bound_session_nonce=session_nonce,
            now=now,
            revalidate_grant=lambda: revalidate_grant(None),
            revalidate_policy=policy_revalidator,
        )
    if action in {"canary_start", "canary_stop"}:
        key_epoch = command.get("key_epoch")
        if _safe_ref(key_epoch) is None:
            return _failure(400, "schema_invalid", action=action)
        adapter = CanaryCommandAdapter(
            key_epoch=key_epoch,
            mutation_coordinator=RepositoryCanaryMutationCoordinator(repository),
            start_grant_revalidator=revalidate_grant,
            stop_grant_revalidator=revalidate_grant,
        )
        return adapter.handle(
            command,
            bound_context_ref=bound_context_ref,
            issuer_ref=verified_grant.issuer_id,
            subject_ref=verified_grant.subject_ref,
            session_nonce=session_nonce,
            now=now,
        )
    if action in _POST_ACTIVATION_ACTIONS:
        key_epoch = command.get("key_epoch")
        if _safe_ref(key_epoch) is None:
            return _failure(400, "schema_invalid", action=action)

        def revalidate_post_activation(
            transaction: object, _operation: object
        ) -> PostActivationAuthority:
            refreshed = revalidate_grant(transaction)
            return PostActivationAuthority(
                refreshed.grant_id,
                refreshed.issuer_id,
                refreshed.subject_ref,
            )

        return PostActivationCommandAdapter(
            key_epoch=key_epoch,
            mutation_coordinator=RepositoryPostActivationCoordinator(
                repository, key_epoch=key_epoch
            ),
            authority_revalidator=revalidate_post_activation,
        ).handle(
            command,
            bound_context_ref=bound_context_ref,
            actor_authority_ref=verified_grant.grant_id,
            issuer_ref=verified_grant.issuer_id,
            subject_ref=verified_grant.subject_ref,
        )
    if action == "feedback_submit":
        return FeedbackCommandAdapter(repository).handle(
            command,
            bound_context_ref=bound_context_ref,
            issuer_ref=verified_grant.issuer_id,
            subject_ref=verified_grant.subject_ref,
            now=now,
            revalidate_grant=revalidate_grant,
        )
    if action in _FIXTURE_ACTIONS:
        try:
            adapter = build_fixture_runtime_adapter(
                repository,
                context_ref=bound_context_ref,
                fixture_grant_revalidator=fixture_grant_revalidator,
                authority_secret_path=plugin_paths.AUTHORITY_SECRET_FILE,
                authority_profile_path=plugin_paths.AUTHORITY_PROFILE_FILE,
                authority_revocations_dir=plugin_paths.AUTHORITY_REVOCATIONS_DIR,
            )
            return adapter.handle(
                command,
                bound_context_ref=bound_context_ref,
                issuer_ref=verified_grant.issuer_id,
                subject_ref=verified_grant.subject_ref,
                now=now,
            )
        except FixtureLedgerUnavailable:
            return _failure(503, "fixture_ledger_unavailable", action=action)
    return _failure(400, "schema_invalid")


class OperatorCommand(ApiHandler):
    """HTTP transport for an already issued context-scoped local grant."""

    async def process(self, input: dict, request: Request) -> dict | Response:
        try:
            if type(input) is not dict or set(input) != _OUTER_FIELDS:
                return _transport(_failure(400, "schema_invalid"))
            context_ref = _safe_ref(input.get("context_id"))
            if context_ref is None:
                return _transport(_failure(400, "schema_invalid"))
            context = AgentContext.get(context_ref)
            if context is None or str(getattr(context, "id", "")) != context_ref:
                return _transport(_failure(404, "context_unavailable"))
            verifier = LocalGrantVerifier(
                plugin_paths.AUTHORITY_SECRET_FILE,
                plugin_paths.AUTHORITY_PROFILE_FILE,
                RevocationFileLedger(plugin_paths.AUTHORITY_REVOCATIONS_DIR),
            )
            result = execute_operator_command(
                input,
                bound_context_ref=context_ref,
                session_state=session,
                verifier=verifier,
                repository_opener=lambda: open_runtime_repository(
                    pre_cutover_path=plugin_paths.SAFE_STORE_FILE,
                    manifest_path=plugin_paths.STORE_AUTHORITY_MANIFEST_FILE,
                ),
            )
            return _transport(result)
        except Exception:
            return _transport(_failure(503, "operator_command_unavailable"))


__all__ = [
    "OperatorCommand",
    "execute_operator_command",
]
