from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from types import SimpleNamespace

from flask import Flask, session

from usr.plugins.dspy_rlm.api import authority_challenge, operator_command, operator_projection
from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    GrantRequest,
    RevocationRequest,
    VerifiedGrant,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
    issue_revocation,
)
from usr.plugins.dspy_rlm.helpers.v3.authority_service import (
    LocalGrantVerifier,
    RevocationFileLedger,
)
from usr.plugins.dspy_rlm.helpers.v3.command_adapter import SafeCommandResponse
from usr.plugins.dspy_rlm.helpers.v3.fixture_command_adapter import FixtureLedgerUnavailable
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
CONTEXT = "context.operator"
SUBJECT = "operator.local"


def _run(awaitable):
    return asyncio.run(awaitable)


def _authority(tmp_path, *, session_nonce: str = "browser.session.nonce.000000000001"):
    secret = tmp_path / "issuer.secret"
    profile_path = tmp_path / "issuer.json"
    revocations_path = tmp_path / "revocations"
    revocations_path.mkdir(mode=0o700)
    profile = bootstrap_local_issuer(
        secret,
        issuer_id="issuer.local",
        key_epoch=1,
        allowed_authority_classes=(AuthorityClass.OPERATOR_AUTHORITY_GRANT,),
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    profile_path.write_bytes(canonical_json(profile.to_record()))
    os.chmod(profile_path, 0o600)
    request = GrantRequest(
        authority_class=AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,
        issuer_id=profile.issuer_id,
        key_epoch=profile.key_epoch,
        subject_ref=SUBJECT,
        context_ref=CONTEXT,
        action="rollback",
        purpose="operator_mutation",
        target_ref=CONTEXT,
        target_revision=4,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=10),
        idempotency_key_digest=digest_idempotency_key("command-1"),
        session_nonce=session_nonce,
    )
    envelope = issue_grant(secret, profile, request)
    ledger = RevocationFileLedger(revocations_path)
    verifier = LocalGrantVerifier(secret, profile_path, ledger)
    command = {
        "action": "rollback",
        "context_ref": CONTEXT,
        "expected_scope_revision": 4,
        "idempotency_key": "command-1",
        "authority_grant_id": envelope["payload"]["grant_id"],
    }
    payload = {
        "context_id": CONTEXT,
        "target_ref": CONTEXT,
        "authority_envelope": envelope,
        "command": command,
    }
    challenge = {
        authority_challenge.CHALLENGE_SESSION_KEY: {
            "context_ref": CONTEXT,
            "session_nonce": session_nonce,
        }
    }
    return profile, ledger, verifier, request, payload, challenge


def test_challenge_rotates_context_bound_nonce_without_issuing_authority(monkeypatch) -> None:
    app = Flask(__name__)
    app.secret_key = "test-only"
    nonces = iter(("a" * 32, "b" * 32))
    monkeypatch.setattr(authority_challenge.secrets, "token_urlsafe", lambda _size: next(nonces))
    monkeypatch.setattr(
        authority_challenge.AgentContext,
        "get",
        staticmethod(lambda context_id: SimpleNamespace(id=context_id)),
    )

    with app.test_request_context("/"):
        handler = authority_challenge.AuthorityChallenge(app, object())
        first = _run(handler.process({"context_id": CONTEXT}, None))
        second = _run(handler.process({"context_id": CONTEXT}, None))

        assert first["session_nonce"] == "a" * 32
        assert second["session_nonce"] == "b" * 32
        assert session[authority_challenge.CHALLENGE_SESSION_KEY] == {
            "context_ref": CONTEXT,
            "session_nonce": "b" * 32,
        }
        assert "grant" not in json.dumps(second)
        assert handler.requires_auth() is True
        assert handler.requires_csrf() is True


def test_command_strips_envelope_and_revalidates_durable_authority_in_coordinator(
    monkeypatch, tmp_path
) -> None:
    _profile, _ledger, delegate, _request, payload, challenge = _authority(tmp_path)
    repository = object()
    calls: list[object] = []

    class CountingVerifier:
        def authorize(self, envelope, expectation, *, now):
            calls.append((envelope, expectation, now))
            return delegate.authorize(envelope, expectation, now=now)

    @contextmanager
    def open_selected():
        calls.append(repository)
        yield repository

    def rollback(selected, *, request, revalidate_grant):
        assert selected is repository
        assert request == "closed-request"
        assert revalidate_grant("transaction").subject_ref == SUBJECT
        return "transition-result"

    class Adapter:
        def __init__(
            self,
            *,
            activate_coordinator,
            rollback_coordinator,
            activate_grant_revalidator,
            rollback_grant_revalidator,
            safety_bypass_coordinator,
            safety_bypass_grant_revalidator,
        ):
            assert callable(activate_coordinator)
            assert callable(safety_bypass_coordinator)
            self.rollback = rollback_coordinator
            assert activate_grant_revalidator is rollback_grant_revalidator
            assert activate_grant_revalidator is safety_bypass_grant_revalidator
            self.revalidate = rollback_grant_revalidator

        def handle(self, command, **bindings):
            assert command is payload["command"]
            assert "authority_envelope" not in command
            assert bindings == {
                "bound_context_ref": CONTEXT,
                "issuer_ref": "issuer.local",
                "subject_ref": SUBJECT,
                "now": NOW,
            }
            assert self.rollback(
                request="closed-request",
                revalidate_grant=self.revalidate,
            ) == "transition-result"
            return SafeCommandResponse(
                200,
                {
                    "schema": "a0.command-response.v1",
                    "accepted": True,
                    "action": "rollback",
                    "receipt_ref": "receipt.operator",
                    "observed_revision": 4,
                    "resulting_revision": 5,
                    "policy_ref": None,
                    "action_state": "rolled_back",
                    "reason_codes": ["predecessor_restored"],
                },
            )

    monkeypatch.setattr(operator_command, "SafeCommandAdapter", Adapter)
    monkeypatch.setattr(operator_command, "rollback_to_predecessor", rollback)
    result = operator_command.execute_operator_command(
        payload,
        bound_context_ref=CONTEXT,
        session_state=challenge,
        verifier=CountingVerifier(),
        repository_opener=open_selected,
        clock=lambda: NOW,
    )

    assert result.status_code == 200
    assert result.body["receipt_ref"] == "receipt.operator"
    assert len([item for item in calls if isinstance(item, tuple)]) == 2
    assert calls.count(repository) == 1


def test_command_denies_session_mismatch_and_durable_revocation_before_store_open(
    tmp_path,
) -> None:
    profile, ledger, verifier, request, payload, challenge = _authority(tmp_path)
    opened: list[bool] = []

    @contextmanager
    def forbidden_open():
        opened.append(True)
        yield object()

    challenge[authority_challenge.CHALLENGE_SESSION_KEY]["session_nonce"] = "x" * 32
    mismatch = operator_command.execute_operator_command(
        payload,
        bound_context_ref=CONTEXT,
        session_state=challenge,
        verifier=verifier,
        repository_opener=forbidden_open,
        clock=lambda: NOW,
    )
    challenge[authority_challenge.CHALLENGE_SESSION_KEY]["session_nonce"] = request.session_nonce
    ledger.append(
        issue_revocation(
            verifier.secret_path,
            profile,
            RevocationRequest(
                grant_id=payload["authority_envelope"]["payload"]["grant_id"],
                issuer_id=profile.issuer_id,
                key_epoch=profile.key_epoch,
                context_ref=CONTEXT,
                revoked_at=NOW,
                reason_code="operator_requested",
                idempotency_key_digest=digest_idempotency_key("revoke-1"),
            ),
        )
    )
    revoked = operator_command.execute_operator_command(
        payload,
        bound_context_ref=CONTEXT,
        session_state=challenge,
        verifier=verifier,
        repository_opener=forbidden_open,
        clock=lambda: NOW,
    )

    assert mismatch.status_code == revoked.status_code == 422
    assert mismatch.body["reason_codes"] == revoked.body["reason_codes"] == [
        "operator_authority_denied"
    ]
    assert opened == []


def test_initial_operator_actions_dispatch_with_exact_outer_authority() -> None:
    commands = (
        ("optimize", {"target_ref": "work:1", "expected_revision": 0}),
        ("work_cancel", {"target_ref": "work:1", "expected_revision": 1}),
        ("canary_start", {"trial_id": "trial:1", "expected_scope_revision": 2}),
        (
            "canary_stop",
            {"trial": {"record_id": "trial:1"}, "expected_scope_revision": 2},
        ),
        ("activate", {"expected_scope_revision": 3}),
        ("rollback", {"expected_scope_revision": 4}),
        ("safety_bypass", {"expected_scope_revision": 5}),
        ("monitor_conclude", {"expected_scope_revision": 6}),
        ("requalification_start", {"expected_scope_revision": 6}),
        ("requalification_conclude", {"expected_scope_revision": 6}),
        ("feedback_submit", {"target_ref": "outcome:1", "expected_revision": 0}),
        ("fixture_draft", {"target_ref": "fixture:1", "target_revision": 1}),
        (
            "fixture_review",
            {"target": {"record_id": "draft:1"}, "target_revision": 1},
        ),
        (
            "fixture_admit",
            {"target": {"record_id": "draft:1"}, "target_revision": 1},
        ),
        (
            "fixture_withdraw",
            {"target": {"record_id": "draft:1"}, "target_revision": 1},
        ),
    )
    dispatched: list[str] = []

    class Verifier:
        def authorize(self, envelope, expectation, *, now):
            assert envelope["payload"]["grant_id"] == expectation_grant_id
            return VerifiedGrant(
                grant_id=expectation_grant_id,
                authority_class=expectation.authority_class,
                issuer_id=expectation.issuer_id,
                key_epoch=1,
                subject_ref=expectation.subject_ref,
                context_ref=expectation.context_ref,
                action=expectation.action,
                purpose=expectation.purpose,
                target_ref=expectation.target_ref,
                target_revision=expectation.target_revision,
                issued_at=NOW - timedelta(seconds=1),
                expires_at=expectation.expires_at,
                idempotency_key_digest=expectation.idempotency_key_digest,
                session_nonce=expectation.session_nonce,
            )

    @contextmanager
    def opened():
        yield object()

    for index, (action, binding) in enumerate(commands):
        expectation_grant_id = f"grant:{index}"
        command = {
            "action": action,
            "context_ref": CONTEXT,
            "idempotency_key": f"key-{index}",
            (
                "fixture_grant_id"
                if action.startswith("fixture_")
                else "authority_grant_id"
            ): expectation_grant_id,
            **binding,
        }
        target = operator_command._command_binding(command, CONTEXT)[0]
        payload = {
            "context_id": CONTEXT,
            "target_ref": target,
            "authority_envelope": {
                "payload": {
                    "grant_id": expectation_grant_id,
                    "issuer_id": "issuer.local",
                    "subject_ref": SUBJECT,
                    "expires_at": "2026-08-26T12:10:00.000000Z",
                }
            },
            "command": command,
        }
        response = operator_command.execute_operator_command(
            payload,
            bound_context_ref=CONTEXT,
            session_state={
                authority_challenge.CHALLENGE_SESSION_KEY: {
                    "context_ref": CONTEXT,
                    "session_nonce": "browser.session.nonce.000000000001",
                }
            },
            verifier=Verifier(),
            repository_opener=opened,
            clock=lambda: NOW,
            command_dispatcher=lambda *, command, **_kwargs: (
                dispatched.append(command["action"])
                or SafeCommandResponse(200, {"action": command["action"]})
            ),
        )
        assert response.status_code == 200

    assert dispatched == [action for action, _binding in commands]


def test_fixture_dispatch_assembles_runtime_service_and_keeps_unavailable_truthful(
    monkeypatch,
) -> None:
    repository = object()
    command = {"action": "fixture_draft"}
    verified = VerifiedGrant(
        grant_id="grant:fixture",
        authority_class="fixture_use_grant",
        issuer_id="issuer.local",
        key_epoch=1,
        subject_ref=SUBJECT,
        context_ref=CONTEXT,
        action="fixture_draft",
        purpose="fixture_authoring",
        target_ref="fixture:1",
        target_revision=1,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=10),
        idempotency_key_digest="a" * 64,
        session_nonce="browser.session.nonce.000000000001",
    )
    fixture_revalidator = lambda _binding: None
    calls = []

    class Adapter:
        def handle(self, selected, **bindings):
            assert selected is command
            assert bindings == {
                "bound_context_ref": CONTEXT,
                "issuer_ref": "issuer.local",
                "subject_ref": SUBJECT,
                "now": NOW,
            }
            return SafeCommandResponse(200, {"accepted": True})

    def build(selected, **kwargs):
        calls.append((selected, kwargs))
        return Adapter()

    monkeypatch.setattr(operator_command, "build_fixture_runtime_adapter", build)
    response = operator_command._dispatch_command(
        command,
        repository=repository,
        bound_context_ref=CONTEXT,
        verified_grant=verified,
        session_nonce=verified.session_nonce,
        now=NOW,
        revalidate_grant=lambda _transaction: verified,
        fixture_grant_revalidator=fixture_revalidator,
    )

    assert response.status_code == 200
    assert calls[0][0] is repository
    assert calls[0][1]["fixture_grant_revalidator"] is fixture_revalidator

    monkeypatch.setattr(
        operator_command,
        "build_fixture_runtime_adapter",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            FixtureLedgerUnavailable("private runtime profile is absent")
        ),
    )
    unavailable = operator_command._dispatch_command(
        command,
        repository=repository,
        bound_context_ref=CONTEXT,
        verified_grant=verified,
        session_nonce=verified.session_nonce,
        now=NOW,
        revalidate_grant=lambda _transaction: verified,
        fixture_grant_revalidator=fixture_revalidator,
    )
    assert unavailable.status_code == 503
    assert unavailable.body["reason_codes"] == ["fixture_ledger_unavailable"]


def test_projection_dispatches_six_views_read_only_and_fails_safe(monkeypatch) -> None:
    app = Flask(__name__)
    app.secret_key = "test-only"
    reader = object()
    facts = object()
    adapter = object()
    opens: list[tuple[object, object]] = []
    views = tuple(operator_projection._PROJECTIONS)

    @contextmanager
    def open_selected(*, pre_cutover_path, manifest_path):
        opens.append((pre_cutover_path, manifest_path))
        yield reader

    monkeypatch.setattr(operator_projection, "open_runtime_reader", open_selected)
    monkeypatch.setattr(
        operator_projection,
        "SafeStoreOperatorReader",
        lambda selected: facts if selected is reader else None,
    )
    monkeypatch.setattr(
        operator_projection,
        "OperatorRepositoryAdapter",
        lambda selected: adapter if selected is facts else None,
    )
    monkeypatch.setattr(
        operator_projection.AgentContext,
        "get",
        staticmethod(lambda context_id: SimpleNamespace(id=context_id)),
    )
    for view in views:
        monkeypatch.setitem(
            operator_projection._PROJECTIONS,
            view,
            lambda selected, context_ref, selected_view=view: {
                "schema": f"test.{selected_view}.v1",
                "view": selected_view,
                "context_ref": context_ref,
                "state": "ready",
            },
        )

    handler = operator_projection.OperatorProjection(app, object())
    for view in views:
        result = _run(handler.process({"context_id": CONTEXT, "view": view}, None))
        assert result["view"] == view
        assert result["context_ref"] == CONTEXT
    assert len(opens) == 6

    def unreadable(**_kwargs):
        raise RuntimeError("private /path and SECRET must not cross the boundary")

    monkeypatch.setattr(operator_projection, "open_runtime_reader", unreadable)
    failed = _run(handler.process({"context_id": CONTEXT, "view": "overview"}, None))
    body = json.loads(failed.response)
    assert failed.status == 503
    assert body["reason_codes"] == ["operator_projection_unavailable"]
    assert "private" not in failed.response and "SECRET" not in failed.response
    assert handler.requires_auth() is True
    assert handler.requires_csrf() is True
