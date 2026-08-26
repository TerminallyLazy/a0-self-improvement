from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    GrantExpectation,
    GrantRequest,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
)
from usr.plugins.dspy_rlm.helpers.v3.fixture_command_adapter import (
    FIXTURE_ADMIT_COMMAND_SCHEMA,
    FIXTURE_DRAFT_COMMAND_SCHEMA,
    FIXTURE_REVIEW_COMMAND_SCHEMA,
    FIXTURE_WITHDRAW_COMMAND_SCHEMA,
    FixtureAcceptedMutation,
    FixtureCommandAdapter,
    FixtureLedgerResult,
    FixtureLedgerUnavailable,
)
from usr.plugins.dspy_rlm.helpers.v3.fixtures import (
    FIXTURE_CONTENT_SCHEMA_ID,
    FixtureAuthority,
    FixtureVaultReceipt,
    GrantAuthority,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json
from usr.plugins.dspy_rlm.helpers.v3.repository import IdempotencyConflict


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
CONTEXT = "context:fixtures"
ISSUER = "issuer:fixtures"
AUTHOR = "operator:author"
REVIEWER = "operator:reviewer"
DIGEST = "a" * 64


class _Vault:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def seal(self, content: bytes, *, fixture_ref: str, plaintext_digest: str):
        ref = "vault:" + hashlib.sha256(fixture_ref.encode()).hexdigest()[:12]
        self.values[ref] = bytes(content)
        return FixtureVaultReceipt(
            ref,
            "encryption:test-v1",
            plaintext_digest,
            hashlib.sha256(b"cipher\0" + content).hexdigest(),
            len(content),
        )

    def open(self, vault_ref: str, *, fixture_ref: str, plaintext_digest: str):
        del fixture_ref, plaintext_digest
        return self.values[vault_ref]

    def withdraw(self, vault_ref: str, *, fixture_ref: str):
        del fixture_ref
        self.values.pop(vault_ref, None)


class _TrackingCoordinator:
    def __init__(self, authority: FixtureAuthority) -> None:
        self.authority = authority
        self.drafts = {}
        self.reviews = {}
        self.admissions = {}

    def create_draft(self, **kwargs):
        result = self.authority.create_draft(**kwargs)
        self.drafts[result.record.record_id] = result
        return result

    def review(self, draft, **kwargs):
        result = self.authority.review(draft, **kwargs)
        self.reviews[result.record.record_id] = result
        return result

    def admit(self, draft, review, **kwargs):
        result = self.authority.admit(draft, review, **kwargs)
        self.admissions[draft.record.record_id] = result
        return result

    def withdraw(self, draft, **kwargs):
        return self.authority.withdraw(draft, **kwargs)


class _TestDurableLedger:
    """Test double for the repository-owned atomic executor contract."""

    def __init__(self) -> None:
        self.accepted = {}
        self.executor_calls = 0

    def execute(self, admission, executor):
        key = (
            admission.issuer_ref,
            admission.subject_ref,
            admission.context_ref,
            admission.action,
            admission.idempotency_key_digest,
        )
        prior = self.accepted.get(key)
        if prior is not None:
            prior_digest, result = prior
            if prior_digest != admission.request_digest:
                raise IdempotencyConflict("changed request")
            return FixtureLedgerResult(admission, result.mutation_receipt_ref, True)
        self.executor_calls += 1
        mutation = executor()
        assert type(mutation) is FixtureAcceptedMutation
        receipt_ref = "fixture-command-receipt:" + admission.request_digest[:24]
        result = FixtureLedgerResult(admission, receipt_ref, False)
        self.accepted[key] = (admission.request_digest, result)
        return result


class _UnavailableLedger:
    def execute(self, admission, executor):
        del admission, executor
        raise FixtureLedgerUnavailable("repository unavailable")


def _content() -> bytes:
    return canonical_json(
        {
            "schema": FIXTURE_CONTENT_SCHEMA_ID,
            "input_message": "PRIVATE fixture content must stay transient",
            "initial_state": ["state:clean"],
            "tool_steps": [],
            "expected_outcome": ["typed result"],
            "execution_bounds": {
                "max_turns": 3,
                "max_tool_steps": 0,
                "max_output_bytes": 4096,
            },
        }
    )


def _system(tmp_path: Path, *, provider=None):
    secret = tmp_path / "fixture-authority.key"
    profile = bootstrap_local_issuer(
        secret,
        issuer_id=ISSUER,
        key_epoch=1,
        allowed_authority_classes=("fixture_use_grant", "operator_content_session"),
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    coordinator = _TrackingCoordinator(
        FixtureAuthority(
            secret_path=secret,
            issuer_profile=profile,
            vault=_Vault(),
            partition_secret=b"fixture-command-partition-secret",
            partition_policy_ref="partition-policy:v1",
            partition_weights={"training": 1, "tuning": 1, "certification_holdout": 1},
        )
    )
    grants: dict[str, GrantAuthority] = {}
    content_calls: list[tuple[str, str]] = []

    def content_provider(session_id: str, handle: str) -> bytes:
        content_calls.append((session_id, handle))
        if provider is not None:
            return provider(session_id, handle)
        return _content()

    def revalidate(binding):
        return grants[binding.authority_ref]

    ledger = _TestDurableLedger()

    def make_adapter(selected_ledger=None):
        return FixtureCommandAdapter(
            coordinator=coordinator,
            ledger=ledger if selected_ledger is None else selected_ledger,
            content_provider=content_provider,
            draft_resolver=lambda exact: coordinator.drafts.get(exact.record_id),
            review_resolver=lambda exact: coordinator.reviews.get(exact.record_id),
            fixture_grant_revalidator=revalidate,
            content_session_revalidator=revalidate,
        )

    return make_adapter, coordinator, ledger, grants, content_calls, secret, profile


def _authority(
    grants,
    secret,
    profile,
    *,
    authority_class: str,
    action: str,
    purpose: str,
    target_ref: str,
    revision: int,
    subject: str,
    idempotency_key: str,
    nonce: str,
) -> str:
    expires = NOW + timedelta(minutes=10)
    digest = digest_idempotency_key(idempotency_key)
    request = GrantRequest(
        authority_class=authority_class,
        issuer_id=ISSUER,
        key_epoch=1,
        subject_ref=subject,
        context_ref=CONTEXT,
        action=action,
        purpose=purpose,
        target_ref=target_ref,
        target_revision=revision,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=expires,
        idempotency_key_digest=digest,
        session_nonce=nonce,
    )
    expectation = GrantExpectation(
        authority_class=authority_class,
        issuer_id=ISSUER,
        subject_ref=subject,
        context_ref=CONTEXT,
        action=action,
        purpose=purpose,
        target_ref=target_ref,
        target_revision=revision,
        expires_at=expires,
        idempotency_key_digest=digest,
        session_nonce=nonce,
    )
    envelope = issue_grant(secret, profile, request)
    ref = envelope["payload"]["grant_id"]
    grants[ref] = GrantAuthority(envelope, expectation)
    return ref


def _draft_payload(grants, secret, profile, *, key="draft-command-1", fixture_ref="case:1"):
    nonce = "session:draft"
    fixture_grant = _authority(
        grants,
        secret,
        profile,
        authority_class="fixture_use_grant",
        action="fixture_draft",
        purpose="fixture_authoring",
        target_ref=fixture_ref,
        revision=1,
        subject=AUTHOR,
        idempotency_key=key,
        nonce=nonce,
    )
    session = _authority(
        grants,
        secret,
        profile,
        authority_class="operator_content_session",
        action="fixture_draft",
        purpose="fixture_authoring",
        target_ref=fixture_ref,
        revision=1,
        subject=AUTHOR,
        idempotency_key=key,
        nonce=nonce,
    )
    return {
        "schema": FIXTURE_DRAFT_COMMAND_SCHEMA,
        "action": "fixture_draft",
        "context_ref": CONTEXT,
        "target_ref": fixture_ref,
        "target_revision": 1,
        "idempotency_key": key,
        "fixture_grant_id": fixture_grant,
        "content_session_id": session,
        "operator_reason_code": "fixture_authoring_requested",
        "content_handle": "content:transient-1",
        "family_ref": "family:1",
        "source_lineage_digest": DIGEST,
        "author_ref": AUTHOR,
        "origin_class": "operator_authored",
        "source_attestation_digest": "b" * 64,
        "protected": True,
        "quarantine_release": None,
    }


def _bound_grants(grants, secret, profile, *, action, purpose, target, revision, subject, key, content=False):
    nonce = "session:" + action
    fixture = _authority(
        grants,
        secret,
        profile,
        authority_class="fixture_use_grant",
        action=action,
        purpose=purpose,
        target_ref=target,
        revision=revision,
        subject=subject,
        idempotency_key=key,
        nonce=nonce,
    )
    session = None
    if content:
        session = _authority(
            grants,
            secret,
            profile,
            authority_class="operator_content_session",
            action=action,
            purpose=purpose,
            target_ref=target,
            revision=revision,
            subject=subject,
            idempotency_key=key,
            nonce=nonce,
        )
    return fixture, session


def _handle(adapter, payload, subject):
    return adapter.handle(
        payload,
        bound_context_ref=CONTEXT,
        issuer_ref=ISSUER,
        subject_ref=subject,
        now=NOW,
    )


def test_draft_uses_transient_content_seam_and_exact_replay(tmp_path: Path) -> None:
    make_adapter, _, ledger, grants, calls, secret, profile = _system(tmp_path)
    adapter = make_adapter()
    payload = _draft_payload(grants, secret, profile)

    first = _handle(adapter, payload, AUTHOR)
    # A fresh adapter process obtains lost-ack replay from the durable seam.
    restarted = make_adapter()
    replay = _handle(restarted, payload, AUTHOR)
    conflict = _handle(restarted, {**payload, "family_ref": "family:other"}, AUTHOR)

    assert first.status_code == replay.status_code == 200
    assert first.body == replay.body
    assert calls == [(payload["content_session_id"], "content:transient-1")]
    assert ledger.executor_calls == 1
    assert conflict.status_code == 409
    encoded = repr((first.body, replay.body, conflict.body))
    assert "PRIVATE fixture content" not in encoded
    assert "content:transient-1" not in encoded
    assert "vault:" not in encoded


def test_review_admit_withdraw_wrap_existing_coordinator_operations(tmp_path: Path) -> None:
    make_adapter, coordinator, _, grants, _, secret, profile = _system(tmp_path)
    adapter = make_adapter()
    draft_response = _handle(adapter, _draft_payload(grants, secret, profile), AUTHOR)
    assert draft_response.status_code == 200
    draft = next(iter(coordinator.drafts.values()))

    review_key = "review-command-1"
    fixture_grant, session = _bound_grants(
        grants,
        secret,
        profile,
        action="fixture_review",
        purpose="fixture_review",
        target=draft.record.record_id,
        revision=1,
        subject=REVIEWER,
        key=review_key,
        content=True,
    )
    review_payload = {
        "schema": FIXTURE_REVIEW_COMMAND_SCHEMA,
        "action": "fixture_review",
        "context_ref": CONTEXT,
        "target_revision": 1,
        "idempotency_key": review_key,
        "fixture_grant_id": fixture_grant,
        "content_session_id": session,
        "operator_reason_code": "fixture_review_requested",
        "target": {"record_id": draft.record.record_id, "digest": draft.record.content_digest},
        "reviewer_ref": REVIEWER,
    }
    review_response = _handle(adapter, review_payload, REVIEWER)
    review = next(iter(coordinator.reviews.values()))

    admit_key = "admit-command-1"
    admit_grant, _ = _bound_grants(
        grants,
        secret,
        profile,
        action="fixture_admit",
        purpose="fixture_replay",
        target=draft.record.record_id,
        revision=1,
        subject=AUTHOR,
        key=admit_key,
    )
    admit_response = _handle(
        adapter,
        {
            "schema": FIXTURE_ADMIT_COMMAND_SCHEMA,
            "action": "fixture_admit",
            "context_ref": CONTEXT,
            "target_revision": 1,
            "idempotency_key": admit_key,
            "fixture_grant_id": admit_grant,
            "operator_reason_code": "fixture_admission_requested",
            "target": {"record_id": draft.record.record_id, "digest": draft.record.content_digest},
            "review": {"record_id": review.record.record_id, "digest": review.record.content_digest},
        },
        AUTHOR,
    )

    withdraw_key = "withdraw-command-1"
    withdraw_grant, _ = _bound_grants(
        grants,
        secret,
        profile,
        action="fixture_withdraw",
        purpose="fixture_replay",
        target=draft.record.record_id,
        revision=1,
        subject=AUTHOR,
        key=withdraw_key,
    )
    withdraw_response = _handle(
        adapter,
        {
            "schema": FIXTURE_WITHDRAW_COMMAND_SCHEMA,
            "action": "fixture_withdraw",
            "context_ref": CONTEXT,
            "target_revision": 1,
            "idempotency_key": withdraw_key,
            "fixture_grant_id": withdraw_grant,
            "operator_reason_code": "fixture_withdrawal_requested",
            "target": {"record_id": draft.record.record_id, "digest": draft.record.content_digest},
        },
        AUTHOR,
    )

    assert [item.status_code for item in (review_response, admit_response, withdraw_response)] == [200, 200, 200]
    assert [item.body["action_state"] for item in (review_response, admit_response, withdraw_response)] == [
        "reviewed",
        "admitted",
        "withdrawn",
    ]
    assert all("PRIVATE" not in repr(item.body) for item in (review_response, admit_response, withdraw_response))


def test_closed_schema_and_framework_bindings_fail_before_coordinator(tmp_path: Path) -> None:
    make_adapter, coordinator, ledger, grants, calls, secret, profile = _system(tmp_path)
    adapter = make_adapter()
    payload = _draft_payload(grants, secret, profile)
    cases = (
        ({**payload, "extra": "forbidden"}, CONTEXT, AUTHOR, 400, "schema_invalid"),
        ({**payload, "context_ref": "context:other"}, CONTEXT, AUTHOR, 422, "context_binding_mismatch"),
        ({**payload, "operator_reason_code": "because_i_said_so"}, CONTEXT, AUTHOR, 422, "reason_code_invalid"),
        ({**payload, "author_ref": REVIEWER}, CONTEXT, AUTHOR, 422, "fixture_policy_denied"),
    )
    for body, bound, subject, status, reason in cases:
        response = adapter.handle(
            body,
            bound_context_ref=bound,
            issuer_ref=ISSUER,
            subject_ref=subject,
            now=NOW,
        )
        assert response.status_code == status
        assert response.body["reason_codes"] == [reason]
    assert coordinator.drafts == {}
    assert calls == []
    assert ledger.executor_calls == 0


def test_stale_authority_content_and_internal_failures_are_settled(tmp_path: Path) -> None:
    def unavailable(_session_id, _handle):
        raise RuntimeError("plaintext/provider detail must not leak")

    make_adapter, coordinator, ledger, grants, calls, secret, profile = _system(
        tmp_path, provider=unavailable
    )
    unavailable_ledger_response = _handle(
        make_adapter(_UnavailableLedger()),
        _draft_payload(grants, secret, profile, key="ledger-unavailable"),
        AUTHOR,
    )
    assert unavailable_ledger_response.status_code == 503
    assert unavailable_ledger_response.body["reason_codes"] == [
        "fixture_ledger_unavailable"
    ]
    assert calls == []
    assert coordinator.drafts == {}

    adapter = make_adapter()
    draft_payload = _draft_payload(grants, secret, profile)
    unavailable_response = _handle(adapter, draft_payload, AUTHOR)
    assert unavailable_response.status_code == 503
    assert unavailable_response.body["reason_codes"] == ["fixture_unavailable"]
    assert "provider detail" not in repr(unavailable_response.body)

    # A revalidated grant for a different exact target is policy-denied.
    wrong_payload = _draft_payload(
        grants, secret, profile, key="wrong-authority-command", fixture_ref="case:wrong"
    )
    wrong_payload["target_ref"] = "case:changed"
    authority_response = _handle(adapter, wrong_payload, AUTHOR)
    assert authority_response.status_code == 422
    assert authority_response.body["reason_codes"] == ["fixture_authority_denied"]
