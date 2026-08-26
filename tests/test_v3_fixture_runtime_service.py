from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path

import pytest

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
    FixtureLedgerUnavailable,
)
from usr.plugins.dspy_rlm.helpers.v3.fixture_repository import (
    FIXTURE_REPOSITORY_REGISTRY,
)
from usr.plugins.dspy_rlm.helpers.v3.fixture_runtime_service import (
    FIXTURE_CONTENT_SESSION_SCHEMA,
    FIXTURE_RUNTIME_PROFILE_SCHEMA,
    build_fixture_runtime_adapter,
    content_session_manifest_filename,
    content_session_payload_digest,
    content_session_payload_filename,
)
from usr.plugins.dspy_rlm.helpers.v3.fixtures import (
    FIXTURE_CONTENT_SCHEMA_ID,
    GrantAuthority,
)
from usr.plugins.dspy_rlm.helpers.v3.quarantine import QuarantineIntegrityError
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Repository
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
CONTEXT = "context:fixture-runtime"
ISSUER = "issuer:fixture-runtime"
AUTHOR = "operator:fixture-author"
REVIEWER = "operator:fixture-reviewer"


class AuthenticatedTestCipher:
    algorithm = "TEST-AUTHENTICATED-CIPHER"
    key_size = 32
    nonce_size = 12

    def generate_key(self) -> bytes:
        return os.urandom(self.key_size)

    def generate_nonce(self) -> bytes:
        return os.urandom(self.nonce_size)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        stream = hashlib.sha256(key + nonce).digest()
        body = bytes(
            value ^ stream[index % len(stream)] for index, value in enumerate(plaintext)
        )
        return body + hmac.new(key, aad + nonce + body, hashlib.sha256).digest()

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(ciphertext) < 32:
            raise QuarantineIntegrityError("test authentication failed")
        body, tag = ciphertext[:-32], ciphertext[-32:]
        expected = hmac.new(key, aad + nonce + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise QuarantineIntegrityError("test authentication failed")
        stream = hashlib.sha256(key + nonce).digest()
        return bytes(
            value ^ stream[index % len(stream)] for index, value in enumerate(body)
        )


def _write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    os.chmod(path, 0o600)


def _content() -> bytes:
    return canonical_json(
        {
            "schema": FIXTURE_CONTENT_SCHEMA_ID,
            "input_message": "PRIVATE fixture runtime content",
            "initial_state": ["private:state"],
            "tool_steps": [],
            "expected_outcome": ["typed result"],
            "execution_bounds": {
                "max_turns": 2,
                "max_tool_steps": 0,
                "max_output_bytes": 2048,
            },
        }
    )


def _authority(
    secret: Path,
    profile,
    *,
    authority_class: str,
    target: str,
    key: str,
    nonce: str,
    action: str = "fixture_draft",
    purpose: str = "fixture_authoring",
    subject: str = AUTHOR,
):
    expires = NOW + timedelta(minutes=10)
    request = GrantRequest(
        authority_class=authority_class,
        issuer_id=ISSUER,
        key_epoch=1,
        subject_ref=subject,
        context_ref=CONTEXT,
        action=action,
        purpose=purpose,
        target_ref=target,
        target_revision=1,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=expires,
        idempotency_key_digest=digest_idempotency_key(key),
        session_nonce=nonce,
    )
    expectation = GrantExpectation(
        authority_class=authority_class,
        issuer_id=ISSUER,
        subject_ref=subject,
        context_ref=CONTEXT,
        action=action,
        purpose=purpose,
        target_ref=target,
        target_revision=1,
        expires_at=expires,
        idempotency_key_digest=digest_idempotency_key(key),
        session_nonce=nonce,
    )
    envelope = issue_grant(secret, profile, request)
    return envelope, expectation


def _runtime(tmp_path: Path):
    authority = tmp_path / "authority"
    sessions = tmp_path / "sessions"
    vault = tmp_path / "vault"
    revocations = authority / "revocations"
    for directory in (authority, sessions, vault, revocations):
        directory.mkdir(mode=0o700)
    secret = authority / "issuer.secret"
    profile_path = authority / "issuer.json"
    profile = bootstrap_local_issuer(
        secret,
        issuer_id=ISSUER,
        key_epoch=1,
        allowed_authority_classes=("fixture_use_grant", "operator_content_session"),
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    _write_private(profile_path, canonical_json(profile.to_record()))
    vault_key = tmp_path / "vault.key"
    partition_secret = tmp_path / "partition.key"
    _write_private(vault_key, b"v" * 32)
    _write_private(partition_secret, b"partition-secret-material")
    runtime_profile = tmp_path / "fixture-runtime.json"
    _write_private(
        runtime_profile,
        canonical_json(
            {
                "schema": FIXTURE_RUNTIME_PROFILE_SCHEMA,
                "content_sessions_root": str(sessions),
                "vault_root": str(vault),
                "vault_key_ref": "fixture-vault-key:1",
                "vault_key_file": str(vault_key),
                "partition_secret_file": str(partition_secret),
                "partition_policy_ref": "fixture-partition-policy:1",
                "partition_weights": {
                    "training": 1,
                    "tuning": 1,
                    "certification_holdout": 1,
                },
                "key_epoch": "fixture-key-epoch:1",
                "record_maximum": 1000,
                "event_maximum": 1000,
                "maximum_content_bytes": 8192,
            }
        ),
    )
    return secret, profile_path, profile, revocations, sessions, vault, runtime_profile


def test_runtime_fixture_lifecycle_is_operational_and_content_separated(tmp_path: Path) -> None:
    secret, profile_path, profile, revocations, sessions, vault, runtime_profile = _runtime(
        tmp_path
    )
    key = "fixture-runtime-command-1"
    target = "fixture:runtime:1"
    nonce = "fixture-runtime-session:1"
    fixture_envelope, fixture_expectation = _authority(
        secret,
        profile,
        authority_class="fixture_use_grant",
        target=target,
        key=key,
        nonce=nonce,
    )
    session_envelope, _session_expectation = _authority(
        secret,
        profile,
        authority_class="operator_content_session",
        target=target,
        key=key,
        nonce=nonce,
    )
    session_id = session_envelope["payload"]["grant_id"]
    handle = "content:fixture-runtime:1"
    content = _content()
    _write_private(
        sessions / content_session_payload_filename(session_id, handle), content
    )
    _write_private(
        sessions / content_session_manifest_filename(session_id),
        canonical_json(
            {
                "schema": FIXTURE_CONTENT_SESSION_SCHEMA,
                "content_session_id": session_id,
                "authority_envelope": session_envelope,
                "content_handles": [
                    {
                        "content_handle": handle,
                        "content_digest": content_session_payload_digest(content),
                        "content_size": len(content),
                    }
                ],
            }
        ),
    )
    fixture_authorities = {
        fixture_envelope["payload"]["grant_id"]: GrantAuthority(
            fixture_envelope, fixture_expectation
        )
    }
    store_path = tmp_path / "safe.sqlite3"
    with V3Repository.create(store_path, registry=FIXTURE_REPOSITORY_REGISTRY) as repository:
        adapter = build_fixture_runtime_adapter(
            repository,
            context_ref=CONTEXT,
            fixture_grant_revalidator=lambda binding: fixture_authorities[
                binding.authority_ref
            ],
            authority_secret_path=secret,
            authority_profile_path=profile_path,
            authority_revocations_dir=revocations,
            profile_path=runtime_profile,
            cipher=AuthenticatedTestCipher(),
        )
        payload = {
            "schema": FIXTURE_DRAFT_COMMAND_SCHEMA,
            "action": "fixture_draft",
            "context_ref": CONTEXT,
            "target_revision": 1,
            "idempotency_key": key,
            "fixture_grant_id": fixture_envelope["payload"]["grant_id"],
            "operator_reason_code": "fixture_authoring_requested",
            "target_ref": target,
            "content_session_id": session_id,
            "content_handle": handle,
            "family_ref": "fixture-family:runtime:1",
            "source_lineage_digest": "a" * 64,
            "author_ref": AUTHOR,
            "origin_class": "operator_authored",
            "source_attestation_digest": "b" * 64,
            "protected": True,
            "quarantine_release": None,
        }
        first = adapter.handle(
            payload,
            bound_context_ref=CONTEXT,
            issuer_ref=ISSUER,
            subject_ref=AUTHOR,
            now=NOW,
        )
        replay = adapter.handle(
            payload,
            bound_context_ref=CONTEXT,
            issuer_ref=ISSUER,
            subject_ref=AUTHOR,
            now=NOW,
        )

        assert first.status_code == replay.status_code == 200
        assert first.body == replay.body
        assert all(content not in path.read_bytes() for path in vault.iterdir())

        draft_receipt = repository.get_record(first.body["receipt_ref"])
        assert draft_receipt is not None
        draft = draft_receipt.payload["domain_result"]
        review_key = "fixture-runtime-review-1"
        review_grant, review_expectation = _authority(
            secret,
            profile,
            authority_class="fixture_use_grant",
            target=draft["record_id"],
            key=review_key,
            nonce="fixture-runtime-review-session:1",
            action="fixture_review",
            purpose="fixture_review",
            subject=REVIEWER,
        )
        review_session, _ = _authority(
            secret,
            profile,
            authority_class="operator_content_session",
            target=draft["record_id"],
            key=review_key,
            nonce="fixture-runtime-review-session:1",
            action="fixture_review",
            purpose="fixture_review",
            subject=REVIEWER,
        )
        fixture_authorities[review_grant["payload"]["grant_id"]] = GrantAuthority(
            review_grant, review_expectation
        )
        review_session_id = review_session["payload"]["grant_id"]
        _write_private(
            sessions / content_session_manifest_filename(review_session_id),
            canonical_json(
                {
                    "schema": FIXTURE_CONTENT_SESSION_SCHEMA,
                    "content_session_id": review_session_id,
                    "authority_envelope": review_session,
                    "content_handles": [],
                }
            ),
        )
        reviewed = adapter.handle(
            {
                "schema": FIXTURE_REVIEW_COMMAND_SCHEMA,
                "action": "fixture_review",
                "context_ref": CONTEXT,
                "target_revision": 1,
                "idempotency_key": review_key,
                "fixture_grant_id": review_grant["payload"]["grant_id"],
                "content_session_id": review_session_id,
                "operator_reason_code": "fixture_review_requested",
                "target": draft,
                "reviewer_ref": REVIEWER,
            },
            bound_context_ref=CONTEXT,
            issuer_ref=ISSUER,
            subject_ref=REVIEWER,
            now=NOW,
        )
        assert reviewed.status_code == 200
        review_receipt = repository.get_record(reviewed.body["receipt_ref"])
        assert review_receipt is not None
        review = review_receipt.payload["domain_result"]

        admit_key = "fixture-runtime-admit-1"
        admit_grant, admit_expectation = _authority(
            secret,
            profile,
            authority_class="fixture_use_grant",
            target=draft["record_id"],
            key=admit_key,
            nonce="fixture-runtime-admit-session:1",
            action="fixture_admit",
            purpose="fixture_replay",
        )
        fixture_authorities[admit_grant["payload"]["grant_id"]] = GrantAuthority(
            admit_grant, admit_expectation
        )
        admitted = adapter.handle(
            {
                "schema": FIXTURE_ADMIT_COMMAND_SCHEMA,
                "action": "fixture_admit",
                "context_ref": CONTEXT,
                "target_revision": 1,
                "idempotency_key": admit_key,
                "fixture_grant_id": admit_grant["payload"]["grant_id"],
                "operator_reason_code": "fixture_admission_requested",
                "target": draft,
                "review": review,
            },
            bound_context_ref=CONTEXT,
            issuer_ref=ISSUER,
            subject_ref=AUTHOR,
            now=NOW,
        )
        assert admitted.status_code == 200

        withdraw_key = "fixture-runtime-withdraw-1"
        withdraw_grant, withdraw_expectation = _authority(
            secret,
            profile,
            authority_class="fixture_use_grant",
            target=draft["record_id"],
            key=withdraw_key,
            nonce="fixture-runtime-withdraw-session:1",
            action="fixture_withdraw",
            purpose="fixture_replay",
        )
        fixture_authorities[withdraw_grant["payload"]["grant_id"]] = GrantAuthority(
            withdraw_grant, withdraw_expectation
        )
        withdrawn = adapter.handle(
            {
                "schema": FIXTURE_WITHDRAW_COMMAND_SCHEMA,
                "action": "fixture_withdraw",
                "context_ref": CONTEXT,
                "target_revision": 1,
                "idempotency_key": withdraw_key,
                "fixture_grant_id": withdraw_grant["payload"]["grant_id"],
                "operator_reason_code": "fixture_withdrawal_requested",
                "target": draft,
            },
            bound_context_ref=CONTEXT,
            issuer_ref=ISSUER,
            subject_ref=AUTHOR,
            now=NOW,
        )
        assert withdrawn.status_code == 200

    assert content not in store_path.read_bytes()
    assert tuple(vault.iterdir()) == ()
    assert handle not in repr(first.body)
    assert session_id not in repr(first.body)


def test_runtime_profile_and_private_custody_are_required(tmp_path: Path) -> None:
    store_path = tmp_path / "safe.sqlite3"
    with V3Repository.create(store_path, registry=FIXTURE_REPOSITORY_REGISTRY) as repository:
        with pytest.raises(FixtureLedgerUnavailable):
            build_fixture_runtime_adapter(
                repository,
                context_ref=CONTEXT,
                fixture_grant_revalidator=lambda _binding: None,
                authority_secret_path=tmp_path / "missing-secret",
                authority_profile_path=tmp_path / "missing-profile",
                authority_revocations_dir=tmp_path / "missing-revocations",
                profile_path=tmp_path / "missing-runtime-profile",
                cipher=AuthenticatedTestCipher(),
            )
