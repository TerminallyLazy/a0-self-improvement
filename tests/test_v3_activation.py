from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

import pytest

from usr.plugins.dspy_rlm.helpers.v3.activation import (
    ACTIVATION_RECEIPT_SCHEMA_ID,
    ACTIVATION_REGISTRY,
    OPERATOR_MUTATION_RECEIPT_SCHEMA_ID,
    GenesisCommand,
    initialize_genesis,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    AuthorityDenied,
    AuthorityPurpose,
    AuthorityUnavailable,
    GrantRequest,
    IssuerProfile,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
)
from usr.plugins.dspy_rlm.helpers.v3.opaque import validate_opaque_reference
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
    RevisionConflict,
    V3Reader,
    V3Repository,
    V3Transaction,
)
from usr.plugins.dspy_rlm.helpers.v3.runtime_composer import compose_runtime


ISSUED_AT = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
EXPIRES_AT = ISSUED_AT + timedelta(minutes=15)
NOW = ISSUED_AT + timedelta(seconds=1)
OPAQUE_KEY = bytes(range(32))
OPAQUE_EPOCH = "opaque-epoch-1"


def _command(
    *,
    idempotency_key: str = "genesis-command-01",
    reason_code: str = "operator_requested",
) -> GenesisCommand:
    return GenesisCommand(
        subject_ref="subject_local_01",
        context_ref="context_01",
        target_ref="activation_scope_01",
        idempotency_key=idempotency_key,
        session_nonce="session_nonce_01",
        authority_expires_at=EXPIRES_AT,
        expected_revision=0,
        reason_code=reason_code,
    )


def _issuer(tmp_path: Path) -> tuple[Path, IssuerProfile]:
    secret_path = tmp_path / "issuer.key"
    profile = bootstrap_local_issuer(
        secret_path,
        issuer_id="issuer_local_01",
        key_epoch=1,
        allowed_authority_classes=[AuthorityClass.OPERATOR_AUTHORITY_GRANT],
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    return secret_path, profile


def _grant(
    secret_path: Path,
    profile: IssuerProfile,
    command: GenesisCommand,
    **overrides: object,
) -> dict:
    values = {
        "authority_class": AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,
        "issuer_id": profile.issuer_id,
        "key_epoch": profile.key_epoch,
        "subject_ref": command.subject_ref,
        "context_ref": command.context_ref,
        "action": "initialize_genesis",
        "purpose": AuthorityPurpose.GENESIS.value,
        "target_ref": command.target_ref,
        "target_revision": command.expected_revision,
        "issued_at": ISSUED_AT,
        "expires_at": command.authority_expires_at,
        "idempotency_key_digest": digest_idempotency_key(command.idempotency_key),
        "session_nonce": command.session_nonce,
    }
    values.update(overrides)
    return issue_grant(secret_path, profile, GrantRequest(**values))


def _run(
    repository: V3Repository,
    *,
    command: GenesisCommand,
    envelope: dict | None,
    secret_path: Path,
    profile: IssuerProfile | None,
):
    return initialize_genesis(
        repository,
        command=command,
        authority_envelope=envelope,
        authority_secret_path=secret_path,
        issuer_profile=profile,
        opaque_key=OPAQUE_KEY,
        opaque_key_epoch=OPAQUE_EPOCH,
        now=NOW,
    )


def _counts(path: Path) -> tuple[int, int, int, int, int]:
    connection = sqlite3.connect(path)
    try:
        return tuple(
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "typed_records",
                "record_links",
                "domain_events",
                "activation_scopes",
                "operator_commands",
            )
        )
    finally:
        connection.close()


def test_genesis_has_no_implicit_issuer_or_default_grant(tmp_path: Path) -> None:
    path = tmp_path / "safe-store.sqlite3"
    command = _command()

    with V3Repository.create(path, registry=ACTIVATION_REGISTRY) as repository:
        with pytest.raises(AuthorityUnavailable, match="issuer profile"):
            _run(
                repository,
                command=command,
                envelope=None,
                secret_path=tmp_path / "missing.key",
                profile=None,
            )

        secret_path, profile = _issuer(tmp_path)
        with pytest.raises(AuthorityDenied, match="explicit operator authority grant"):
            _run(
                repository,
                command=command,
                envelope=None,
                secret_path=secret_path,
                profile=profile,
            )

    assert _counts(path) == (0, 0, 0, 0, 0)


def test_missing_local_issuer_and_wrong_grant_binding_write_nothing(tmp_path: Path) -> None:
    path = tmp_path / "safe-store.sqlite3"
    command = _command()
    secret_path, profile = _issuer(tmp_path)
    envelope = _grant(secret_path, profile, command)

    with V3Repository.create(path, registry=ACTIVATION_REGISTRY) as repository:
        secret_path.unlink()
        with pytest.raises(AuthorityUnavailable, match="not bootstrapped"):
            _run(
                repository,
                command=command,
                envelope=envelope,
                secret_path=secret_path,
                profile=profile,
            )

    assert _counts(path) == (0, 0, 0, 0, 0)


def test_exact_binding_denial_is_receipt_free(tmp_path: Path) -> None:
    path = tmp_path / "safe-store.sqlite3"
    command = _command()
    secret_path, profile = _issuer(tmp_path)
    wrong = _grant(
        secret_path,
        profile,
        command,
        purpose=AuthorityPurpose.OPERATOR_MUTATION.value,
    )

    with V3Repository.create(path, registry=ACTIVATION_REGISTRY) as repository:
        with pytest.raises(AuthorityDenied, match="exact request binding"):
            _run(
                repository,
                command=command,
                envelope=wrong,
                secret_path=secret_path,
                profile=profile,
            )

    assert _counts(path) == (0, 0, 0, 0, 0)


def test_authorized_genesis_commits_exact_receipts_scope_event_and_identity_profile(
    tmp_path: Path,
) -> None:
    path = tmp_path / "safe-store.sqlite3"
    command = _command()
    secret_path, profile = _issuer(tmp_path)
    envelope = _grant(secret_path, profile, command)

    with V3Repository.create(path, registry=ACTIVATION_REGISTRY) as repository:
        result = _run(
            repository,
            command=command,
            envelope=envelope,
            secret_path=secret_path,
            profile=profile,
        )

    assert result.replayed is False
    assert result.scope.scope_revision == 0
    assert result.scope.mode == "normal"
    assert result.activation_receipt.schema_id == ACTIVATION_RECEIPT_SCHEMA_ID
    assert result.mutation_receipt.schema_id == OPERATOR_MUTATION_RECEIPT_SCHEMA_ID
    assert result.command.mutation_receipt_id == result.mutation_receipt.record_id
    assert _counts(path) == (6, 6, 1, 1, 1)

    for value in (
        result.scope.current_profile_id,
        result.activation_receipt.record_id,
        result.mutation_receipt.record_id,
        result.command.command_id,
    ):
        assert validate_opaque_reference(value) == value
        assert command.context_ref not in value

    with V3Reader.open(path, registry=ACTIVATION_REGISTRY) as reader:
        activation = reader.get_record(result.activation_receipt.record_id)
        mutation = reader.get_record(result.mutation_receipt.record_id)
        assert activation is not None
        assert mutation is not None
        assert [link.role for link in activation.links] == [
            "activated_profile",
            "authority_grant_use",
        ]
        assert activation.links[0].target_id == result.scope.current_profile_id
        assert activation.links[0].target_digest == result.scope.current_profile_digest
        assert mutation.links[0].target_id == activation.record_id
        assert mutation.links[0].target_digest == activation.content_digest
        assert mutation.links[1] == activation.links[1]

        prompt = ["core instructions\n", "tool contract"]
        composed = compose_runtime(
            reader, context_ref=command.context_ref, system_prompt=prompt
        )
        assert composed.state == "active"
        assert composed.segments == tuple(prompt)
        assert "\0".join(composed.segments).encode() == "\0".join(prompt).encode()


def test_same_key_and_request_returns_exact_receipts_without_duplicate_event(
    tmp_path: Path,
) -> None:
    path = tmp_path / "safe-store.sqlite3"
    command = _command()
    secret_path, profile = _issuer(tmp_path)
    envelope = _grant(secret_path, profile, command)

    with V3Repository.create(path, registry=ACTIVATION_REGISTRY) as repository:
        first = _run(
            repository,
            command=command,
            envelope=envelope,
            secret_path=secret_path,
            profile=profile,
        )
        before = _counts(path)
        replay = _run(
            repository,
            command=command,
            envelope=envelope,
            secret_path=secret_path,
            profile=profile,
        )

    assert replay.replayed is True
    assert replay.scope == first.scope
    assert replay.activation_receipt == first.activation_receipt
    assert replay.mutation_receipt == first.mutation_receipt
    assert replay.command == first.command
    assert _counts(path) == before == (6, 6, 1, 1, 1)


def test_same_idempotency_key_with_different_request_rolls_back_all_new_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "safe-store.sqlite3"
    command = _command()
    changed = replace(command, reason_code="recovery_requested")
    secret_path, profile = _issuer(tmp_path)
    envelope = _grant(secret_path, profile, command)

    with V3Repository.create(path, registry=ACTIVATION_REGISTRY) as repository:
        _run(
            repository,
            command=command,
            envelope=envelope,
            secret_path=secret_path,
            profile=profile,
        )
        before = _counts(path)
        with pytest.raises(IdempotencyConflict, match="different request"):
            _run(
                repository,
                command=changed,
                envelope=envelope,
                secret_path=secret_path,
                profile=profile,
            )

    assert _counts(path) == before == (6, 6, 1, 1, 1)


def test_existing_scope_refuses_other_genesis_atomically(tmp_path: Path) -> None:
    path = tmp_path / "safe-store.sqlite3"
    first_command = _command()
    second_command = _command(idempotency_key="genesis-command-02")
    secret_path, profile = _issuer(tmp_path)
    first_grant = _grant(secret_path, profile, first_command)
    second_grant = _grant(secret_path, profile, second_command)

    with V3Repository.create(path, registry=ACTIVATION_REGISTRY) as repository:
        _run(
            repository,
            command=first_command,
            envelope=first_grant,
            secret_path=secret_path,
            profile=profile,
        )
        before = _counts(path)
        with pytest.raises(RevisionConflict, match="absent revision-zero"):
            _run(
                repository,
                command=second_command,
                envelope=second_grant,
                secret_path=secret_path,
                profile=profile,
            )

    assert _counts(path) == before == (6, 6, 1, 1, 1)


def test_failure_after_event_and_command_admission_rolls_back_entire_write_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "safe-store.sqlite3"
    command = _command()
    secret_path, profile = _issuer(tmp_path)
    envelope = _grant(secret_path, profile, command)

    def fail_scope(*_args, **_kwargs):
        raise RuntimeError("injected scope failure")

    monkeypatch.setattr(V3Transaction, "initialize_activation_scope", fail_scope)
    with V3Repository.create(path, registry=ACTIVATION_REGISTRY) as repository:
        with pytest.raises(RuntimeError, match="injected scope failure"):
            _run(
                repository,
                command=command,
                envelope=envelope,
                secret_path=secret_path,
                profile=profile,
            )

    assert _counts(path) == (0, 0, 0, 0, 0)
