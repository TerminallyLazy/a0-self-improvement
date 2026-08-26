from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import sqlite3

import pytest

from usr.plugins.dspy_rlm.helpers.v3 import (
    DEFAULT_REGISTRY,
    DomainEvent,
    IdentityCollision,
    IntegrityFailure,
    OperatorCommand,
    RevisionConflict,
    StoreAlreadyExistsError,
    StoreNotFoundError,
    V3Reader,
    V3Repository,
    activation_profile,
    canonical_json,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)


def _genesis(context_ref: str = "context-1"):
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id=f"{context_ref}:profile:genesis",
        context_ref=context_ref,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="opaque-v1",
    )
    return guidance, prompt, profile


def _insert_genesis(repository: V3Repository, context_ref: str = "context-1"):
    guidance, prompt, profile = _genesis(context_ref)
    with repository.transaction() as transaction:
        transaction.insert_record(guidance)
        transaction.insert_record(prompt)
        transaction.insert_record(profile)
    return guidance, prompt, profile


def test_store_creation_is_explicit_and_reading_missing_path_has_no_side_effects(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "absent" / "safe-store.sqlite3"
    before = set(tmp_path.rglob("*"))

    with pytest.raises(StoreNotFoundError):
        V3Reader.open(missing)
    with pytest.raises(StoreNotFoundError):
        V3Repository.open(missing)

    assert set(tmp_path.rglob("*")) == before
    with pytest.raises(StoreNotFoundError, match="parent directory"):
        V3Repository.create(missing)

    explicit = tmp_path / "safe-store.sqlite3"
    with V3Repository.create(explicit):
        assert explicit.is_file()
    with pytest.raises(StoreAlreadyExistsError):
        V3Repository.create(explicit)


def test_equivalent_insert_is_idempotent_and_identity_reuse_fails(tmp_path: Path) -> None:
    path = tmp_path / "safe-store.sqlite3"
    with V3Repository.create(path) as repository:
        guidance = null_guidance_artifact()
        with repository.transaction() as transaction:
            assert transaction.insert_record(guidance).inserted is True
        with repository.transaction() as transaction:
            assert transaction.insert_record(guidance).inserted is False

        collision = replace(guidance, key_epoch="other-key-epoch")
        with pytest.raises(IdentityCollision):
            with repository.transaction() as transaction:
                transaction.insert_record(collision)

        assert repository.get_record(guidance.record_id) == guidance


def test_record_and_all_links_commit_atomically_with_target_digest_integrity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "safe-store.sqlite3"
    guidance, prompt, profile = _genesis()
    with V3Repository.create(path) as repository:
        with pytest.raises(IntegrityFailure, match="does not exist"):
            with repository.transaction() as transaction:
                transaction.insert_record(profile)
        assert repository.get_record(profile.record_id) is None

        with repository.transaction() as transaction:
            transaction.insert_record(guidance)
            transaction.insert_record(prompt)
            transaction.insert_record(profile)
        assert repository.get_record(profile.record_id) == profile

        wrong_target = replace(guidance, content_digest="0" * 64)
        bad_profile = activation_profile(
            record_id="context-1:profile:bad-target",
            context_ref="context-1",
            guidance_artifact=wrong_target,
            prompt_patch_artifact=prompt,
            key_epoch="opaque-v1",
        )
        with pytest.raises(IntegrityFailure, match="digest mismatch"):
            with repository.transaction() as transaction:
                transaction.insert_record(bad_profile)
        assert repository.get_record(bad_profile.record_id) is None


def test_sqlite_triggers_reject_updates_deletes_and_manifest_extension(tmp_path: Path) -> None:
    path = tmp_path / "safe-store.sqlite3"
    with V3Repository.create(path) as repository:
        guidance, prompt, profile = _insert_genesis(repository)

    connection = sqlite3.connect(path)
    connection.create_function("a0_link_matches", 6, lambda *_args: 0)
    connection.execute("PRAGMA foreign_keys = ON")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute(
            "UPDATE typed_records SET key_epoch = 'tampered' WHERE record_id = ?",
            (guidance.record_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("DELETE FROM record_links WHERE source_id = ?", (profile.record_id,))
    with pytest.raises(sqlite3.IntegrityError, match="digest-covered"):
        connection.execute(
            """INSERT INTO record_links
               (source_id, manifest_index, role, ordinal, target_id, target_digest)
               VALUES (?, 2, 'extra', 0, ?, ?)""",
            (profile.record_id, prompt.record_id, prompt.content_digest),
        )
    connection.close()


def test_reader_detects_canonical_byte_tampering(tmp_path: Path) -> None:
    path = tmp_path / "safe-store.sqlite3"
    with V3Repository.create(path) as repository:
        guidance, _, _ = _insert_genesis(repository)

    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER typed_records_no_update")
    connection.execute(
        "UPDATE typed_records SET canonical_bytes = ? WHERE record_id = ?",
        (canonical_json({"tampered": True}), guidance.record_id),
    )
    connection.commit()
    connection.close()

    with V3Reader.open(path) as reader:
        with pytest.raises(IntegrityFailure, match="failed validation"):
            reader.get_record(guidance.record_id)


def test_read_only_reader_is_query_only_and_creates_no_sidecars(tmp_path: Path) -> None:
    path = tmp_path / "safe-store.sqlite3"
    with V3Repository.create(path) as repository:
        _, _, profile = _insert_genesis(repository)
    before = {item.name for item in tmp_path.iterdir()}

    with V3Reader.open(path) as reader:
        assert reader.query_only is True
        assert reader.get_record(profile.record_id) == profile
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            reader._connection.execute("CREATE TABLE forbidden (id INTEGER)")

    assert {item.name for item in tmp_path.iterdir()} == before


def test_coordinator_can_commit_records_event_scope_and_command_atomically(
    tmp_path: Path,
) -> None:
    path = tmp_path / "safe-store.sqlite3"
    guidance, prompt, profile = _genesis()
    command = OperatorCommand(
        command_id="command-1",
        issuer_ref="issuer-1",
        subject_ref="operator-1",
        context_ref="context-1",
        action="initialize_genesis",
        idempotency_key_digest=sha256(b"idempotency-1").hexdigest(),
        request_digest=sha256(b"request-1").hexdigest(),
        observed_revision=0,
        state="accepted",
        mutation_receipt_id=profile.record_id,
    )
    event = DomainEvent(
        event_id="event-1",
        subject_id=profile.record_id,
        subject_kind="activation_profile",
        sequence=0,
        event_type="genesis_initialized",
        payload_record_id=profile.record_id,
        actor_authority_ref="issuer-1",
    )

    with V3Repository.create(path) as repository:
        with repository.transaction() as transaction:
            transaction.insert_record(guidance)
            transaction.insert_record(prompt)
            transaction.insert_record(profile)
            transaction.append_event(event)
            scope = transaction.initialize_activation_scope(
                context_ref="context-1",
                profile_id=profile.record_id,
                profile_digest=profile.content_digest,
            )
            admission = transaction.admit_command(command)
        assert scope.scope_revision == 0
        assert admission.replayed is False

        with repository.transaction() as transaction:
            replay = transaction.admit_command(command)
        assert replay.replayed is True
        assert replay.command == command

        with pytest.raises(RevisionConflict):
            with repository.transaction() as transaction:
                transaction.initialize_activation_scope(
                    context_ref="context-1",
                    profile_id=profile.record_id,
                    profile_digest=profile.content_digest,
                )

    connection = sqlite3.connect(path)
    assert connection.execute("SELECT count(*) FROM domain_events").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM operator_commands").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM activation_scopes").fetchone()[0] == 1
    connection.close()
