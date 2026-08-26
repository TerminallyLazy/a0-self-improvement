from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat

import pytest

from usr.plugins.dspy_rlm.helpers.v3.migration import (
    MIGRATION_REGISTRY,
    MigrationCommand,
    MigrationPreconditionError,
    migrate_legacy_store,
)
from usr.plugins.dspy_rlm.helpers.v3.migration_repository import (
    MIGRATION_PHASES,
    MigrationRepository,
)
from usr.plugins.dspy_rlm.helpers.v3.quarantine import (
    AES256GCMKeyCustody,
    QuarantineIntegrityError,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Reader
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_reader
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_loads
from usr.plugins.dspy_rlm.helpers.v3.store_authority import (
    StaleStoreAuthorityRevision,
    StoreAuthorityManifestStore,
)


class HeldBarrier:
    held = True


class DeterministicAuthenticatedCipher:
    algorithm = "TEST-AUTHENTICATED-CIPHER"
    key_size = 32
    nonce_size = 12

    def __init__(self) -> None:
        self.counter = 0

    def _fresh(self, label: bytes, size: int) -> bytes:
        self.counter += 1
        return hashlib.sha256(label + self.counter.to_bytes(4, "big")).digest()[:size]

    def generate_key(self) -> bytes:
        return self._fresh(b"key", self.key_size)

    def generate_nonce(self) -> bytes:
        return self._fresh(b"nonce", self.nonce_size)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        stream = hashlib.sha256(key + nonce).digest()
        body = bytes(value ^ stream[index % len(stream)] for index, value in enumerate(plaintext))
        return body + hmac.new(key, aad + nonce + body, hashlib.sha256).digest()

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        body, tag = ciphertext[:-32], ciphertext[-32:]
        expected = hmac.new(key, aad + nonce + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise QuarantineIntegrityError("test authentication failed")
        stream = hashlib.sha256(key + nonce).digest()
        return bytes(value ^ stream[index % len(stream)] for index, value in enumerate(body))


def _legacy_source(path: Path, marker: str = "RAW_SECRET_MARKER") -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(
        """
        CREATE TABLE objective_samples (
          sample_id TEXT PRIMARY KEY, objective_payload TEXT, created_at REAL
        );
        CREATE TABLE optimization_jobs (
          job_key TEXT PRIMARY KEY, context_id TEXT, status TEXT, attempts INTEGER,
          max_retries INTEGER, payload_json TEXT, result_json TEXT,
          last_error TEXT, created_at REAL, updated_at REAL
        );
        CREATE TABLE guidance_versions (
          context_id TEXT, objective_bucket TEXT, objective_signature TEXT,
          guidance_version TEXT PRIMARY KEY, guidance_text TEXT, metadata_json TEXT,
          created_at REAL
        );
        """
    )
    connection.execute(
        "INSERT INTO objective_samples VALUES (?,?,?)",
        ("sample-1", json.dumps({"secret": marker}), 1.0),
    )
    connection.commit()
    assert (path.parent / f"{path.name}-wal").exists()
    return connection


def _command(run_id: str, now: datetime) -> MigrationCommand:
    return MigrationCommand(
        run_id=run_id,
        owner_id="operator-process-1",
        quarantine_ref=f"quarantine-{run_id}",
        quarantine_revision=1,
        generation_ref=f"generation-{run_id}",
        context_ref=f"opaque-context-{run_id}",
        source_context_id="legacy-context-raw",
        source_size_limit=2 * 1024 * 1024,
        transformation_policy="a0.v2-to-v3.safe-projection.v1",
        expected_authority_revision=0,
        key_epoch="migration-v1",
        created_at=now,
        lease_expires_at=now + timedelta(hours=1),
    )


def _environment(tmp_path: Path, run_id: str):
    root = (tmp_path / run_id).resolve()
    root.mkdir()
    now = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
    source = _legacy_source(root / "legacy.sqlite")
    ledger = MigrationRepository.create(root / "migration-ledger.sqlite")
    cipher = DeterministicAuthenticatedCipher()
    return {
        "command": _command(run_id, now),
        "source_connection": source,
        "source_barrier": HeldBarrier(),
        "workers_stopped": True,
        "ledger": ledger,
        "manifest_store": StoreAuthorityManifestStore(root / "authority.json"),
        "generation_path": root / "safe-generation.sqlite",
        "ciphertext_path": root / "quarantine.enc",
        "wrapped_key_path": root / "quarantine.key",
        "cipher": cipher,
        "custody": AES256GCMKeyCustody("test-custody", b"K" * 32, cipher=cipher),
        "now": now,
        "forbidden_markers": (b"RAW_SECRET_MARKER", b"legacy-context-raw"),
    }


def _close(env) -> None:
    try:
        env["source_connection"].close()
    finally:
        env["ledger"].close()


def test_wal_snapshot_migrates_to_content_free_null_generation(tmp_path: Path) -> None:
    env = _environment(tmp_path, "run-main")
    try:
        result = migrate_legacy_store(**env)

        assert env["ledger"].phases("run-main") == MIGRATION_PHASES
        assert result.disposition_counts == {
            "projected": 0, "quarantined": 1, "unsupported": 0, "invalid": 0
        }
        assert stat.S_IMODE(env["ciphertext_path"].stat().st_mode) == 0o600
        assert stat.S_IMODE(env["wrapped_key_path"].stat().st_mode) == 0o600
        assert b"RAW_SECRET_MARKER" not in env["generation_path"].read_bytes()
        assert b"RAW_SECRET_MARKER" not in env["ledger"].path.read_bytes()
        assert canonical_loads(result.migration_receipt)["compatibility_guidance_present"] is False
        with V3Reader.open(env["generation_path"], registry=MIGRATION_REGISTRY) as reader:
            assert reader.get_activation_scope("opaque-context-run-main").scope_revision == 0
        with open_runtime_reader(
            pre_cutover_path=(env["generation_path"].parent / "unused.sqlite").resolve(),
            manifest_path=env["manifest_store"].path,
        ) as reader:
            assert reader.get_activation_scope("opaque-context-run-main").scope_revision == 0
    finally:
        _close(env)


def test_interruption_resumes_at_every_phase_boundary(tmp_path: Path) -> None:
    for boundary in MIGRATION_PHASES:
        env = _environment(tmp_path, f"resume-{boundary}")
        interrupted = False

        def stop(phase: str) -> None:
            nonlocal interrupted
            if not interrupted and phase == boundary:
                interrupted = True
                raise RuntimeError("simulated phase-boundary interruption")

        try:
            with pytest.raises(RuntimeError, match="simulated"):
                migrate_legacy_store(**env, phase_observer=stop)
            result = migrate_legacy_store(**env)
            assert result.generation_path == env["generation_path"]
            assert env["ledger"].phases(env["command"].run_id) == MIGRATION_PHASES
        finally:
            _close(env)


def test_stale_manifest_cas_cannot_replace_selected_generation(tmp_path: Path) -> None:
    env = _environment(tmp_path, "stale")
    prior = (tmp_path / "prior.sqlite").resolve()
    prior.write_bytes(b"prior selected generation")
    os.chmod(prior, 0o600)
    env["manifest_store"].compare_and_swap(
        expected_revision=0, generation_ref="prior-generation",
        generation_path=prior, migration_receipt=b"prior receipt",
    )
    try:
        with pytest.raises(StaleStoreAuthorityRevision):
            migrate_legacy_store(**env)
        assert env["manifest_store"].read().generation_ref == "prior-generation"
    finally:
        _close(env)


def test_post_manifest_replace_recovery_never_reads_v2(tmp_path: Path) -> None:
    env = _environment(tmp_path, "lost-ack")
    try:
        with pytest.raises(RuntimeError, match="lost acknowledgement"):
            migrate_legacy_store(
                **env,
                after_manifest_commit=lambda: (_ for _ in ()).throw(
                    RuntimeError("lost acknowledgement")
                ),
            )
        env["source_connection"].close()
        result = migrate_legacy_store(**env)
        assert result.recovered_after_cutover is True
        assert env["ledger"].phases("lost-ack") == MIGRATION_PHASES
        assert env["ledger"].receipt("lost-ack") == result.migration_receipt

        env["ledger"].close()
        env["ledger"] = MigrationRepository.create(
            env["generation_path"].parent / "rebuilt-migration-ledger.sqlite"
        )
        rebuilt = migrate_legacy_store(**env)
        assert rebuilt.recovered_after_cutover is True
        assert env["ledger"].phases("lost-ack") == ()
        assert env["ledger"].receipt("lost-ack") == rebuilt.migration_receipt
        assert env["ledger"].receipt("lost-ack", "post_cutover_verification") is not None
    finally:
        env["ledger"].close()


def test_missing_barrier_worker_stop_crypto_or_explicit_size_budget_fails_closed(tmp_path: Path) -> None:
    env = _environment(tmp_path, "closed")
    try:
        class OpenBarrier:
            held = False

        with pytest.raises(MigrationPreconditionError, match="barrier"):
            migrate_legacy_store(**{**env, "source_barrier": OpenBarrier()})
        with pytest.raises(MigrationPreconditionError, match="workers"):
            migrate_legacy_store(**{**env, "workers_stopped": False})
        with pytest.raises(MigrationPreconditionError, match="exceeds"):
            migrate_legacy_store(
                **{**env, "command": replace(env["command"], source_size_limit=1)}
            )
        with pytest.raises(MigrationPreconditionError, match="crypto"):
            migrate_legacy_store(**{**env, "custody": None})
    finally:
        _close(env)
