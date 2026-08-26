from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

from usr.plugins.dspy_rlm.helpers.v3.migration_repository import MIGRATION_PHASES


CLI = Path(__file__).resolve().parents[1] / "scripts" / "a0_local_authority.py"
NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)


def _fake_cryptography(root: Path) -> Path:
    package = root / "test-crypto"
    aead = package / "cryptography" / "hazmat" / "primitives" / "ciphers"
    aead.mkdir(parents=True)
    for parent in (
        package / "cryptography",
        package / "cryptography" / "hazmat",
        package / "cryptography" / "hazmat" / "primitives",
        aead,
    ):
        (parent / "__init__.py").write_text("")
    (aead / "aead.py").write_text(
        """
import hashlib
import hmac

class AESGCM:
    def __init__(self, key):
        self.key = key

    def encrypt(self, nonce, plaintext, aad):
        stream = hashlib.sha256(self.key + nonce).digest()
        body = bytes(value ^ stream[index % len(stream)] for index, value in enumerate(plaintext))
        return body + hmac.new(self.key, aad + nonce + body, hashlib.sha256).digest()

    def decrypt(self, nonce, ciphertext, aad):
        body, tag = ciphertext[:-32], ciphertext[-32:]
        expected = hmac.new(self.key, aad + nonce + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError('authentication failed')
        stream = hashlib.sha256(self.key + nonce).digest()
        return bytes(value ^ stream[index % len(stream)] for index, value in enumerate(body))
""".lstrip()
    )
    return package


def _legacy_source(path: Path) -> None:
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
        ("sample-1", json.dumps({"secret": "RAW_SECRET_MARKER"}), 1.0),
    )
    connection.commit()
    connection.close()


def _environment(tmp_path: Path) -> tuple[list[str], dict[str, Path], dict[str, str]]:
    paths = {
        "source": tmp_path / "legacy.sqlite",
        "ledger": tmp_path / "migration.sqlite",
        "manifest": tmp_path / "authority.json",
        "generation": tmp_path / "generation.sqlite",
        "ciphertext": tmp_path / "quarantine.enc",
        "wrapped": tmp_path / "quarantine.key",
        "custody": tmp_path / "custody.key",
    }
    _legacy_source(paths["source"])
    paths["custody"].write_bytes(b"K" * 32)
    paths["custody"].chmod(0o600)
    crypto = _fake_cryptography(tmp_path)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(crypto)
    arguments = [
        "--run-id", "cli-migration-01",
        "--owner-id", "operator-process-01",
        "--source-store", str(paths["source"]),
        "--source-context-id", "legacy-context-raw",
        "--source-size-limit", str(2 * 1024 * 1024),
        "--transformation-policy", "a0.v2-to-v3.safe-projection.v1",
        "--generation-ref", "safe-generation-01",
        "--generation-path", str(paths["generation"]),
        "--context", "opaque-context-cli",
        "--quarantine-ref", "quarantine-cli-01",
        "--quarantine-revision", "1",
        "--quarantine-ciphertext", str(paths["ciphertext"]),
        "--quarantine-wrapped-key", str(paths["wrapped"]),
        "--ledger", str(paths["ledger"]),
        "--manifest", str(paths["manifest"]),
        "--expected-authority-revision", "0",
        "--key-epoch", "migration-v1",
        "--created-at", NOW.isoformat(),
        "--now", NOW.isoformat(),
        "--lease-expires-at", (NOW + timedelta(hours=1)).isoformat(),
        "--custody-key", str(paths["custody"]),
        "--custody-key-ref", "local-migration-key-01",
        "--workers-stopped", "true",
        "--source-mutation-barrier", "sqlite-immediate",
        "--cipher-profile", "AES-256-GCM",
        "--forbidden-marker", "RAW_SECRET_MARKER",
        "--forbidden-marker", "legacy-context-raw",
    ]
    return arguments, paths, environment


def _invoke(command: str, arguments: list[str], environment: dict[str, str]):
    completed = subprocess.run(
        [sys.executable, str(CLI), command, *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    output = completed.stdout if completed.returncode == 0 else completed.stderr
    return completed.returncode, json.loads(output)


def test_local_migration_requires_explicit_cutover_and_recovers_without_v2(tmp_path: Path):
    arguments, paths, environment = _environment(tmp_path)

    status, preflight = _invoke("migration-preflight", arguments, environment)
    assert status == 0 and preflight["state"] == "ready"
    assert not paths["ledger"].exists() and not paths["manifest"].exists()

    status, started = _invoke("migration-start", arguments, environment)
    assert status == 0
    assert started["state"] == "awaiting_cutover"
    assert started["phases"] == list(MIGRATION_PHASES[:7])
    assert not paths["manifest"].exists()

    inspect_arguments = [
        "--ledger", str(paths["ledger"]),
        "--manifest", str(paths["manifest"]),
        "--run-id", "cli-migration-01",
        "--generation-ref", "safe-generation-01",
        "--context", "opaque-context-cli",
        "--expected-authority-revision", "0",
    ]
    status, inspected = _invoke("migration-inspect", inspect_arguments, environment)
    assert status == 0
    assert inspected["cutover_state"] == "awaiting_confirmation"
    assert inspected["receipt_present"] is True

    status, confirmed = _invoke(
        "migration-confirm-cutover",
        [*arguments, "--confirm", "CONFIRM_A0_V3_STORE_AUTHORITY_CUTOVER"],
        environment,
    )
    assert status == 0
    assert confirmed["state"] == "completed"
    assert confirmed["phases"] == list(MIGRATION_PHASES)
    assert paths["manifest"].exists()

    paths["source"].unlink()
    paths["custody"].unlink()
    status, recovered = _invoke("migration-resume", arguments, environment)
    assert status == 0
    assert recovered["state"] == "recovered"
    assert recovered["phases"] == list(MIGRATION_PHASES)
    assert b"RAW_SECRET_MARKER" not in paths["generation"].read_bytes()
    assert b"RAW_SECRET_MARKER" not in paths["ledger"].read_bytes()


def test_local_migration_rejects_unverified_worker_stop_before_writing(tmp_path: Path):
    arguments, paths, environment = _environment(tmp_path)
    position = arguments.index("--workers-stopped") + 1
    arguments[position] = "false"

    status, output = _invoke("migration-start", arguments, environment)

    assert status == 1
    assert output["reason_code"] == "LocalProtocolError"
    assert not paths["ledger"].exists()
    assert not paths["generation"].exists()
    assert not paths["manifest"].exists()
