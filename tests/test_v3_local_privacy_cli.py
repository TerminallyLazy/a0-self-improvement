from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys

from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    GrantRequest,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
)
from usr.plugins.dspy_rlm.helpers.v3.migration_repository import (
    MigrationRepository,
    MigrationRun,
)
from usr.plugins.dspy_rlm.helpers.v3.privacy_lifecycle import WAIVER_ACKNOWLEDGEMENT
from usr.plugins.dspy_rlm.helpers.v3.quarantine import (
    AES256GCMKeyCustody,
    QuarantineIntegrityError,
    RetainedQuarantine,
    encrypt_quarantine,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json


CLI = Path(__file__).resolve().parents[1] / "scripts" / "a0_local_authority.py"
NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
EXPIRES = NOW + timedelta(minutes=30)
QUARANTINE_REF = "quarantine-cli-privacy"
CONTEXT = "context:privacy-cli"


class TestAuthenticatedCipher:
    algorithm = "AES-256-GCM"
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
        body, tag = ciphertext[:-32], ciphertext[-32:]
        expected = hmac.new(key, aad + nonce + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise QuarantineIntegrityError("test authentication failed")
        stream = hashlib.sha256(key + nonce).digest()
        return bytes(
            value ^ stream[index % len(stream)] for index, value in enumerate(body)
        )


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


def _grant(
    path: Path,
    *,
    secret: Path,
    profile,
    action: str,
    purpose: str,
    idempotency_key: str,
) -> None:
    envelope = issue_grant(
        secret,
        profile,
        GrantRequest(
            authority_class=AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,
            issuer_id=profile.issuer_id,
            key_epoch=profile.key_epoch,
            subject_ref="operator:privacy-cli",
            context_ref=CONTEXT,
            action=action,
            purpose=purpose,
            target_ref=QUARANTINE_REF,
            target_revision=1,
            issued_at=NOW,
            expires_at=EXPIRES,
            idempotency_key_digest=digest_idempotency_key(idempotency_key),
            session_nonce="session:privacy-cli",
        ),
    )
    path.write_bytes(canonical_json(envelope))
    path.chmod(0o600)


def _setup(tmp_path: Path):
    custody_key = tmp_path / "custody.key"
    custody_key.write_bytes(b"K" * 32)
    custody_key.chmod(0o600)
    cipher = TestAuthenticatedCipher()
    custody = AES256GCMKeyCustody(
        "custody-key-cli", custody_key.read_bytes(), cipher=cipher
    )
    encrypted = encrypt_quarantine(
        b"legacy plaintext that must never be exported",
        quarantine_ref=QUARANTINE_REF,
        revision=1,
        cipher=cipher,
        custody=custody,
    )
    ciphertext = tmp_path / "retained.enc"
    wrapped = tmp_path / "retained.key"
    ciphertext.write_bytes(encrypted.ciphertext_envelope)
    wrapped.write_bytes(encrypted.wrapped_key_envelope)
    ciphertext.chmod(0o600)
    wrapped.chmod(0o600)

    ledger = tmp_path / "migration-ledger.sqlite"
    with MigrationRepository.create(ledger) as repository:
        repository.ensure_run(
            MigrationRun(
                "migration-privacy-cli",
                QUARANTINE_REF,
                "generation-privacy-cli",
                CONTEXT,
                1_000_000,
                "a0.v2-to-v3.safe-projection.v1",
                0,
                NOW.isoformat(),
            )
        )
        lease = repository.acquire_lease(
            run_id="migration-privacy-cli",
            owner_id="operator:privacy-cli",
            now=NOW,
            expires_at=EXPIRES,
        )
        repository.record_quarantine(
            lease=lease,
            quarantine=RetainedQuarantine(
                QUARANTINE_REF,
                1,
                ciphertext,
                wrapped,
                sha256(encrypted.ciphertext_envelope).hexdigest(),
            ),
            wrapped_key_digest=sha256(encrypted.wrapped_key_envelope).hexdigest(),
            now=NOW,
        )

    secret = tmp_path / "issuer.secret"
    profile_path = tmp_path / "issuer-profile.json"
    profile = bootstrap_local_issuer(
        secret,
        issuer_id="issuer:privacy-cli",
        key_epoch=1,
        allowed_authority_classes=(AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,),
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    profile_path.write_bytes(canonical_json(profile.to_record()))
    profile_path.chmod(0o600)
    revocations = tmp_path / "revocations"
    revocations.mkdir(mode=0o700)
    export_grant = tmp_path / "export-grant.json"
    delete_grant = tmp_path / "delete-grant.json"
    _grant(
        export_grant,
        secret=secret,
        profile=profile,
        action="quarantine_export",
        purpose="quarantine_export",
        idempotency_key="export-key",
    )
    _grant(
        delete_grant,
        secret=secret,
        profile=profile,
        action="quarantine_delete",
        purpose="quarantine_deletion",
        idempotency_key="delete-key",
    )
    archive = tmp_path / "archive"
    archive.mkdir(mode=0o700)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(_fake_cryptography(tmp_path))
    return {
        "ledger": ledger,
        "ciphertext": ciphertext,
        "wrapped": wrapped,
        "custody": custody_key,
        "secret": secret,
        "profile": profile_path,
        "revocations": revocations,
        "export_grant": export_grant,
        "delete_grant": delete_grant,
        "archive": archive,
        "encrypted": encrypted,
        "environment": environment,
    }


def _grant_args(env, grant: Path, *, idempotency_key: str, now: datetime) -> list[str]:
    return [
        "--ledger", str(env["ledger"]),
        "--quarantine-ref", QUARANTINE_REF,
        "--quarantine-revision", "1",
        "--secret", str(env["secret"]),
        "--profile", str(env["profile"]),
        "--grant", str(grant),
        "--revocation-ledger", str(env["revocations"]),
        "--issuer", "issuer:privacy-cli",
        "--subject", "operator:privacy-cli",
        "--context", CONTEXT,
        "--authority-class", "operator_authority_grant",
        "--authority-expires-at", EXPIRES.isoformat(),
        "--idempotency-key", idempotency_key,
        "--session-nonce", "session:privacy-cli",
        "--now", now.isoformat(),
    ]


def _crypto_args(env) -> list[str]:
    return [
        "--custody-key", str(env["custody"]),
        "--custody-key-ref", "custody-key-cli",
        "--quarantine-ciphertext", str(env["ciphertext"]),
        "--quarantine-wrapped-key", str(env["wrapped"]),
        "--cipher-profile", "AES-256-GCM",
    ]


def _invoke(env, arguments: list[str]):
    completed = subprocess.run(
        [sys.executable, str(CLI), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=env["environment"],
    )
    output = completed.stdout if completed.returncode == 0 else completed.stderr
    return completed.returncode, json.loads(output)


def test_local_quarantine_export_challenge_and_cryptographic_erasure(tmp_path: Path):
    env = _setup(tmp_path)
    export_args = _grant_args(
        env, env["export_grant"], idempotency_key="export-key", now=NOW
    )
    status, exported = _invoke(
        env,
        ["quarantine-export", *export_args, *_crypto_args(env), "--destination", str(env["archive"])],
    )
    assert status == 0 and exported["contains_plaintext"] is False
    assert {path.read_bytes() for path in env["archive"].iterdir()} == {
        env["encrypted"].ciphertext_envelope,
        env["encrypted"].wrapped_key_envelope,
    }

    delete_args = _grant_args(
        env, env["delete_grant"], idempotency_key="delete-key", now=NOW
    )
    status, waived = _invoke(
        env,
        ["quarantine-export-waive", *delete_args, "--acknowledgement", WAIVER_ACKNOWLEDGEMENT],
    )
    assert status == 0 and waived["state"] == "export_waived"
    status, challenge = _invoke(
        env,
        [
            "quarantine-delete-challenge",
            *delete_args,
            "--challenge-expires-at",
            (NOW + timedelta(minutes=5)).isoformat(),
        ],
    )
    assert status == 0 and challenge["state"] == "challenge_issued"

    begin_args = _grant_args(
        env,
        env["delete_grant"],
        idempotency_key="delete-key",
        now=NOW + timedelta(minutes=1),
    )
    evidence = [
        "--evidence-kind", "export_waiver",
        "--evidence-ref", waived["export_waiver_ref"],
        "--challenge-ref", challenge["challenge_ref"],
    ]
    status, begun = _invoke(
        env,
        [
            "quarantine-delete", "begin", *begin_args, *_crypto_args(env), *evidence,
            "--typed-confirmation", challenge["required_confirmation"],
        ],
    )
    assert status == 0 and begun["state"] == "intent_admitted"
    assert env["ciphertext"].exists() and env["wrapped"].exists()

    inspect_args = [
        "--ledger", str(env["ledger"]),
        "--quarantine-ref", QUARANTINE_REF,
        "--quarantine-revision", "1",
        "--quarantine-ciphertext", str(env["ciphertext"]),
        "--quarantine-wrapped-key", str(env["wrapped"]),
        "--operation-ref", begun["operation_ref"],
    ]
    status, inspected = _invoke(
        env, ["quarantine-delete-inspect", *inspect_args]
    )
    assert status == 0 and inspected["state"] == "intent_admitted"
    assert inspected["physical_overwrite_claimed"] is None

    resume_args = _grant_args(
        env,
        env["delete_grant"],
        idempotency_key="delete-key",
        now=NOW + timedelta(minutes=2),
    )
    status, deleted = _invoke(
        env,
        [
            "quarantine-delete", "resume", *resume_args,
            "--quarantine-ciphertext", str(env["ciphertext"]),
            "--quarantine-wrapped-key", str(env["wrapped"]),
            *evidence,
            "--operation-ref", begun["operation_ref"],
        ],
    )
    assert status == 0 and deleted["state"] == "deleted"
    assert deleted["physical_overwrite_claimed"] is False
    assert not env["ciphertext"].exists() and not env["wrapped"].exists()
    assert all(path.exists() for path in env["archive"].iterdir())

    status, completed = _invoke(
        env, ["quarantine-delete-inspect", *inspect_args]
    )
    assert status == 0 and completed["state"] == "completed"
    assert completed["physical_overwrite_claimed"] is False
