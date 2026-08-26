from __future__ import annotations

import builtins
import hashlib
import hmac
from pathlib import Path

import pytest

from usr.plugins.dspy_rlm.helpers.v3.quarantine import (
    AES256GCMCipher,
    AES256GCMKeyCustody,
    CryptographicDeletionPlan,
    EncryptedQuarantine,
    QuarantineIntegrityError,
    QuarantineUnavailable,
    QuarantineValidationError,
    RetainedQuarantine,
    decrypt_quarantine,
    encrypt_quarantine,
    exact_ciphertext_export,
    plan_cryptographic_deletion,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json, canonical_loads


class DeterministicAuthenticatedCipher:
    """Test-only authenticated cipher; never a production fallback."""

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
        if len(ciphertext) < 32:
            raise QuarantineIntegrityError("test authentication failed")
        body, tag = ciphertext[:-32], ciphertext[-32:]
        expected = hmac.new(key, aad + nonce + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise QuarantineIntegrityError("test authentication failed")
        stream = hashlib.sha256(key + nonce).digest()
        return bytes(value ^ stream[index % len(stream)] for index, value in enumerate(body))


def _bundle() -> tuple[EncryptedQuarantine, DeterministicAuthenticatedCipher, AES256GCMKeyCustody]:
    cipher = DeterministicAuthenticatedCipher()
    custody = AES256GCMKeyCustody("custody_epoch_1", b"K" * 32, cipher=cipher)
    envelope = encrypt_quarantine(
        b"legacy bytes that must remain quarantined",
        quarantine_ref="quarantine_01",
        revision=1,
        cipher=cipher,
        custody=custody,
    )
    return envelope, cipher, custody


def test_envelope_round_trip_uses_fresh_values_and_exports_exact_ciphertext() -> None:
    first, cipher, custody = _bundle()
    second = encrypt_quarantine(
        b"legacy bytes that must remain quarantined",
        quarantine_ref="quarantine_01",
        revision=1,
        cipher=cipher,
        custody=custody,
    )

    assert first != second
    assert decrypt_quarantine(first, cipher=cipher, custody=custody) == (
        b"legacy bytes that must remain quarantined"
    )
    assert exact_ciphertext_export(first, cipher=cipher, custody=custody) == first
    assert "wrapped" not in canonical_loads(first.ciphertext_envelope)
    with pytest.raises(QuarantineValidationError, match="wrapped-key envelope"):
        decrypt_quarantine(
            EncryptedQuarantine(first.ciphertext_envelope, b""),
            cipher=cipher,
            custody=custody,
        )


def test_payload_and_wrapped_dek_tampering_fail_closed() -> None:
    encrypted, cipher, custody = _bundle()
    for envelope_name, field in (
        ("ciphertext_envelope", "payload_ciphertext"),
        ("wrapped_key_envelope", "ciphertext"),
    ):
        record = canonical_loads(getattr(encrypted, envelope_name))
        value = record[field]
        record[field] = ("A" if value[0] != "A" else "B") + value[1:]
        replacement = canonical_json(record)
        tampered = EncryptedQuarantine(
            ciphertext_envelope=(
                replacement if envelope_name == "ciphertext_envelope" else encrypted.ciphertext_envelope
            ),
            wrapped_key_envelope=(
                replacement if envelope_name == "wrapped_key_envelope" else encrypted.wrapped_key_envelope
            ),
        )

        with pytest.raises(QuarantineIntegrityError):
            decrypt_quarantine(tampered, cipher=cipher, custody=custody)


def test_production_cipher_is_unavailable_without_cryptography(monkeypatch) -> None:
    original_import = builtins.__import__

    def reject_cryptography(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ModuleNotFoundError("blocked for fail-closed contract test")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_cryptography)
    with pytest.raises(QuarantineUnavailable, match="unavailable"):
        AES256GCMCipher().generate_key()


def test_deletion_plan_uses_only_ledger_resolved_exact_paths(tmp_path: Path) -> None:
    retained = RetainedQuarantine(
        quarantine_ref="quarantine_01",
        revision=2,
        ciphertext_path=tmp_path / "retained.enc",
        wrapped_key_path=tmp_path / "retained.key",
        ciphertext_digest="a" * 64,
    )

    class Ledger:
        def resolve_retained(self, quarantine_ref: str, revision: int) -> RetainedQuarantine:
            assert (quarantine_ref, revision) == ("quarantine_01", 2)
            return retained

    plan = plan_cryptographic_deletion("quarantine_01", 2, ledger=Ledger())

    assert plan == CryptographicDeletionPlan(
        quarantine_ref="quarantine_01",
        revision=2,
        ciphertext_path=retained.ciphertext_path,
        wrapped_key_path=retained.wrapped_key_path,
        ciphertext_digest=retained.ciphertext_digest,
    )
