import hashlib
import hmac
import os

import pytest

from usr.plugins.dspy_rlm.helpers.v3.fixture_vault import LocalEncryptedFixtureVault
from usr.plugins.dspy_rlm.helpers.v3.fixtures import (
    FIXTURE_CONTENT_SCHEMA_ID,
    FixtureValidationError,
)
from usr.plugins.dspy_rlm.helpers.v3.quarantine import QuarantineIntegrityError
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json, schema_digest


class AuthenticatedTestCipher:
    """Test-only injected cipher; production continues to require AES-256-GCM."""

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


def _content() -> bytes:
    return canonical_json(
        {
            "schema": FIXTURE_CONTENT_SCHEMA_ID,
            "input_message": "private replay input",
            "initial_state": ["private state"],
            "tool_steps": [],
            "expected_outcome": ["bounded result"],
            "execution_bounds": {
                "max_turns": 2,
                "max_tool_steps": 0,
                "max_output_bytes": 1024,
            },
        }
    )


def _digest(content: bytes) -> str:
    return schema_digest("fixture-content", FIXTURE_CONTENT_SCHEMA_ID, content)


def test_encrypted_vault_round_trip_survives_restart_without_plaintext(tmp_path):
    root = tmp_path / "vault"
    root.mkdir(mode=0o700)
    key = b"k" * 32
    content = _content()
    digest = _digest(content)

    first = LocalEncryptedFixtureVault(
        root,
        key_ref="fixture-key-01",
        key_encryption_key=key,
        cipher=AuthenticatedTestCipher(),
    )
    receipt = first.seal(content, fixture_ref="case-01", plaintext_digest=digest)

    stored = tuple(root.iterdir())
    assert len(stored) == 2
    assert all(os.stat(path).st_mode & 0o077 == 0 for path in stored)
    assert all(content not in path.read_bytes() for path in stored)

    reopened = LocalEncryptedFixtureVault(
        root,
        key_ref="fixture-key-01",
        key_encryption_key=key,
        cipher=AuthenticatedTestCipher(),
    )
    assert reopened.open(
        receipt.vault_ref, fixture_ref="case-01", plaintext_digest=digest
    ) == content
    assert reopened.seal(
        content, fixture_ref="case-01", plaintext_digest=digest
    ) == receipt


def test_encrypted_vault_fails_closed_on_tamper_and_wrong_withdrawal_binding(tmp_path):
    root = tmp_path / "vault"
    root.mkdir(mode=0o700)
    content = _content()
    digest = _digest(content)
    vault = LocalEncryptedFixtureVault(
        root,
        key_ref="fixture-key-01",
        key_encryption_key=b"k" * 32,
        cipher=AuthenticatedTestCipher(),
    )
    receipt = vault.seal(content, fixture_ref="case-01", plaintext_digest=digest)

    with pytest.raises(FixtureValidationError):
        vault.withdraw(receipt.vault_ref, fixture_ref="case-02")
    assert len(tuple(root.iterdir())) == 2

    ciphertext = next(path for path in root.iterdir() if path.suffix == ".enc")
    envelope = bytearray(ciphertext.read_bytes())
    envelope[-2] ^= 1
    ciphertext.write_bytes(envelope)
    with pytest.raises(FixtureValidationError):
        vault.open(
            receipt.vault_ref, fixture_ref="case-01", plaintext_digest=digest
        )
