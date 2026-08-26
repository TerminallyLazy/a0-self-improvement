"""Envelope encryption primitives for the v3 Privacy Quarantine.

The normal runtime must never import this module.  Migration authority callers
inject both the authenticated cipher and key-custody boundary; plaintext is
accepted and returned only as bytes and is never staged on disk here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
from typing import Protocol, runtime_checkable

from .schemas import canonical_json, canonical_loads


QUARANTINE_ENVELOPE_SCHEMA = "a0.privacy-quarantine-envelope.v1"
WRAPPED_KEY_ENVELOPE_SCHEMA = "a0.privacy-quarantine-wrapped-key.v1"
AES_256_GCM = "AES-256-GCM"
_PAYLOAD_AAD_DOMAIN = b"a0.self-improvement.quarantine.payload.v1\x00"
_DEK_WRAP_AAD_DOMAIN = b"a0.self-improvement.quarantine.dek-wrap.v1\x00"
_PLAINTEXT_DIGEST_DOMAIN = b"a0.self-improvement.quarantine.plaintext.v1\x00"
_WRAPPED_KEY_DIGEST_DOMAIN = b"a0.self-improvement.quarantine.wrapped-key.v1\x00"
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class QuarantineError(RuntimeError):
    """Base class for quarantine failures."""


class QuarantineUnavailable(QuarantineError):
    """Raised when an authenticated encryption implementation is unavailable."""


class QuarantineValidationError(QuarantineError):
    """Raised when an envelope or ledger resolution is structurally invalid."""


class QuarantineIntegrityError(QuarantineError):
    """Raised when authenticated bytes, keys, or plaintext digests do not match."""


@runtime_checkable
class QuarantineCipher(Protocol):
    """Authenticated cipher contract used for payload and DEK encryption."""

    algorithm: str
    key_size: int
    nonce_size: int

    def generate_key(self) -> bytes: ...

    def generate_nonce(self) -> bytes: ...

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class WrappedDEK:
    algorithm: str
    key_ref: str
    nonce: bytes
    ciphertext: bytes


@runtime_checkable
class KeyCustody(Protocol):
    """Custody contract; implementations must not expose their wrapping key."""

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDEK: ...

    def unwrap_dek(self, wrapped: WrappedDEK, *, aad: bytes) -> bytes: ...


class AES256GCMCipher:
    """Production AES-256-GCM primitive with a lazy optional dependency.

    Importing this module remains safe in the standalone plugin.  The first
    cryptographic operation fails closed if ``cryptography`` is unavailable.
    """

    algorithm = AES_256_GCM
    key_size = 32
    nonce_size = 12

    @staticmethod
    def _implementation():
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except (ImportError, ModuleNotFoundError) as exc:
            raise QuarantineUnavailable(
                "AES-256-GCM is unavailable; install an approved cryptography runtime"
            ) from exc
        return AESGCM

    def generate_key(self) -> bytes:
        self._implementation()
        return os.urandom(self.key_size)

    def generate_nonce(self) -> bytes:
        self._implementation()
        return os.urandom(self.nonce_size)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        _require_bytes(key, "key", exact_length=self.key_size)
        _require_bytes(nonce, "nonce", exact_length=self.nonce_size)
        _require_bytes(plaintext, "plaintext")
        _require_bytes(aad, "aad")
        return self._implementation()(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        _require_bytes(key, "key", exact_length=self.key_size)
        _require_bytes(nonce, "nonce", exact_length=self.nonce_size)
        _require_bytes(ciphertext, "ciphertext")
        _require_bytes(aad, "aad")
        try:
            return self._implementation()(key).decrypt(nonce, ciphertext, aad)
        except QuarantineUnavailable:
            raise
        except Exception as exc:
            raise QuarantineIntegrityError("AES-GCM authentication failed") from exc


class AES256GCMKeyCustody:
    """AES-GCM DEK wrapping adapter for a key supplied by approved custody.

    The caller owns acquisition and lifetime of the 32-byte key-encryption key;
    it is deliberately never serialized into a quarantine envelope.
    """

    def __init__(self, key_ref: str, key_encryption_key: bytes, cipher: QuarantineCipher | None = None):
        self._key_ref = _bounded_ref(key_ref, "key_ref")
        self._cipher = cipher or AES256GCMCipher()
        self._key = _require_bytes(
            key_encryption_key, "key_encryption_key", exact_length=self._cipher.key_size
        )

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDEK:
        _require_bytes(dek, "dek", exact_length=self._cipher.key_size)
        nonce = self._cipher.generate_nonce()
        return WrappedDEK(
            algorithm=self._cipher.algorithm,
            key_ref=self._key_ref,
            nonce=nonce,
            ciphertext=self._cipher.encrypt(self._key, nonce, dek, aad),
        )

    def unwrap_dek(self, wrapped: WrappedDEK, *, aad: bytes) -> bytes:
        if wrapped.algorithm != self._cipher.algorithm or wrapped.key_ref != self._key_ref:
            raise QuarantineIntegrityError("wrapped DEK custody identity does not match")
        return self._cipher.decrypt(self._key, wrapped.nonce, wrapped.ciphertext, aad)


@dataclass(frozen=True, slots=True)
class EncryptedQuarantine:
    """Physically separable ciphertext and wrapped-key envelopes."""

    ciphertext_envelope: bytes
    wrapped_key_envelope: bytes


def encrypt_quarantine(
    plaintext: bytes,
    *,
    quarantine_ref: str,
    revision: int,
    cipher: QuarantineCipher,
    custody: KeyCustody,
) -> EncryptedQuarantine:
    """Return separate canonical ciphertext and wrapped-key bytes."""

    plaintext = _require_bytes(plaintext, "plaintext")
    metadata = _metadata(
        quarantine_ref=quarantine_ref,
        revision=revision,
        cipher_algorithm=cipher.algorithm,
        plaintext_size=len(plaintext),
        plaintext_digest=_plaintext_digest(plaintext),
    )
    metadata_bytes = canonical_json(metadata)
    dek = _require_bytes(cipher.generate_key(), "generated DEK", exact_length=cipher.key_size)
    payload_nonce = _require_bytes(
        cipher.generate_nonce(), "generated payload nonce", exact_length=cipher.nonce_size
    )
    payload_ciphertext = cipher.encrypt(
        dek, payload_nonce, plaintext, _PAYLOAD_AAD_DOMAIN + metadata_bytes
    )
    wrapped = custody.wrap_dek(dek, aad=_DEK_WRAP_AAD_DOMAIN + metadata_bytes)
    wrapped_key_envelope = canonical_json(
        {
            **metadata,
            "schema": WRAPPED_KEY_ENVELOPE_SCHEMA,
            "algorithm": _bounded_ref(wrapped.algorithm, "wrapped_dek.algorithm"),
            "key_ref": _bounded_ref(wrapped.key_ref, "wrapped_dek.key_ref"),
            "nonce": _b64encode(_require_bytes(wrapped.nonce, "wrapped_dek.nonce")),
            "ciphertext": _b64encode(
                _require_bytes(wrapped.ciphertext, "wrapped_dek.ciphertext")
            ),
        }
    )
    ciphertext_envelope = canonical_json({
        **metadata,
        "payload_nonce": _b64encode(payload_nonce),
        "payload_ciphertext": _b64encode(payload_ciphertext),
        "wrapped_key_digest": _wrapped_key_digest(wrapped_key_envelope),
    })
    return EncryptedQuarantine(
        ciphertext_envelope=ciphertext_envelope,
        wrapped_key_envelope=wrapped_key_envelope,
    )


def decrypt_quarantine(
    encrypted: EncryptedQuarantine,
    *,
    cipher: QuarantineCipher,
    custody: KeyCustody,
) -> bytes:
    """Authenticate both files, decrypt, and digest-check the plaintext."""

    if type(encrypted) is not EncryptedQuarantine:
        raise QuarantineValidationError("both quarantine envelopes are required")
    envelope = _parse_ciphertext_envelope(encrypted.ciphertext_envelope)
    wrapped_record = _parse_wrapped_key_envelope(encrypted.wrapped_key_envelope)
    if _wrapped_key_digest(encrypted.wrapped_key_envelope) != envelope["wrapped_key_digest"]:
        raise QuarantineIntegrityError("wrapped-key envelope digest does not match")
    if envelope["cipher_algorithm"] != cipher.algorithm:
        raise QuarantineValidationError("quarantine cipher algorithm does not match")
    metadata = {key: envelope[key] for key in _METADATA_FIELDS}
    wrapped_metadata = {key: wrapped_record[key] for key in _METADATA_FIELDS}
    wrapped_metadata["schema"] = QUARANTINE_ENVELOPE_SCHEMA
    if wrapped_metadata != metadata:
        raise QuarantineIntegrityError("ciphertext and wrapped-key identities do not match")
    metadata_bytes = canonical_json(metadata)
    wrapped = WrappedDEK(
        algorithm=wrapped_record["algorithm"],
        key_ref=wrapped_record["key_ref"],
        nonce=_b64decode(wrapped_record["nonce"], "wrapped_key.nonce"),
        ciphertext=_b64decode(wrapped_record["ciphertext"], "wrapped_key.ciphertext"),
    )
    try:
        dek = custody.unwrap_dek(wrapped, aad=_DEK_WRAP_AAD_DOMAIN + metadata_bytes)
        _require_bytes(dek, "unwrapped DEK", exact_length=cipher.key_size)
        plaintext = cipher.decrypt(
            dek,
            _b64decode(envelope["payload_nonce"], "payload_nonce"),
            _b64decode(envelope["payload_ciphertext"], "payload_ciphertext"),
            _PAYLOAD_AAD_DOMAIN + metadata_bytes,
        )
    except QuarantineUnavailable:
        raise
    except QuarantineIntegrityError:
        raise
    except Exception as exc:
        raise QuarantineIntegrityError("quarantine authentication failed") from exc
    if len(plaintext) != envelope["plaintext_size"]:
        raise QuarantineIntegrityError("quarantine plaintext size does not match")
    if _plaintext_digest(plaintext) != envelope["plaintext_digest"]:
        raise QuarantineIntegrityError("quarantine plaintext digest does not match")
    return plaintext


def exact_ciphertext_export(
    encrypted: EncryptedQuarantine,
    *,
    cipher: QuarantineCipher,
    custody: KeyCustody,
) -> EncryptedQuarantine:
    """Authenticate and return both exact retained encrypted files unchanged.

    Export deliberately requires custody access.  Missing keys or tampered
    bytes therefore block instead of producing an unverifiable archive.
    """

    decrypt_quarantine(encrypted, cipher=cipher, custody=custody)
    return EncryptedQuarantine(
        ciphertext_envelope=bytes(encrypted.ciphertext_envelope),
        wrapped_key_envelope=bytes(encrypted.wrapped_key_envelope),
    )


@dataclass(frozen=True, slots=True)
class RetainedQuarantine:
    quarantine_ref: str
    revision: int
    ciphertext_path: Path
    wrapped_key_path: Path
    ciphertext_digest: str


class QuarantineLedger(Protocol):
    def resolve_retained(self, quarantine_ref: str, revision: int) -> RetainedQuarantine: ...


@dataclass(frozen=True, slots=True)
class CryptographicDeletionPlan:
    quarantine_ref: str
    revision: int
    ciphertext_path: Path
    wrapped_key_path: Path
    ciphertext_digest: str


def plan_cryptographic_deletion(
    quarantine_ref: str,
    revision: int,
    *,
    ledger: QuarantineLedger,
) -> CryptographicDeletionPlan:
    """Resolve deletion targets solely through the authoritative ledger.

    There is intentionally no caller-supplied path parameter.  Execution of
    the irreversible deletion belongs to the separately authorized coordinator.
    """

    expected_ref = _bounded_ref(quarantine_ref, "quarantine_ref")
    expected_revision = _positive_revision(revision)
    retained = ledger.resolve_retained(expected_ref, expected_revision)
    if retained.quarantine_ref != expected_ref or retained.revision != expected_revision:
        raise QuarantineValidationError("ledger returned a different quarantine identity")
    ciphertext_path = _exact_absolute_path(retained.ciphertext_path, "ciphertext_path")
    wrapped_key_path = _exact_absolute_path(retained.wrapped_key_path, "wrapped_key_path")
    if ciphertext_path == wrapped_key_path:
        raise QuarantineValidationError("ciphertext and wrapped-key targets must be distinct")
    if type(retained.ciphertext_digest) is not str or not _HEX_DIGEST.fullmatch(
        retained.ciphertext_digest
    ):
        raise QuarantineValidationError("ledger ciphertext digest is invalid")
    return CryptographicDeletionPlan(
        quarantine_ref=expected_ref,
        revision=expected_revision,
        ciphertext_path=ciphertext_path,
        wrapped_key_path=wrapped_key_path,
        ciphertext_digest=retained.ciphertext_digest,
    )


_METADATA_FIELDS = (
    "schema",
    "quarantine_ref",
    "revision",
    "cipher_algorithm",
    "plaintext_size",
    "plaintext_digest",
)
_CIPHERTEXT_ENVELOPE_FIELDS = frozenset(
    (*_METADATA_FIELDS, "payload_nonce", "payload_ciphertext", "wrapped_key_digest")
)
_WRAPPED_KEY_ENVELOPE_FIELDS = frozenset(
    (*_METADATA_FIELDS, "algorithm", "key_ref", "nonce", "ciphertext")
)


def _metadata(
    *,
    quarantine_ref: str,
    revision: int,
    cipher_algorithm: str,
    plaintext_size: int,
    plaintext_digest: str,
) -> dict[str, object]:
    if type(plaintext_size) is not int or plaintext_size < 0:
        raise QuarantineValidationError("plaintext_size must be a non-negative integer")
    if type(plaintext_digest) is not str or not _HEX_DIGEST.fullmatch(plaintext_digest):
        raise QuarantineValidationError("plaintext_digest is invalid")
    return {
        "schema": QUARANTINE_ENVELOPE_SCHEMA,
        "quarantine_ref": _bounded_ref(quarantine_ref, "quarantine_ref"),
        "revision": _positive_revision(revision),
        "cipher_algorithm": _bounded_ref(cipher_algorithm, "cipher_algorithm"),
        "plaintext_size": plaintext_size,
        "plaintext_digest": plaintext_digest,
    }


def _parse_ciphertext_envelope(envelope_bytes: bytes) -> dict[str, object]:
    try:
        record = canonical_loads(_require_bytes(envelope_bytes, "envelope_bytes"))
    except Exception as exc:
        raise QuarantineValidationError("quarantine envelope is not canonical JSON") from exc
    if type(record) is not dict or record.keys() != _CIPHERTEXT_ENVELOPE_FIELDS:
        raise QuarantineValidationError("ciphertext envelope fields do not match schema")
    metadata = _metadata(
        quarantine_ref=record["quarantine_ref"],
        revision=record["revision"],
        cipher_algorithm=record["cipher_algorithm"],
        plaintext_size=record["plaintext_size"],
        plaintext_digest=record["plaintext_digest"],
    )
    if record["schema"] != metadata["schema"]:
        raise QuarantineValidationError("unsupported quarantine envelope schema")
    _b64decode(record["payload_nonce"], "payload_nonce")
    _b64decode(record["payload_ciphertext"], "payload_ciphertext")
    if type(record["wrapped_key_digest"]) is not str or not _HEX_DIGEST.fullmatch(
        record["wrapped_key_digest"]
    ):
        raise QuarantineValidationError("wrapped_key_digest is invalid")
    return record


def _parse_wrapped_key_envelope(envelope_bytes: bytes) -> dict[str, object]:
    try:
        record = canonical_loads(_require_bytes(envelope_bytes, "wrapped_key_envelope"))
    except Exception as exc:
        raise QuarantineValidationError("wrapped-key envelope is not canonical JSON") from exc
    if type(record) is not dict or record.keys() != _WRAPPED_KEY_ENVELOPE_FIELDS:
        raise QuarantineValidationError("wrapped-key envelope fields do not match schema")
    if record["schema"] != WRAPPED_KEY_ENVELOPE_SCHEMA:
        raise QuarantineValidationError("unsupported wrapped-key envelope schema")
    metadata = _metadata(
        quarantine_ref=record["quarantine_ref"],
        revision=record["revision"],
        cipher_algorithm=record["cipher_algorithm"],
        plaintext_size=record["plaintext_size"],
        plaintext_digest=record["plaintext_digest"],
    )
    if record["schema"] == metadata["schema"]:
        raise QuarantineValidationError("wrapped-key envelope used ciphertext schema")
    _bounded_ref(record["algorithm"], "wrapped_key.algorithm")
    _bounded_ref(record["key_ref"], "wrapped_key.key_ref")
    _b64decode(record["nonce"], "wrapped_key.nonce")
    _b64decode(record["ciphertext"], "wrapped_key.ciphertext")
    return record


def _plaintext_digest(plaintext: bytes) -> str:
    return hashlib.sha256(_PLAINTEXT_DIGEST_DOMAIN + plaintext).hexdigest()


def _wrapped_key_digest(envelope_bytes: bytes) -> str:
    return hashlib.sha256(_WRAPPED_KEY_DIGEST_DOMAIN + envelope_bytes).hexdigest()


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: object, field: str) -> bytes:
    if type(value) is not str or not value:
        raise QuarantineValidationError(f"{field} must be non-empty base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise QuarantineValidationError(f"{field} is invalid base64") from exc
    if _b64encode(decoded) != value:
        raise QuarantineValidationError(f"{field} is not canonical base64")
    return decoded


def _require_bytes(value: object, field: str, *, exact_length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise QuarantineValidationError(f"{field} must be bytes")
    if exact_length is not None and len(value) != exact_length:
        raise QuarantineValidationError(f"{field} must contain exactly {exact_length} bytes")
    return value


def _bounded_ref(value: object, field: str) -> str:
    if type(value) is not str or _OPAQUE_REF.fullmatch(value) is None:
        raise QuarantineValidationError(f"{field} is not a bounded reference")
    return value


def _positive_revision(value: object) -> int:
    if type(value) is not int or value < 1:
        raise QuarantineValidationError("revision must be a positive integer")
    return value


def _exact_absolute_path(value: object, field: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        raise QuarantineValidationError(f"ledger {field} must be an exact absolute path")
    return value
