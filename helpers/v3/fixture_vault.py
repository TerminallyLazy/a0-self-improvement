"""Authenticated local encrypted custody for fixture plaintext."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from .fixtures import (
    FIXTURE_CONTENT_SCHEMA_ID,
    FixtureValidationError,
    FixtureVaultReceipt,
)
from .quarantine import (
    AES256GCMCipher,
    AES256GCMKeyCustody,
    EncryptedQuarantine,
    KeyCustody,
    QuarantineCipher,
    QuarantineError,
    decrypt_quarantine,
    encrypt_quarantine,
)
from .schemas import schema_digest, validate_digest


_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VAULT_REF = re.compile(r"^fixture-vault:([0-9a-f]{24}):([0-9a-f]{64})$")


class LocalEncryptedFixtureVault:
    """Filesystem fixture vault using the pinned AES-256-GCM custody seam.

    The caller supplies the wrapping key from its custody boundary.  Neither
    that key nor fixture plaintext is written to disk.  Only authenticated
    ciphertext and a separately wrapped data-encryption key are persisted.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        key_ref: str,
        key_encryption_key: bytes,
        cipher: QuarantineCipher | None = None,
        custody: KeyCustody | None = None,
    ) -> None:
        selected_root = Path(root)
        if not selected_root.is_absolute() or not selected_root.is_dir():
            raise FixtureValidationError("fixture vault root must be an existing directory")
        selected_root = selected_root.resolve(strict=True)
        mode = stat.S_IMODE(selected_root.stat().st_mode)
        if mode & 0o077:
            raise FixtureValidationError("fixture vault root permissions are not private")
        if type(key_ref) is not str or _REF.fullmatch(key_ref) is None:
            raise FixtureValidationError("fixture vault key_ref is not an opaque reference")
        selected_cipher = cipher or AES256GCMCipher()
        selected_custody = custody or AES256GCMKeyCustody(
            key_ref, key_encryption_key, cipher=selected_cipher
        )
        if not isinstance(selected_cipher, QuarantineCipher):
            raise FixtureValidationError("fixture vault cipher is unavailable")
        if not isinstance(selected_custody, KeyCustody):
            raise FixtureValidationError("fixture vault custody is unavailable")
        self._root = selected_root
        self._cipher = selected_cipher
        self._custody = selected_custody
        self._profile_ref = (
            "local-aes256gcm:"
            + hashlib.sha256(key_ref.encode("utf-8")).hexdigest()[:24]
        )

    def seal(
        self, content: bytes, *, fixture_ref: str, plaintext_digest: str
    ) -> FixtureVaultReceipt:
        content = _content_bytes(content)
        fixture = _fixture_ref(fixture_ref)
        digest = _fixture_digest(content, plaintext_digest)
        vault_ref = _vault_ref(fixture, digest)
        ciphertext_path, wrapped_path = self._paths(vault_ref)
        if ciphertext_path.exists() or wrapped_path.exists():
            if not (ciphertext_path.is_file() and wrapped_path.is_file()):
                raise FixtureValidationError("fixture vault custody pair is incomplete")
            return self._verified_receipt(
                vault_ref,
                fixture,
                digest,
                ciphertext_path,
                wrapped_path,
                expected_content=content,
            )
        try:
            encrypted = encrypt_quarantine(
                content,
                quarantine_ref=vault_ref,
                revision=1,
                cipher=self._cipher,
                custody=self._custody,
            )
            _write_exclusive(ciphertext_path, encrypted.ciphertext_envelope)
            try:
                _write_exclusive(wrapped_path, encrypted.wrapped_key_envelope)
            except BaseException:
                ciphertext_path.unlink(missing_ok=True)
                raise
            _sync_directory(self._root)
            return self._verified_receipt(
                vault_ref,
                fixture,
                digest,
                ciphertext_path,
                wrapped_path,
                expected_content=content,
            )
        except FixtureValidationError:
            raise
        except QuarantineError as exc:
            raise FixtureValidationError("fixture encryption failed closed") from exc
        except OSError as exc:
            raise FixtureValidationError("fixture ciphertext persistence failed") from exc

    def open(
        self, vault_ref: str, *, fixture_ref: str, plaintext_digest: str
    ) -> bytes:
        fixture = _fixture_ref(fixture_ref)
        digest = validate_digest(plaintext_digest, "plaintext_digest")
        _require_vault_binding(vault_ref, fixture, digest)
        ciphertext_path, wrapped_path = self._paths(vault_ref)
        try:
            encrypted = EncryptedQuarantine(
                _read_exact(ciphertext_path), _read_exact(wrapped_path)
            )
            content = decrypt_quarantine(
                encrypted, cipher=self._cipher, custody=self._custody
            )
        except QuarantineError as exc:
            raise FixtureValidationError("fixture ciphertext authentication failed") from exc
        except OSError as exc:
            raise FixtureValidationError("fixture ciphertext is unavailable") from exc
        _fixture_digest(content, digest)
        return content

    def withdraw(self, vault_ref: str, *, fixture_ref: str) -> None:
        fixture = _fixture_ref(fixture_ref)
        _require_vault_binding(vault_ref, fixture, None)
        ciphertext_path, wrapped_path = self._paths(vault_ref)
        try:
            ciphertext_path.unlink(missing_ok=True)
            wrapped_path.unlink(missing_ok=True)
            _sync_directory(self._root)
        except OSError as exc:
            raise FixtureValidationError("fixture vault cleanup failed") from exc

    def _verified_receipt(
        self,
        vault_ref: str,
        fixture_ref: str,
        plaintext_digest: str,
        ciphertext_path: Path,
        wrapped_path: Path,
        *,
        expected_content: bytes,
    ) -> FixtureVaultReceipt:
        try:
            ciphertext = _read_exact(ciphertext_path)
            wrapped = _read_exact(wrapped_path)
            actual = decrypt_quarantine(
                EncryptedQuarantine(ciphertext, wrapped),
                cipher=self._cipher,
                custody=self._custody,
            )
        except QuarantineError as exc:
            raise FixtureValidationError("fixture ciphertext authentication failed") from exc
        except OSError as exc:
            raise FixtureValidationError("fixture ciphertext is unavailable") from exc
        if actual != expected_content:
            raise FixtureValidationError("fixture vault identity has different plaintext")
        _require_vault_binding(vault_ref, fixture_ref, plaintext_digest)
        return FixtureVaultReceipt(
            vault_ref=vault_ref,
            encryption_profile_ref=self._profile_ref,
            plaintext_digest=plaintext_digest,
            ciphertext_digest=hashlib.sha256(
                b"a0.fixture-vault.ciphertext.v1\0" + ciphertext + b"\0" + wrapped
            ).hexdigest(),
            plaintext_size=len(actual),
        )

    def _paths(self, vault_ref: str) -> tuple[Path, Path]:
        if _VAULT_REF.fullmatch(vault_ref) is None:
            raise FixtureValidationError("fixture vault_ref is invalid")
        stem = vault_ref.replace(":", "_")
        return self._root / f"{stem}.enc", self._root / f"{stem}.key"


def _content_bytes(value: bytes) -> bytes:
    if type(value) is not bytes or not value:
        raise FixtureValidationError("fixture content must be non-empty bytes")
    return value


def _fixture_ref(value: str) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise FixtureValidationError("fixture_ref is not an opaque reference")
    return value


def _fixture_digest(content: bytes, expected: str) -> str:
    digest = validate_digest(expected, "plaintext_digest")
    actual = schema_digest("fixture-content", FIXTURE_CONTENT_SCHEMA_ID, content)
    if actual != digest:
        raise FixtureValidationError("fixture plaintext digest does not match")
    return digest


def _vault_ref(fixture_ref: str, plaintext_digest: str) -> str:
    fixture_hash = hashlib.sha256(fixture_ref.encode("utf-8")).hexdigest()[:24]
    return f"fixture-vault:{fixture_hash}:{plaintext_digest}"


def _require_vault_binding(
    vault_ref: str, fixture_ref: str, plaintext_digest: str | None
) -> None:
    match = _VAULT_REF.fullmatch(vault_ref) if type(vault_ref) is str else None
    fixture_hash = hashlib.sha256(fixture_ref.encode("utf-8")).hexdigest()[:24]
    if match is None or match.group(1) != fixture_hash:
        raise FixtureValidationError("fixture vault identity does not match fixture_ref")
    if plaintext_digest is not None and match.group(2) != plaintext_digest:
        raise FixtureValidationError("fixture vault identity does not match plaintext")


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _read_exact(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise FixtureValidationError("fixture ciphertext custody is not private")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["LocalEncryptedFixtureVault"]
