"""Local grant verification backed by an append-only revocation ledger.

The browser may carry a signed capability after explicit local step-up, but it
never receives issuer custody.  HTTP adapters inject this verifier and a
session-bound expectation; they do not scan arbitrary paths or accept a caller-
supplied revocation list.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from .authority import (
    GrantExpectation,
    IssuerProfile,
    VerifiedGrant,
    authorize_grant,
)
from .schemas import canonical_json, canonical_loads


_REVOCATION_ID = re.compile(r"^revocation_[0-9a-f]{64}$")


class AuthorityServiceError(RuntimeError):
    """Fail-closed local authority persistence or custody failure."""


def load_issuer_profile(path: Path) -> IssuerProfile:
    payload = _read_protected_file(path, expected_mode=0o600)
    try:
        decoded = canonical_loads(payload)
    except ValueError as exc:
        raise AuthorityServiceError("issuer profile is not canonical") from exc
    if type(decoded) is not dict or canonical_json(decoded) != payload:
        raise AuthorityServiceError("issuer profile is not an exact canonical object")
    try:
        return IssuerProfile.from_record(decoded)
    except ValueError as exc:
        raise AuthorityServiceError("issuer profile is invalid") from exc


class RevocationFileLedger:
    """A current-owner, mode-0700 directory of immutable signed envelopes."""

    def __init__(self, directory: Path) -> None:
        if not isinstance(directory, Path) or not directory.is_absolute():
            raise AuthorityServiceError("revocation ledger path must be absolute")
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise AuthorityServiceError("revocation ledger is unavailable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AuthorityServiceError("revocation ledger custody must be current-owner 0700")
        self.directory = directory

    def append(self, envelope: Mapping[str, Any]) -> str:
        encoded = canonical_json(dict(envelope))
        revocation_id = self._identity(envelope)
        target = self.directory / f"{revocation_id}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(target, flags, 0o600)
        except FileExistsError:
            existing = _read_protected_file(target, expected_mode=0o600)
            if existing != encoded:
                raise AuthorityServiceError("revocation identity already has different bytes")
            return revocation_id
        except OSError as exc:
            raise AuthorityServiceError("revocation could not be appended") from exc
        try:
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise AuthorityServiceError("revocation append was incomplete")
                remaining = remaining[written:]
            os.fsync(descriptor)
        except BaseException:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        directory_fd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return revocation_id

    def load(self) -> tuple[dict[str, Any], ...]:
        result: list[dict[str, Any]] = []
        try:
            paths = sorted(self.directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise AuthorityServiceError("revocation ledger cannot be enumerated") from exc
        for path in paths:
            if not path.name.endswith(".json"):
                raise AuthorityServiceError("revocation ledger contains an unknown entry")
            stem = path.name.removesuffix(".json")
            if _REVOCATION_ID.fullmatch(stem) is None:
                raise AuthorityServiceError("revocation ledger entry identity is invalid")
            encoded = _read_protected_file(path, expected_mode=0o600)
            try:
                decoded = canonical_loads(encoded)
            except ValueError as exc:
                raise AuthorityServiceError("revocation ledger entry is not canonical") from exc
            if type(decoded) is not dict or canonical_json(decoded) != encoded:
                raise AuthorityServiceError("revocation ledger entry is not an exact object")
            if self._identity(decoded) != stem:
                raise AuthorityServiceError("revocation filename does not match its identity")
            result.append(decoded)
        return tuple(result)

    @staticmethod
    def _identity(envelope: Mapping[str, Any]) -> str:
        payload = envelope.get("payload") if isinstance(envelope, Mapping) else None
        value = payload.get("revocation_id") if isinstance(payload, Mapping) else None
        if type(value) is not str or _REVOCATION_ID.fullmatch(value) is None:
            raise AuthorityServiceError("signed revocation identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class LocalGrantVerifier:
    secret_path: Path
    issuer_profile_path: Path
    revocations: RevocationFileLedger

    def authorize(
        self,
        envelope: Mapping[str, Any],
        expectation: GrantExpectation,
        *,
        now: datetime,
    ) -> VerifiedGrant:
        profile = load_issuer_profile(self.issuer_profile_path)
        try:
            return authorize_grant(
                envelope,
                self.secret_path,
                profile,
                expectation,
                now=now,
                revocations=self.revocations.load(),
            )
        except AuthorityServiceError:
            raise
        except Exception as exc:
            raise AuthorityServiceError("grant verification was denied") from exc


def _read_protected_file(path: Path, *, expected_mode: int) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise AuthorityServiceError("authority path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AuthorityServiceError("authority file is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        raise AuthorityServiceError("authority file custody is invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AuthorityServiceError("authority file cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise AuthorityServiceError("authority file custody changed while opening")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 4_194_304:
                raise AuthorityServiceError("authority file exceeds its fixed bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


__all__ = [
    "AuthorityServiceError",
    "LocalGrantVerifier",
    "RevocationFileLedger",
    "load_issuer_profile",
]
