"""Crash-safe Store Authority Manifest selection for v3 cutover."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterator

from .schemas import canonical_json, canonical_loads


STORE_AUTHORITY_MANIFEST_SCHEMA = "a0.store-authority-manifest.v1"
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BOUNDED_IDENTITY = re.compile(r"^[^\x00\r\n]{1,2048}$")
_FIELDS = frozenset(
    {
        "schema",
        "revision",
        "generation_ref",
        "generation_path_identity",
        "initial_digest",
        "migration_receipt",
        "migration_receipt_digest",
    }
)
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024


class StoreAuthorityError(RuntimeError):
    """Base class for manifest authority failures."""


class StoreAuthorityCorrupt(StoreAuthorityError):
    """Raised when authority bytes or filesystem custody are invalid."""


class StaleStoreAuthorityRevision(StoreAuthorityError):
    """Raised when compare-and-swap observes a different authority revision."""


@dataclass(frozen=True, slots=True)
class StoreAuthorityManifest:
    revision: int
    generation_ref: str
    generation_path_identity: str
    initial_digest: str
    migration_receipt: bytes
    migration_receipt_digest: str
    schema: str = STORE_AUTHORITY_MANIFEST_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        revision: int,
        generation_ref: str,
        generation_path_identity: str,
        initial_digest: str,
        migration_receipt: bytes,
    ) -> "StoreAuthorityManifest":
        receipt = _exact_bytes(migration_receipt, "migration_receipt", allow_empty=False)
        return cls(
            revision=_revision(revision),
            generation_ref=_identity(generation_ref, "generation_ref"),
            generation_path_identity=_identity(
                generation_path_identity, "generation_path_identity"
            ),
            initial_digest=_digest(initial_digest, "initial_digest"),
            migration_receipt=receipt,
            migration_receipt_digest=hashlib.sha256(receipt).hexdigest(),
        )

    def to_record(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "revision": self.revision,
            "generation_ref": self.generation_ref,
            "generation_path_identity": self.generation_path_identity,
            "initial_digest": self.initial_digest,
            "migration_receipt": base64.b64encode(self.migration_receipt).decode("ascii"),
            "migration_receipt_digest": self.migration_receipt_digest,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_record())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "StoreAuthorityManifest":
        try:
            record = canonical_loads(_exact_bytes(raw, "manifest bytes", allow_empty=False))
        except Exception as exc:
            raise StoreAuthorityCorrupt("manifest is not canonical JSON") from exc
        if type(record) is not dict or record.keys() != _FIELDS:
            raise StoreAuthorityCorrupt("manifest fields do not match the closed schema")
        if record["schema"] != STORE_AUTHORITY_MANIFEST_SCHEMA:
            raise StoreAuthorityCorrupt("unsupported manifest schema")
        try:
            receipt_text = record["migration_receipt"]
            if type(receipt_text) is not str or not receipt_text:
                raise ValueError("receipt is not non-empty base64")
            receipt = base64.b64decode(receipt_text, validate=True)
            if base64.b64encode(receipt).decode("ascii") != receipt_text:
                raise ValueError("receipt base64 is not canonical")
            result = cls(
                revision=_revision(record["revision"]),
                generation_ref=_identity(record["generation_ref"], "generation_ref"),
                generation_path_identity=_identity(
                    record["generation_path_identity"], "generation_path_identity"
                ),
                initial_digest=_digest(record["initial_digest"], "initial_digest"),
                migration_receipt=receipt,
                migration_receipt_digest=_digest(
                    record["migration_receipt_digest"], "migration_receipt_digest"
                ),
            )
        except (TypeError, ValueError, StoreAuthorityCorrupt) as exc:
            raise StoreAuthorityCorrupt("manifest contains invalid field values") from exc
        if hashlib.sha256(receipt).hexdigest() != result.migration_receipt_digest:
            raise StoreAuthorityCorrupt("migration receipt digest does not match exact bytes")
        if result.canonical_bytes() != raw:
            raise StoreAuthorityCorrupt("manifest bytes do not round-trip canonically")
        return result


@dataclass(frozen=True, slots=True)
class ManifestCommit:
    manifest: StoreAuthorityManifest
    recovered_lost_ack: bool


class StoreAuthorityManifestStore:
    """One local manifest guarded by an OS lock and revision CAS."""

    def __init__(self, path: Path):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("manifest path must be an exact absolute Path")
        self.path = path
        self.lock_path = path.with_name(path.name + ".lock")

    def read(self) -> StoreAuthorityManifest | None:
        """Read authority and verify its exact selected generation."""

        manifest = self._read_manifest_file()
        if manifest is None:
            return None
        _inspect_generation(
            Path(manifest.generation_path_identity), calculate_initial_digest=False
        )
        return manifest

    def resolve_selected_generation(self) -> Path | None:
        """Resolve only the verified authoritative generation, with no fallback."""

        manifest = self.read()
        return None if manifest is None else Path(manifest.generation_path_identity)

    def _read_manifest_file(self) -> StoreAuthorityManifest | None:
        """Return missing only for true manifest absence."""

        try:
            descriptor = os.open(self.path, os.O_RDONLY | _no_follow_flag())
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StoreAuthorityCorrupt("manifest cannot be opened safely") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise StoreAuthorityCorrupt("manifest is not a regular file")
            if info.st_uid != os.geteuid():
                raise StoreAuthorityCorrupt("manifest is not owned by the current user")
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise StoreAuthorityCorrupt("manifest mode must be exactly 0600")
            if info.st_size <= 0 or info.st_size > _MAX_MANIFEST_BYTES:
                raise StoreAuthorityCorrupt("manifest size is outside the admitted bounds")
            raw = _read_all(descriptor, _MAX_MANIFEST_BYTES)
        finally:
            os.close(descriptor)
        return StoreAuthorityManifest.from_bytes(raw)

    def compare_and_swap(
        self,
        *,
        expected_revision: int,
        generation_ref: str,
        generation_path: Path,
        migration_receipt: bytes,
    ) -> ManifestCommit:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._exclusive_lock():
            current = self.read()
            current_revision = 0 if current is None else current.revision
            if current is not None and current_revision == expected_revision + 1:
                resolved_generation, _ = _inspect_generation(
                    generation_path, calculate_initial_digest=False
                )
                exact_receipt = _exact_bytes(
                    migration_receipt, "migration_receipt", allow_empty=False
                )
                if (
                    current.generation_ref == _identity(generation_ref, "generation_ref")
                    and current.generation_path_identity == str(resolved_generation)
                    and current.migration_receipt == exact_receipt
                ):
                    return ManifestCommit(manifest=current, recovered_lost_ack=True)
            if current_revision != expected_revision:
                raise StaleStoreAuthorityRevision(
                    f"expected authority revision {expected_revision}, observed {current_revision}"
                )
            resolved_generation, observed_digest = _inspect_generation(
                generation_path, calculate_initial_digest=True
            )
            if observed_digest is None:  # defensive: cutover must bind exact closed bytes
                raise StoreAuthorityCorrupt("cutover did not calculate an initial digest")
            candidate = StoreAuthorityManifest.create(
                revision=expected_revision + 1,
                generation_ref=generation_ref,
                generation_path_identity=str(resolved_generation),
                initial_digest=observed_digest,
                migration_receipt=migration_receipt,
            )
            self._atomic_replace(candidate.canonical_bytes())
            return ManifestCommit(manifest=candidate, recovered_lost_ack=False)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        flags = os.O_CREAT | os.O_RDWR | _no_follow_flag()
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            raise StoreAuthorityCorrupt("manifest lock cannot be opened safely") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise StoreAuthorityCorrupt("manifest lock must be a regular 0600 file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _atomic_replace(self, raw: bytes) -> None:
        descriptor, temp_name = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
        )
        temp_path = Path(temp_name)
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, raw)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temp_path, self.path)
            directory_descriptor = os.open(
                self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def _read_all(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise StoreAuthorityCorrupt("manifest exceeds the maximum admitted size")


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise StoreAuthorityError("manifest write made no progress")
        view = view[written:]


def _no_follow_flag() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _inspect_generation(
    path: Path, *, calculate_initial_digest: bool
) -> tuple[Path, str | None]:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise StoreAuthorityCorrupt("generation path must be exact and absolute")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise StoreAuthorityCorrupt("selected generation is missing or unresolvable") from exc
    if resolved != path:
        raise StoreAuthorityCorrupt("generation path must already be fully resolved")
    try:
        descriptor = os.open(resolved, os.O_RDONLY | _no_follow_flag())
    except OSError as exc:
        raise StoreAuthorityCorrupt("selected generation cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StoreAuthorityCorrupt("selected generation is not a regular file")
        if before.st_uid != os.geteuid():
            raise StoreAuthorityCorrupt("selected generation is not owned by the current user")
        if stat.S_IMODE(before.st_mode) & 0o022:
            raise StoreAuthorityCorrupt("selected generation is writable outside current-user custody")
        digest = None
        after = before
        if calculate_initial_digest:
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise StoreAuthorityCorrupt("selected generation changed during verification")
        try:
            path_info = os.stat(resolved, follow_symlinks=False)
        except OSError as exc:
            raise StoreAuthorityCorrupt("selected generation disappeared during verification") from exc
        if (path_info.st_dev, path_info.st_ino) != (after.st_dev, after.st_ino):
            raise StoreAuthorityCorrupt("selected generation path changed during verification")
        return resolved, None if digest is None else digest.hexdigest()
    finally:
        os.close(descriptor)


def _exact_bytes(value: object, field: str, *, allow_empty: bool) -> bytes:
    if type(value) is not bytes or (not allow_empty and not value):
        raise StoreAuthorityCorrupt(f"{field} must be non-empty bytes")
    return value


def _revision(value: object) -> int:
    if type(value) is not int or value < 1:
        raise StoreAuthorityCorrupt("manifest revision must be a positive integer")
    return value


def _identity(value: object, field: str) -> str:
    if type(value) is not str or _BOUNDED_IDENTITY.fullmatch(value) is None:
        raise StoreAuthorityCorrupt(f"{field} is not a bounded exact identity")
    return value


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        raise StoreAuthorityCorrupt(f"{field} is not a lowercase SHA-256 digest")
    return value
