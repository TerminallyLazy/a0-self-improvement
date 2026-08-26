"""Fail-closed production assembly for governed fixture commands.

Fixture plaintext is resolved only from an explicitly configured private
content-session directory.  The signed HTTP command carries opaque session and
content handles; neither fixture plaintext nor a filesystem path crosses the
HTTP or safe-store boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from .authority import (
    AuthorityDenied,
    AuthorityValidationError,
    GrantExpectation,
    authorize_grant,
)
from .authority_service import RevocationFileLedger, load_issuer_profile
from .fixture_command_adapter import (
    AuthorityRevalidator,
    FixtureCommandAdapter,
    FixtureLedgerUnavailable,
)
from .fixture_repository import (
    RepositoryFixtureCommandLedger,
    RepositoryFixtureResolvers,
)
from .fixture_vault import LocalEncryptedFixtureVault
from .fixtures import FixtureAuthority, GrantAuthority, PARTITIONS
from .quarantine import KeyCustody, QuarantineCipher
from .repository import V3Repository
from .schemas import canonical_json, canonical_loads, validate_digest


FIXTURE_RUNTIME_PROFILE_ENV = "DSPY_RLM_FIXTURE_RUNTIME_PROFILE"
FIXTURE_RUNTIME_PROFILE_SCHEMA = "a0.fixture-runtime-profile.v1"
FIXTURE_CONTENT_SESSION_SCHEMA = "a0.fixture-content-session.v1"

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_PROFILE_FIELDS = {
    "schema",
    "content_sessions_root",
    "vault_root",
    "vault_key_ref",
    "vault_key_file",
    "partition_secret_file",
    "partition_policy_ref",
    "partition_weights",
    "key_epoch",
    "record_maximum",
    "event_maximum",
    "maximum_content_bytes",
}
_SESSION_FIELDS = {
    "schema",
    "content_session_id",
    "authority_envelope",
    "content_handles",
}
_CONTENT_FIELDS = {"content_handle", "content_digest", "content_size"}


@dataclass(frozen=True, slots=True)
class FixtureRuntimeProfile:
    content_sessions_root: Path
    vault_root: Path
    vault_key_ref: str
    vault_key_file: Path
    partition_secret_file: Path
    partition_policy_ref: str
    partition_weights: dict[str, int]
    key_epoch: str
    record_maximum: int
    event_maximum: int
    maximum_content_bytes: int


class PrivateContentSessionStore:
    """Resolve exact signed sessions and their separately stored plaintext."""

    def __init__(
        self,
        root: Path,
        *,
        authority_secret_path: Path,
        authority_profile_path: Path,
        authority_revocations_dir: Path,
        maximum_content_bytes: int,
    ) -> None:
        self._root = _private_directory(root, "content_sessions_root")
        self._secret_path = _protected_file(
            authority_secret_path, "authority_secret_path", maximum=4_194_304
        )[0]
        # Validate these eagerly so a partially provisioned runtime remains
        # unavailable rather than accepting a command and failing later.
        load_issuer_profile(authority_profile_path)
        self._profile_path = authority_profile_path
        self._revocations = RevocationFileLedger(authority_revocations_dir)
        if type(maximum_content_bytes) is not int or maximum_content_bytes < 1:
            raise FixtureLedgerUnavailable(
                "maximum_content_bytes must be an explicit positive integer"
            )
        self._maximum_content_bytes = maximum_content_bytes
        self._authorized_manifests: dict[str, bytes] = {}

    def revalidate(self, binding: Any) -> GrantAuthority:
        session_id = _reference(getattr(binding, "authority_ref", None), "content_session_id")
        manifest = self._manifest(session_id)
        envelope = manifest["authority_envelope"]
        payload = envelope.get("payload") if isinstance(envelope, Mapping) else None
        if not isinstance(payload, Mapping) or payload.get("grant_id") != session_id:
            raise AuthorityDenied("content session identity is not bound")
        expectation = GrantExpectation(
            authority_class="operator_content_session",
            issuer_id=_reference(getattr(binding, "issuer_ref", None), "issuer_ref"),
            subject_ref=_reference(getattr(binding, "subject_ref", None), "subject_ref"),
            context_ref=_reference(getattr(binding, "context_ref", None), "context_ref"),
            action=_reference(getattr(binding, "action", None), "action"),
            purpose=_reference(getattr(binding, "purpose", None), "purpose"),
            target_ref=_reference(getattr(binding, "target_ref", None), "target_ref"),
            target_revision=_nonnegative(
                getattr(binding, "target_revision", None), "target_revision"
            ),
            expires_at=_timestamp(payload.get("expires_at")),
            idempotency_key_digest=validate_digest(
                getattr(binding, "idempotency_key_digest", None),
                "idempotency_key_digest",
            ),
            session_nonce=_reference(payload.get("session_nonce"), "session_nonce"),
        )
        now = getattr(binding, "now", None)
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise AuthorityValidationError("content session time is invalid")
        profile = load_issuer_profile(self._profile_path)
        revocations = self._revocations.load()
        authorize_grant(
            envelope,
            self._secret_path,
            profile,
            expectation,
            now=now,
            revocations=revocations,
        )
        self._authorized_manifests[session_id] = canonical_json(manifest)
        return GrantAuthority(envelope, expectation, revocations)

    def open_content(self, session_id: str, content_handle: str) -> bytes:
        session = _reference(session_id, "content_session_id")
        handle = _reference(content_handle, "content_handle")
        manifest = self._manifest(session)
        if self._authorized_manifests.get(session) != canonical_json(manifest):
            raise AuthorityDenied("content session changed after authority validation")
        entries = {
            item["content_handle"]: item for item in manifest["content_handles"]
        }
        entry = entries.get(handle)
        if entry is None:
            raise AuthorityDenied("content handle is not bound to the content session")
        path = self._root / _content_filename(session, handle)
        _selected, content = _protected_file(
            path, "content session payload", maximum=self._maximum_content_bytes
        )
        if len(content) != entry["content_size"] or _content_digest(content) != entry[
            "content_digest"
        ]:
            raise AuthorityValidationError("content session payload identity changed")
        return content

    def _manifest(self, session_id: str) -> dict[str, Any]:
        path = self._root / _session_filename(session_id)
        _selected, encoded = _protected_file(
            path, "content session manifest", maximum=4_194_304
        )
        try:
            decoded = canonical_loads(encoded)
        except ValueError as exc:
            raise AuthorityValidationError("content session manifest is invalid") from exc
        if type(decoded) is not dict or canonical_json(decoded) != encoded:
            raise AuthorityValidationError("content session manifest is not canonical")
        if set(decoded) != _SESSION_FIELDS or decoded["schema"] != FIXTURE_CONTENT_SESSION_SCHEMA:
            raise AuthorityValidationError("content session manifest schema is invalid")
        if decoded["content_session_id"] != session_id:
            raise AuthorityDenied("content session manifest identity is not bound")
        if type(decoded["authority_envelope"]) is not dict:
            raise AuthorityValidationError("content session authority envelope is invalid")
        raw_handles = decoded["content_handles"]
        if type(raw_handles) is not list:
            raise AuthorityValidationError("content session handles are invalid")
        handles: list[str] = []
        for item in raw_handles:
            if type(item) is not dict or set(item) != _CONTENT_FIELDS:
                raise AuthorityValidationError("content session handle binding is invalid")
            handles.append(_reference(item["content_handle"], "content_handle"))
            validate_digest(item["content_digest"], "content_digest")
            size = item["content_size"]
            if type(size) is not int or not 1 <= size <= self._maximum_content_bytes:
                raise AuthorityValidationError("content session payload size is invalid")
        if handles != sorted(set(handles)):
            raise AuthorityValidationError("content session handles must be sorted and unique")
        return decoded


def build_fixture_runtime_adapter(
    repository: V3Repository,
    *,
    context_ref: str,
    fixture_grant_revalidator: AuthorityRevalidator,
    authority_secret_path: Path,
    authority_profile_path: Path,
    authority_revocations_dir: Path,
    profile_path: Path | None = None,
    cipher: QuarantineCipher | None = None,
    custody: KeyCustody | None = None,
) -> FixtureCommandAdapter:
    """Assemble the production fixture coordinator from explicit local state."""

    if not isinstance(repository, V3Repository):
        raise FixtureLedgerUnavailable("fixture runtime requires a V3Repository")
    if not callable(fixture_grant_revalidator):
        raise FixtureLedgerUnavailable("fixture grant revalidator is unavailable")
    selected_context = _reference(context_ref, "context_ref")
    selected_profile = profile_path
    if selected_profile is None:
        raw = os.environ.get(FIXTURE_RUNTIME_PROFILE_ENV)
        if type(raw) is not str or not raw:
            raise FixtureLedgerUnavailable("fixture runtime profile is not configured")
        selected_profile = Path(raw)
    profile = load_fixture_runtime_profile(selected_profile)
    _vault_key_path, vault_key = _protected_file(
        profile.vault_key_file, "vault_key_file", maximum=32
    )
    if len(vault_key) != 32:
        raise FixtureLedgerUnavailable("vault key must be exactly 32 bytes")
    _partition_path, partition_secret = _protected_file(
        profile.partition_secret_file, "partition_secret_file", maximum=4_096
    )
    if len(partition_secret) < 16:
        raise FixtureLedgerUnavailable("partition secret must contain at least 16 bytes")
    try:
        issuer_profile = load_issuer_profile(authority_profile_path)
        vault = LocalEncryptedFixtureVault(
            profile.vault_root,
            key_ref=profile.vault_key_ref,
            key_encryption_key=vault_key,
            cipher=cipher,
            custody=custody,
        )
        coordinator = FixtureAuthority(
            secret_path=authority_secret_path,
            issuer_profile=issuer_profile,
            vault=vault,
            partition_secret=partition_secret,
            partition_policy_ref=profile.partition_policy_ref,
            partition_weights=profile.partition_weights,
            key_epoch=profile.key_epoch,
        )
        resolvers = RepositoryFixtureResolvers(
            repository,
            coordinator,
            context_ref=selected_context,
            record_maximum=profile.record_maximum,
            event_maximum=profile.event_maximum,
        )
        sessions = PrivateContentSessionStore(
            profile.content_sessions_root,
            authority_secret_path=authority_secret_path,
            authority_profile_path=authority_profile_path,
            authority_revocations_dir=authority_revocations_dir,
            maximum_content_bytes=profile.maximum_content_bytes,
        )
        ledger = RepositoryFixtureCommandLedger(
            repository, withdrawal_finalizer=resolvers.finalize_withdrawal
        )
        return FixtureCommandAdapter(
            coordinator=coordinator,
            ledger=ledger,
            content_provider=sessions.open_content,
            draft_resolver=resolvers.resolve_draft,
            review_resolver=resolvers.resolve_review,
            fixture_grant_revalidator=fixture_grant_revalidator,
            content_session_revalidator=sessions.revalidate,
        )
    except FixtureLedgerUnavailable:
        raise
    except Exception as exc:
        raise FixtureLedgerUnavailable("fixture runtime custody is unavailable") from exc


def load_fixture_runtime_profile(path: Path) -> FixtureRuntimeProfile:
    selected, encoded = _protected_file(path, "fixture runtime profile", maximum=65_536)
    try:
        payload = canonical_loads(encoded)
    except ValueError as exc:
        raise FixtureLedgerUnavailable("fixture runtime profile is invalid") from exc
    if type(payload) is not dict or canonical_json(payload) != encoded:
        raise FixtureLedgerUnavailable("fixture runtime profile is not canonical")
    if set(payload) != _PROFILE_FIELDS or payload["schema"] != FIXTURE_RUNTIME_PROFILE_SCHEMA:
        raise FixtureLedgerUnavailable("fixture runtime profile schema is invalid")
    weights = payload["partition_weights"]
    if type(weights) is not dict or set(weights) != set(PARTITIONS):
        raise FixtureLedgerUnavailable("fixture partition weights are incomplete")
    if any(type(value) is not int or not 1 <= value <= 1_000_000 for value in weights.values()):
        raise FixtureLedgerUnavailable("fixture partition weights are invalid")
    return FixtureRuntimeProfile(
        content_sessions_root=_absolute(payload["content_sessions_root"], "content_sessions_root"),
        vault_root=_private_directory(
            _absolute(payload["vault_root"], "vault_root"), "vault_root"
        ),
        vault_key_ref=_reference(payload["vault_key_ref"], "vault_key_ref"),
        vault_key_file=_absolute(payload["vault_key_file"], "vault_key_file"),
        partition_secret_file=_absolute(
            payload["partition_secret_file"], "partition_secret_file"
        ),
        partition_policy_ref=_reference(
            payload["partition_policy_ref"], "partition_policy_ref"
        ),
        partition_weights=dict(weights),
        key_epoch=_reference(payload["key_epoch"], "key_epoch"),
        record_maximum=_positive(payload["record_maximum"], "record_maximum"),
        event_maximum=_positive(payload["event_maximum"], "event_maximum"),
        maximum_content_bytes=_positive(
            payload["maximum_content_bytes"], "maximum_content_bytes"
        ),
    )


def content_session_manifest_filename(session_id: str) -> str:
    """Return the path-safe filename for one opaque session reference."""

    return _session_filename(_reference(session_id, "content_session_id"))


def content_session_payload_filename(session_id: str, content_handle: str) -> str:
    """Return the path-safe filename for one session-bound content handle."""

    return _content_filename(
        _reference(session_id, "content_session_id"),
        _reference(content_handle, "content_handle"),
    )


def content_session_payload_digest(content: bytes) -> str:
    if type(content) is not bytes or not content:
        raise AuthorityValidationError("content session payload must be non-empty bytes")
    return _content_digest(content)


def _private_directory(path: Path, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise FixtureLedgerUnavailable(f"{field} must be an absolute directory")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise FixtureLedgerUnavailable(f"{field} is unavailable") from exc
    if (
        resolved != path
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise FixtureLedgerUnavailable(f"{field} custody must be current-owner 0700")
    return path


def _protected_file(path: Path, field: str, *, maximum: int) -> tuple[Path, bytes]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise FixtureLedgerUnavailable(f"{field} must be an absolute file")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FixtureLedgerUnavailable(f"{field} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise FixtureLedgerUnavailable(f"{field} custody must be current-owner 0600")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FixtureLedgerUnavailable(f"{field} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise FixtureLedgerUnavailable(f"{field} changed while opening")
        content = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if not content or len(content) > maximum:
        raise FixtureLedgerUnavailable(f"{field} exceeds its explicit bound")
    return path, content


def _absolute(value: Any, field: str) -> Path:
    if type(value) is not str:
        raise FixtureLedgerUnavailable(f"{field} must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise FixtureLedgerUnavailable(f"{field} must be an absolute path")
    return path


def _reference(value: Any, field: str) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise AuthorityValidationError(f"{field} must be an opaque reference")
    return value


def _positive(value: Any, field: str) -> int:
    if type(value) is not int or value < 1:
        raise FixtureLedgerUnavailable(f"{field} must be an explicit positive integer")
    return value


def _nonnegative(value: Any, field: str) -> int:
    if type(value) is not int or value < 0:
        raise AuthorityValidationError(f"{field} must be non-negative")
    return value


def _timestamp(value: Any) -> datetime:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise AuthorityValidationError("content session expiry is invalid")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    return parsed.replace(tzinfo=timezone.utc)


def _session_filename(session_id: str) -> str:
    digest = hashlib.sha256(
        b"a0.fixture-content-session.v1\0" + session_id.encode("utf-8")
    ).hexdigest()
    return f"session_{digest}.json"


def _content_filename(session_id: str, content_handle: str) -> str:
    digest = hashlib.sha256(
        b"a0.fixture-content-session-payload.v1\0"
        + session_id.encode("utf-8")
        + b"\0"
        + content_handle.encode("utf-8")
    ).hexdigest()
    return f"content_{digest}.bin"


def _content_digest(content: bytes) -> str:
    return hashlib.sha256(b"a0.fixture-content-session-content.v1\0" + content).hexdigest()


__all__ = [
    "FIXTURE_CONTENT_SESSION_SCHEMA",
    "FIXTURE_RUNTIME_PROFILE_ENV",
    "FIXTURE_RUNTIME_PROFILE_SCHEMA",
    "FixtureRuntimeProfile",
    "PrivateContentSessionStore",
    "build_fixture_runtime_adapter",
    "content_session_manifest_filename",
    "content_session_payload_digest",
    "content_session_payload_filename",
    "load_fixture_runtime_profile",
]
