"""Project-scoped, inert Genesis enrollment for ordinary Agent Zero chats.

This coordinator owns one deliberately narrow convenience authority: it may
create the v3 store before cutover and establish revision-zero Null Genesis for
chat contexts in the current Agent Zero project.  It cannot enqueue work,
promote candidates, activate improvements, or roll back a profile.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Iterator

from .. import paths
from .activation import GenesisCommand, GenesisResult, initialize_genesis
from .authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityAction,
    AuthorityClass,
    AuthorityPurpose,
    GrantRequest,
    IssuerProfile,
    bootstrap_local_issuer,
    canonical_json_bytes,
    digest_idempotency_key,
    issue_grant,
    require_local_issuer,
)
from .registry import V3_REGISTRY
from .repository import RevisionConflict, V3Repository
from .store_authority import StoreAuthorityManifestStore
from .store_selection import open_runtime_repository


_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ISSUER_ID = "issuer_automatic_project_genesis_01"
_SUBJECT_REF = "automatic_project_genesis"
_OPAQUE_KEY_EPOCH = "automatic_project_genesis_epoch_1"
_GRANT_LIFETIME = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class AutomaticGenesisResult:
    project_ref: str
    discovered_context_count: int
    initialized_context_refs: tuple[str, ...]
    already_ready_count: int


@dataclass(frozen=True, slots=True)
class _CustodyPaths:
    root: Path
    secret: Path
    profile: Path
    opaque_key: Path
    grants: Path
    lock: Path


def _custody_paths() -> _CustodyPaths:
    root = paths.AUTHORITY_DIR / "automatic-project-genesis"
    return _CustodyPaths(
        root=root,
        secret=root / "issuer-root.secret",
        profile=root / "issuer-profile.json",
        opaque_key=root / "opaque-reference.key",
        grants=root / "grants",
        lock=root / "coordinator.lock",
    )


def _safe_ref(value: object, name: str) -> str:
    if type(value) is not str or _SAFE_REF.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bounded opaque reference")
    return value


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise PermissionError("automatic Genesis custody directory is unavailable")
    os.chmod(path, 0o700)


def _write_private_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("automatic Genesis custody write was incomplete")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def _read_private(path: Path, *, expected_size: int | None = None) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise PermissionError("automatic Genesis custody file is not owner-only")
        chunks: list[bytes] = []
        remaining = metadata.st_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if expected_size is not None and len(payload) != expected_size:
        raise ValueError("automatic Genesis custody file has an invalid size")
    return payload


@contextmanager
def _coordinator_lock(custody: _CustodyPaths) -> Iterator[None]:
    _ensure_private_dir(paths.STATE_DIR)
    _ensure_private_dir(paths.AUTHORITY_DIR)
    _ensure_private_dir(custody.root)
    _ensure_private_dir(custody.grants)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(custody.lock, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise PermissionError("automatic Genesis coordinator lock is unavailable")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _load_or_create_authority(custody: _CustodyPaths) -> tuple[IssuerProfile, bytes]:
    expected_profile = IssuerProfile(
        issuer_id=_ISSUER_ID,
        key_epoch=1,
        allowed_authority_classes=(AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,),
    )
    if not custody.secret.exists():
        if custody.profile.exists():
            raise RuntimeError("automatic Genesis issuer secret is unavailable")
        profile = bootstrap_local_issuer(
            custody.secret,
            issuer_id=_ISSUER_ID,
            key_epoch=1,
            allowed_authority_classes=(AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,),
            confirmation=BOOTSTRAP_CONFIRMATION,
        )
    else:
        profile = require_local_issuer(custody.secret, expected_profile.to_record())

    if not custody.profile.exists():
        _write_private_new(custody.profile, canonical_json_bytes(profile.to_record()))
    if not custody.opaque_key.exists():
        _write_private_new(custody.opaque_key, os.urandom(32))

    profile_payload = json.loads(_read_private(custody.profile).decode("utf-8"))
    profile = IssuerProfile.from_record(profile_payload)
    if (
        profile.issuer_id != _ISSUER_ID
        or profile.key_epoch != 1
        or profile.allowed_authority_classes
        != (AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,)
    ):
        raise RuntimeError("automatic Genesis issuer profile is not the narrow built-in profile")
    return profile, _read_private(custody.opaque_key, expected_size=32)


def _project_context_refs(
    chats_dir: Path,
    *,
    project_ref: str,
    current_context_ref: str,
) -> tuple[str, ...]:
    """Discover only context identifiers assigned to the current project."""

    contexts = {current_context_ref}
    try:
        metadata = chats_dir.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
        ):
            return tuple(sorted(contexts))
        for chat_file in chats_dir.glob("*/chat.json"):
            try:
                file_metadata = chat_file.lstat()
                if (
                    stat.S_ISLNK(file_metadata.st_mode)
                    or not stat.S_ISREG(file_metadata.st_mode)
                    or file_metadata.st_uid != os.geteuid()
                    or file_metadata.st_size > 1_000_000
                ):
                    continue
                payload = json.loads(chat_file.read_text(encoding="utf-8"))
                data = payload.get("data") if type(payload) is dict else None
                if type(data) is not dict or data.get("project") != project_ref:
                    continue
                context_ref = _safe_ref(payload.get("id"), "chat context")
                if chat_file.parent.name == context_ref:
                    contexts.add(context_ref)
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
                continue
    except OSError:
        pass
    return tuple(sorted(contexts))


def _repository() -> V3Repository:
    manifest = StoreAuthorityManifestStore(paths.STORE_AUTHORITY_MANIFEST_FILE).read()
    if manifest is None and not paths.SAFE_STORE_FILE.exists():
        return V3Repository.create(paths.SAFE_STORE_FILE, registry=V3_REGISTRY)
    return open_runtime_repository(
        pre_cutover_path=paths.SAFE_STORE_FILE,
        manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
    )


def _binding(project_ref: str, context_ref: str) -> tuple[str, str, str | bytes]:
    digest = hashlib.sha256(
        b"a0.automatic-project-genesis.v1\x00"
        + project_ref.encode("utf-8")
        + b"\x00"
        + context_ref.encode("utf-8")
    ).hexdigest()[:40]
    return (
        f"activation_scope_{digest}",
        f"automatic_genesis_{digest}",
        f"automatic-project-genesis-v1:{project_ref}:{context_ref}",
    )


def _initialize_context(
    repository: V3Repository,
    *,
    custody: _CustodyPaths,
    profile: IssuerProfile,
    opaque_key: bytes,
    project_ref: str,
    context_ref: str,
    now: datetime,
) -> GenesisResult:
    target_ref, session_nonce, idempotency_key = _binding(project_ref, context_ref)
    expires_at = now + _GRANT_LIFETIME
    command = GenesisCommand(
        subject_ref=_SUBJECT_REF,
        context_ref=context_ref,
        target_ref=target_ref,
        idempotency_key=idempotency_key,
        session_nonce=session_nonce,
        authority_expires_at=expires_at,
        expected_revision=0,
        reason_code="automatic_project_enrollment",
    )
    envelope = issue_grant(
        custody.secret,
        profile,
        GrantRequest(
            authority_class=AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,
            issuer_id=profile.issuer_id,
            key_epoch=profile.key_epoch,
            subject_ref=command.subject_ref,
            context_ref=context_ref,
            action=AuthorityAction.INITIALIZE_GENESIS.value,
            purpose=AuthorityPurpose.GENESIS.value,
            target_ref=target_ref,
            target_revision=0,
            issued_at=now,
            expires_at=expires_at,
            idempotency_key_digest=digest_idempotency_key(idempotency_key),
            session_nonce=session_nonce,
        ),
    )
    grant_id = envelope["payload"]["grant_id"]
    grant_path = custody.grants / f"{grant_id}.json"
    if not grant_path.exists():
        _write_private_new(grant_path, canonical_json_bytes(envelope))
    return initialize_genesis(
        repository,
        command=command,
        authority_envelope=envelope,
        authority_secret_path=custody.secret,
        issuer_profile=profile,
        opaque_key=opaque_key,
        opaque_key_epoch=_OPAQUE_KEY_EPOCH,
        now=now,
        revocations=(),
    )


def ensure_project_genesis(
    *,
    project_ref: str,
    current_context_ref: str,
    chats_dir: Path | None = None,
    now: datetime | None = None,
) -> AutomaticGenesisResult:
    """Ensure inert Genesis for all discoverable chats in one project.

    The file lock serializes first-install bootstrap and project enrollment
    across parallel Agent Zero loops.  A caller must still enforce the plugin
    enablement, automatic-enrollment, and offline-replay gates.
    """

    project = _safe_ref(project_ref, "project_ref")
    current = _safe_ref(current_context_ref, "current_context_ref")
    reference_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    discovered = _project_context_refs(
        chats_dir or paths.PLUGIN_ROOT.parents[1] / "chats",
        project_ref=project,
        current_context_ref=current,
    )
    custody = _custody_paths()
    initialized: list[str] = []
    already_ready = 0
    with _coordinator_lock(custody):
        with _repository() as repository:
            missing = tuple(
                context_ref
                for context_ref in discovered
                if repository.get_activation_scope(context_ref) is None
            )
            already_ready = len(discovered) - len(missing)
            if missing:
                profile, opaque_key = _load_or_create_authority(custody)
            for context_ref in missing:
                try:
                    _initialize_context(
                        repository,
                        custody=custody,
                        profile=profile,
                        opaque_key=opaque_key,
                        project_ref=project,
                        context_ref=context_ref,
                        now=reference_time,
                    )
                    initialized.append(context_ref)
                except RevisionConflict:
                    if repository.get_activation_scope(context_ref) is None:
                        raise
                    already_ready += 1
    return AutomaticGenesisResult(
        project_ref=project,
        discovered_context_count=len(discovered),
        initialized_context_refs=tuple(initialized),
        already_ready_count=already_ready,
    )
