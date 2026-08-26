#!/usr/bin/env python3
"""Local-only v3 authority and inert Genesis protocol; opens no listener."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from typing import Any, Iterator, Sequence


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from helpers.v3.activation import (  # noqa: E402
    ACTIVATION_REGISTRY,
    GenesisCommand,
    initialize_genesis,
)
from helpers.v3.authority import (  # noqa: E402
    BOOTSTRAP_CONFIRMATION,
    GrantExpectation,
    AuthorityAction,
    AuthorityClass,
    AuthorityPurpose,
    GrantRequest,
    IssuerProfile,
    RevocationReason,
    RevocationRequest,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
    issue_revocation,
    project_grant,
)
from helpers.v3.authority_service import (  # noqa: E402
    LocalGrantVerifier,
    RevocationFileLedger,
)
from helpers.v3.calibration_authority import (  # noqa: E402
    CalibrationApprovalRequest,
    CalibrationGrantBinding,
    CalibrationLifecycleFact,
    CalibrationWithdrawalRequest,
    ExactRecord,
    approve_policy_calibration,
    reduce_calibration_eligibility,
    withdraw_policy_calibration,
)
from helpers.v3.canary import POLICY_CALIBRATION_SCHEMA_ID  # noqa: E402
from helpers.v3.migration import (  # noqa: E402
    MIGRATION_RECEIPT_SCHEMA_ID,
    MIGRATION_REGISTRY,
    MigrationCommand,
    MigrationResult,
    migrate_legacy_store,
    recover_committed_migration,
)
from helpers.v3.migration_repository import (  # noqa: E402
    MIGRATION_PHASES,
    MigrationRepository,
    MigrationRun,
)
from helpers.v3.privacy_lifecycle import (  # noqa: E402
    WAIVER_ACKNOWLEDGEMENT,
    DeletionEvidenceRef,
    DeletionProgress,
    delete_quarantine,
    export_quarantine,
    issue_deletion_challenge,
    issue_export_waiver,
    resume_cryptographic_deletion,
)
from helpers.v3.quarantine import (  # noqa: E402
    AES_256_GCM,
    AES256GCMCipher,
    AES256GCMKeyCustody,
    decrypt_quarantine,
    encrypt_quarantine,
)
from helpers.v3.registry import V3_REGISTRY  # noqa: E402
from helpers.v3.public_projection import project_public_status  # noqa: E402
from helpers.v3.repository import (  # noqa: E402
    IntegrityFailure,
    StoreNotFoundError,
    V3Reader,
    V3Repository,
)
from helpers.v3.schemas import canonical_json, canonical_loads  # noqa: E402
from helpers.v3.store_authority import StoreAuthorityManifestStore  # noqa: E402
from helpers.v3.store_selection import (  # noqa: E402
    open_runtime_reader,
    open_runtime_repository,
    resolve_runtime_store,
)


MIGRATION_CUTOVER_CONFIRMATION = "CONFIRM_A0_V3_STORE_AUTHORITY_CUTOVER"
PROJECT_GENESIS_CONFIRMATION = "BOOTSTRAP_PROJECT_GENESIS"


class LocalProtocolError(RuntimeError):
    pass


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise LocalProtocolError("local authority paths must be absolute")
    return path


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LocalProtocolError("timestamps must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise LocalProtocolError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _strict_boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("boolean values must be exactly true or false")


def _safe_ref(value: Any, field: str) -> str:
    first = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
    allowed = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
    )
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or value[0] not in first
        or any(character not in allowed for character in value)
    ):
        raise LocalProtocolError(f"{field} must be a bounded opaque reference")
    return value


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _nonnegative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be a non-negative integer")
    return parsed


def _owned_existing_file(path: Path, field: str) -> Path:
    """Resolve an exact, non-symlink file owned by this local operator."""

    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LocalProtocolError(f"{field} is unavailable") from exc
    if (
        resolved != path
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise LocalProtocolError(f"{field} must be an exact current-owner regular file")
    return path


def _owned_output_path(path: Path, field: str, *, must_be_new: bool) -> Path:
    """Validate an exact current-owner output identity without creating it."""

    try:
        parent = path.parent.resolve(strict=True)
        parent_metadata = path.parent.lstat()
    except OSError as exc:
        raise LocalProtocolError(f"{field} parent is unavailable") from exc
    if (
        parent != path.parent
        or stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
    ):
        raise LocalProtocolError(f"{field} parent must be an exact current-owner directory")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise LocalProtocolError(f"{field} cannot be inspected") from exc
    if must_be_new:
        raise LocalProtocolError(f"{field} must not already exist")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or path.resolve(strict=True) != path
    ):
        raise LocalProtocolError(f"{field} must be an exact current-owner regular file")
    return path


def _write_new(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    if not path.parent.is_dir():
        raise LocalProtocolError("output parent directory must already exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise LocalProtocolError("local authority write was incomplete")
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


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = canonical_loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise LocalProtocolError("authority input is unavailable or invalid") from exc
    if type(payload) is not dict:
        raise LocalProtocolError("authority input must be an object")
    return payload


def _load_opaque_key(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LocalProtocolError("opaque-reference key is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise LocalProtocolError("opaque-reference key custody must be current-owner 0600")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LocalProtocolError("opaque-reference key could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise LocalProtocolError("opaque-reference key custody changed while opening")
        content = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    if len(content) != 32:
        raise LocalProtocolError("opaque-reference key must be exactly 32 bytes")
    return content


def command_bootstrap(args: argparse.Namespace) -> dict[str, Any]:
    secret = _absolute(args.secret)
    profile_path = _absolute(args.profile)
    profile = bootstrap_local_issuer(
        secret,
        issuer_id=args.issuer,
        key_epoch=args.key_epoch,
        allowed_authority_classes=args.authority_class,
        confirmation=args.confirm,
    )
    try:
        _write_new(profile_path, canonical_json(profile.to_record()))
    except BaseException:
        try:
            secret.unlink()
        except OSError:
            pass
        raise
    return {"state": "bootstrapped", "issuer_ref": profile.issuer_id, "key_epoch": profile.key_epoch}


def command_opaque_key_bootstrap(args: argparse.Namespace) -> dict[str, Any]:
    path = _absolute(args.output)
    if args.confirm != "BOOTSTRAP_OPAQUE_REFERENCE_KEY":
        raise LocalProtocolError("explicit opaque-key bootstrap confirmation is required")
    _write_new(path, os.urandom(32))
    return {"state": "bootstrapped", "key_epoch": args.key_epoch}


def command_grant_issue(args: argparse.Namespace) -> dict[str, Any]:
    secret = _absolute(args.secret)
    profile = IssuerProfile.from_record(_read_json(_absolute(args.profile)))
    issued_at = _utc(args.issued_at)
    expires_at = _utc(args.expires_at)
    envelope = issue_grant(
        secret,
        profile,
        GrantRequest(
            authority_class=args.authority_class,
            issuer_id=profile.issuer_id,
            key_epoch=profile.key_epoch,
            subject_ref=args.subject,
            context_ref=args.context,
            action=args.action,
            purpose=args.purpose,
            target_ref=args.target,
            target_revision=args.target_revision,
            issued_at=issued_at,
            expires_at=expires_at,
            idempotency_key_digest=digest_idempotency_key(args.idempotency_key),
            session_nonce=args.session_nonce,
        ),
    )
    _write_new(_absolute(args.output), canonical_json(envelope))
    return {
        "state": "issued",
        "authority_ref": envelope["payload"]["grant_id"],
        "expires_at": envelope["payload"]["expires_at"],
    }


def command_grant_inspect(args: argparse.Namespace) -> dict[str, Any]:
    profile = IssuerProfile.from_record(_read_json(_absolute(args.profile)))
    return project_grant(
        _read_json(_absolute(args.grant)),
        _absolute(args.secret),
        profile,
        now=_utc(args.now),
        revocations=[_read_json(_absolute(path)) for path in args.revocation],
    )


def command_grant_revoke(args: argparse.Namespace) -> dict[str, Any]:
    profile = IssuerProfile.from_record(_read_json(_absolute(args.profile)))
    envelope = issue_revocation(
        _absolute(args.secret),
        profile,
        RevocationRequest(
            grant_id=args.grant_id,
            issuer_id=profile.issuer_id,
            key_epoch=profile.key_epoch,
            context_ref=args.context,
            revoked_at=_utc(args.revoked_at),
            reason_code=args.reason_code,
            idempotency_key_digest=digest_idempotency_key(args.idempotency_key),
        ),
    )
    RevocationFileLedger(_absolute(args.ledger_dir)).append(envelope)
    if args.output:
        _write_new(_absolute(args.output), canonical_json(envelope))
    return {
        "state": "revoked",
        "revocation_ref": envelope["payload"]["revocation_id"],
        "authority_ref": envelope["payload"]["grant_id"],
    }


def command_genesis(args: argparse.Namespace) -> dict[str, Any]:
    store = _absolute(args.store)
    profile = IssuerProfile.from_record(_read_json(_absolute(args.profile)))
    envelope = _read_json(_absolute(args.grant))
    opaque_key = _load_opaque_key(_absolute(args.opaque_key))
    command = GenesisCommand(
        subject_ref=args.subject,
        context_ref=args.context,
        target_ref=args.target,
        idempotency_key=args.idempotency_key,
        session_nonce=args.session_nonce,
        authority_expires_at=_utc(args.authority_expires_at),
        expected_revision=0,
        reason_code=args.reason_code,
    )
    opener = V3Repository.create if args.create_store else V3Repository.open
    with opener(store, registry=ACTIVATION_REGISTRY) as repository:
        result = initialize_genesis(
            repository,
            command=command,
            authority_envelope=envelope,
            authority_secret_path=_absolute(args.secret),
            issuer_profile=profile,
            opaque_key=opaque_key,
            opaque_key_epoch=args.opaque_key_epoch,
            now=_utc(args.now),
            revocations=[_read_json(_absolute(path)) for path in args.revocation],
        )
    return {
        "state": "replayed" if result.replayed else "initialized",
        "profile_ref": result.scope.current_profile_id,
        "scope_revision": result.scope.scope_revision,
        "activation_receipt_ref": result.activation_receipt.record_id,
        "mutation_receipt_ref": result.mutation_receipt.record_id,
    }


def command_readiness_inspect(args: argparse.Namespace) -> dict[str, Any]:
    """Inspect selected-store and context Genesis readiness without writing."""

    store = _absolute(args.store)
    manifest = _absolute(args.manifest)
    selection = resolve_runtime_store(
        pre_cutover_path=store,
        manifest_path=manifest,
    )
    authority = {
        "source": selection.source,
        "manifest_revision": (
            selection.manifest.revision if selection.manifest is not None else 0
        ),
        "generation_ref": (
            selection.manifest.generation_ref
            if selection.manifest is not None
            else "pre_cutover"
        ),
    }
    try:
        with open_runtime_reader(
            pre_cutover_path=store,
            manifest_path=manifest,
        ) as reader:
            status = project_public_status(
                context_ref=args.context,
                enabled=True,
                reader=reader,
            )
    except StoreNotFoundError:
        return {
            "schema": "a0.local-readiness.v1",
            "state": "uninitialized",
            "context_ref": args.context,
            "store_authority": authority,
            "activation_scope": {
                "state": "uninitialized",
                "reason_codes": ["safe_store_missing"],
            },
        }

    return {
        "schema": "a0.local-readiness.v1",
        "state": status["plugin_state"],
        "context_ref": status["context_ref"],
        "store_authority": authority,
        "activation_scope": status["activation_scope"],
    }


def _project_context_refs(chats_dir: Path, project_ref: str) -> tuple[str, ...]:
    _safe_ref(project_ref, "project")
    try:
        metadata = chats_dir.lstat()
    except OSError as exc:
        raise LocalProtocolError("chat metadata directory is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise LocalProtocolError(
            "chat metadata directory must be a current-owner directory"
        )

    contexts: list[str] = []
    try:
        chat_files = tuple(chats_dir.glob("*/chat.json"))
        for chat_file in chat_files:
            _owned_existing_file(chat_file, "chat metadata")
            payload = json.loads(chat_file.read_text(encoding="utf-8"))
            data = payload.get("data") if type(payload) is dict else None
            if type(data) is not dict or data.get("project") != project_ref:
                continue
            context_ref = _safe_ref(payload.get("id"), "chat context")
            if chat_file.parent.name != context_ref:
                raise LocalProtocolError("chat context identity does not match custody")
            contexts.append(context_ref)
    except (OSError, ValueError) as exc:
        raise LocalProtocolError("project chat metadata is unavailable") from exc
    return tuple(sorted(set(contexts)))


def command_project_readiness_inspect(args: argparse.Namespace) -> dict[str, Any]:
    """Verify every currently enrolled chat context for one explicit project."""

    store = _absolute(args.store)
    manifest = _absolute(args.manifest)
    contexts = _project_context_refs(_absolute(args.chats_dir), args.project)
    selection = resolve_runtime_store(
        pre_cutover_path=store,
        manifest_path=manifest,
    )
    authority = {
        "source": selection.source,
        "manifest_revision": (
            selection.manifest.revision if selection.manifest is not None else 0
        ),
        "generation_ref": (
            selection.manifest.generation_ref
            if selection.manifest is not None
            else "pre_cutover"
        ),
    }
    missing = list(contexts)
    try:
        with open_runtime_reader(
            pre_cutover_path=store,
            manifest_path=manifest,
        ) as reader:
            missing = [
                context_ref
                for context_ref in contexts
                if project_public_status(
                    context_ref=context_ref,
                    enabled=True,
                    reader=reader,
                )["plugin_state"]
                != "ready"
            ]
    except StoreNotFoundError:
        pass

    ready_count = len(contexts) - len(missing)
    return {
        "schema": "a0.project-readiness.v1",
        "state": "ready" if contexts and not missing else "incomplete",
        "project_ref": args.project,
        "context_count": len(contexts),
        "ready_count": ready_count,
        "missing_context_refs": missing,
        "store_authority": authority,
    }


def command_project_genesis(args: argparse.Namespace) -> dict[str, Any]:
    """Explicitly initialize every missing context in one Agent Zero project."""

    if args.confirm != PROJECT_GENESIS_CONFIRMATION:
        raise LocalProtocolError("explicit project Genesis confirmation is required")
    contexts = _project_context_refs(_absolute(args.chats_dir), args.project)
    if not contexts:
        raise LocalProtocolError("project has no discoverable chat contexts")

    store = _absolute(args.store)
    manifest = _absolute(args.manifest)
    grant_dir = _absolute(args.grant_dir)
    try:
        grant_dir_metadata = grant_dir.lstat()
    except OSError as exc:
        raise LocalProtocolError("grant directory is unavailable") from exc
    if (
        stat.S_ISLNK(grant_dir_metadata.st_mode)
        or not stat.S_ISDIR(grant_dir_metadata.st_mode)
        or grant_dir_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(grant_dir_metadata.st_mode) != 0o700
    ):
        raise LocalProtocolError("grant directory must be current-owner 0700")

    profile = IssuerProfile.from_record(_read_json(_absolute(args.profile)))
    opaque_key = _load_opaque_key(_absolute(args.opaque_key))
    secret = _absolute(args.secret)
    now = _utc(args.now)
    expires_at = _utc(args.authority_expires_at)
    if expires_at <= now:
        raise LocalProtocolError("project Genesis authority must be unexpired")
    idempotency_prefix = _safe_ref(args.idempotency_prefix, "idempotency prefix")
    nonce_prefix = _safe_ref(args.session_nonce_prefix, "session nonce prefix")

    if args.create_store:
        if StoreAuthorityManifestStore(manifest).read() is not None:
            raise LocalProtocolError("cannot create a pre-cutover store after cutover")
        repository_context = V3Repository.create(store, registry=V3_REGISTRY)
    else:
        repository_context = open_runtime_repository(
            pre_cutover_path=store,
            manifest_path=manifest,
        )

    initialized_contexts: list[str] = []
    receipt_refs: list[str] = []
    with repository_context as repository:
        for context_ref in contexts:
            if repository.get_activation_scope(context_ref) is not None:
                continue
            target_ref = _safe_ref(
                f"activation_scope_{context_ref}", "activation target"
            )
            idempotency_key = _safe_ref(
                f"{idempotency_prefix}:{context_ref}", "idempotency key"
            )
            session_nonce = _safe_ref(
                f"{nonce_prefix}:{context_ref}", "session nonce"
            )
            command = GenesisCommand(
                subject_ref=args.subject,
                context_ref=context_ref,
                target_ref=target_ref,
                idempotency_key=idempotency_key,
                session_nonce=session_nonce,
                authority_expires_at=expires_at,
                expected_revision=0,
                reason_code=args.reason_code,
            )
            envelope = issue_grant(
                secret,
                profile,
                GrantRequest(
                    authority_class=AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,
                    issuer_id=profile.issuer_id,
                    key_epoch=profile.key_epoch,
                    subject_ref=args.subject,
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
            grant_ref = envelope["payload"]["grant_id"]
            _write_new(grant_dir / f"{grant_ref}.json", canonical_json(envelope))
            result = initialize_genesis(
                repository,
                command=command,
                authority_envelope=envelope,
                authority_secret_path=secret,
                issuer_profile=profile,
                opaque_key=opaque_key,
                opaque_key_epoch=args.opaque_key_epoch,
                now=now,
                revocations=(),
            )
            initialized_contexts.append(context_ref)
            receipt_refs.append(result.activation_receipt.record_id)

    return {
        "schema": "a0.project-genesis.v1",
        "state": "ready",
        "project_ref": args.project,
        "context_count": len(contexts),
        "initialized_context_refs": initialized_contexts,
        "already_ready_count": len(contexts) - len(initialized_contexts),
        "activation_receipt_refs": receipt_refs,
    }


@dataclass(frozen=True, slots=True)
class _MigrationPaths:
    source: Path
    ledger: Path
    manifest: Path
    generation: Path
    ciphertext: Path
    wrapped_key: Path
    custody_key: Path


class _AwaitingCutover(RuntimeError):
    """Internal phase boundary: the manifest has deliberately not been changed."""


class _SQLiteImmediateBarrier:
    """A held SQLite writer reservation used as the source mutation barrier."""

    def __init__(self, source: Path) -> None:
        try:
            self._connection = sqlite3.connect(source, isolation_level=None, timeout=0.0)
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise LocalProtocolError("SQLite source mutation barrier is unavailable") from exc
        self._held = True

    @property
    def held(self) -> bool:
        return self._held

    def close(self) -> None:
        try:
            if self._held:
                self._connection.rollback()
                self._held = False
        finally:
            self._connection.close()


def _migration_command(args: argparse.Namespace) -> MigrationCommand:
    created_at = _utc(args.created_at)
    now = _utc(args.now)
    lease_expires_at = _utc(args.lease_expires_at)
    if lease_expires_at <= now:
        raise LocalProtocolError("migration lease expiry must be after explicit now")
    return MigrationCommand(
        run_id=args.run_id,
        owner_id=args.owner_id,
        quarantine_ref=args.quarantine_ref,
        quarantine_revision=args.quarantine_revision,
        generation_ref=args.generation_ref,
        context_ref=args.context,
        source_context_id=args.source_context_id,
        source_size_limit=args.source_size_limit,
        transformation_policy=args.transformation_policy,
        expected_authority_revision=args.expected_authority_revision,
        key_epoch=args.key_epoch,
        created_at=created_at,
        lease_expires_at=lease_expires_at,
    )


def _migration_paths(args: argparse.Namespace) -> _MigrationPaths:
    paths = _MigrationPaths(
        source=_absolute(args.source_store),
        ledger=_absolute(args.ledger),
        manifest=_absolute(args.manifest),
        generation=_absolute(args.generation_path),
        ciphertext=_absolute(args.quarantine_ciphertext),
        wrapped_key=_absolute(args.quarantine_wrapped_key),
        custody_key=_absolute(args.custody_key),
    )
    values = (
        paths.source,
        paths.ledger,
        paths.manifest,
        paths.generation,
        paths.ciphertext,
        paths.wrapped_key,
        paths.custody_key,
    )
    if len(set(values)) != len(values):
        raise LocalProtocolError("migration paths must be pairwise distinct")
    return paths


def _validate_sqlite_sidecars(source: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = source.with_name(source.name + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            _owned_existing_file(sidecar, f"source-store{suffix}")


def _forbidden_markers(args: argparse.Namespace) -> tuple[bytes, ...]:
    values = tuple(item.encode("utf-8") for item in args.forbidden_marker)
    if (
        not values
        or any(not item or len(item) > 4096 for item in values)
        or len(values) != len(set(values))
    ):
        raise LocalProtocolError("forbidden markers must be explicit, bounded, and unique")
    return values


def _validate_migration_inputs(
    args: argparse.Namespace,
    paths: _MigrationPaths,
    *,
    new_run: bool,
) -> None:
    _validate_migration_flags(args)
    _owned_existing_file(paths.source, "source-store")
    _owned_existing_file(paths.custody_key, "custody-key")
    _owned_output_path(paths.manifest, "manifest", must_be_new=False)
    _owned_output_path(paths.ledger, "ledger", must_be_new=new_run)
    _owned_output_path(paths.generation, "generation-path", must_be_new=new_run)
    _owned_output_path(
        paths.ciphertext, "quarantine-ciphertext", must_be_new=new_run
    )
    _owned_output_path(
        paths.wrapped_key, "quarantine-wrapped-key", must_be_new=new_run
    )


def _validate_migration_flags(args: argparse.Namespace) -> None:
    if args.workers_stopped is not True:
        raise LocalProtocolError("workers-stopped must be explicitly true")
    if args.source_mutation_barrier != "sqlite-immediate":
        raise LocalProtocolError("unsupported source mutation barrier")
    if args.cipher_profile != AES_256_GCM:
        raise LocalProtocolError("unsupported migration cipher profile")
    _forbidden_markers(args)


def _migration_crypto(args: argparse.Namespace, paths: _MigrationPaths):
    cipher = AES256GCMCipher()
    custody = AES256GCMKeyCustody(
        args.custody_key_ref,
        _load_opaque_key(paths.custody_key),
        cipher=cipher,
    )
    return cipher, custody


@contextmanager
def _held_source(
    paths: _MigrationPaths,
) -> Iterator[tuple[sqlite3.Connection, _SQLiteImmediateBarrier]]:
    _validate_sqlite_sidecars(paths.source)
    barrier = _SQLiteImmediateBarrier(paths.source)
    source: sqlite3.Connection | None = None
    try:
        source = sqlite3.connect(
            paths.source.as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
        )
        source.execute("PRAGMA query_only = ON")
        _validate_sqlite_sidecars(paths.source)
        yield source, barrier
    except sqlite3.Error as exc:
        raise LocalProtocolError("legacy SQLite source cannot be opened safely") from exc
    finally:
        if source is not None:
            source.close()
        barrier.close()


def _manifest_store_at_expected_revision(
    command: MigrationCommand, paths: _MigrationPaths
) -> StoreAuthorityManifestStore:
    store = StoreAuthorityManifestStore(paths.manifest)
    manifest = store.read()
    observed_revision = 0 if manifest is None else manifest.revision
    if observed_revision != command.expected_authority_revision:
        raise LocalProtocolError("store authority manifest revision differs from explicit input")
    return store


def _ensure_run(ledger: MigrationRepository, command: MigrationCommand) -> None:
    ledger.ensure_run(
        MigrationRun(
            run_id=command.run_id,
            quarantine_ref=command.quarantine_ref,
            generation_ref=command.generation_ref,
            context_ref=command.context_ref,
            source_size_limit=command.source_size_limit,
            transformation_policy=command.transformation_policy,
            expected_authority_revision=command.expected_authority_revision,
            created_at=command.created_at.isoformat(),
        )
    )


def _recover_without_legacy(
    *,
    command: MigrationCommand,
    ledger: MigrationRepository,
    manifest_store: StoreAuthorityManifestStore,
    now: datetime,
) -> MigrationResult | None:
    _ensure_run(ledger, command)
    lease = ledger.acquire_lease(
        run_id=command.run_id,
        owner_id=command.owner_id,
        now=now,
        expires_at=command.lease_expires_at,
    )
    return recover_committed_migration(
        command=command,
        ledger=ledger,
        lease=lease,
        manifest_store=manifest_store,
        now=now,
    )


def _run_migration(
    args: argparse.Namespace,
    *,
    command: MigrationCommand,
    paths: _MigrationPaths,
    ledger: MigrationRepository,
    manifest_store: StoreAuthorityManifestStore,
    stop_before_cutover: bool,
) -> MigrationResult | None:
    cipher, custody = _migration_crypto(args, paths)

    def phase_observer(phase: str) -> None:
        if stop_before_cutover and phase == "awaiting_cutover":
            raise _AwaitingCutover

    try:
        with _held_source(paths) as (source, barrier):
            return migrate_legacy_store(
                command=command,
                source_connection=source,
                source_barrier=barrier,
                workers_stopped=args.workers_stopped,
                ledger=ledger,
                manifest_store=manifest_store,
                generation_path=paths.generation,
                ciphertext_path=paths.ciphertext,
                wrapped_key_path=paths.wrapped_key,
                cipher=cipher,
                custody=custody,
                now=_utc(args.now),
                forbidden_markers=_forbidden_markers(args),
                phase_observer=phase_observer,
            )
    except _AwaitingCutover:
        return None


def _require_phase_prefix(phases: tuple[str, ...]) -> None:
    if phases != MIGRATION_PHASES[: len(phases)]:
        raise LocalProtocolError("migration ledger phases are not an exact ordered prefix")


def _awaiting_response(
    command: MigrationCommand, ledger: MigrationRepository
) -> dict[str, Any]:
    phases = ledger.phases(command.run_id)
    _require_phase_prefix(phases)
    if not phases or phases[-1] != "awaiting_cutover":
        raise LocalProtocolError("migration did not reach the cutover confirmation boundary")
    return {
        "state": "awaiting_cutover",
        "run_ref": command.run_id,
        "generation_ref": command.generation_ref,
        "phases": list(phases),
    }


def _completed_response(
    command: MigrationCommand,
    ledger: MigrationRepository,
    result: MigrationResult,
) -> dict[str, Any]:
    phases = ledger.phases(command.run_id)
    _require_phase_prefix(phases)
    return {
        "state": "recovered" if result.recovered_after_cutover else "completed",
        "run_ref": result.run_id,
        "generation_ref": command.generation_ref,
        "profile_ref": result.profile_id,
        "disposition_counts": dict(result.disposition_counts),
        "phases": list(phases),
    }


def command_migration_preflight(args: argparse.Namespace) -> dict[str, Any]:
    command = _migration_command(args)
    paths = _migration_paths(args)
    _validate_migration_inputs(args, paths, new_run=True)
    _manifest_store_at_expected_revision(command, paths)
    cipher, custody = _migration_crypto(args, paths)
    probe = encrypt_quarantine(
        b"a0-migration-preflight",
        quarantine_ref=command.quarantine_ref,
        revision=command.quarantine_revision,
        cipher=cipher,
        custody=custody,
    )
    if decrypt_quarantine(probe, cipher=cipher, custody=custody) != b"a0-migration-preflight":
        raise LocalProtocolError("migration custody preflight did not round-trip")
    with _held_source(paths) as (source, barrier):
        if barrier.held is not True or source.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise LocalProtocolError("legacy SQLite source failed integrity preflight")
    return {
        "state": "ready",
        "run_ref": command.run_id,
        "generation_ref": command.generation_ref,
        "expected_authority_revision": command.expected_authority_revision,
        "source_mutation_barrier": "sqlite-immediate",
    }


def command_migration_start(args: argparse.Namespace) -> dict[str, Any]:
    command = _migration_command(args)
    paths = _migration_paths(args)
    _validate_migration_inputs(args, paths, new_run=True)
    manifest_store = _manifest_store_at_expected_revision(command, paths)
    with MigrationRepository.create(paths.ledger) as ledger:
        result = _run_migration(
            args,
            command=command,
            paths=paths,
            ledger=ledger,
            manifest_store=manifest_store,
            stop_before_cutover=True,
        )
        if result is not None:
            return _completed_response(command, ledger, result)
        return _awaiting_response(command, ledger)


def command_migration_resume(args: argparse.Namespace) -> dict[str, Any]:
    command = _migration_command(args)
    paths = _migration_paths(args)
    _validate_migration_flags(args)
    _owned_existing_file(paths.ledger, "ledger")
    _owned_output_path(paths.manifest, "manifest", must_be_new=False)
    manifest_store = StoreAuthorityManifestStore(paths.manifest)
    with MigrationRepository.open(paths.ledger) as ledger:
        recovered = _recover_without_legacy(
            command=command,
            ledger=ledger,
            manifest_store=manifest_store,
            now=_utc(args.now),
        )
        if recovered is not None:
            return _completed_response(command, ledger, recovered)
        _validate_migration_inputs(args, paths, new_run=False)
        _manifest_store_at_expected_revision(command, paths)
        phases = ledger.phases(command.run_id)
        _require_phase_prefix(phases)
        if phases and phases[-1] == "awaiting_cutover":
            return _awaiting_response(command, ledger)
        result = _run_migration(
            args,
            command=command,
            paths=paths,
            ledger=ledger,
            manifest_store=manifest_store,
            stop_before_cutover=True,
        )
        if result is not None:
            return _completed_response(command, ledger, result)
        return _awaiting_response(command, ledger)


def command_migration_confirm_cutover(args: argparse.Namespace) -> dict[str, Any]:
    if args.confirm != MIGRATION_CUTOVER_CONFIRMATION:
        raise LocalProtocolError("explicit migration cutover confirmation is required")
    command = _migration_command(args)
    paths = _migration_paths(args)
    _validate_migration_flags(args)
    _owned_existing_file(paths.ledger, "ledger")
    _owned_output_path(paths.manifest, "manifest", must_be_new=False)
    manifest_store = StoreAuthorityManifestStore(paths.manifest)
    with MigrationRepository.open(paths.ledger) as ledger:
        recovered = _recover_without_legacy(
            command=command,
            ledger=ledger,
            manifest_store=manifest_store,
            now=_utc(args.now),
        )
        if recovered is not None:
            return _completed_response(command, ledger, recovered)
        _validate_migration_inputs(args, paths, new_run=False)
        _manifest_store_at_expected_revision(command, paths)
        phases = ledger.phases(command.run_id)
        _require_phase_prefix(phases)
        if phases != MIGRATION_PHASES[: MIGRATION_PHASES.index("cutover_committed")]:
            raise LocalProtocolError("cutover confirmation requires exact awaiting-cutover state")
        result = _run_migration(
            args,
            command=command,
            paths=paths,
            ledger=ledger,
            manifest_store=manifest_store,
            stop_before_cutover=False,
        )
        if result is None:
            raise LocalProtocolError("cutover did not return a verified migration result")
        return _completed_response(command, ledger, result)


def command_migration_inspect(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = _owned_existing_file(_absolute(args.ledger), "ledger")
    manifest_path = _absolute(args.manifest)
    _owned_output_path(manifest_path, "manifest", must_be_new=False)
    with MigrationRepository.open(ledger_path) as ledger:
        phases = ledger.phases(args.run_id)
        _require_phase_prefix(phases)
        checkpoints = [ledger.checkpoint(args.run_id, phase) for phase in phases]
        receipt = ledger.receipt(args.run_id)
    receipt_payload = None
    if receipt is not None:
        decoded = canonical_loads(receipt)
        receipt_payload = MIGRATION_REGISTRY.schema(
            MIGRATION_RECEIPT_SCHEMA_ID, "migration_receipt"
        ).validate(decoded)
        if canonical_json(receipt_payload) != receipt:
            raise LocalProtocolError("migration receipt is not exact canonical bytes")
        if (
            receipt_payload["run_id"] != args.run_id
            or receipt_payload["generation_ref"] != args.generation_ref
            or receipt_payload["context_ref"] != args.context
            or receipt_payload["expected_authority_revision"]
            != args.expected_authority_revision
        ):
            raise LocalProtocolError("migration receipt differs from inspection bindings")
    manifest = StoreAuthorityManifestStore(manifest_path).read()
    if manifest is not None:
        if (
            manifest.revision != args.expected_authority_revision + 1
            or manifest.generation_ref != args.generation_ref
            or receipt is None
            or manifest.migration_receipt != receipt
        ):
            raise LocalProtocolError("manifest differs from inspection bindings")
    cutover_state = (
        "committed"
        if manifest is not None
        else "awaiting_confirmation"
        if phases and phases[-1] == "awaiting_cutover"
        else "not_committed"
        if phases
        else "not_observed"
    )
    return {
        "state": "inspected",
        "run_ref": args.run_id,
        "generation_ref": args.generation_ref,
        "phases": list(phases),
        "phase_counts": {
            checkpoint.phase: dict(checkpoint.counts)
            for checkpoint in checkpoints
            if checkpoint is not None
        },
        "receipt_present": receipt_payload is not None,
        "cutover_state": cutover_state,
        "manifest_revision": None if manifest is None else manifest.revision,
        "manifest_digest": None if manifest is None else manifest.initial_digest,
    }


class _DeletionIntentAdmitted(RuntimeError):
    def __init__(self, progress: DeletionProgress) -> None:
        super().__init__("deletion intent durably admitted")
        self.progress = progress


class _IntentOnlyLifecycleLedger:
    """Stop the coordinator after atomic challenge consumption and intent append."""

    def __init__(self, repository: MigrationRepository) -> None:
        self._repository = repository

    def resolve_export_receipt(self, receipt_ref: str):
        return self._repository.resolve_export_receipt(receipt_ref)

    def resolve_export_waiver(self, waiver_ref: str):
        return self._repository.resolve_export_waiver(waiver_ref)

    def consume_challenge_and_begin(self, consumption, intent):
        progress = self._repository.consume_challenge_and_begin(consumption, intent)
        raise _DeletionIntentAdmitted(progress)


def _owned_directory(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LocalProtocolError(f"{field} is unavailable") from exc
    if (
        resolved != path
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise LocalProtocolError(f"{field} must be an exact current-owner directory")
    return path


def _privacy_authority(
    args: argparse.Namespace,
    *,
    action: str,
    purpose: str,
):
    secret = _owned_existing_file(_absolute(args.secret), "secret")
    profile = _owned_existing_file(_absolute(args.profile), "profile")
    grant_path = _owned_existing_file(_absolute(args.grant), "grant")
    revocations = RevocationFileLedger(
        _owned_directory(_absolute(args.revocation_ledger), "revocation-ledger")
    )
    now = _utc(args.now)
    expectation = GrantExpectation(
        authority_class=args.authority_class,
        issuer_id=args.issuer,
        subject_ref=args.subject,
        context_ref=args.context,
        action=action,
        purpose=purpose,
        target_ref=args.quarantine_ref,
        target_revision=args.quarantine_revision,
        expires_at=_utc(args.authority_expires_at),
        idempotency_key_digest=digest_idempotency_key(args.idempotency_key),
        session_nonce=args.session_nonce,
    )
    return (
        _read_json(grant_path),
        expectation,
        LocalGrantVerifier(secret, profile, revocations),
        now,
    )


def _privacy_crypto(args: argparse.Namespace):
    if args.cipher_profile != AES_256_GCM:
        raise LocalProtocolError("unsupported quarantine cipher profile")
    cipher = AES256GCMCipher()
    custody = AES256GCMKeyCustody(
        args.custody_key_ref,
        _load_opaque_key(_absolute(args.custody_key)),
        cipher=cipher,
    )
    return cipher, custody


def _require_retained_binding(
    repository: MigrationRepository,
    args: argparse.Namespace,
    *,
    require_files: bool,
):
    retained = repository.resolve_retained(
        args.quarantine_ref, args.quarantine_revision
    )
    ciphertext = _absolute(args.quarantine_ciphertext)
    wrapped_key = _absolute(args.quarantine_wrapped_key)
    if (
        retained.ciphertext_path != ciphertext
        or retained.wrapped_key_path != wrapped_key
        or ciphertext == wrapped_key
    ):
        raise LocalProtocolError("explicit encrypted paths differ from retained custody")
    if require_files:
        _owned_existing_file(ciphertext, "quarantine-ciphertext")
        _owned_existing_file(wrapped_key, "quarantine-wrapped-key")
    return retained


def command_quarantine_export(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = _owned_existing_file(_absolute(args.ledger), "ledger")
    destination = _owned_directory(_absolute(args.destination), "destination")
    envelope, expectation, authorizer, now = _privacy_authority(
        args,
        action=AuthorityAction.QUARANTINE_EXPORT.value,
        purpose=AuthorityPurpose.QUARANTINE_EXPORT.value,
    )
    cipher, custody = _privacy_crypto(args)
    with MigrationRepository.open(ledger_path) as repository:
        _require_retained_binding(repository, args, require_files=True)
        receipt = export_quarantine(
            args.quarantine_ref,
            args.quarantine_revision,
            grant_envelope=envelope,
            grant_expectation=expectation,
            authorizer=authorizer,
            quarantine_ledger=repository,
            lifecycle_ledger=repository,
            cipher=cipher,
            custody=custody,
            destination=destination,
            now=now,
        )
    return {
        "state": "exported",
        "quarantine_ref": receipt.quarantine_ref,
        "quarantine_revision": receipt.revision,
        "export_receipt_ref": receipt.receipt_ref,
        "archive_ref": receipt.archive_ref,
        "archive_digest": receipt.archive_digest,
        "contains_plaintext": receipt.contains_plaintext,
    }


def command_quarantine_export_waive(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = _owned_existing_file(_absolute(args.ledger), "ledger")
    envelope, expectation, authorizer, now = _privacy_authority(
        args,
        action=AuthorityAction.QUARANTINE_DELETE.value,
        purpose=AuthorityPurpose.QUARANTINE_DELETION.value,
    )
    with MigrationRepository.open(ledger_path) as repository:
        repository.resolve_retained(args.quarantine_ref, args.quarantine_revision)
        waiver = issue_export_waiver(
            args.quarantine_ref,
            args.quarantine_revision,
            grant_envelope=envelope,
            grant_expectation=expectation,
            authorizer=authorizer,
            lifecycle_ledger=repository,
            acknowledgement=args.acknowledgement,
            now=now,
        )
    return {
        "state": "export_waived",
        "quarantine_ref": waiver.quarantine_ref,
        "quarantine_revision": waiver.revision,
        "export_waiver_ref": waiver.waiver_ref,
        "acknowledgement": waiver.acknowledgement,
    }


def command_quarantine_delete_challenge(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = _owned_existing_file(_absolute(args.ledger), "ledger")
    envelope, expectation, authorizer, now = _privacy_authority(
        args,
        action=AuthorityAction.QUARANTINE_DELETE.value,
        purpose=AuthorityPurpose.QUARANTINE_DELETION.value,
    )
    with MigrationRepository.open(ledger_path) as repository:
        repository.resolve_retained(args.quarantine_ref, args.quarantine_revision)
        challenge = issue_deletion_challenge(
            args.quarantine_ref,
            args.quarantine_revision,
            grant_envelope=envelope,
            grant_expectation=expectation,
            authorizer=authorizer,
            lifecycle_ledger=repository,
            now=now,
            expires_at=_utc(args.challenge_expires_at),
        )
    return {
        "state": "challenge_issued",
        "quarantine_ref": challenge.quarantine_ref,
        "quarantine_revision": challenge.revision,
        "challenge_ref": challenge.challenge_ref,
        "expires_at": challenge.expires_at,
        "required_confirmation": challenge.required_confirmation,
    }


def _require_progress_bindings(progress: DeletionProgress, args: argparse.Namespace) -> None:
    intent = progress.intent
    if (
        intent.operation_ref != args.operation_ref
        or intent.quarantine_ref != args.quarantine_ref
        or intent.revision != args.quarantine_revision
        or intent.challenge_ref != args.challenge_ref
        or intent.evidence_kind != args.evidence_kind
        or intent.evidence_ref != args.evidence_ref
    ):
        raise LocalProtocolError("deletion resume inputs differ from durable intent")


def command_quarantine_delete(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = _owned_existing_file(_absolute(args.ledger), "ledger")
    envelope, expectation, authorizer, now = _privacy_authority(
        args,
        action=AuthorityAction.QUARANTINE_DELETE.value,
        purpose=AuthorityPurpose.QUARANTINE_DELETION.value,
    )
    evidence = DeletionEvidenceRef(args.evidence_kind, args.evidence_ref)
    with MigrationRepository.open(ledger_path) as repository:
        _require_retained_binding(
            repository, args, require_files=args.deletion_mode == "begin"
        )
        if args.deletion_mode == "begin":
            cipher, custody = _privacy_crypto(args)
            try:
                delete_quarantine(
                    args.quarantine_ref,
                    args.quarantine_revision,
                    grant_envelope=envelope,
                    grant_expectation=expectation,
                    authorizer=authorizer,
                    quarantine_ledger=repository,
                    lifecycle_ledger=_IntentOnlyLifecycleLedger(repository),
                    cipher=cipher,
                    custody=custody,
                    challenge_ref=args.challenge_ref,
                    typed_confirmation=args.typed_confirmation,
                    evidence=evidence,
                    now=now,
                )
            except _DeletionIntentAdmitted as admitted:
                progress = admitted.progress
            else:  # pragma: no cover - the intent-only ledger always interrupts
                raise LocalProtocolError("deletion intent was not durably admitted")
            return {
                "state": "intent_admitted",
                "quarantine_ref": progress.intent.quarantine_ref,
                "quarantine_revision": progress.intent.revision,
                "operation_ref": progress.intent.operation_ref,
                "wrapped_key_unlinked": progress.wrapped_key_unlinked,
                "ciphertext_unlinked": progress.ciphertext_unlinked,
            }

        progress = repository.load_deletion(args.operation_ref)
        _require_progress_bindings(progress, args)
        verified = authorizer.authorize(envelope, expectation, now=now)
        if verified.grant_id != progress.intent.authority_ref:
            raise LocalProtocolError("deletion resume grant differs from durable intent")
        receipt = resume_cryptographic_deletion(
            args.operation_ref,
            quarantine_ledger=repository,
            lifecycle_ledger=repository,
            now=now,
        )
    return {
        "state": "deleted",
        "quarantine_ref": receipt.quarantine_ref,
        "quarantine_revision": receipt.revision,
        "operation_ref": receipt.operation_ref,
        "deletion_receipt_ref": receipt.receipt_ref,
        "deletion_method": receipt.deletion_method,
        "wrapped_key_unlinked": receipt.wrapped_key_unlinked,
        "ciphertext_unlinked": receipt.ciphertext_unlinked,
        "physical_overwrite_claimed": receipt.physical_overwrite_claimed,
    }


def command_quarantine_delete_inspect(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = _owned_existing_file(_absolute(args.ledger), "ledger")
    with MigrationRepository.open(ledger_path) as repository:
        _require_retained_binding(repository, args, require_files=False)
        progress = repository.load_deletion(args.operation_ref)
    if (
        progress.intent.quarantine_ref != args.quarantine_ref
        or progress.intent.revision != args.quarantine_revision
    ):
        raise LocalProtocolError("deletion inspection differs from durable intent")
    state = (
        "completed"
        if progress.receipt is not None
        else "ciphertext_unlinked"
        if progress.ciphertext_unlinked
        else "wrapped_key_unlinked"
        if progress.wrapped_key_unlinked
        else "intent_admitted"
    )
    return {
        "state": state,
        "quarantine_ref": progress.intent.quarantine_ref,
        "quarantine_revision": progress.intent.revision,
        "operation_ref": progress.intent.operation_ref,
        "evidence_kind": progress.intent.evidence_kind,
        "evidence_ref": progress.intent.evidence_ref,
        "wrapped_key_unlinked": progress.wrapped_key_unlinked,
        "ciphertext_unlinked": progress.ciphertext_unlinked,
        "deletion_receipt_ref": (
            None if progress.receipt is None else progress.receipt.receipt_ref
        ),
        "physical_overwrite_claimed": (
            None
            if progress.receipt is None
            else progress.receipt.physical_overwrite_claimed
        ),
    }


def _exact(record_id: str, digest: str) -> ExactRecord:
    return ExactRecord(record_id, digest)


def _activation_authorities(values: Sequence[str]) -> tuple[str, ...]:
    result = tuple(sorted(values))
    if not result or len(result) != len(set(result)):
        raise LocalProtocolError("activation authorities must be explicit and unique")
    return result


def _calibration_revalidator(
    args: argparse.Namespace,
    *,
    expected_operation: str,
    policy: ExactRecord,
    canary_plan_record: ExactRecord,
    monitor_plan_record: ExactRecord,
):
    envelope = _read_json(_absolute(args.grant))
    verifier = LocalGrantVerifier(
        _absolute(args.secret),
        _absolute(args.profile),
        RevocationFileLedger(_absolute(args.revocation_ledger)),
    )
    now = _utc(args.now)
    authority_expires_at = _utc(args.authority_expires_at)

    def revalidate(binding: CalibrationGrantBinding):
        if (
            binding.operation != expected_operation
            or binding.issuer_ref != args.issuer
            or binding.subject_ref != args.subject
            or binding.context_ref != args.context
            or binding.environment_ref != args.environment
            or binding.target_revision != args.policy_revision
            or binding.policy != policy
            or binding.canary_plan != canary_plan_record
            or binding.monitor_plan != monitor_plan_record
        ):
            raise LocalProtocolError("calibration grant binding differs from explicit CLI inputs")
        return verifier.authorize(
            envelope,
            GrantExpectation(
                authority_class=binding.authority_class,
                issuer_id=binding.issuer_ref,
                subject_ref=binding.subject_ref,
                context_ref=binding.context_ref,
                action=binding.action,
                purpose=binding.purpose,
                target_ref=binding.target_ref,
                target_revision=binding.target_revision,
                expires_at=authority_expires_at,
                idempotency_key_digest=binding.idempotency_key_digest,
                session_nonce=binding.session_nonce,
            ),
            now=now,
        )

    return revalidate


def command_calibration_approve(args: argparse.Namespace) -> dict[str, Any]:
    store = _absolute(args.store)
    policy = _exact(args.policy_id, args.policy_digest)
    canary = _exact(args.canary_plan_id, args.canary_plan_digest)
    monitor = _exact(args.monitor_plan_id, args.monitor_plan_digest)
    request = CalibrationApprovalRequest(
        calibration_id=args.calibration_id,
        receipt_id=args.receipt_id,
        context_ref=args.context,
        expected_policy_revision=args.policy_revision,
        environment_ref=args.environment,
        policy=policy,
        canary_plan=canary,
        monitor_plan=monitor,
        activation_authorities=_activation_authorities(args.activation_authority),
        soft_rollback_authorized=args.soft_rollback_authorized,
        issuer_ref=args.issuer,
        subject_ref=args.subject,
        idempotency_key_digest=digest_idempotency_key(args.idempotency_key),
        session_nonce=args.session_nonce,
        reason_code=args.reason_code,
        key_epoch=args.key_epoch,
    )
    revalidate = _calibration_revalidator(
        args,
        expected_operation="approve",
        policy=policy,
        canary_plan_record=canary,
        monitor_plan_record=monitor,
    )
    with V3Repository.open(store, registry=V3_REGISTRY) as repository:
        result = approve_policy_calibration(
            repository,
            request=request,
            revalidate_grant=revalidate,
        )
    return {
        "state": "replayed" if result.replayed else "approved",
        "calibration_ref": result.calibration.record_id,
        "receipt_ref": result.receipt.record_id,
        "eligibility": "approved",
    }


def _require_withdrawal_snapshot(
    repository: V3Repository,
    args: argparse.Namespace,
    *,
    calibration: ExactRecord,
    policy: ExactRecord,
    canary: ExactRecord,
    monitor: ExactRecord,
    activation_authorities: tuple[str, ...],
) -> None:
    record = repository.get_record(calibration.record_id)
    if (
        record is None
        or record.content_digest != calibration.digest
        or record.schema_id != POLICY_CALIBRATION_SCHEMA_ID
        or record.record_kind != "policy_calibration"
        or record.context_ref != args.context
    ):
        raise IntegrityFailure("missing, cross-context, or tampered policy_calibration")
    payload = record.payload
    if (
        payload["environment_ref"] != args.environment
        or payload["policy_revision"] != args.policy_revision
        or (payload["policy_id"], payload["policy_digest"])
        != (policy.record_id, policy.digest)
        or (payload["canary_plan_id"], payload["canary_plan_digest"])
        != (canary.record_id, canary.digest)
        or (payload["monitor_plan_id"], payload["monitor_plan_digest"])
        != (monitor.record_id, monitor.digest)
        or tuple(payload["activation_authorities"]) != activation_authorities
        or payload["soft_rollback_authorized"] is not args.soft_rollback_authorized
    ):
        raise IntegrityFailure("withdrawal snapshot differs from explicit CLI inputs")


def command_calibration_withdraw(args: argparse.Namespace) -> dict[str, Any]:
    store = _absolute(args.store)
    calibration = _exact(args.calibration_id, args.calibration_digest)
    policy = _exact(args.policy_id, args.policy_digest)
    canary = _exact(args.canary_plan_id, args.canary_plan_digest)
    monitor = _exact(args.monitor_plan_id, args.monitor_plan_digest)
    authorities = _activation_authorities(args.activation_authority)
    request = CalibrationWithdrawalRequest(
        receipt_id=args.receipt_id,
        context_ref=args.context,
        expected_policy_revision=args.policy_revision,
        environment_ref=args.environment,
        calibration=calibration,
        issuer_ref=args.issuer,
        subject_ref=args.subject,
        idempotency_key_digest=digest_idempotency_key(args.idempotency_key),
        session_nonce=args.session_nonce,
        reason_code=args.reason_code,
        key_epoch=args.key_epoch,
    )
    revalidate = _calibration_revalidator(
        args,
        expected_operation="withdraw",
        policy=policy,
        canary_plan_record=canary,
        monitor_plan_record=monitor,
    )
    with V3Repository.open(store, registry=V3_REGISTRY) as repository:
        _require_withdrawal_snapshot(
            repository,
            args,
            calibration=calibration,
            policy=policy,
            canary=canary,
            monitor=monitor,
            activation_authorities=authorities,
        )
        result = withdraw_policy_calibration(
            repository,
            request=request,
            revalidate_grant=revalidate,
        )
    return {
        "state": "replayed" if result.replayed else "withdrawn",
        "calibration_ref": result.calibration.record_id,
        "receipt_ref": result.receipt.record_id,
        "eligibility": "withdrawn",
    }


def command_calibration_inspect(args: argparse.Namespace) -> dict[str, Any]:
    store = _absolute(args.store)
    calibration = _exact(args.calibration_id, args.calibration_digest)
    with V3Reader.open(store, registry=V3_REGISTRY) as reader:
        record = reader.get_record(calibration.record_id)
        if (
            record is None
            or record.content_digest != calibration.digest
            or record.schema_id != POLICY_CALIBRATION_SCHEMA_ID
            or record.record_kind != "policy_calibration"
            or record.context_ref != args.context
        ):
            raise IntegrityFailure("missing, cross-context, or tampered policy_calibration")
        observations = reader.list_domain_events_for_context(
            args.context, maximum=args.maximum_events
        )
        facts: list[CalibrationLifecycleFact] = []
        for observation in observations:
            event = observation.event
            if event.subject_id != record.record_id or event.subject_kind != "policy_calibration":
                continue
            receipt = (
                reader.get_record(event.payload_record_id)
                if event.payload_record_id is not None
                else None
            )
            if receipt is None:
                raise IntegrityFailure("calibration lifecycle event lost its receipt")
            facts.append(CalibrationLifecycleFact(receipt, event))
        eligibility = reduce_calibration_eligibility(record, tuple(facts))
    return {
        "state": "inspected",
        "calibration_ref": record.record_id,
        "eligibility": eligibility.state,
        "reason_codes": list(eligibility.reason_codes),
        "receipt_refs": [fact.receipt.record_id for fact in facts],
    }


def _add_calibration_mutation_arguments(parser: argparse.ArgumentParser) -> None:
    for name in (
        "store",
        "receipt-id",
        "context",
        "environment",
        "policy-id",
        "policy-digest",
        "canary-plan-id",
        "canary-plan-digest",
        "monitor-plan-id",
        "monitor-plan-digest",
        "issuer",
        "subject",
        "profile",
        "secret",
        "grant",
        "revocation-ledger",
        "session-nonce",
        "idempotency-key",
        "authority-expires-at",
        "now",
        "key-epoch",
    ):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--policy-revision", required=True, type=_positive_integer)
    parser.add_argument(
        "--activation-authority",
        action="append",
        required=True,
        choices=("automatic", "manual"),
    )
    parser.add_argument(
        "--soft-rollback-authorized", required=True, type=_strict_boolean
    )


def _add_migration_arguments(parser: argparse.ArgumentParser) -> None:
    for name in (
        "run-id",
        "owner-id",
        "source-store",
        "source-context-id",
        "transformation-policy",
        "generation-ref",
        "generation-path",
        "context",
        "quarantine-ref",
        "quarantine-ciphertext",
        "quarantine-wrapped-key",
        "ledger",
        "manifest",
        "key-epoch",
        "created-at",
        "now",
        "lease-expires-at",
        "custody-key",
        "custody-key-ref",
    ):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--source-size-limit", required=True, type=_positive_integer)
    parser.add_argument("--quarantine-revision", required=True, type=_positive_integer)
    parser.add_argument(
        "--expected-authority-revision", required=True, type=_nonnegative_integer
    )
    parser.add_argument("--workers-stopped", required=True, type=_strict_boolean)
    parser.add_argument(
        "--source-mutation-barrier",
        required=True,
        choices=("sqlite-immediate",),
    )
    parser.add_argument("--cipher-profile", required=True, choices=(AES_256_GCM,))
    parser.add_argument("--forbidden-marker", action="append", required=True)


def _add_privacy_grant_arguments(parser: argparse.ArgumentParser) -> None:
    for name in (
        "ledger",
        "quarantine-ref",
        "secret",
        "profile",
        "grant",
        "revocation-ledger",
        "issuer",
        "subject",
        "context",
        "authority-expires-at",
        "idempotency-key",
        "session-nonce",
        "now",
    ):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--quarantine-revision", required=True, type=_positive_integer)
    parser.add_argument(
        "--authority-class",
        required=True,
        choices=(AuthorityClass.OPERATOR_AUTHORITY_GRANT.value,),
    )


def _add_quarantine_crypto_arguments(parser: argparse.ArgumentParser) -> None:
    for name in (
        "custody-key",
        "custody-key-ref",
        "quarantine-ciphertext",
        "quarantine-wrapped-key",
    ):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--cipher-profile", required=True, choices=(AES_256_GCM,))


def _add_deletion_evidence_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--evidence-kind",
        required=True,
        choices=("export_receipt", "export_waiver"),
    )
    parser.add_argument("--evidence-ref", required=True)
    parser.add_argument("--challenge-ref", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    bootstrap = commands.add_parser("issuer-bootstrap")
    bootstrap.add_argument("--secret", required=True)
    bootstrap.add_argument("--profile", required=True)
    bootstrap.add_argument("--issuer", required=True)
    bootstrap.add_argument("--key-epoch", required=True, type=int)
    bootstrap.add_argument(
        "--authority-class",
        action="append",
        required=True,
        choices=[item.value for item in AuthorityClass],
    )
    bootstrap.add_argument("--confirm", required=True, help=f"must equal {BOOTSTRAP_CONFIRMATION}")
    bootstrap.set_defaults(handler=command_bootstrap)

    opaque = commands.add_parser("opaque-key-bootstrap")
    opaque.add_argument("--output", required=True)
    opaque.add_argument("--key-epoch", required=True)
    opaque.add_argument("--confirm", required=True)
    opaque.set_defaults(handler=command_opaque_key_bootstrap)

    grant = commands.add_parser("grant-issue")
    for name in ("secret", "profile", "output", "subject", "context", "action", "purpose", "target", "issued-at", "expires-at", "idempotency-key", "session-nonce"):
        grant.add_argument(f"--{name}", required=True)
    grant.add_argument("--authority-class", required=True, choices=[item.value for item in AuthorityClass])
    grant.add_argument("--target-revision", required=True, type=int)
    grant.set_defaults(handler=command_grant_issue)

    inspect = commands.add_parser("grant-inspect")
    for name in ("secret", "profile", "grant", "now"):
        inspect.add_argument(f"--{name}", required=True)
    inspect.add_argument("--revocation", action="append", default=[])
    inspect.set_defaults(handler=command_grant_inspect)

    revoke = commands.add_parser("grant-revoke")
    for name in ("secret", "profile", "grant-id", "context", "revoked-at", "idempotency-key", "ledger-dir"):
        revoke.add_argument(f"--{name}", required=True)
    revoke.add_argument("--output")
    revoke.add_argument(
        "--reason-code",
        required=True,
        choices=[item.value for item in RevocationReason],
    )
    revoke.set_defaults(handler=command_grant_revoke)

    genesis = commands.add_parser("genesis")
    for name in ("store", "secret", "profile", "grant", "opaque-key", "opaque-key-epoch", "subject", "context", "target", "idempotency-key", "session-nonce", "authority-expires-at", "now"):
        genesis.add_argument(f"--{name}", required=True)
    genesis.add_argument("--reason-code", choices=["operator_requested", "recovery_requested"], default="operator_requested")
    genesis.add_argument("--create-store", action="store_true")
    genesis.add_argument("--revocation", action="append", default=[])
    genesis.set_defaults(handler=command_genesis)

    readiness = commands.add_parser("readiness-inspect")
    for name in ("store", "manifest", "context"):
        readiness.add_argument(f"--{name}", required=True)
    readiness.set_defaults(handler=command_readiness_inspect)

    project_readiness = commands.add_parser("project-readiness-inspect")
    for name in ("store", "manifest", "chats-dir", "project"):
        project_readiness.add_argument(f"--{name}", required=True)
    project_readiness.set_defaults(handler=command_project_readiness_inspect)

    project_genesis = commands.add_parser("project-genesis")
    for name in (
        "store",
        "manifest",
        "chats-dir",
        "project",
        "secret",
        "profile",
        "opaque-key",
        "opaque-key-epoch",
        "grant-dir",
        "subject",
        "idempotency-prefix",
        "session-nonce-prefix",
        "authority-expires-at",
        "now",
        "confirm",
    ):
        project_genesis.add_argument(f"--{name}", required=True)
    project_genesis.add_argument(
        "--reason-code",
        choices=["operator_requested", "recovery_requested"],
        default="operator_requested",
    )
    project_genesis.add_argument("--create-store", action="store_true")
    project_genesis.set_defaults(handler=command_project_genesis)

    migration_preflight = commands.add_parser("migration-preflight")
    _add_migration_arguments(migration_preflight)
    migration_preflight.set_defaults(handler=command_migration_preflight)

    migration_start = commands.add_parser("migration-start")
    _add_migration_arguments(migration_start)
    migration_start.set_defaults(handler=command_migration_start)

    migration_resume = commands.add_parser("migration-resume")
    _add_migration_arguments(migration_resume)
    migration_resume.set_defaults(handler=command_migration_resume)

    migration_confirm = commands.add_parser("migration-confirm-cutover")
    _add_migration_arguments(migration_confirm)
    migration_confirm.add_argument(
        "--confirm", required=True, choices=(MIGRATION_CUTOVER_CONFIRMATION,)
    )
    migration_confirm.set_defaults(handler=command_migration_confirm_cutover)

    migration_inspect = commands.add_parser("migration-inspect")
    for name in ("ledger", "manifest", "run-id", "generation-ref", "context"):
        migration_inspect.add_argument(f"--{name}", required=True)
    migration_inspect.add_argument(
        "--expected-authority-revision", required=True, type=_nonnegative_integer
    )
    migration_inspect.set_defaults(handler=command_migration_inspect)

    quarantine_export = commands.add_parser("quarantine-export")
    _add_privacy_grant_arguments(quarantine_export)
    _add_quarantine_crypto_arguments(quarantine_export)
    quarantine_export.add_argument("--destination", required=True)
    quarantine_export.set_defaults(handler=command_quarantine_export)

    quarantine_waive = commands.add_parser("quarantine-export-waive")
    _add_privacy_grant_arguments(quarantine_waive)
    quarantine_waive.add_argument(
        "--acknowledgement", required=True, choices=(WAIVER_ACKNOWLEDGEMENT,)
    )
    quarantine_waive.set_defaults(handler=command_quarantine_export_waive)

    quarantine_challenge = commands.add_parser("quarantine-delete-challenge")
    _add_privacy_grant_arguments(quarantine_challenge)
    quarantine_challenge.add_argument("--challenge-expires-at", required=True)
    quarantine_challenge.set_defaults(handler=command_quarantine_delete_challenge)

    quarantine_delete = commands.add_parser("quarantine-delete")
    deletion_modes = quarantine_delete.add_subparsers(
        dest="deletion_mode", required=True
    )
    quarantine_delete_begin = deletion_modes.add_parser("begin")
    _add_privacy_grant_arguments(quarantine_delete_begin)
    _add_quarantine_crypto_arguments(quarantine_delete_begin)
    _add_deletion_evidence_arguments(quarantine_delete_begin)
    quarantine_delete_begin.add_argument("--typed-confirmation", required=True)
    quarantine_delete_begin.set_defaults(handler=command_quarantine_delete)

    quarantine_delete_resume = deletion_modes.add_parser("resume")
    _add_privacy_grant_arguments(quarantine_delete_resume)
    for name in ("quarantine-ciphertext", "quarantine-wrapped-key"):
        quarantine_delete_resume.add_argument(f"--{name}", required=True)
    _add_deletion_evidence_arguments(quarantine_delete_resume)
    quarantine_delete_resume.add_argument("--operation-ref", required=True)
    quarantine_delete_resume.set_defaults(handler=command_quarantine_delete)

    quarantine_delete_inspect = commands.add_parser("quarantine-delete-inspect")
    for name in (
        "ledger",
        "quarantine-ref",
        "quarantine-ciphertext",
        "quarantine-wrapped-key",
        "operation-ref",
    ):
        quarantine_delete_inspect.add_argument(f"--{name}", required=True)
    quarantine_delete_inspect.add_argument(
        "--quarantine-revision", required=True, type=_positive_integer
    )
    quarantine_delete_inspect.set_defaults(
        handler=command_quarantine_delete_inspect
    )

    calibration_approve = commands.add_parser("calibration-approve")
    _add_calibration_mutation_arguments(calibration_approve)
    calibration_approve.add_argument("--calibration-id", required=True)
    calibration_approve.add_argument(
        "--reason-code", required=True, choices=("calibration_approved",)
    )
    calibration_approve.set_defaults(handler=command_calibration_approve)

    calibration_withdraw = commands.add_parser("calibration-withdraw")
    _add_calibration_mutation_arguments(calibration_withdraw)
    calibration_withdraw.add_argument("--calibration-id", required=True)
    calibration_withdraw.add_argument("--calibration-digest", required=True)
    calibration_withdraw.add_argument(
        "--reason-code",
        required=True,
        choices=(
            "authority_withdrawn",
            "calibration_withdrawn",
            "environment_retired",
            "policy_superseded",
        ),
    )
    calibration_withdraw.set_defaults(handler=command_calibration_withdraw)

    calibration_inspect = commands.add_parser("calibration-inspect")
    for name in ("store", "context", "calibration-id", "calibration-digest"):
        calibration_inspect.add_argument(f"--{name}", required=True)
    calibration_inspect.add_argument(
        "--maximum-events", required=True, type=_positive_integer
    )
    calibration_inspect.set_defaults(handler=command_calibration_inspect)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = args.handler(args)
    except Exception as exc:
        print(json.dumps({"ok": False, "reason_code": type(exc).__name__}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
