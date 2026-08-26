"""Operator-invoked, copy-on-write v2-to-v3 Migration Authority.

This module is deliberately local-only and dependency-injected.  It has no
network entry point, no implicit size threshold, no plaintext staging path,
and no fallback from a committed v3 authority manifest to the v2 source.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
from typing import Callable, Mapping, Protocol, runtime_checkable

from .artifacts import (
    DEFAULT_REGISTRY,
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from .migration_decoder import CompatibilityGuidanceMember, decode_legacy_snapshot
from .migration_repository import (
    MIGRATION_PHASES,
    MigrationDisposition,
    MigrationLease,
    MigrationRepository,
    MigrationRun,
)
from .quarantine import (
    EncryptedQuarantine,
    KeyCustody,
    QuarantineCipher,
    RetainedQuarantine,
    decrypt_quarantine,
    encrypt_quarantine,
)
from .repository import V3Reader, V3Repository
from .runtime_composer import compose_runtime
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    canonical_loads,
    strict_boolean,
    strict_integer,
    strict_list,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)
from .store_authority import StoreAuthorityManifestStore


COMPATIBILITY_GUIDANCE_SCHEMA_ID = "a0.self-improvement.compatibility-guidance-set.v1"
MIGRATION_RECEIPT_SCHEMA_ID = "a0.self-improvement.migration-receipt.v1"
POST_CUTOVER_RECEIPT_SCHEMA = "a0.self-improvement.post-cutover-verification-receipt.v1"
COMPATIBILITY_SELECTOR_ID = "a0.guidance-v1.last-objective-bucket-or-reasoning.v1"
COMPATIBILITY_RENDERER_ID = "a0.guidance-v1.system-prompt-renderer.v1"


class MigrationError(RuntimeError):
    """Base class for closed migration failures."""


class MigrationPreconditionError(MigrationError):
    pass


class MigrationVerificationError(MigrationError):
    pass


@runtime_checkable
class SourceMutationBarrier(Protocol):
    """Caller-owned barrier that must already be held before source capture."""

    @property
    def held(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class MigrationCommand:
    run_id: str
    owner_id: str
    quarantine_ref: str
    quarantine_revision: int
    generation_ref: str
    context_ref: str
    source_context_id: str
    source_size_limit: int
    transformation_policy: str
    expected_authority_revision: int
    key_epoch: str
    created_at: datetime
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class MigrationResult:
    run_id: str
    generation_path: Path
    profile_id: str
    migration_receipt: bytes
    disposition_counts: Mapping[str, int]
    recovered_after_cutover: bool


def _compatibility_member(value: object, path: str) -> dict[str, object]:
    rule = strict_object(
        {
            "rule_type": strict_string(maximum=128),
            "max_retries": strict_nullable(strict_integer(minimum=0, maximum=1000)),
        }
    )
    return strict_object(
        {
            "objective_bucket": strict_string(maximum=128),
            "rules": strict_list(rule, minimum=1, maximum=256),
            "engine_profile_id": strict_string(maximum=256),
            "engine_version": strict_string(maximum=128),
            "issued_at": strict_string(maximum=64),
            "expires_at": strict_string(maximum=64),
        }
    )(value, path)


def _migration_receipt(value: object, path: str) -> dict[str, object]:
    return strict_object(
        {
            "receipt_type": strict_literal("migration_cutover"),
            "run_id": strict_string(maximum=256),
            "generation_ref": strict_string(maximum=256),
            "context_ref": strict_string(maximum=256),
            "source_snapshot_digest": validate_digest,
            "target_projection_digest": validate_digest,
            "source_schema_version": strict_integer(minimum=1, maximum=2),
            "source_schema_variant": strict_string(maximum=64),
            "transformation_policy": strict_string(maximum=256),
            "expected_authority_revision": strict_integer(minimum=0),
            "disposition_counts": strict_object(
                {
                    "projected": strict_integer(minimum=0),
                    "quarantined": strict_integer(minimum=0),
                    "unsupported": strict_integer(minimum=0),
                    "invalid": strict_integer(minimum=0),
                }
            ),
            "profile_id": strict_string(maximum=512),
            "profile_digest": validate_digest,
            "compatibility_guidance_present": strict_boolean(),
            "links": validate_links,
        }
    )(value, path)


MIGRATION_REGISTRY = SchemaRegistry(
    (
        *DEFAULT_REGISTRY.schemas.values(),
        RecordSchema(
            schema_id=COMPATIBILITY_GUIDANCE_SCHEMA_ID,
            record_kind="guidance_artifact",
            payload_validator=strict_object(
                {
                    "artifact_type": strict_literal("compatibility_guidance_set"),
                    "legacy_schema": strict_literal("guidance.v1"),
                    "selector_id": strict_literal(COMPATIBILITY_SELECTOR_ID),
                    "renderer_id": strict_literal(COMPATIBILITY_RENDERER_ID),
                    "promotable": strict_literal(False),
                    "members": strict_list(_compatibility_member, minimum=1, maximum=1024),
                    "links": validate_links,
                }
            ),
        ),
        RecordSchema(
            schema_id=MIGRATION_RECEIPT_SCHEMA_ID,
            record_kind="migration_receipt",
            payload_validator=_migration_receipt,
        ),
    )
)


def _exact_text(value: object, field: str) -> str:
    if type(value) is not str or not value or "\x00" in value or len(value) > 2048:
        raise MigrationPreconditionError(f"{field} is not an exact bounded identity")
    return value


def _require_command(command: MigrationCommand) -> None:
    for field in (
        "run_id", "owner_id", "quarantine_ref", "generation_ref", "context_ref",
        "source_context_id", "transformation_policy", "key_epoch",
    ):
        _exact_text(getattr(command, field), field)
    if type(command.source_size_limit) is not int or command.source_size_limit <= 0:
        raise MigrationPreconditionError("source_size_limit must be explicitly positive")
    if type(command.quarantine_revision) is not int or command.quarantine_revision <= 0:
        raise MigrationPreconditionError("quarantine_revision must be positive")
    if type(command.expected_authority_revision) is not int or command.expected_authority_revision < 0:
        raise MigrationPreconditionError("expected_authority_revision must be non-negative")


def _phase(
    ledger: MigrationRepository,
    lease: MigrationLease,
    phase: str,
    *,
    input_digest: str,
    output_digest: str,
    counts: Mapping[str, int],
    now: datetime,
    observer: Callable[[str], None] | None,
) -> None:
    ledger.append_checkpoint(
        lease=lease, phase=phase, input_digest=input_digest,
        output_digest=output_digest, counts=counts, now=now,
    )
    if observer is not None:
        observer(phase)


def _capture_snapshot(connection: sqlite3.Connection, maximum: int) -> bytes:
    if not isinstance(connection, sqlite3.Connection):
        raise MigrationPreconditionError("an open SQLite source connection is required")
    if connection.in_transaction:
        raise MigrationPreconditionError("source connection must not have an open transaction")
    snapshot = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.backup(snapshot)
        raw_buffer = bytearray(snapshot.serialize())
        # SQLite backup copies the source file header, including WAL read/write
        # version bytes.  A deserialized in-memory database cannot open a WAL
        # sidecar, so normalize only those two transport bytes to rollback mode.
        # The logical pages are the exact WAL-consistent backup image.
        if len(raw_buffer) >= 20 and raw_buffer[:16] == b"SQLite format 3\x00":
            raw_buffer[18:20] = b"\x01\x01"
        raw = bytes(raw_buffer)
    finally:
        snapshot.close()
    if len(raw) > maximum:
        raise MigrationPreconditionError("WAL-consistent source snapshot exceeds the explicit limit")
    return raw


def _snapshot_connection(raw: bytes) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.deserialize(raw)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def _write_exclusive(path: Path, raw: bytes) -> str:
    if not path.is_absolute() or not path.parent.is_dir():
        raise MigrationPreconditionError("quarantine paths must be absolute with existing parents")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise MigrationError("quarantine write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return sha256(raw).hexdigest()


def _read_encrypted(ciphertext_path: Path, wrapped_key_path: Path) -> EncryptedQuarantine:
    return EncryptedQuarantine(ciphertext_path.read_bytes(), wrapped_key_path.read_bytes())


def _compatibility_record(
    command: MigrationCommand,
    members: tuple[CompatibilityGuidanceMember, ...],
) -> TypedRecord | None:
    selected = tuple(member for member in members if member.context_id == command.source_context_id)
    if not selected:
        return None
    safe_members = [
        {
            "objective_bucket": member.objective_bucket,
            "rules": [
                {"rule_type": rule.rule_type, "max_retries": rule.max_retries}
                for rule in member.rules
            ],
            "engine_profile_id": member.engine_profile_id,
            "engine_version": member.engine_version,
            "issued_at": member.issued_at,
            "expires_at": member.expires_at,
        }
        for member in sorted(selected, key=lambda item: item.objective_bucket)
    ]
    return build_typed_record(
        record_id=f"migration:{command.run_id}:compatibility-guidance",
        context_ref=command.context_ref,
        record_kind="guidance_artifact",
        schema_id=COMPATIBILITY_GUIDANCE_SCHEMA_ID,
        payload={
            "artifact_type": "compatibility_guidance_set",
            "legacy_schema": "guidance.v1",
            "selector_id": COMPATIBILITY_SELECTOR_ID,
            "renderer_id": COMPATIBILITY_RENDERER_ID,
            "promotable": False,
            "members": safe_members,
            "links": [],
        },
        key_epoch=command.key_epoch,
        registry=MIGRATION_REGISTRY,
    )


def _projection_digest(reader: V3Reader, profile_id: str) -> str:
    profile = reader.get_record(profile_id)
    if profile is None or profile.context_ref is None:
        raise MigrationVerificationError("staged activation profile is missing")
    scope = reader.get_activation_scope(profile.context_ref)
    if scope is None:
        raise MigrationVerificationError("staged activation profile is missing")
    records = [profile]
    for link in profile.links:
        target = reader.get_record(link.target_id)
        if target is None:
            raise MigrationVerificationError("staged profile link is missing")
        records.append(target)
    return sha256(
        canonical_json(
            {
                "records": sorted(
                    ({"record_id": item.record_id, "digest": item.content_digest} for item in records),
                    key=lambda item: item["record_id"],
                ),
                "scope": {
                    "context_ref": scope.context_ref,
                    "profile_id": scope.current_profile_id,
                    "profile_digest": scope.current_profile_digest,
                    "revision": scope.scope_revision,
                    "mode": scope.mode,
                },
            }
        )
    ).hexdigest()


def _assert_forbidden_absent(paths: tuple[Path, ...], markers: tuple[bytes, ...]) -> None:
    for marker in markers:
        if type(marker) is not bytes or not marker:
            raise MigrationPreconditionError("forbidden markers must be non-empty bytes")
    for path in paths:
        raw = path.read_bytes()
        if any(marker in raw for marker in markers):
            raise MigrationVerificationError(f"forbidden legacy content reached {path.name}")


def _parse_receipt(raw: bytes) -> dict[str, object]:
    payload = canonical_loads(raw)
    validated = _migration_receipt(payload, "receipt")
    if canonical_json(validated) != raw:
        raise MigrationVerificationError("manifest receipt is not exact canonical v3 schema")
    return validated


def recover_committed_migration(
    *,
    command: MigrationCommand,
    ledger: MigrationRepository,
    lease: MigrationLease,
    manifest_store: StoreAuthorityManifestStore,
    now: datetime,
    phase_observer: Callable[[str], None] | None = None,
) -> MigrationResult | None:
    """Finish only from committed manifest authority; never consult legacy v2."""

    manifest = manifest_store.read()
    if manifest is None:
        return None
    if manifest.generation_ref != command.generation_ref:
        return None
    receipt = _parse_receipt(manifest.migration_receipt)
    if receipt["run_id"] != command.run_id:
        return None
    if (
        receipt["generation_ref"] != command.generation_ref
        or receipt["context_ref"] != command.context_ref
        or receipt["expected_authority_revision"] != command.expected_authority_revision
        or manifest.generation_ref != command.generation_ref
    ):
        raise MigrationVerificationError("committed manifest conflicts with the requested migration")
    generation_path = manifest_store.resolve_selected_generation()
    if generation_path is None:  # pragma: no cover - read above proved presence
        raise MigrationVerificationError("committed generation disappeared")
    profile_id = str(receipt["profile_id"])
    with V3Reader.open(generation_path, registry=MIGRATION_REGISTRY) as reader:
        profile = reader.get_record(profile_id)
        stored_receipt = reader.get_record(f"migration:{command.run_id}:receipt")
        if (
            profile is None or profile.content_digest != receipt["profile_digest"]
            or stored_receipt is None or stored_receipt.canonical_bytes != manifest.migration_receipt
        ):
            raise MigrationVerificationError("selected generation does not contain its embedded receipt")
        composition = compose_runtime(
            reader, context_ref=command.context_ref, system_prompt=("base",),
            now=command.created_at,
        )
        if composition.state != "active":
            raise MigrationVerificationError("post-cutover composition is unavailable")
    ledger.append_receipt(
        lease=lease, receipt_kind="migration", canonical_bytes=manifest.migration_receipt, now=now
    )
    phases = ledger.phases(command.run_id)
    source_digest = str(receipt["source_snapshot_digest"])
    projection_digest = str(receipt["target_projection_digest"])
    counts = dict(receipt["disposition_counts"])
    # The manifest is the cutover authority.  A surviving ordered checkpoint
    # prefix may be completed, but a rebuilt/partial ledger must not fabricate
    # pre-cutover phase proofs it no longer possesses.  Exact receipt
    # projection and post-cutover verification remain independently durable.
    if phases == MIGRATION_PHASES[: MIGRATION_PHASES.index("cutover_committed")]:
        _phase(
            ledger, lease, "cutover_committed", input_digest=projection_digest,
            output_digest=manifest.initial_digest, counts=counts, now=now, observer=phase_observer,
        )
    post_receipt = canonical_json(
        {
            "schema": POST_CUTOVER_RECEIPT_SCHEMA,
            "run_id": command.run_id,
            "manifest_revision": manifest.revision,
            "generation_ref": manifest.generation_ref,
            "generation_digest": manifest.initial_digest,
            "migration_receipt_digest": manifest.migration_receipt_digest,
            "verified": True,
        }
    )
    ledger.append_receipt(
        lease=lease, receipt_kind="post_cutover_verification",
        canonical_bytes=post_receipt, now=now,
    )
    phases = ledger.phases(command.run_id)
    if phases == MIGRATION_PHASES[: MIGRATION_PHASES.index("completed")]:
        _phase(
            ledger, lease, "completed", input_digest=manifest.initial_digest,
            output_digest=sha256(post_receipt).hexdigest(), counts=counts,
            now=now, observer=phase_observer,
        )
    return MigrationResult(
        command.run_id, generation_path, profile_id, manifest.migration_receipt,
        counts, True,
    )


def migrate_legacy_store(
    *,
    command: MigrationCommand,
    source_connection: sqlite3.Connection,
    source_barrier: SourceMutationBarrier,
    workers_stopped: bool,
    ledger: MigrationRepository,
    manifest_store: StoreAuthorityManifestStore,
    generation_path: Path,
    ciphertext_path: Path,
    wrapped_key_path: Path,
    cipher: QuarantineCipher,
    custody: KeyCustody,
    now: datetime,
    forbidden_markers: tuple[bytes, ...] = (),
    phase_observer: Callable[[str], None] | None = None,
    after_manifest_commit: Callable[[], None] | None = None,
) -> MigrationResult:
    """Run or resume the exact nine-phase local migration vertical."""

    _require_command(command)
    if not isinstance(source_barrier, SourceMutationBarrier) or source_barrier.held is not True:
        raise MigrationPreconditionError("source mutation barrier must be injected and held")
    if workers_stopped is not True:
        raise MigrationPreconditionError("plugin workers must be explicitly verified stopped")
    if cipher is None or custody is None:
        raise MigrationPreconditionError("authenticated crypto and key custody are required")
    for path in (generation_path, ciphertext_path, wrapped_key_path):
        if not isinstance(path, Path) or not path.is_absolute():
            raise MigrationPreconditionError("migration paths must be exact absolute Paths")
    run = MigrationRun(
        run_id=command.run_id, quarantine_ref=command.quarantine_ref,
        generation_ref=command.generation_ref, context_ref=command.context_ref,
        source_size_limit=command.source_size_limit,
        transformation_policy=command.transformation_policy,
        expected_authority_revision=command.expected_authority_revision,
        created_at=command.created_at.isoformat(),
    )
    ledger.ensure_run(run)
    lease = ledger.acquire_lease(
        run_id=command.run_id, owner_id=command.owner_id, now=now,
        expires_at=command.lease_expires_at,
    )
    recovered = recover_committed_migration(
        command=command, ledger=ledger, lease=lease, manifest_store=manifest_store,
        now=now, phase_observer=phase_observer,
    )
    if recovered is not None:
        return recovered

    phases = ledger.phases(command.run_id)
    run_digest = sha256(
        canonical_json(
            {
                "run_id": command.run_id,
                "generation_ref": command.generation_ref,
                "context_ref": command.context_ref,
                "source_size_limit": command.source_size_limit,
                "transformation_policy": command.transformation_policy,
                "expected_authority_revision": command.expected_authority_revision,
            }
        )
    ).hexdigest()
    if "preflight" not in phases:
        _phase(
            ledger, lease, "preflight", input_digest=run_digest,
            output_digest=run_digest, counts={"mutation_barriers": 1},
            now=now, observer=phase_observer,
        )
    phases = ledger.phases(command.run_id)
    if "workers_stopped" not in phases:
        _phase(
            ledger, lease, "workers_stopped", input_digest=run_digest,
            output_digest=run_digest, counts={"workers_running": 0},
            now=now, observer=phase_observer,
        )

    snapshot_raw = _capture_snapshot(source_connection, command.source_size_limit)
    source_digest = sha256(snapshot_raw).hexdigest()
    snapshot_checkpoint = ledger.checkpoint(command.run_id, "snapshot_verified")
    if snapshot_checkpoint is not None and snapshot_checkpoint.input_digest != source_digest:
        raise MigrationVerificationError("legacy source changed after snapshot checkpoint")
    if "snapshot_verified" not in ledger.phases(command.run_id):
        if ciphertext_path.exists() != wrapped_key_path.exists():
            raise MigrationVerificationError("partial quarantine persistence requires operator recovery")
        if ciphertext_path.exists():
            persisted = _read_encrypted(ciphertext_path, wrapped_key_path)
            ciphertext_digest = sha256(persisted.ciphertext_envelope).hexdigest()
            wrapped_digest = sha256(persisted.wrapped_key_envelope).hexdigest()
        else:
            encrypted = encrypt_quarantine(
                snapshot_raw, quarantine_ref=command.quarantine_ref,
                revision=command.quarantine_revision, cipher=cipher, custody=custody,
            )
            ciphertext_digest = _write_exclusive(ciphertext_path, encrypted.ciphertext_envelope)
            wrapped_digest = _write_exclusive(wrapped_key_path, encrypted.wrapped_key_envelope)
            persisted = _read_encrypted(ciphertext_path, wrapped_key_path)
        if decrypt_quarantine(persisted, cipher=cipher, custody=custody) != snapshot_raw:
            raise MigrationVerificationError("persisted quarantine failed exact decrypt verification")
        ledger.record_quarantine(
            lease=lease,
            quarantine=RetainedQuarantine(
                command.quarantine_ref, command.quarantine_revision,
                ciphertext_path, wrapped_key_path, ciphertext_digest,
            ),
            wrapped_key_digest=wrapped_digest, now=now,
        )
        _phase(
            ledger, lease, "snapshot_verified", input_digest=source_digest,
            output_digest=sha256(
                persisted.ciphertext_envelope + persisted.wrapped_key_envelope
            ).hexdigest(),
            counts={"snapshot_bytes": len(snapshot_raw), "ciphertext_files": 2},
            now=now, observer=phase_observer,
        )
    persisted = _read_encrypted(ciphertext_path, wrapped_key_path)
    decoded_raw = decrypt_quarantine(persisted, cipher=cipher, custody=custody)
    if sha256(decoded_raw).hexdigest() != source_digest:
        raise MigrationVerificationError("retained quarantine no longer matches the captured source")

    snapshot = _snapshot_connection(decoded_raw)
    try:
        decoded = decode_legacy_snapshot(snapshot, as_of=command.created_at)
    finally:
        snapshot.close()
    counts = dict(decoded.counts)
    dispositions = tuple(
        MigrationDisposition(item.source_table, item.source_ordinal, item.disposition, item.reason_code)
        for item in decoded.dispositions
    )
    disposition_digest = sha256(
        canonical_json(
            [
                {
                    "source_table": item.source_table,
                    "source_ordinal": item.source_ordinal,
                    "disposition": item.disposition,
                    "reason_code": item.reason_code,
                }
                for item in dispositions
            ]
        )
    ).hexdigest()
    profile_id = f"migration:{command.run_id}:profile"
    compatible = _compatibility_record(command, decoded.compatibility_members)
    if "staging_created" not in ledger.phases(command.run_id):
        if generation_path.exists():
            raise MigrationPreconditionError("uncheckpointed generation path already exists")
        with V3Repository.create(generation_path, registry=MIGRATION_REGISTRY) as repository:
            with repository.transaction() as transaction:
                transaction.insert_record(null_guidance_artifact())
                transaction.insert_record(null_prompt_patch_artifact())
        os.chmod(generation_path, 0o600)
        _phase(
            ledger, lease, "staging_created", input_digest=source_digest,
            output_digest=sha256(generation_path.read_bytes()).hexdigest(), counts=counts,
            now=now, observer=phase_observer,
        )

    if "projecting" not in ledger.phases(command.run_id):
        ledger.append_dispositions(lease=lease, dispositions=dispositions, now=now)
        with V3Repository.open(generation_path, registry=MIGRATION_REGISTRY) as repository:
            with repository.transaction() as transaction:
                null_guidance = transaction.get_record(null_guidance_artifact().record_id)
                null_prompt = transaction.get_record(null_prompt_patch_artifact().record_id)
                if null_guidance is None or null_prompt is None:
                    raise MigrationVerificationError("staging generation lost its Null Artifacts")
                guidance = transaction.insert_record(compatible).record if compatible is not None else null_guidance
                profile = activation_profile(
                    record_id=profile_id, context_ref=command.context_ref,
                    guidance_artifact=guidance, prompt_patch_artifact=null_prompt,
                    key_epoch=command.key_epoch,
                )
                profile = transaction.insert_record(profile).record
                existing_scope = transaction.get_activation_scope(command.context_ref)
                if existing_scope is None:
                    transaction.initialize_activation_scope(
                        context_ref=command.context_ref, profile_id=profile.record_id,
                        profile_digest=profile.content_digest,
                    )
                elif (
                    existing_scope.current_profile_id != profile.record_id
                    or existing_scope.current_profile_digest != profile.content_digest
                    or existing_scope.scope_revision != 0
                ):
                    raise MigrationVerificationError("staging activation scope differs from projection")
        _phase(
            ledger, lease, "projecting", input_digest=disposition_digest,
            output_digest=sha256(generation_path.read_bytes()).hexdigest(), counts=counts,
            now=now, observer=phase_observer,
        )

    with V3Reader.open(generation_path, registry=MIGRATION_REGISTRY) as reader:
        projection_digest = _projection_digest(reader, profile_id)
        profile = reader.get_record(profile_id)
        if profile is None:
            raise MigrationVerificationError("staged profile is absent")
        composition = compose_runtime(
            reader, context_ref=command.context_ref, system_prompt=("base",),
            now=command.created_at,
        )
        if composition.state != "active":
            raise MigrationVerificationError("pure composition is unavailable")
    _assert_forbidden_absent((generation_path, ledger.path), forbidden_markers)
    if len(ledger.dispositions(command.run_id)) != len(decoded.dispositions):
        raise MigrationVerificationError("disposition ledger count differs from decoder count")
    if "projection_verified" not in ledger.phases(command.run_id):
        _phase(
            ledger, lease, "projection_verified", input_digest=disposition_digest,
            output_digest=projection_digest, counts=counts, now=now, observer=phase_observer,
        )

    receipt_record = build_typed_record(
        record_id=f"migration:{command.run_id}:receipt",
        context_ref=command.context_ref,
        record_kind="migration_receipt",
        schema_id=MIGRATION_RECEIPT_SCHEMA_ID,
        payload={
            "receipt_type": "migration_cutover", "run_id": command.run_id,
            "generation_ref": command.generation_ref, "context_ref": command.context_ref,
            "source_snapshot_digest": source_digest,
            "target_projection_digest": projection_digest,
            "source_schema_version": decoded.fingerprint.version,
            "source_schema_variant": decoded.fingerprint.variant,
            "transformation_policy": command.transformation_policy,
            "expected_authority_revision": command.expected_authority_revision,
            "disposition_counts": counts,
            "profile_id": profile.record_id, "profile_digest": profile.content_digest,
            "compatibility_guidance_present": compatible is not None,
            "links": [{
                "role": "activation_profile", "ordinal": 0,
                "target_id": profile.record_id, "target_digest": profile.content_digest,
            }],
        },
        key_epoch=command.key_epoch, registry=MIGRATION_REGISTRY,
    )
    receipt_bytes = receipt_record.canonical_bytes
    if "awaiting_cutover" not in ledger.phases(command.run_id):
        with V3Repository.open(generation_path, registry=MIGRATION_REGISTRY) as repository:
            with repository.transaction() as transaction:
                transaction.insert_record(receipt_record)
        _assert_forbidden_absent((generation_path, ledger.path), forbidden_markers)
        ledger.append_receipt(
            lease=lease, receipt_kind="migration", canonical_bytes=receipt_bytes, now=now,
        )
        _phase(
            ledger, lease, "awaiting_cutover", input_digest=projection_digest,
            output_digest=sha256(receipt_bytes).hexdigest(), counts=counts,
            now=now, observer=phase_observer,
        )

    manifest_store.compare_and_swap(
        expected_revision=command.expected_authority_revision,
        generation_ref=command.generation_ref, generation_path=generation_path,
        migration_receipt=receipt_bytes,
    )
    if after_manifest_commit is not None:
        after_manifest_commit()
    result = recover_committed_migration(
        command=command, ledger=ledger, lease=lease, manifest_store=manifest_store,
        now=now, phase_observer=phase_observer,
    )
    if result is None:  # pragma: no cover
        raise MigrationVerificationError("manifest CAS did not establish authority")
    return MigrationResult(
        result.run_id, result.generation_path, result.profile_id,
        result.migration_receipt, result.disposition_counts, False,
    )


__all__ = [
    "COMPATIBILITY_GUIDANCE_SCHEMA_ID", "MIGRATION_RECEIPT_SCHEMA_ID", "MIGRATION_REGISTRY",
    "MigrationCommand", "MigrationError", "MigrationPreconditionError", "MigrationResult",
    "MigrationVerificationError", "SourceMutationBarrier", "migrate_legacy_store",
    "recover_committed_migration",
]
