"""Dedicated append-only ledger for the local v3 Migration Authority.

The ledger is intentionally separate from both the raw legacy source and the
runtime Safe Projection Store.  It contains only content-free run metadata,
phase proofs, row dispositions, and receipts.  Every append is fenced by the
one local migration lease.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import sqlite3
from typing import Iterable, Literal, Mapping

from .privacy_lifecycle import (
    DELETION_CHALLENGE_SCHEMA,
    DELETION_INTENT_SCHEMA,
    DELETION_METHOD,
    DELETION_RECEIPT_SCHEMA,
    EXPORT_RECEIPT_SCHEMA,
    EXPORT_WAIVER_SCHEMA,
    WAIVER_ACKNOWLEDGEMENT,
    ChallengeConsumption,
    DeletionChallenge,
    DeletionIntent,
    DeletionProgress,
    DeletionReceipt,
    ExportReceipt,
    ExportWaiver,
    PrivacyLifecycleDenied,
    PrivacyLifecycleStateError,
)
from .quarantine import RetainedQuarantine
from .schemas import canonical_json, canonical_loads


MIGRATION_PHASES = (
    "preflight",
    "workers_stopped",
    "snapshot_verified",
    "staging_created",
    "projecting",
    "projection_verified",
    "awaiting_cutover",
    "cutover_committed",
    "completed",
)
Disposition = Literal["projected", "quarantined", "unsupported", "invalid"]


class MigrationLedgerError(RuntimeError):
    """Base class for migration-ledger failures."""


class MigrationLeaseConflict(MigrationLedgerError):
    pass


class MigrationFenceRejected(MigrationLedgerError):
    pass


class MigrationIdentityConflict(MigrationLedgerError):
    pass


class MigrationPhaseConflict(MigrationLedgerError):
    pass


@dataclass(frozen=True, slots=True)
class MigrationRun:
    run_id: str
    quarantine_ref: str
    generation_ref: str
    context_ref: str
    source_size_limit: int
    transformation_policy: str
    expected_authority_revision: int
    created_at: str


@dataclass(frozen=True, slots=True)
class MigrationLease:
    run_id: str
    owner_id: str
    fence_token: int
    expires_at: str


@dataclass(frozen=True, slots=True)
class MigrationCheckpoint:
    run_id: str
    ordinal: int
    phase: str
    input_digest: str
    output_digest: str
    counts: Mapping[str, int]
    fence_token: int
    created_at: str


@dataclass(frozen=True, slots=True)
class MigrationDisposition:
    source_table: str
    source_ordinal: int
    disposition: Disposition
    reason_code: str


_SCHEMA = """
PRAGMA user_version = 1;
CREATE TABLE migration_runs (
  run_id TEXT PRIMARY KEY,
  quarantine_ref TEXT NOT NULL,
  generation_ref TEXT NOT NULL,
  context_ref TEXT NOT NULL,
  source_size_limit INTEGER NOT NULL CHECK(source_size_limit > 0),
  transformation_policy TEXT NOT NULL,
  expected_authority_revision INTEGER NOT NULL CHECK(expected_authority_revision >= 0),
  created_at TEXT NOT NULL
);
CREATE TABLE migration_checkpoints (
  run_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  phase TEXT NOT NULL CHECK(phase IN (
    'preflight','workers_stopped','snapshot_verified','staging_created','projecting',
    'projection_verified','awaiting_cutover','cutover_committed','completed'
  )),
  input_digest TEXT NOT NULL CHECK(length(input_digest) = 64),
  output_digest TEXT NOT NULL CHECK(length(output_digest) = 64),
  counts_json BLOB NOT NULL,
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, ordinal),
  UNIQUE (run_id, phase),
  FOREIGN KEY (run_id) REFERENCES migration_runs(run_id)
);
CREATE TABLE migration_dispositions (
  run_id TEXT NOT NULL,
  source_table TEXT NOT NULL,
  source_ordinal INTEGER NOT NULL CHECK(source_ordinal >= 0),
  disposition TEXT NOT NULL CHECK(disposition IN ('projected','quarantined','unsupported','invalid')),
  reason_code TEXT NOT NULL,
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, source_table, source_ordinal),
  FOREIGN KEY (run_id) REFERENCES migration_runs(run_id)
);
CREATE TABLE migration_receipts (
  run_id TEXT NOT NULL,
  receipt_kind TEXT NOT NULL CHECK(receipt_kind IN ('migration','post_cutover_verification')),
  canonical_bytes BLOB NOT NULL,
  receipt_digest TEXT NOT NULL CHECK(length(receipt_digest) = 64),
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, receipt_kind),
  FOREIGN KEY (run_id) REFERENCES migration_runs(run_id)
);
CREATE TABLE retained_quarantines (
  run_id TEXT PRIMARY KEY,
  quarantine_ref TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK(revision > 0),
  ciphertext_path TEXT NOT NULL,
  wrapped_key_path TEXT NOT NULL,
  ciphertext_digest TEXT NOT NULL CHECK(length(ciphertext_digest) = 64),
  wrapped_key_digest TEXT NOT NULL CHECK(length(wrapped_key_digest) = 64),
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  created_at TEXT NOT NULL,
  UNIQUE (quarantine_ref, revision),
  FOREIGN KEY (run_id) REFERENCES migration_runs(run_id)
);
CREATE TABLE migration_lease (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  run_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  expires_at TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES migration_runs(run_id)
);
CREATE TABLE privacy_export_receipts (
  receipt_ref TEXT PRIMARY KEY,
  canonical_bytes BLOB NOT NULL,
  record_digest TEXT NOT NULL CHECK(length(record_digest) = 64)
);
CREATE TABLE privacy_export_waivers (
  waiver_ref TEXT PRIMARY KEY,
  canonical_bytes BLOB NOT NULL,
  record_digest TEXT NOT NULL CHECK(length(record_digest) = 64)
);
CREATE TABLE privacy_deletion_challenges (
  challenge_ref TEXT PRIMARY KEY,
  canonical_bytes BLOB NOT NULL,
  record_digest TEXT NOT NULL CHECK(length(record_digest) = 64)
);
CREATE TABLE privacy_deletion_intents (
  operation_ref TEXT PRIMARY KEY,
  challenge_ref TEXT NOT NULL UNIQUE,
  canonical_bytes BLOB NOT NULL,
  record_digest TEXT NOT NULL CHECK(length(record_digest) = 64),
  UNIQUE (operation_ref, challenge_ref),
  FOREIGN KEY (challenge_ref) REFERENCES privacy_deletion_challenges(challenge_ref),
  FOREIGN KEY (operation_ref, challenge_ref)
    REFERENCES privacy_challenge_consumptions(operation_ref, challenge_ref)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE privacy_challenge_consumptions (
  challenge_ref TEXT PRIMARY KEY,
  operation_ref TEXT NOT NULL UNIQUE,
  canonical_bytes BLOB NOT NULL,
  record_digest TEXT NOT NULL CHECK(length(record_digest) = 64),
  UNIQUE (operation_ref, challenge_ref),
  FOREIGN KEY (challenge_ref) REFERENCES privacy_deletion_challenges(challenge_ref),
  FOREIGN KEY (operation_ref, challenge_ref)
    REFERENCES privacy_deletion_intents(operation_ref, challenge_ref)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE privacy_deletion_steps (
  operation_ref TEXT NOT NULL,
  step TEXT NOT NULL CHECK(step IN ('wrapped_key_unlinked','ciphertext_unlinked')),
  ordinal INTEGER NOT NULL CHECK(
    (step = 'wrapped_key_unlinked' AND ordinal = 1)
    OR (step = 'ciphertext_unlinked' AND ordinal = 2)
  ),
  PRIMARY KEY (operation_ref, step),
  UNIQUE (operation_ref, ordinal),
  FOREIGN KEY (operation_ref) REFERENCES privacy_deletion_intents(operation_ref)
);
CREATE TABLE privacy_deletion_receipts (
  receipt_ref TEXT PRIMARY KEY,
  operation_ref TEXT NOT NULL UNIQUE,
  canonical_bytes BLOB NOT NULL,
  record_digest TEXT NOT NULL CHECK(length(record_digest) = 64),
  FOREIGN KEY (operation_ref) REFERENCES privacy_deletion_intents(operation_ref)
);

CREATE TRIGGER migration_runs_no_update BEFORE UPDATE ON migration_runs
BEGIN SELECT RAISE(ABORT, 'migration runs are immutable'); END;
CREATE TRIGGER migration_runs_no_delete BEFORE DELETE ON migration_runs
BEGIN SELECT RAISE(ABORT, 'migration runs are immutable'); END;
CREATE TRIGGER migration_checkpoints_no_update BEFORE UPDATE ON migration_checkpoints
BEGIN SELECT RAISE(ABORT, 'migration checkpoints are append-only'); END;
CREATE TRIGGER migration_checkpoints_no_delete BEFORE DELETE ON migration_checkpoints
BEGIN SELECT RAISE(ABORT, 'migration checkpoints are append-only'); END;
CREATE TRIGGER migration_dispositions_no_update BEFORE UPDATE ON migration_dispositions
BEGIN SELECT RAISE(ABORT, 'migration dispositions are append-only'); END;
CREATE TRIGGER migration_dispositions_no_delete BEFORE DELETE ON migration_dispositions
BEGIN SELECT RAISE(ABORT, 'migration dispositions are append-only'); END;
CREATE TRIGGER migration_receipts_no_update BEFORE UPDATE ON migration_receipts
BEGIN SELECT RAISE(ABORT, 'migration receipts are append-only'); END;
CREATE TRIGGER migration_receipts_no_delete BEFORE DELETE ON migration_receipts
BEGIN SELECT RAISE(ABORT, 'migration receipts are append-only'); END;
CREATE TRIGGER retained_quarantines_no_update BEFORE UPDATE ON retained_quarantines
BEGIN SELECT RAISE(ABORT, 'retained quarantines are immutable'); END;
CREATE TRIGGER retained_quarantines_no_delete BEFORE DELETE ON retained_quarantines
BEGIN SELECT RAISE(ABORT, 'retained quarantines are immutable'); END;
CREATE TRIGGER privacy_export_receipts_no_update BEFORE UPDATE ON privacy_export_receipts
BEGIN SELECT RAISE(ABORT, 'privacy export receipts are immutable'); END;
CREATE TRIGGER privacy_export_receipts_no_delete BEFORE DELETE ON privacy_export_receipts
BEGIN SELECT RAISE(ABORT, 'privacy export receipts are immutable'); END;
CREATE TRIGGER privacy_export_waivers_no_update BEFORE UPDATE ON privacy_export_waivers
BEGIN SELECT RAISE(ABORT, 'privacy export waivers are immutable'); END;
CREATE TRIGGER privacy_export_waivers_no_delete BEFORE DELETE ON privacy_export_waivers
BEGIN SELECT RAISE(ABORT, 'privacy export waivers are immutable'); END;
CREATE TRIGGER privacy_deletion_challenges_no_update BEFORE UPDATE ON privacy_deletion_challenges
BEGIN SELECT RAISE(ABORT, 'privacy deletion challenges are immutable'); END;
CREATE TRIGGER privacy_deletion_challenges_no_delete BEFORE DELETE ON privacy_deletion_challenges
BEGIN SELECT RAISE(ABORT, 'privacy deletion challenges are immutable'); END;
CREATE TRIGGER privacy_deletion_intents_no_update BEFORE UPDATE ON privacy_deletion_intents
BEGIN SELECT RAISE(ABORT, 'privacy deletion intents are immutable'); END;
CREATE TRIGGER privacy_deletion_intents_no_delete BEFORE DELETE ON privacy_deletion_intents
BEGIN SELECT RAISE(ABORT, 'privacy deletion intents are immutable'); END;
CREATE TRIGGER privacy_challenge_consumptions_no_update BEFORE UPDATE ON privacy_challenge_consumptions
BEGIN SELECT RAISE(ABORT, 'privacy challenge consumptions are immutable'); END;
CREATE TRIGGER privacy_challenge_consumptions_no_delete BEFORE DELETE ON privacy_challenge_consumptions
BEGIN SELECT RAISE(ABORT, 'privacy challenge consumptions are immutable'); END;
CREATE TRIGGER privacy_deletion_steps_no_update BEFORE UPDATE ON privacy_deletion_steps
BEGIN SELECT RAISE(ABORT, 'privacy deletion steps are append-only'); END;
CREATE TRIGGER privacy_deletion_steps_no_delete BEFORE DELETE ON privacy_deletion_steps
BEGIN SELECT RAISE(ABORT, 'privacy deletion steps are append-only'); END;
CREATE TRIGGER privacy_deletion_steps_in_order BEFORE INSERT ON privacy_deletion_steps
WHEN NEW.step = 'ciphertext_unlinked' AND NOT EXISTS (
  SELECT 1 FROM privacy_deletion_steps
  WHERE operation_ref = NEW.operation_ref AND step = 'wrapped_key_unlinked'
)
BEGIN SELECT RAISE(ABORT, 'wrapped key must be unlinked first'); END;
CREATE TRIGGER privacy_deletion_receipts_no_update BEFORE UPDATE ON privacy_deletion_receipts
BEGIN SELECT RAISE(ABORT, 'privacy deletion receipts are immutable'); END;
CREATE TRIGGER privacy_deletion_receipts_no_delete BEFORE DELETE ON privacy_deletion_receipts
BEGIN SELECT RAISE(ABORT, 'privacy deletion receipts are immutable'); END;
CREATE TRIGGER privacy_deletion_receipts_require_steps BEFORE INSERT ON privacy_deletion_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM privacy_deletion_steps
  WHERE operation_ref = NEW.operation_ref AND step = 'wrapped_key_unlinked'
) OR NOT EXISTS (
  SELECT 1 FROM privacy_deletion_steps
  WHERE operation_ref = NEW.operation_ref AND step = 'ciphertext_unlinked'
)
BEGIN SELECT RAISE(ABORT, 'deletion receipt requires both unlink markers'); END;
"""


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{field} must be a non-empty bounded identity")
    if len(value) > 2048:
        raise ValueError(f"{field} is too long")
    return value


def _sha(value: object, field: str) -> str:
    if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _positive_revision(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("revision must be a positive integer")
    return value


def _parse_timestamp(value: object, field: str) -> datetime:
    text = _text(value, field)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError(f"{field} must be a canonical UTC timestamp") from exc
    if _timestamp(parsed) != text:
        raise ValueError(f"{field} must be a canonical UTC timestamp")
    return parsed


def _record_bytes(record: object, expected_type: type) -> bytes:
    if type(record) is not expected_type:
        raise ValueError(f"record must be exactly {expected_type.__name__}")
    return canonical_json(asdict(record))


def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL "
            "ORDER BY type,name"
        )
    )


def _expected_schema_signature() -> tuple[tuple[object, ...], ...]:
    expected = sqlite3.connect(":memory:")
    try:
        expected.executescript(_SCHEMA)
        return _schema_signature(expected)
    finally:
        expected.close()


def _verify_schema(connection: sqlite3.Connection) -> None:
    if int(connection.execute("PRAGMA user_version").fetchone()[0]) != 1:
        raise MigrationLedgerError("migration ledger schema is unsupported")
    if _schema_signature(connection) != _expected_schema_signature():
        raise MigrationLedgerError("migration ledger schema fingerprint does not match")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise MigrationLedgerError("migration ledger foreign-key integrity failed")
    integrity = connection.execute("PRAGMA integrity_check(1)").fetchone()
    if integrity is None or integrity[0] != "ok":
        raise MigrationLedgerError("migration ledger integrity check failed")


def _validate_export_receipt(receipt: ExportReceipt) -> None:
    _text(receipt.receipt_ref, "receipt_ref")
    _text(receipt.quarantine_ref, "quarantine_ref")
    _positive_revision(receipt.revision)
    _text(receipt.authority_ref, "authority_ref")
    _text(receipt.archive_ref, "archive_ref")
    _sha(receipt.ciphertext_digest, "ciphertext_digest")
    _sha(receipt.wrapped_key_digest, "wrapped_key_digest")
    _sha(receipt.archive_digest, "archive_digest")
    _parse_timestamp(receipt.exported_at, "exported_at")
    if receipt.schema != EXPORT_RECEIPT_SCHEMA or receipt.contains_plaintext is not False:
        raise ValueError("export receipt schema and plaintext claim must be exact")


def _validate_export_waiver(waiver: ExportWaiver) -> None:
    _text(waiver.waiver_ref, "waiver_ref")
    _text(waiver.quarantine_ref, "quarantine_ref")
    _positive_revision(waiver.revision)
    _text(waiver.authority_ref, "authority_ref")
    _parse_timestamp(waiver.acknowledged_at, "acknowledged_at")
    if waiver.schema != EXPORT_WAIVER_SCHEMA or waiver.acknowledgement != WAIVER_ACKNOWLEDGEMENT:
        raise ValueError("export waiver schema and acknowledgement must be exact")


def _validate_deletion_challenge(challenge: DeletionChallenge) -> None:
    _text(challenge.challenge_ref, "challenge_ref")
    _text(challenge.quarantine_ref, "quarantine_ref")
    _positive_revision(challenge.revision)
    _text(challenge.authority_ref, "authority_ref")
    issued = _parse_timestamp(challenge.issued_at, "issued_at")
    expires = _parse_timestamp(challenge.expires_at, "expires_at")
    _text(challenge.required_confirmation, "required_confirmation")
    _sha(challenge.required_confirmation_digest, "required_confirmation_digest")
    confirmation_digest = sha256(
        b"a0.quarantine.deletion-confirmation.v1\x00"
        + challenge.required_confirmation.encode("utf-8")
    ).hexdigest()
    if (
        challenge.schema != DELETION_CHALLENGE_SCHEMA
        or expires <= issued
        or challenge.required_confirmation_digest != confirmation_digest
    ):
        raise ValueError("deletion challenge schema or expiry is invalid")


def _validate_challenge_consumption(consumption: ChallengeConsumption) -> None:
    _text(consumption.challenge_ref, "challenge_ref")
    _text(consumption.quarantine_ref, "quarantine_ref")
    _positive_revision(consumption.revision)
    _text(consumption.authority_ref, "authority_ref")
    _sha(consumption.confirmation_digest, "confirmation_digest")
    _parse_timestamp(consumption.consumed_at, "consumed_at")


def _validate_deletion_intent(intent: DeletionIntent) -> None:
    _text(intent.operation_ref, "operation_ref")
    _text(intent.quarantine_ref, "quarantine_ref")
    _positive_revision(intent.revision)
    _text(intent.authority_ref, "authority_ref")
    _text(intent.challenge_ref, "challenge_ref")
    if intent.evidence_kind not in ("export_receipt", "export_waiver"):
        raise ValueError("deletion evidence kind is unsupported")
    _text(intent.evidence_ref, "evidence_ref")
    _sha(intent.ciphertext_digest, "ciphertext_digest")
    _sha(intent.wrapped_key_digest, "wrapped_key_digest")
    _parse_timestamp(intent.begun_at, "begun_at")
    if intent.schema != DELETION_INTENT_SCHEMA:
        raise ValueError("deletion intent schema is invalid")


def _validate_deletion_receipt(receipt: DeletionReceipt) -> None:
    _text(receipt.receipt_ref, "receipt_ref")
    _text(receipt.operation_ref, "operation_ref")
    _text(receipt.quarantine_ref, "quarantine_ref")
    _positive_revision(receipt.revision)
    _text(receipt.authority_ref, "authority_ref")
    if receipt.evidence_kind not in ("export_receipt", "export_waiver"):
        raise ValueError("deletion evidence kind is unsupported")
    _text(receipt.evidence_ref, "evidence_ref")
    _parse_timestamp(receipt.completed_at, "completed_at")
    if (
        receipt.schema != DELETION_RECEIPT_SCHEMA
        or receipt.deletion_method != DELETION_METHOD
        or receipt.wrapped_key_unlinked is not True
        or receipt.ciphertext_unlinked is not True
        or receipt.physical_overwrite_claimed is not False
    ):
        raise ValueError("deletion receipt claims are invalid")


def _decode_record(
    row: sqlite3.Row,
    expected_type: type,
    validator,
) -> object:
    payload = bytes(row["canonical_bytes"])
    if row["record_digest"] != _digest(payload):
        raise MigrationLedgerError("privacy record digest does not match canonical bytes")
    try:
        decoded = canonical_loads(payload)
        if canonical_json(decoded) != payload or type(decoded) is not dict:
            raise ValueError("record is not an exact canonical object")
        record = expected_type(**decoded)
        if canonical_json(asdict(record)) != payload:
            raise ValueError("record did not round-trip exactly")
        validator(record)
    except (MigrationLedgerError, ValueError, TypeError) as exc:
        if isinstance(exc, MigrationLedgerError):
            raise
        raise MigrationLedgerError("privacy record canonical bytes are invalid") from exc
    return record


class MigrationRepository:
    """Explicit writer for the local immutable migration ledger."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection

    @classmethod
    def create(cls, path: str | Path) -> "MigrationRepository":
        ledger_path = Path(path)
        if ledger_path.exists():
            raise MigrationLedgerError(f"refusing to replace migration ledger: {ledger_path}")
        if not ledger_path.parent.is_dir():
            raise MigrationLedgerError("migration ledger parent must already exist")
        connection = sqlite3.connect(ledger_path, isolation_level=None, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.executescript(_SCHEMA)
        _verify_schema(connection)
        return cls(ledger_path, connection)

    @classmethod
    def open(cls, path: str | Path) -> "MigrationRepository":
        ledger_path = Path(path)
        if not ledger_path.is_file():
            raise MigrationLedgerError(f"migration ledger is missing: {ledger_path}")
        connection = sqlite3.connect(ledger_path, isolation_level=None, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            _verify_schema(connection)
        except BaseException:
            connection.close()
            raise
        return cls(ledger_path, connection)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "MigrationRepository":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def ensure_run(self, run: MigrationRun) -> MigrationRun:
        if type(run.source_size_limit) is not int or run.source_size_limit <= 0:
            raise ValueError("source_size_limit must be explicitly positive")
        if type(run.expected_authority_revision) is not int or run.expected_authority_revision < 0:
            raise ValueError("expected_authority_revision must be non-negative")
        values = (
            _text(run.run_id, "run_id"),
            _text(run.quarantine_ref, "quarantine_ref"),
            _text(run.generation_ref, "generation_ref"),
            _text(run.context_ref, "context_ref"),
            run.source_size_limit,
            _text(run.transformation_policy, "transformation_policy"),
            run.expected_authority_revision,
            _text(run.created_at, "created_at"),
        )
        existing = self._connection.execute(
            "SELECT * FROM migration_runs WHERE run_id = ?", (run.run_id,)
        ).fetchone()
        if existing is not None:
            admitted = MigrationRun(**dict(existing))
            if admitted != run:
                raise MigrationIdentityConflict("migration run identity was reused with different inputs")
            return admitted
        self._connection.execute(
            "INSERT INTO migration_runs VALUES (?,?,?,?,?,?,?,?)", values
        )
        return run

    def acquire_lease(
        self,
        *,
        run_id: str,
        owner_id: str,
        now: datetime,
        expires_at: datetime,
    ) -> MigrationLease:
        now_text = _timestamp(now)
        expiry_text = _timestamp(expires_at)
        if expiry_text <= now_text:
            raise ValueError("lease expiry must be after now")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self._connection.execute("SELECT * FROM migration_lease WHERE singleton=1").fetchone()
            if current is None:
                fence = 1
                self._connection.execute(
                    "INSERT INTO migration_lease VALUES (1,?,?,?,?)",
                    (run_id, owner_id, fence, expiry_text),
                )
            elif current["expires_at"] > now_text and (
                current["run_id"] != run_id or current["owner_id"] != owner_id
            ):
                raise MigrationLeaseConflict("another unexpired migration lease is held")
            else:
                fence = int(current["fence_token"])
                if current["run_id"] != run_id or current["owner_id"] != owner_id:
                    fence += 1
                self._connection.execute(
                    "UPDATE migration_lease SET run_id=?, owner_id=?, fence_token=?, expires_at=? WHERE singleton=1",
                    (run_id, owner_id, fence, expiry_text),
                )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return MigrationLease(run_id, owner_id, fence, expiry_text)

    def _require_fence(self, lease: MigrationLease, now: datetime) -> None:
        row = self._connection.execute("SELECT * FROM migration_lease WHERE singleton=1").fetchone()
        if row is None or (
            row["run_id"], row["owner_id"], row["fence_token"]
        ) != (lease.run_id, lease.owner_id, lease.fence_token):
            raise MigrationFenceRejected("migration lease fence is stale")
        if row["expires_at"] <= _timestamp(now):
            raise MigrationFenceRejected("migration lease has expired")

    def phases(self, run_id: str) -> tuple[str, ...]:
        return tuple(
            row[0] for row in self._connection.execute(
                "SELECT phase FROM migration_checkpoints WHERE run_id=? ORDER BY ordinal", (run_id,)
            )
        )

    def checkpoint(self, run_id: str, phase: str) -> MigrationCheckpoint | None:
        row = self._connection.execute(
            "SELECT * FROM migration_checkpoints WHERE run_id=? AND phase=?",
            (run_id, phase),
        ).fetchone()
        if row is None:
            return None
        return MigrationCheckpoint(
            run_id=row["run_id"], ordinal=row["ordinal"], phase=row["phase"],
            input_digest=row["input_digest"], output_digest=row["output_digest"],
            counts=canonical_loads(bytes(row["counts_json"])),
            fence_token=row["fence_token"], created_at=row["created_at"],
        )

    def append_checkpoint(
        self,
        *,
        lease: MigrationLease,
        phase: str,
        input_digest: str,
        output_digest: str,
        counts: Mapping[str, int],
        now: datetime,
    ) -> MigrationCheckpoint:
        if phase not in MIGRATION_PHASES:
            raise ValueError("unknown migration phase")
        normalized = {str(key): int(value) for key, value in counts.items()}
        if any(value < 0 for value in normalized.values()):
            raise ValueError("checkpoint counts cannot be negative")
        counts_bytes = canonical_json(normalized)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_fence(lease, now)
            existing_rows = self._connection.execute(
                "SELECT * FROM migration_checkpoints WHERE run_id=? ORDER BY ordinal", (lease.run_id,)
            ).fetchall()
            ordinal = MIGRATION_PHASES.index(phase)
            if len(existing_rows) > ordinal:
                row = existing_rows[ordinal]
                admitted = MigrationCheckpoint(
                    run_id=row["run_id"], ordinal=row["ordinal"], phase=row["phase"],
                    input_digest=row["input_digest"], output_digest=row["output_digest"],
                    counts=canonical_loads(bytes(row["counts_json"])),
                    fence_token=row["fence_token"], created_at=row["created_at"],
                )
                if (
                    admitted.phase != phase or admitted.input_digest != input_digest
                    or admitted.output_digest != output_digest or dict(admitted.counts) != normalized
                ):
                    raise MigrationPhaseConflict("phase retry differs from its immutable checkpoint")
                self._connection.commit()
                return admitted
            if len(existing_rows) != ordinal:
                raise MigrationPhaseConflict("migration phases must be appended in exact order")
            created_at = _timestamp(now)
            self._connection.execute(
                "INSERT INTO migration_checkpoints VALUES (?,?,?,?,?,?,?,?)",
                (lease.run_id, ordinal, phase, _sha(input_digest, "input_digest"),
                 _sha(output_digest, "output_digest"), counts_bytes, lease.fence_token, created_at),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return MigrationCheckpoint(
            lease.run_id, ordinal, phase, input_digest, output_digest,
            normalized, lease.fence_token, created_at,
        )

    def append_dispositions(
        self,
        *,
        lease: MigrationLease,
        dispositions: Iterable[MigrationDisposition],
        now: datetime,
    ) -> None:
        created_at = _timestamp(now)
        values = tuple(dispositions)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_fence(lease, now)
            for item in values:
                fields = (
                    lease.run_id, _text(item.source_table, "source_table"),
                    item.source_ordinal, item.disposition,
                    _text(item.reason_code, "reason_code"), lease.fence_token, created_at,
                )
                existing = self._connection.execute(
                    "SELECT source_table,source_ordinal,disposition,reason_code FROM migration_dispositions "
                    "WHERE run_id=? AND source_table=? AND source_ordinal=?",
                    fields[:3],
                ).fetchone()
                if existing is not None:
                    if tuple(existing) != fields[1:5]:
                        raise MigrationIdentityConflict("disposition identity was reused")
                    continue
                self._connection.execute(
                    "INSERT INTO migration_dispositions VALUES (?,?,?,?,?,?,?)", fields
                )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def dispositions(self, run_id: str) -> tuple[MigrationDisposition, ...]:
        return tuple(
            MigrationDisposition(*row)
            for row in self._connection.execute(
                "SELECT source_table,source_ordinal,disposition,reason_code "
                "FROM migration_dispositions WHERE run_id=? ORDER BY source_table,source_ordinal",
                (run_id,),
            )
        )

    def record_quarantine(
        self,
        *,
        lease: MigrationLease,
        quarantine: RetainedQuarantine,
        wrapped_key_digest: str,
        now: datetime,
    ) -> None:
        self._require_fence(lease, now)
        values = (
            lease.run_id, quarantine.quarantine_ref, quarantine.revision,
            str(quarantine.ciphertext_path), str(quarantine.wrapped_key_path),
            _sha(quarantine.ciphertext_digest, "ciphertext_digest"),
            _sha(wrapped_key_digest, "wrapped_key_digest"), lease.fence_token, _timestamp(now),
        )
        existing = self._connection.execute(
            "SELECT run_id,quarantine_ref,revision,ciphertext_path,wrapped_key_path,ciphertext_digest,wrapped_key_digest "
            "FROM retained_quarantines WHERE run_id=?", (lease.run_id,),
        ).fetchone()
        if existing is not None:
            if tuple(existing) != values[:7]:
                raise MigrationIdentityConflict("retained quarantine identity differs")
            return
        self._connection.execute("INSERT INTO retained_quarantines VALUES (?,?,?,?,?,?,?,?,?)", values)

    def resolve_retained(self, quarantine_ref: str, revision: int) -> RetainedQuarantine:
        row = self._connection.execute(
            "SELECT quarantine_ref,revision,ciphertext_path,wrapped_key_path,ciphertext_digest "
            "FROM retained_quarantines WHERE quarantine_ref=? AND revision=?",
            (quarantine_ref, revision),
        ).fetchone()
        if row is None:
            raise MigrationLedgerError("retained quarantine is not in the ledger")
        return RetainedQuarantine(
            quarantine_ref=row["quarantine_ref"], revision=row["revision"],
            ciphertext_path=Path(row["ciphertext_path"]),
            wrapped_key_path=Path(row["wrapped_key_path"]),
            ciphertext_digest=row["ciphertext_digest"],
        )

    def append_receipt(
        self,
        *,
        lease: MigrationLease,
        receipt_kind: Literal["migration", "post_cutover_verification"],
        canonical_bytes: bytes,
        now: datetime,
    ) -> str:
        if type(canonical_bytes) is not bytes or canonical_json(canonical_loads(canonical_bytes)) != canonical_bytes:
            raise ValueError("receipt must be exact canonical JSON bytes")
        digest = _digest(canonical_bytes)
        self._require_fence(lease, now)
        existing = self._connection.execute(
            "SELECT canonical_bytes,receipt_digest FROM migration_receipts WHERE run_id=? AND receipt_kind=?",
            (lease.run_id, receipt_kind),
        ).fetchone()
        if existing is not None:
            if bytes(existing["canonical_bytes"]) != canonical_bytes or existing["receipt_digest"] != digest:
                raise MigrationIdentityConflict("receipt identity was reused")
            return digest
        self._connection.execute(
            "INSERT INTO migration_receipts VALUES (?,?,?,?,?,?)",
            (lease.run_id, receipt_kind, canonical_bytes, digest, lease.fence_token, _timestamp(now)),
        )
        return digest

    def receipt(self, run_id: str, receipt_kind: str = "migration") -> bytes | None:
        row = self._connection.execute(
            "SELECT canonical_bytes FROM migration_receipts WHERE run_id=? AND receipt_kind=?",
            (run_id, receipt_kind),
        ).fetchone()
        return None if row is None else bytes(row[0])

    def _append_privacy_record(
        self,
        *,
        table: str,
        key_column: str,
        key: str,
        payload: bytes,
    ) -> None:
        allowed = {
            ("privacy_export_receipts", "receipt_ref"),
            ("privacy_export_waivers", "waiver_ref"),
            ("privacy_deletion_challenges", "challenge_ref"),
        }
        if (table, key_column) not in allowed:
            raise ValueError("privacy table is not appendable through this path")
        digest = _digest(payload)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._connection.execute(
                f"SELECT canonical_bytes,record_digest FROM {table} WHERE {key_column}=?",
                (key,),
            ).fetchone()
            if existing is not None:
                if bytes(existing["canonical_bytes"]) != payload or existing["record_digest"] != digest:
                    raise MigrationIdentityConflict(
                        "privacy record identity was reused with different canonical bytes"
                    )
                self._connection.commit()
                return
            self._connection.execute(
                f"INSERT INTO {table} ({key_column},canonical_bytes,record_digest) VALUES (?,?,?)",
                (key, payload, digest),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def append_export_receipt(self, receipt: ExportReceipt) -> ExportReceipt:
        payload = _record_bytes(receipt, ExportReceipt)
        _validate_export_receipt(receipt)
        self._append_privacy_record(
            table="privacy_export_receipts",
            key_column="receipt_ref",
            key=receipt.receipt_ref,
            payload=payload,
        )
        return receipt

    def append_export_waiver(self, waiver: ExportWaiver) -> ExportWaiver:
        payload = _record_bytes(waiver, ExportWaiver)
        _validate_export_waiver(waiver)
        self._append_privacy_record(
            table="privacy_export_waivers",
            key_column="waiver_ref",
            key=waiver.waiver_ref,
            payload=payload,
        )
        return waiver

    def append_deletion_challenge(self, challenge: DeletionChallenge) -> DeletionChallenge:
        payload = _record_bytes(challenge, DeletionChallenge)
        _validate_deletion_challenge(challenge)
        self._append_privacy_record(
            table="privacy_deletion_challenges",
            key_column="challenge_ref",
            key=challenge.challenge_ref,
            payload=payload,
        )
        return challenge

    def resolve_export_receipt(self, receipt_ref: str) -> ExportReceipt:
        row = self._connection.execute(
            "SELECT canonical_bytes,record_digest FROM privacy_export_receipts WHERE receipt_ref=?",
            (_text(receipt_ref, "receipt_ref"),),
        ).fetchone()
        if row is None:
            raise MigrationLedgerError("export receipt is not in the privacy ledger")
        receipt = _decode_record(row, ExportReceipt, _validate_export_receipt)
        if receipt.receipt_ref != receipt_ref:
            raise MigrationLedgerError("export receipt identity does not match its row")
        return receipt

    def resolve_export_waiver(self, waiver_ref: str) -> ExportWaiver:
        row = self._connection.execute(
            "SELECT canonical_bytes,record_digest FROM privacy_export_waivers WHERE waiver_ref=?",
            (_text(waiver_ref, "waiver_ref"),),
        ).fetchone()
        if row is None:
            raise MigrationLedgerError("export waiver is not in the privacy ledger")
        waiver = _decode_record(row, ExportWaiver, _validate_export_waiver)
        if waiver.waiver_ref != waiver_ref:
            raise MigrationLedgerError("export waiver identity does not match its row")
        return waiver

    def consume_challenge_and_begin(
        self,
        consumption: ChallengeConsumption,
        intent: DeletionIntent,
    ) -> DeletionProgress:
        consumption_payload = _record_bytes(consumption, ChallengeConsumption)
        intent_payload = _record_bytes(intent, DeletionIntent)
        _validate_challenge_consumption(consumption)
        _validate_deletion_intent(intent)
        if (
            consumption.challenge_ref != intent.challenge_ref
            or consumption.quarantine_ref != intent.quarantine_ref
            or consumption.revision != intent.revision
            or consumption.authority_ref != intent.authority_ref
            or consumption.consumed_at != intent.begun_at
        ):
            raise PrivacyLifecycleDenied("challenge consumption and deletion intent bindings differ")

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            challenge_row = self._connection.execute(
                "SELECT canonical_bytes,record_digest FROM privacy_deletion_challenges "
                "WHERE challenge_ref=?",
                (consumption.challenge_ref,),
            ).fetchone()
            if challenge_row is None:
                raise PrivacyLifecycleDenied("deletion challenge is unavailable")
            challenge = _decode_record(
                challenge_row, DeletionChallenge, _validate_deletion_challenge
            )
            if (
                challenge.challenge_ref != consumption.challenge_ref
                or challenge.quarantine_ref != consumption.quarantine_ref
                or challenge.revision != consumption.revision
                or challenge.authority_ref != consumption.authority_ref
                or challenge.required_confirmation_digest != consumption.confirmation_digest
            ):
                raise PrivacyLifecycleDenied("deletion challenge binding does not match")

            existing_consumption = self._connection.execute(
                "SELECT challenge_ref,operation_ref,canonical_bytes,record_digest "
                "FROM privacy_challenge_consumptions WHERE challenge_ref=? OR operation_ref=?",
                (consumption.challenge_ref, intent.operation_ref),
            ).fetchall()
            existing_intent = self._connection.execute(
                "SELECT operation_ref,challenge_ref,canonical_bytes,record_digest "
                "FROM privacy_deletion_intents WHERE operation_ref=? OR challenge_ref=?",
                (intent.operation_ref, intent.challenge_ref),
            ).fetchall()
            if existing_consumption or existing_intent:
                if len(existing_consumption) != 1 or len(existing_intent) != 1:
                    raise MigrationIdentityConflict("deletion identity maps to multiple durable records")
                admitted_consumption = existing_consumption[0]
                admitted_intent = existing_intent[0]
                if (
                    admitted_consumption["challenge_ref"] != consumption.challenge_ref
                    or admitted_consumption["operation_ref"] != intent.operation_ref
                    or bytes(admitted_consumption["canonical_bytes"]) != consumption_payload
                    or admitted_consumption["record_digest"] != _digest(consumption_payload)
                    or admitted_intent["operation_ref"] != intent.operation_ref
                    or admitted_intent["challenge_ref"] != intent.challenge_ref
                    or bytes(admitted_intent["canonical_bytes"]) != intent_payload
                    or admitted_intent["record_digest"] != _digest(intent_payload)
                ):
                    raise MigrationIdentityConflict(
                        "deletion retry differs from exact consumed challenge and intent"
                    )
                self._connection.commit()
                return self.load_deletion(intent.operation_ref)

            consumed_at = _parse_timestamp(consumption.consumed_at, "consumed_at")
            if consumed_at < _parse_timestamp(challenge.issued_at, "issued_at"):
                raise PrivacyLifecycleDenied("deletion challenge predates its issue time")
            if consumed_at >= _parse_timestamp(challenge.expires_at, "expires_at"):
                raise PrivacyLifecycleDenied("deletion challenge expired")

            self._connection.execute(
                "INSERT INTO privacy_deletion_intents "
                "(operation_ref,challenge_ref,canonical_bytes,record_digest) VALUES (?,?,?,?)",
                (intent.operation_ref, intent.challenge_ref, intent_payload, _digest(intent_payload)),
            )
            self._connection.execute(
                "INSERT INTO privacy_challenge_consumptions "
                "(challenge_ref,operation_ref,canonical_bytes,record_digest) VALUES (?,?,?,?)",
                (
                    consumption.challenge_ref,
                    intent.operation_ref,
                    consumption_payload,
                    _digest(consumption_payload),
                ),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return self.load_deletion(intent.operation_ref)

    def load_deletion(self, operation_ref: str) -> DeletionProgress:
        operation = _text(operation_ref, "operation_ref")
        row = self._connection.execute(
            "SELECT operation_ref,challenge_ref,canonical_bytes,record_digest "
            "FROM privacy_deletion_intents WHERE operation_ref=?",
            (operation,),
        ).fetchone()
        if row is None:
            raise PrivacyLifecycleStateError("deletion operation is not in the privacy ledger")
        intent = _decode_record(row, DeletionIntent, _validate_deletion_intent)
        if intent.operation_ref != operation or intent.challenge_ref != row["challenge_ref"]:
            raise MigrationLedgerError("deletion intent identity does not match its row")
        steps = {
            item[0]
            for item in self._connection.execute(
                "SELECT step FROM privacy_deletion_steps WHERE operation_ref=? ORDER BY ordinal",
                (operation,),
            )
        }
        receipt_row = self._connection.execute(
            "SELECT receipt_ref,operation_ref,canonical_bytes,record_digest "
            "FROM privacy_deletion_receipts WHERE operation_ref=?",
            (operation,),
        ).fetchone()
        receipt = None
        if receipt_row is not None:
            receipt = _decode_record(
                receipt_row, DeletionReceipt, _validate_deletion_receipt
            )
            if receipt.receipt_ref != receipt_row["receipt_ref"]:
                raise MigrationLedgerError("deletion receipt identity does not match its row")
            self._require_receipt_matches_intent(receipt, intent)
        return DeletionProgress(
            intent=intent,
            wrapped_key_unlinked="wrapped_key_unlinked" in steps,
            ciphertext_unlinked="ciphertext_unlinked" in steps,
            receipt=receipt,
        )

    def _append_deletion_step(self, operation_ref: str, step: str, ordinal: int) -> DeletionProgress:
        operation = _text(operation_ref, "operation_ref")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            if self._connection.execute(
                "SELECT 1 FROM privacy_deletion_intents WHERE operation_ref=?", (operation,)
            ).fetchone() is None:
                raise PrivacyLifecycleStateError("deletion operation is not in the privacy ledger")
            existing = self._connection.execute(
                "SELECT ordinal FROM privacy_deletion_steps WHERE operation_ref=? AND step=?",
                (operation, step),
            ).fetchone()
            if existing is not None:
                if existing["ordinal"] != ordinal:
                    raise MigrationIdentityConflict("deletion step ordinal differs")
                self._connection.commit()
                return self.load_deletion(operation)
            if step == "ciphertext_unlinked" and self._connection.execute(
                "SELECT 1 FROM privacy_deletion_steps "
                "WHERE operation_ref=? AND step='wrapped_key_unlinked'",
                (operation,),
            ).fetchone() is None:
                raise PrivacyLifecycleStateError("wrapped key must be unlinked first")
            self._connection.execute(
                "INSERT INTO privacy_deletion_steps (operation_ref,step,ordinal) VALUES (?,?,?)",
                (operation, step, ordinal),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return self.load_deletion(operation)

    def mark_wrapped_key_unlinked(self, operation_ref: str) -> DeletionProgress:
        return self._append_deletion_step(operation_ref, "wrapped_key_unlinked", 1)

    def mark_ciphertext_unlinked(self, operation_ref: str) -> DeletionProgress:
        return self._append_deletion_step(operation_ref, "ciphertext_unlinked", 2)

    @staticmethod
    def _require_receipt_matches_intent(
        receipt: DeletionReceipt, intent: DeletionIntent
    ) -> None:
        if (
            receipt.operation_ref != intent.operation_ref
            or receipt.quarantine_ref != intent.quarantine_ref
            or receipt.revision != intent.revision
            or receipt.authority_ref != intent.authority_ref
            or receipt.evidence_kind != intent.evidence_kind
            or receipt.evidence_ref != intent.evidence_ref
            or _parse_timestamp(receipt.completed_at, "completed_at")
            < _parse_timestamp(intent.begun_at, "begun_at")
        ):
            raise PrivacyLifecycleStateError(
                "deletion receipt does not match the exact durable intent"
            )

    def complete_deletion(self, receipt: DeletionReceipt) -> DeletionReceipt:
        payload = _record_bytes(receipt, DeletionReceipt)
        _validate_deletion_receipt(receipt)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            intent_row = self._connection.execute(
                "SELECT operation_ref,challenge_ref,canonical_bytes,record_digest "
                "FROM privacy_deletion_intents WHERE operation_ref=?",
                (receipt.operation_ref,),
            ).fetchone()
            if intent_row is None:
                raise PrivacyLifecycleStateError("deletion operation is not in the privacy ledger")
            intent = _decode_record(intent_row, DeletionIntent, _validate_deletion_intent)
            self._require_receipt_matches_intent(receipt, intent)
            steps = {
                row[0]
                for row in self._connection.execute(
                    "SELECT step FROM privacy_deletion_steps WHERE operation_ref=?",
                    (receipt.operation_ref,),
                )
            }
            if steps != {"wrapped_key_unlinked", "ciphertext_unlinked"}:
                raise PrivacyLifecycleStateError(
                    "deletion completion requires both durable unlink markers"
                )
            existing = self._connection.execute(
                "SELECT receipt_ref,canonical_bytes,record_digest "
                "FROM privacy_deletion_receipts WHERE operation_ref=? OR receipt_ref=?",
                (receipt.operation_ref, receipt.receipt_ref),
            ).fetchall()
            if existing:
                if len(existing) != 1 or (
                    existing[0]["receipt_ref"] != receipt.receipt_ref
                    or bytes(existing[0]["canonical_bytes"]) != payload
                    or existing[0]["record_digest"] != _digest(payload)
                ):
                    raise MigrationIdentityConflict(
                        "deletion completion retry differs from exact receipt bytes"
                    )
                self._connection.commit()
                return receipt
            self._connection.execute(
                "INSERT INTO privacy_deletion_receipts "
                "(receipt_ref,operation_ref,canonical_bytes,record_digest) VALUES (?,?,?,?)",
                (receipt.receipt_ref, receipt.operation_ref, payload, _digest(payload)),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return receipt


__all__ = [
    "MIGRATION_PHASES", "MigrationCheckpoint", "MigrationDisposition", "MigrationFenceRejected",
    "MigrationIdentityConflict", "MigrationLease", "MigrationLeaseConflict", "MigrationLedgerError",
    "MigrationPhaseConflict", "MigrationRepository", "MigrationRun",
]
