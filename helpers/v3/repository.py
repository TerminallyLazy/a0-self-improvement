"""Fresh v3 SQLite authority with strict writes and side-effect-free reads."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Iterator, Literal

from .artifacts import DEFAULT_REGISTRY
from .schemas import (
    RecordLink,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    canonical_loads,
    validate_digest,
)


STORE_USER_VERSION = 3


class V3RepositoryError(RuntimeError):
    """Base class for v3 persistence failures."""


class StoreNotFoundError(V3RepositoryError):
    pass


class StoreAlreadyExistsError(V3RepositoryError):
    pass


class StoreSchemaError(V3RepositoryError):
    pass


class IntegrityFailure(V3RepositoryError):
    pass


class IdentityCollision(IntegrityFailure):
    pass


class IdempotencyConflict(IntegrityFailure):
    pass


class RevisionConflict(V3RepositoryError):
    pass


@dataclass(frozen=True, slots=True)
class RecordInsertResult:
    record: TypedRecord
    inserted: bool


@dataclass(frozen=True, slots=True)
class DomainEvent:
    event_id: str
    subject_id: str
    subject_kind: str
    sequence: int
    event_type: str
    payload_record_id: str | None
    actor_authority_ref: str
    fence_token: int | None = None


@dataclass(frozen=True, slots=True)
class ActivationScope:
    context_ref: str
    current_profile_id: str
    current_profile_digest: str
    scope_revision: int
    mode: Literal["normal", "safety_bypass"]
    updated_at: str


@dataclass(frozen=True, slots=True)
class OperationSlot:
    context_ref: str
    operation_kind: Literal["canary", "monitor", "requalification"]
    operation_id: str | None
    operation_digest: str | None
    operation_revision: int
    updated_at: str


@dataclass(frozen=True, slots=True)
class OperatorCommand:
    command_id: str
    issuer_ref: str
    subject_ref: str
    context_ref: str
    action: str
    idempotency_key_digest: str
    request_digest: str
    observed_revision: int
    state: Literal["accepted", "refused"]
    mutation_receipt_id: str


@dataclass(frozen=True, slots=True)
class CommandAdmission:
    command: OperatorCommand
    replayed: bool


@dataclass(frozen=True, slots=True)
class StoredRecordObservation:
    record: TypedRecord
    created_at: str


@dataclass(frozen=True, slots=True)
class StoredDomainEventObservation:
    event: DomainEvent
    created_at: str


@dataclass(frozen=True, slots=True)
class StoredOperatorCommandObservation:
    command: OperatorCommand
    created_at: str


_SCHEMA = """
CREATE TABLE typed_records (
  record_id TEXT PRIMARY KEY,
  context_ref TEXT,
  record_kind TEXT NOT NULL,
  schema_id TEXT NOT NULL,
  canonical_bytes BLOB NOT NULL,
  content_digest TEXT NOT NULL CHECK(length(content_digest) = 64),
  link_manifest_digest TEXT NOT NULL CHECK(length(link_manifest_digest) = 64),
  key_epoch TEXT NOT NULL,
  manifest_link_count INTEGER NOT NULL CHECK(manifest_link_count >= 0),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE record_links (
  source_id TEXT NOT NULL,
  manifest_index INTEGER NOT NULL CHECK(manifest_index >= 0),
  role TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  target_id TEXT NOT NULL,
  target_digest TEXT NOT NULL CHECK(length(target_digest) = 64),
  PRIMARY KEY (source_id, role, ordinal),
  UNIQUE (source_id, manifest_index),
  FOREIGN KEY (source_id) REFERENCES typed_records(record_id),
  FOREIGN KEY (target_id) REFERENCES typed_records(record_id)
);

CREATE TABLE domain_events (
  event_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 0),
  event_type TEXT NOT NULL,
  payload_record_id TEXT,
  actor_authority_ref TEXT NOT NULL,
  fence_token INTEGER CHECK(fence_token IS NULL OR fence_token >= 0),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (subject_id, sequence),
  FOREIGN KEY (payload_record_id) REFERENCES typed_records(record_id)
);

CREATE TABLE activation_scopes (
  context_ref TEXT PRIMARY KEY,
  current_profile_id TEXT NOT NULL,
  current_profile_digest TEXT NOT NULL CHECK(length(current_profile_digest) = 64),
  scope_revision INTEGER NOT NULL CHECK(scope_revision >= 0),
  mode TEXT NOT NULL CHECK(mode IN ('normal', 'safety_bypass')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (current_profile_id) REFERENCES typed_records(record_id)
);

CREATE TABLE operation_slots (
  context_ref TEXT NOT NULL,
  operation_kind TEXT NOT NULL CHECK(operation_kind IN (
    'canary', 'monitor', 'requalification'
  )),
  operation_id TEXT,
  operation_digest TEXT CHECK(
    operation_digest IS NULL OR length(operation_digest) = 64
  ),
  operation_revision INTEGER NOT NULL CHECK(operation_revision >= 0),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (context_ref, operation_kind),
  FOREIGN KEY (operation_id) REFERENCES typed_records(record_id),
  CHECK((operation_id IS NULL) = (operation_digest IS NULL))
);

CREATE TABLE operator_commands (
  command_id TEXT PRIMARY KEY,
  issuer_ref TEXT NOT NULL,
  subject_ref TEXT NOT NULL,
  context_ref TEXT NOT NULL,
  action TEXT NOT NULL,
  idempotency_key_digest TEXT NOT NULL CHECK(length(idempotency_key_digest) = 64),
  request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
  observed_revision INTEGER NOT NULL CHECK(observed_revision >= 0),
  state TEXT NOT NULL CHECK(state IN ('accepted', 'refused')),
  mutation_receipt_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (issuer_ref, subject_ref, context_ref, action, idempotency_key_digest),
  FOREIGN KEY (mutation_receipt_id) REFERENCES typed_records(record_id)
);

CREATE TABLE budget_ledgers (
  ledger_id TEXT PRIMARY KEY,
  run_ref TEXT NOT NULL,
  budget_profile_ref TEXT NOT NULL,
  budget_profile_digest TEXT NOT NULL CHECK(length(budget_profile_digest) = 64),
  created_at TEXT NOT NULL
);

CREATE TABLE budget_dimensions (
  ledger_id TEXT NOT NULL,
  dimension TEXT NOT NULL,
  limit_amount INTEGER NOT NULL CHECK(limit_amount >= 0),
  reserved_amount INTEGER NOT NULL DEFAULT 0 CHECK(reserved_amount >= 0),
  consumed_amount INTEGER NOT NULL DEFAULT 0 CHECK(consumed_amount >= 0),
  unreconciled_amount INTEGER NOT NULL DEFAULT 0 CHECK(unreconciled_amount >= 0),
  PRIMARY KEY (ledger_id, dimension),
  FOREIGN KEY (ledger_id) REFERENCES budget_ledgers(ledger_id),
  CHECK(reserved_amount + consumed_amount + unreconciled_amount <= limit_amount)
);

CREATE TABLE work_items (
  work_id TEXT PRIMARY KEY,
  idempotency_key_digest TEXT NOT NULL CHECK(length(idempotency_key_digest) = 64),
  context_ref TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  input_record_id TEXT NOT NULL,
  input_digest TEXT NOT NULL CHECK(length(input_digest) = 64),
  budget_ledger_id TEXT,
  state TEXT NOT NULL CHECK(state IN (
    'queued', 'leased', 'cancel_requested', 'recovery_required',
    'completed', 'failed', 'cancelled'
  )),
  current_attempt_id TEXT,
  attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
  max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
  available_at TEXT NOT NULL,
  deadline_at TEXT NOT NULL,
  cancel_requested_at TEXT,
  recovery_required_at TEXT,
  fence_token INTEGER NOT NULL CHECK(fence_token >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (context_ref, operation_kind, idempotency_key_digest),
  FOREIGN KEY (input_record_id) REFERENCES typed_records(record_id),
  FOREIGN KEY (budget_ledger_id) REFERENCES budget_ledgers(ledger_id),
  CHECK(
    (state = 'queued' AND current_attempt_id IS NULL
      AND cancel_requested_at IS NULL AND recovery_required_at IS NULL)
    OR (state = 'leased' AND current_attempt_id IS NOT NULL
      AND cancel_requested_at IS NULL AND recovery_required_at IS NULL)
    OR (state = 'cancel_requested' AND cancel_requested_at IS NOT NULL)
    OR (state = 'recovery_required' AND current_attempt_id IS NOT NULL
      AND recovery_required_at IS NOT NULL)
    OR state IN ('completed', 'failed', 'cancelled')
  )
);

CREATE TABLE work_leases (
  work_id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL UNIQUE,
  owner_id TEXT NOT NULL,
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  process_nonce TEXT NOT NULL,
  process_start_identity TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  FOREIGN KEY (work_id) REFERENCES work_items(work_id)
);

CREATE TABLE worker_heartbeats (
  work_id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  heartbeat_at TEXT NOT NULL,
  FOREIGN KEY (work_id) REFERENCES work_items(work_id)
);

CREATE TABLE budget_entries (
  entry_id TEXT PRIMARY KEY,
  reservation_id TEXT NOT NULL,
  ledger_id TEXT NOT NULL,
  dimension TEXT NOT NULL,
  entry_kind TEXT NOT NULL CHECK(entry_kind IN (
    'reserve', 'reconcile', 'release', 'unreconciled'
  )),
  amount INTEGER NOT NULL CHECK(amount >= 0),
  work_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  lease_owner_id TEXT NOT NULL,
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  created_at TEXT NOT NULL,
  UNIQUE (reservation_id, dimension, entry_kind),
  FOREIGN KEY (ledger_id, dimension) REFERENCES budget_dimensions(ledger_id, dimension),
  FOREIGN KEY (work_id) REFERENCES work_items(work_id)
);

CREATE TRIGGER typed_records_no_update
BEFORE UPDATE ON typed_records BEGIN
  SELECT RAISE(ABORT, 'typed_records are append-only');
END;
CREATE TRIGGER typed_records_no_delete
BEFORE DELETE ON typed_records BEGIN
  SELECT RAISE(ABORT, 'typed_records are append-only');
END;
CREATE TRIGGER record_links_no_update
BEFORE UPDATE ON record_links BEGIN
  SELECT RAISE(ABORT, 'record_links are append-only');
END;
CREATE TRIGGER record_links_no_delete
BEFORE DELETE ON record_links BEGIN
  SELECT RAISE(ABORT, 'record_links are append-only');
END;
CREATE TRIGGER domain_events_no_update
BEFORE UPDATE ON domain_events BEGIN
  SELECT RAISE(ABORT, 'domain_events are append-only');
END;
CREATE TRIGGER domain_events_no_delete
BEFORE DELETE ON domain_events BEGIN
  SELECT RAISE(ABORT, 'domain_events are append-only');
END;
CREATE TRIGGER operator_commands_no_update
BEFORE UPDATE ON operator_commands BEGIN
  SELECT RAISE(ABORT, 'operator_commands are append-only');
END;
CREATE TRIGGER operator_commands_no_delete
BEFORE DELETE ON operator_commands BEGIN
  SELECT RAISE(ABORT, 'operator_commands are append-only');
END;
CREATE TRIGGER budget_ledgers_no_update
BEFORE UPDATE ON budget_ledgers BEGIN
  SELECT RAISE(ABORT, 'budget_ledgers are append-only');
END;
CREATE TRIGGER budget_ledgers_no_delete
BEFORE DELETE ON budget_ledgers BEGIN
  SELECT RAISE(ABORT, 'budget_ledgers are append-only');
END;
CREATE TRIGGER budget_entries_no_update
BEFORE UPDATE ON budget_entries BEGIN
  SELECT RAISE(ABORT, 'budget_entries are append-only');
END;
CREATE TRIGGER budget_entries_no_delete
BEFORE DELETE ON budget_entries BEGIN
  SELECT RAISE(ABORT, 'budget_entries are append-only');
END;
CREATE TRIGGER budget_dimensions_frozen_identity
BEFORE UPDATE OF ledger_id, dimension, limit_amount ON budget_dimensions BEGIN
  SELECT RAISE(ABORT, 'budget dimension identity and limit are frozen');
END;
CREATE TRIGGER budget_dimensions_no_delete
BEFORE DELETE ON budget_dimensions BEGIN
  SELECT RAISE(ABORT, 'budget dimensions cannot be deleted');
END;
CREATE TRIGGER work_items_frozen_inputs
BEFORE UPDATE OF work_id, idempotency_key_digest, context_ref, operation_kind,
                 input_record_id, input_digest, budget_ledger_id, max_attempts,
                 deadline_at, created_at
ON work_items BEGIN
  SELECT RAISE(ABORT, 'work item frozen inputs cannot change');
END;
CREATE TRIGGER work_items_no_delete
BEFORE DELETE ON work_items BEGIN
  SELECT RAISE(ABORT, 'work items cannot be deleted');
END;
CREATE TRIGGER work_leases_frozen_identity
BEFORE UPDATE OF work_id, attempt_id, owner_id, fence_token,
                 process_nonce, process_start_identity
ON work_leases BEGIN
  SELECT RAISE(ABORT, 'work lease identity is frozen');
END;
CREATE TRIGGER work_leases_match_item_insert
BEFORE INSERT ON work_leases BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM work_items item
    WHERE item.work_id = NEW.work_id
      AND item.state = 'leased'
      AND item.current_attempt_id = NEW.attempt_id
      AND item.fence_token = NEW.fence_token
  ) THEN RAISE(ABORT, 'work lease does not match current fenced attempt') END;
END;
CREATE TRIGGER work_leases_match_item_update
BEFORE UPDATE OF expires_at, heartbeat_at ON work_leases BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM work_items item
    WHERE item.work_id = NEW.work_id
      AND item.state = 'leased'
      AND item.current_attempt_id = NEW.attempt_id
      AND item.fence_token = NEW.fence_token
  ) THEN RAISE(ABORT, 'work lease is no longer current') END;
END;
CREATE TRIGGER worker_heartbeats_match_lease_insert
BEFORE INSERT ON worker_heartbeats BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM work_leases lease
    WHERE lease.work_id = NEW.work_id
      AND lease.attempt_id = NEW.attempt_id
      AND lease.owner_id = NEW.owner_id
      AND lease.fence_token = NEW.fence_token
  ) THEN RAISE(ABORT, 'worker heartbeat does not match lease') END;
END;
CREATE TRIGGER worker_heartbeats_match_lease_update
BEFORE UPDATE ON worker_heartbeats BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM work_leases lease
    WHERE lease.work_id = NEW.work_id
      AND lease.attempt_id = NEW.attempt_id
      AND lease.owner_id = NEW.owner_id
      AND lease.fence_token = NEW.fence_token
  ) THEN RAISE(ABORT, 'worker heartbeat does not match lease') END;
END;
CREATE TRIGGER budget_entries_match_lease
BEFORE INSERT ON budget_entries BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM work_leases lease
    WHERE lease.work_id = NEW.work_id
      AND lease.attempt_id = NEW.attempt_id
      AND lease.owner_id = NEW.lease_owner_id
      AND lease.fence_token = NEW.fence_token
  ) THEN RAISE(ABORT, 'budget entry does not match exact lease') END;
END;

CREATE TRIGGER record_links_match_manifest
BEFORE INSERT ON record_links BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM typed_records source
    WHERE source.record_id = NEW.source_id
      AND a0_link_matches(
        source.canonical_bytes,
        NEW.manifest_index,
        NEW.role,
        NEW.ordinal,
        NEW.target_id,
        NEW.target_digest
      ) = 1
  ) THEN RAISE(ABORT, 'link is not in the digest-covered source manifest') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM typed_records target
    WHERE target.record_id = NEW.target_id
      AND target.content_digest = NEW.target_digest
  ) THEN RAISE(ABORT, 'link target digest mismatch') END;
END;

CREATE TRIGGER activation_scope_profile_insert
BEFORE INSERT ON activation_scopes BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM typed_records profile
    WHERE profile.record_id = NEW.current_profile_id
      AND profile.record_kind = 'activation_profile'
      AND profile.content_digest = NEW.current_profile_digest
  ) THEN RAISE(ABORT, 'activation profile identity or digest mismatch') END;
END;
CREATE TRIGGER activation_scope_profile_update
BEFORE UPDATE OF current_profile_id, current_profile_digest ON activation_scopes BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM typed_records profile
    WHERE profile.record_id = NEW.current_profile_id
      AND profile.record_kind = 'activation_profile'
      AND profile.content_digest = NEW.current_profile_digest
  ) THEN RAISE(ABORT, 'activation profile identity or digest mismatch') END;
END;
CREATE TRIGGER operation_slot_occupant_insert
BEFORE INSERT ON operation_slots WHEN NEW.operation_id IS NOT NULL BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM typed_records operation
    WHERE operation.record_id = NEW.operation_id
      AND operation.content_digest = NEW.operation_digest
      AND operation.context_ref = NEW.context_ref
      AND (
        (NEW.operation_kind = 'canary' AND operation.record_kind = 'canary_trial')
        OR (NEW.operation_kind = 'monitor'
            AND operation.record_kind = 'post_promotion_monitor')
        OR (NEW.operation_kind = 'requalification'
            AND operation.record_kind = 'evidence_requalification_window')
      )
  ) THEN RAISE(ABORT, 'operation slot occupant identity, kind, or context mismatch') END;
END;
CREATE TRIGGER operation_slot_claim_insert_only
BEFORE INSERT ON operation_slots
WHEN NEW.operation_id IS NULL OR NEW.operation_revision != 1 BEGIN
  SELECT RAISE(ABORT, 'operation slot insertion must be the first exact claim');
END;
CREATE TRIGGER operation_slot_scope_insert
BEFORE INSERT ON operation_slots WHEN NOT EXISTS (
  SELECT 1 FROM activation_scopes scope WHERE scope.context_ref = NEW.context_ref
) BEGIN
  SELECT RAISE(ABORT, 'operation slot requires an existing activation scope');
END;
CREATE TRIGGER operation_slot_occupant_update
BEFORE UPDATE OF operation_id, operation_digest ON operation_slots
WHEN NEW.operation_id IS NOT NULL BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM typed_records operation
    WHERE operation.record_id = NEW.operation_id
      AND operation.content_digest = NEW.operation_digest
      AND operation.context_ref = NEW.context_ref
      AND (
        (NEW.operation_kind = 'canary' AND operation.record_kind = 'canary_trial')
        OR (NEW.operation_kind = 'monitor'
            AND operation.record_kind = 'post_promotion_monitor')
        OR (NEW.operation_kind = 'requalification'
            AND operation.record_kind = 'evidence_requalification_window')
      )
  ) THEN RAISE(ABORT, 'operation slot occupant identity, kind, or context mismatch') END;
END;
CREATE TRIGGER operation_slots_frozen_identity
BEFORE UPDATE OF context_ref, operation_kind ON operation_slots BEGIN
  SELECT RAISE(ABORT, 'operation slot identity is frozen');
END;
CREATE TRIGGER operation_slots_monotonic_revision
BEFORE UPDATE ON operation_slots WHEN NEW.operation_revision != OLD.operation_revision + 1 BEGIN
  SELECT RAISE(ABORT, 'operation slot revision must advance exactly once');
END;
CREATE TRIGGER operation_slots_toggle_only
BEFORE UPDATE ON operation_slots
WHEN (OLD.operation_id IS NULL) = (NEW.operation_id IS NULL) BEGIN
  SELECT RAISE(ABORT, 'operation slot updates must claim empty or clear exact occupant');
END;
CREATE TRIGGER operation_slots_no_delete
BEFORE DELETE ON operation_slots BEGIN
  SELECT RAISE(ABORT, 'operation slots cannot be deleted');
END;
"""


def _sqlite_uri(path: Path, mode: str, *, immutable: bool = False) -> str:
    query = f"mode={mode}"
    if immutable:
        query += "&immutable=1"
    return f"{path.resolve().as_uri()}?{query}"


def _link_matches(
    canonical_bytes: bytes,
    manifest_index: int,
    role: str,
    ordinal: int,
    target_id: str,
    target_digest: str,
) -> int:
    try:
        payload = canonical_loads(bytes(canonical_bytes))
        links = payload["links"]
        expected = links[manifest_index]
        actual = {
            "role": role,
            "ordinal": ordinal,
            "target_id": target_id,
            "target_digest": target_digest,
        }
        return int(expected == actual)
    except (IndexError, KeyError, TypeError, ValueError):
        return 0


def _connect_writer(path: Path, mode: str) -> sqlite3.Connection:
    connection = sqlite3.connect(
        _sqlite_uri(path, mode), uri=True, isolation_level=None, timeout=5.0
    )
    connection.row_factory = sqlite3.Row
    connection.create_function("a0_link_matches", 6, _link_matches, deterministic=True)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


def _require_store_schema(connection: sqlite3.Connection) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != STORE_USER_VERSION:
        raise StoreSchemaError(
            f"expected fresh v3 store user_version {STORE_USER_VERSION}, found {version}"
        )
    required = {
        "typed_records",
        "record_links",
        "domain_events",
        "activation_scopes",
        "operation_slots",
        "operator_commands",
        "work_items",
        "work_leases",
        "budget_ledgers",
        "budget_dimensions",
        "budget_entries",
        "worker_heartbeats",
    }
    found = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    if not required <= found:
        raise StoreSchemaError(f"v3 store is missing tables: {sorted(required - found)}")


def _validate_text(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise SchemaValidationError(f"{name} must be a non-empty string")
    return value


class _RecordReader:
    _connection: sqlite3.Connection
    _registry: SchemaRegistry

    def _typed_from_row(self, row: sqlite3.Row) -> TypedRecord:
        try:
            payload = canonical_loads(bytes(row["canonical_bytes"]))
            links = tuple(RecordLink.from_mapping(item) for item in payload["links"])
            record = TypedRecord(
                record_id=row["record_id"],
                context_ref=row["context_ref"],
                record_kind=row["record_kind"],
                schema_id=row["schema_id"],
                canonical_bytes=bytes(row["canonical_bytes"]),
                content_digest=row["content_digest"],
                link_manifest_digest=row["link_manifest_digest"],
                key_epoch=row["key_epoch"],
                links=links,
            )
            record.verify(self._registry)
            if row["manifest_link_count"] != len(record.links):
                raise IntegrityFailure("stored manifest link count does not match the record")
            return record
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, IntegrityFailure):
                raise
            raise IntegrityFailure(f"record {row['record_id']!r} failed validation") from exc

    def get_record(self, record_id: str) -> TypedRecord | None:
        row = self._connection.execute(
            "SELECT * FROM typed_records WHERE record_id = ?", (record_id,)
        ).fetchone()
        if row is None:
            return None
        record = self._typed_from_row(row)
        indexed_rows = self._connection.execute(
            """SELECT manifest_index, role, ordinal, target_id, target_digest
               FROM record_links WHERE source_id = ? ORDER BY manifest_index""",
            (record_id,),
        ).fetchall()
        indexed = tuple(
            RecordLink(
                role=item["role"],
                ordinal=item["ordinal"],
                target_id=item["target_id"],
                target_digest=item["target_digest"],
            )
            for item in indexed_rows
        )
        if indexed != record.links:
            raise IntegrityFailure("record link index differs from digest-covered manifest")
        if [item["manifest_index"] for item in indexed_rows] != list(range(len(record.links))):
            raise IntegrityFailure("record link manifest indexes are not complete and ordered")
        for link in record.links:
            target_row = self._connection.execute(
                "SELECT * FROM typed_records WHERE record_id = ?", (link.target_id,)
            ).fetchone()
            if target_row is None:
                raise IntegrityFailure("record link target is missing")
            target = self._typed_from_row(target_row)
            if target.content_digest != link.target_digest:
                raise IntegrityFailure("record link target digest no longer matches")
        return record

    def get_activation_scope(self, context_ref: str) -> ActivationScope | None:
        row = self._connection.execute(
            "SELECT * FROM activation_scopes WHERE context_ref = ?", (context_ref,)
        ).fetchone()
        if row is None:
            return None
        profile = self.get_record(row["current_profile_id"])
        if profile is None or profile.record_kind != "activation_profile":
            raise IntegrityFailure("activation scope points to a missing or invalid profile")
        if profile.content_digest != row["current_profile_digest"]:
            raise IntegrityFailure("activation scope profile digest mismatch")
        return ActivationScope(
            context_ref=row["context_ref"],
            current_profile_id=row["current_profile_id"],
            current_profile_digest=row["current_profile_digest"],
            scope_revision=row["scope_revision"],
            mode=row["mode"],
            updated_at=row["updated_at"],
        )

    def get_operation_slot(
        self,
        context_ref: str,
        operation_kind: Literal["canary", "monitor", "requalification"],
    ) -> OperationSlot | None:
        _validate_text(context_ref, "context_ref")
        if operation_kind not in ("canary", "monitor", "requalification"):
            raise SchemaValidationError("operation_kind is not admitted")
        row = self._connection.execute(
            """SELECT context_ref, operation_kind, operation_id, operation_digest,
                      operation_revision, updated_at
               FROM operation_slots
               WHERE context_ref = ? AND operation_kind = ?""",
            (context_ref, operation_kind),
        ).fetchone()
        if row is None:
            return None
        if row["operation_id"] is not None:
            operation = self.get_record(row["operation_id"])
            admitted_kind = {
                "canary": "canary_trial",
                "monitor": "post_promotion_monitor",
                "requalification": "evidence_requalification_window",
            }[operation_kind]
            if (
                operation is None
                or operation.content_digest != row["operation_digest"]
                or operation.record_kind != admitted_kind
                or operation.context_ref != context_ref
            ):
                raise IntegrityFailure("operation slot occupant identity or digest mismatch")
        return OperationSlot(**dict(row))

    def get_operator_command(
        self,
        *,
        issuer_ref: str,
        subject_ref: str,
        context_ref: str,
        action: str,
        idempotency_key_digest: str,
    ) -> OperatorCommand | None:
        for value, name in (
            (issuer_ref, "issuer_ref"),
            (subject_ref, "subject_ref"),
            (context_ref, "context_ref"),
            (action, "action"),
        ):
            _validate_text(value, name)
        validate_digest(idempotency_key_digest, "idempotency_key_digest")
        row = self._connection.execute(
            """SELECT command_id, issuer_ref, subject_ref, context_ref, action,
                      idempotency_key_digest, request_digest, observed_revision, state,
                      mutation_receipt_id
               FROM operator_commands
               WHERE issuer_ref = ? AND subject_ref = ? AND context_ref = ?
                 AND action = ? AND idempotency_key_digest = ?""",
            (
                issuer_ref,
                subject_ref,
                context_ref,
                action,
                idempotency_key_digest,
            ),
        ).fetchone()
        return None if row is None else OperatorCommand(**dict(row))

    def next_domain_event_sequence(self, subject_id: str) -> int:
        _validate_text(subject_id, "subject_id")
        row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), -1) + 1 FROM domain_events WHERE subject_id = ?",
            (subject_id,),
        ).fetchone()
        return int(row[0])

    def get_domain_event(self, subject_id: str, sequence: int) -> DomainEvent | None:
        """Read one exact immutable event without exposing the store connection."""

        _validate_text(subject_id, "subject_id")
        if type(sequence) is not int or sequence < 0:
            raise SchemaValidationError("event sequence must be a non-negative integer")
        row = self._connection.execute(
            """SELECT event_id, subject_id, subject_kind, sequence, event_type,
                      payload_record_id, actor_authority_ref, fence_token
               FROM domain_events WHERE subject_id = ? AND sequence = ?""",
            (subject_id, sequence),
        ).fetchone()
        return None if row is None else DomainEvent(**dict(row))


class V3Reader(_RecordReader):
    """A genuinely read-only view that never initializes or repairs state."""

    def __init__(self, connection: sqlite3.Connection, registry: SchemaRegistry) -> None:
        self._connection = connection
        self._registry = registry
        self._closed = False

    @classmethod
    def open(
        cls, path: str | Path, *, registry: SchemaRegistry = DEFAULT_REGISTRY
    ) -> "V3Reader":
        store_path = Path(path)
        if not store_path.is_file():
            raise StoreNotFoundError(f"v3 store does not exist: {store_path}")
        connection = sqlite3.connect(
            _sqlite_uri(store_path, "ro", immutable=True),
            uri=True,
            isolation_level=None,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA foreign_keys = ON")
            _require_store_schema(connection)
        except BaseException:
            connection.close()
            raise
        return cls(connection, registry)

    @property
    def query_only(self) -> bool:
        return bool(self._connection.execute("PRAGMA query_only").fetchone()[0])

    @staticmethod
    def _enumeration_maximum(value: int) -> int:
        if type(value) is not int or value < 0 or value >= (1 << 63):
            raise SchemaValidationError(
                "enumeration maximum must be a non-negative SQLite integer"
            )
        return value

    def count_records_for_context(self, context_ref: str) -> int:
        _validate_text(context_ref, "context_ref")
        row = self._connection.execute(
            "SELECT count(*) FROM typed_records WHERE context_ref = ?", (context_ref,)
        ).fetchone()
        return int(row[0])

    def list_records_for_context(
        self, context_ref: str, *, maximum: int
    ) -> tuple[StoredRecordObservation, ...]:
        """Return a complete context page or fail instead of truncating it."""

        _validate_text(context_ref, "context_ref")
        admitted_maximum = self._enumeration_maximum(maximum)
        if self.count_records_for_context(context_ref) > admitted_maximum:
            raise V3RepositoryError("record enumeration bound exceeded")
        rows = self._connection.execute(
            """SELECT * FROM typed_records
               WHERE context_ref = ?
               ORDER BY created_at, record_id
               LIMIT ?""",
            (context_ref, admitted_maximum),
        ).fetchall()
        return tuple(
            StoredRecordObservation(self._typed_from_row(row), row["created_at"])
            for row in rows
        )

    def count_domain_events_for_context(self, context_ref: str) -> int:
        _validate_text(context_ref, "context_ref")
        row = self._connection.execute(
            """SELECT count(*)
               FROM domain_events event
               LEFT JOIN typed_records payload
                 ON payload.record_id = event.payload_record_id
               LEFT JOIN typed_records subject
                 ON subject.record_id = event.subject_id
               WHERE COALESCE(payload.context_ref, subject.context_ref) = ?""",
            (context_ref,),
        ).fetchone()
        return int(row[0])

    def list_domain_events_for_context(
        self, context_ref: str, *, maximum: int
    ) -> tuple[StoredDomainEventObservation, ...]:
        """Return verified context-attributed events with their stored timestamp."""

        _validate_text(context_ref, "context_ref")
        admitted_maximum = self._enumeration_maximum(maximum)
        if self.count_domain_events_for_context(context_ref) > admitted_maximum:
            raise V3RepositoryError("domain-event enumeration bound exceeded")
        rows = self._connection.execute(
            """SELECT event.event_id, event.subject_id, event.subject_kind,
                      event.sequence, event.event_type, event.payload_record_id,
                      event.actor_authority_ref, event.fence_token, event.created_at
               FROM domain_events event
               LEFT JOIN typed_records payload
                 ON payload.record_id = event.payload_record_id
               LEFT JOIN typed_records subject
                 ON subject.record_id = event.subject_id
               WHERE COALESCE(payload.context_ref, subject.context_ref) = ?
               ORDER BY event.created_at, event.event_id
               LIMIT ?""",
            (context_ref, admitted_maximum),
        ).fetchall()
        result: list[StoredDomainEventObservation] = []
        for row in rows:
            values = dict(row)
            created_at = values.pop("created_at")
            event = DomainEvent(**values)
            if event.payload_record_id is not None:
                payload = self.get_record(event.payload_record_id)
                if payload is None:
                    raise IntegrityFailure("domain event payload record is missing")
            result.append(StoredDomainEventObservation(event, created_at))
        return tuple(result)

    def count_operator_commands_for_context(self, context_ref: str) -> int:
        _validate_text(context_ref, "context_ref")
        row = self._connection.execute(
            "SELECT count(*) FROM operator_commands WHERE context_ref = ?",
            (context_ref,),
        ).fetchone()
        return int(row[0])

    def list_operator_commands_for_context(
        self, context_ref: str, *, maximum: int
    ) -> tuple[StoredOperatorCommandObservation, ...]:
        """Return verified context commands with their authoritative row timestamp."""

        _validate_text(context_ref, "context_ref")
        admitted_maximum = self._enumeration_maximum(maximum)
        if self.count_operator_commands_for_context(context_ref) > admitted_maximum:
            raise V3RepositoryError("operator-command enumeration bound exceeded")
        rows = self._connection.execute(
            """SELECT command_id, issuer_ref, subject_ref, context_ref, action,
                      idempotency_key_digest, request_digest, observed_revision, state,
                      mutation_receipt_id, created_at
               FROM operator_commands
               WHERE context_ref = ?
               ORDER BY created_at, command_id
               LIMIT ?""",
            (context_ref, admitted_maximum),
        ).fetchall()
        result: list[StoredOperatorCommandObservation] = []
        for row in rows:
            values = dict(row)
            created_at = values.pop("created_at")
            command = OperatorCommand(**values)
            receipt = self.get_record(command.mutation_receipt_id)
            if receipt is None:
                raise IntegrityFailure("operator command mutation receipt is missing")
            result.append(StoredOperatorCommandObservation(command, created_at))
        return tuple(result)

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> "V3Reader":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class V3Repository(_RecordReader):
    """Explicitly opened writable authority; construction never happens on reads."""

    def __init__(self, path: Path, connection: sqlite3.Connection, registry: SchemaRegistry) -> None:
        self.path = path
        self._connection = connection
        self._registry = registry
        self._closed = False
        self._in_transaction = False

    @classmethod
    def create(
        cls, path: str | Path, *, registry: SchemaRegistry = DEFAULT_REGISTRY
    ) -> "V3Repository":
        store_path = Path(path)
        if store_path.exists():
            raise StoreAlreadyExistsError(f"refusing to replace existing path: {store_path}")
        if not store_path.parent.is_dir():
            raise StoreNotFoundError(
                f"parent directory must exist before explicit store creation: {store_path.parent}"
            )
        connection = _connect_writer(store_path, "rwc")
        try:
            connection.executescript(_SCHEMA)
            connection.execute(f"PRAGMA user_version = {STORE_USER_VERSION}")
            _require_store_schema(connection)
        except BaseException:
            connection.close()
            raise
        return cls(store_path, connection, registry)

    @classmethod
    def open(
        cls, path: str | Path, *, registry: SchemaRegistry = DEFAULT_REGISTRY
    ) -> "V3Repository":
        store_path = Path(path)
        if not store_path.is_file():
            raise StoreNotFoundError(f"v3 store does not exist: {store_path}")
        connection = _connect_writer(store_path, "rw")
        try:
            _require_store_schema(connection)
        except BaseException:
            connection.close()
            raise
        return cls(store_path, connection, registry)

    @contextmanager
    def transaction(self) -> Iterator["V3Transaction"]:
        if self._closed:
            raise V3RepositoryError("repository is closed")
        if self._in_transaction:
            raise V3RepositoryError("nested coordinator transactions are not supported")
        self._connection.execute("BEGIN IMMEDIATE")
        self._in_transaction = True
        transaction = V3Transaction(self._connection, self._registry)
        try:
            yield transaction
        except BaseException:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()
        finally:
            transaction._active = False
            self._in_transaction = False

    def close(self) -> None:
        if not self._closed:
            if self._in_transaction:
                self._connection.rollback()
            self._connection.close()
            self._closed = True

    def __enter__(self) -> "V3Repository":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class V3Transaction(_RecordReader):
    """Coordinator-owned atomic write set."""

    def __init__(self, connection: sqlite3.Connection, registry: SchemaRegistry) -> None:
        self._connection = connection
        self._registry = registry
        self._active = True

    def _require_active(self) -> None:
        if not self._active:
            raise V3RepositoryError("transaction is no longer active")

    def insert_record(self, record: TypedRecord) -> RecordInsertResult:
        self._require_active()
        try:
            record.verify(self._registry)
        except ValueError as exc:
            raise IntegrityFailure("record failed strict schema validation") from exc
        existing_row = self._connection.execute(
            "SELECT * FROM typed_records WHERE record_id = ?", (record.record_id,)
        ).fetchone()
        if existing_row is not None:
            existing = self.get_record(record.record_id)
            if existing != record:
                raise IdentityCollision(
                    f"record identity {record.record_id!r} already has different canonical content"
                )
            return RecordInsertResult(existing, False)

        for link in record.links:
            target = self.get_record(link.target_id)
            if target is None:
                raise IntegrityFailure(f"link target {link.target_id!r} does not exist")
            if target.content_digest != link.target_digest:
                raise IntegrityFailure(f"link target {link.target_id!r} digest mismatch")
        try:
            self._connection.execute(
                """INSERT INTO typed_records (
                     record_id, context_ref, record_kind, schema_id, canonical_bytes,
                     content_digest, link_manifest_digest, key_epoch, manifest_link_count
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.record_id,
                    record.context_ref,
                    record.record_kind,
                    record.schema_id,
                    record.canonical_bytes,
                    record.content_digest,
                    record.link_manifest_digest,
                    record.key_epoch,
                    len(record.links),
                ),
            )
            for manifest_index, link in enumerate(record.links):
                self._connection.execute(
                    """INSERT INTO record_links (
                         source_id, manifest_index, role, ordinal, target_id, target_digest
                       ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        record.record_id,
                        manifest_index,
                        link.role,
                        link.ordinal,
                        link.target_id,
                        link.target_digest,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise IntegrityFailure("SQLite rejected the typed record write set") from exc
        inserted = self.get_record(record.record_id)
        if inserted is None:  # pragma: no cover - SQLite acknowledged the insert
            raise IntegrityFailure("inserted record is not discoverable in its transaction")
        return RecordInsertResult(inserted, True)

    def append_event(self, event: DomainEvent) -> DomainEvent:
        self._require_active()
        for name in ("event_id", "subject_id", "subject_kind", "event_type", "actor_authority_ref"):
            _validate_text(getattr(event, name), name)
        if type(event.sequence) is not int or event.sequence < 0:
            raise SchemaValidationError("event sequence must be a non-negative integer")
        if event.fence_token is not None and (
            type(event.fence_token) is not int or event.fence_token < 0
        ):
            raise SchemaValidationError("fence_token must be null or a non-negative integer")
        subject = self.get_record(event.subject_id)
        if subject is not None and subject.record_kind != event.subject_kind:
            raise IntegrityFailure("event subject identity or kind mismatch")
        if subject is None and event.subject_kind in self._registry.record_kinds:
            raise IntegrityFailure("event subject record does not exist")
        if event.payload_record_id is not None and self.get_record(event.payload_record_id) is None:
            raise IntegrityFailure("event payload record does not exist")
        existing = self._connection.execute(
            """SELECT event_id, subject_id, subject_kind, sequence, event_type,
                      payload_record_id, actor_authority_ref, fence_token
               FROM domain_events WHERE event_id = ?""",
            (event.event_id,),
        ).fetchone()
        if existing is not None:
            admitted = DomainEvent(**dict(existing))
            if admitted != event:
                raise IdentityCollision(f"event identity {event.event_id!r} was reused")
            return admitted
        try:
            self._connection.execute(
                """INSERT INTO domain_events (
                     event_id, subject_id, subject_kind, sequence, event_type,
                     payload_record_id, actor_authority_ref, fence_token
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    event.subject_id,
                    event.subject_kind,
                    event.sequence,
                    event.event_type,
                    event.payload_record_id,
                    event.actor_authority_ref,
                    event.fence_token,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityCollision("event identity or subject sequence already exists") from exc
        return event

    def initialize_activation_scope(
        self,
        *,
        context_ref: str,
        profile_id: str,
        profile_digest: str,
        mode: Literal["normal", "safety_bypass"] = "normal",
    ) -> ActivationScope:
        self._require_active()
        _validate_text(context_ref, "context_ref")
        if mode not in ("normal", "safety_bypass"):
            raise SchemaValidationError("activation mode is not admitted")
        validate_digest(profile_digest, "profile_digest")
        if self.get_activation_scope(context_ref) is not None:
            raise RevisionConflict("activation scope already exists")
        try:
            self._connection.execute(
                """INSERT INTO activation_scopes (
                     context_ref, current_profile_id, current_profile_digest, scope_revision, mode
                   ) VALUES (?, ?, ?, 0, ?)""",
                (context_ref, profile_id, profile_digest, mode),
            )
        except sqlite3.IntegrityError as exc:
            raise IntegrityFailure("SQLite rejected Genesis activation scope") from exc
        scope = self.get_activation_scope(context_ref)
        if scope is None:  # pragma: no cover
            raise IntegrityFailure("Genesis activation scope was not stored")
        return scope

    def compare_and_swap_activation_scope(
        self,
        *,
        context_ref: str,
        expected_revision: int,
        profile_id: str,
        profile_digest: str,
        mode: Literal["normal", "safety_bypass"],
    ) -> ActivationScope:
        self._require_active()
        if type(expected_revision) is not int or expected_revision < 0:
            raise SchemaValidationError("expected_revision must be a non-negative integer")
        if mode not in ("normal", "safety_bypass"):
            raise SchemaValidationError("activation mode is not admitted")
        validate_digest(profile_digest, "profile_digest")
        try:
            cursor = self._connection.execute(
                """UPDATE activation_scopes
                   SET current_profile_id = ?, current_profile_digest = ?,
                       scope_revision = scope_revision + 1, mode = ?,
                       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                   WHERE context_ref = ? AND scope_revision = ?""",
                (profile_id, profile_digest, mode, context_ref, expected_revision),
            )
        except sqlite3.IntegrityError as exc:
            raise IntegrityFailure("SQLite rejected activation scope successor") from exc
        if cursor.rowcount != 1:
            raise RevisionConflict("activation scope revision did not match")
        scope = self.get_activation_scope(context_ref)
        if scope is None:  # pragma: no cover
            raise IntegrityFailure("activation scope disappeared during CAS")
        return scope

    def claim_empty_operation_slot(
        self,
        *,
        context_ref: str,
        operation_kind: Literal["canary", "monitor", "requalification"],
        expected_revision: int,
        expected_scope_revision: int,
        operation_id: str,
        operation_digest: str,
    ) -> OperationSlot:
        """Claim only an absent/empty exact-revision slot under the current scope."""

        self._require_active()
        _validate_text(context_ref, "context_ref")
        _validate_text(operation_id, "operation_id")
        if operation_kind not in ("canary", "monitor", "requalification"):
            raise SchemaValidationError("operation_kind is not admitted")
        for value, name in (
            (expected_revision, "expected_revision"),
            (expected_scope_revision, "expected_scope_revision"),
        ):
            if type(value) is not int or value < 0:
                raise SchemaValidationError(f"{name} must be a non-negative integer")
        validate_digest(operation_digest, "operation_digest")
        scope = self.get_activation_scope(context_ref)
        if scope is None or scope.scope_revision != expected_scope_revision:
            raise RevisionConflict("activation scope revision did not match slot claim")
        current = self.get_operation_slot(context_ref, operation_kind)
        try:
            if current is None:
                if expected_revision != 0:
                    raise RevisionConflict("absent operation slot has revision zero")
                self._connection.execute(
                    """INSERT INTO operation_slots (
                         context_ref, operation_kind, operation_id, operation_digest,
                         operation_revision
                       ) VALUES (?, ?, ?, ?, 1)""",
                    (context_ref, operation_kind, operation_id, operation_digest),
                )
            else:
                cursor = self._connection.execute(
                    """UPDATE operation_slots
                       SET operation_id = ?, operation_digest = ?,
                           operation_revision = operation_revision + 1,
                           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                       WHERE context_ref = ? AND operation_kind = ?
                         AND operation_revision = ? AND operation_id IS NULL
                         AND operation_digest IS NULL""",
                    (
                        operation_id,
                        operation_digest,
                        context_ref,
                        operation_kind,
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RevisionConflict("operation slot is occupied or revision-stale")
        except sqlite3.IntegrityError as exc:
            raise IntegrityFailure("SQLite rejected the exact operation slot claim") from exc
        claimed = self.get_operation_slot(context_ref, operation_kind)
        if claimed is None:  # pragma: no cover
            raise IntegrityFailure("claimed operation slot disappeared")
        return claimed

    def clear_exact_operation_slot(
        self,
        *,
        context_ref: str,
        operation_kind: Literal["canary", "monitor", "requalification"],
        expected_revision: int,
        expected_scope_revision: int,
        operation_id: str,
        operation_digest: str,
    ) -> OperationSlot:
        """Clear only the exact occupant; never replace or silently displace it."""

        self._require_active()
        _validate_text(context_ref, "context_ref")
        _validate_text(operation_id, "operation_id")
        if operation_kind not in ("canary", "monitor", "requalification"):
            raise SchemaValidationError("operation_kind is not admitted")
        for value, name in (
            (expected_revision, "expected_revision"),
            (expected_scope_revision, "expected_scope_revision"),
        ):
            if type(value) is not int or value < 0:
                raise SchemaValidationError(f"{name} must be a non-negative integer")
        validate_digest(operation_digest, "operation_digest")
        scope = self.get_activation_scope(context_ref)
        if scope is None or scope.scope_revision != expected_scope_revision:
            raise RevisionConflict("activation scope revision did not match slot clear")
        cursor = self._connection.execute(
            """UPDATE operation_slots
               SET operation_id = NULL, operation_digest = NULL,
                   operation_revision = operation_revision + 1,
                   updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               WHERE context_ref = ? AND operation_kind = ?
                 AND operation_revision = ? AND operation_id = ?
                 AND operation_digest = ?""",
            (
                context_ref,
                operation_kind,
                expected_revision,
                operation_id,
                operation_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise RevisionConflict("operation slot occupant or revision did not match")
        cleared = self.get_operation_slot(context_ref, operation_kind)
        if cleared is None:  # pragma: no cover
            raise IntegrityFailure("cleared operation slot disappeared")
        return cleared

    def admit_command(self, command: OperatorCommand) -> CommandAdmission:
        self._require_active()
        for name in (
            "command_id",
            "issuer_ref",
            "subject_ref",
            "context_ref",
            "action",
            "mutation_receipt_id",
        ):
            _validate_text(getattr(command, name), name)
        validate_digest(command.idempotency_key_digest, "idempotency_key_digest")
        validate_digest(command.request_digest, "request_digest")
        if type(command.observed_revision) is not int or command.observed_revision < 0:
            raise SchemaValidationError("observed_revision must be a non-negative integer")
        if command.state not in ("accepted", "refused"):
            raise SchemaValidationError("command state is not admitted")
        if self.get_record(command.mutation_receipt_id) is None:
            raise IntegrityFailure("command mutation receipt does not exist")
        identity = (
            command.issuer_ref,
            command.subject_ref,
            command.context_ref,
            command.action,
            command.idempotency_key_digest,
        )
        existing = self._connection.execute(
            """SELECT command_id, issuer_ref, subject_ref, context_ref, action,
                      idempotency_key_digest, request_digest, observed_revision, state,
                      mutation_receipt_id
               FROM operator_commands
               WHERE issuer_ref = ? AND subject_ref = ? AND context_ref = ?
                 AND action = ? AND idempotency_key_digest = ?""",
            identity,
        ).fetchone()
        if existing is not None:
            admitted = OperatorCommand(**dict(existing))
            if admitted.request_digest != command.request_digest:
                raise IdempotencyConflict("idempotency key was reused with a different request")
            return CommandAdmission(admitted, True)
        collision = self._connection.execute(
            "SELECT 1 FROM operator_commands WHERE command_id = ?", (command.command_id,)
        ).fetchone()
        if collision is not None:
            raise IdentityCollision(f"command identity {command.command_id!r} was reused")
        try:
            self._connection.execute(
                """INSERT INTO operator_commands (
                     command_id, issuer_ref, subject_ref, context_ref, action,
                     idempotency_key_digest, request_digest, observed_revision, state,
                     mutation_receipt_id
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    command.command_id,
                    command.issuer_ref,
                    command.subject_ref,
                    command.context_ref,
                    command.action,
                    command.idempotency_key_digest,
                    command.request_digest,
                    command.observed_revision,
                    command.state,
                    command.mutation_receipt_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IntegrityFailure("SQLite rejected operator command") from exc
        return CommandAdmission(command, False)
