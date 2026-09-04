"""Authoritative local SQLite persistence for the DSPy RLM plugin.

The store is deliberately local-process/machine only.  Mutable pointers use short
``BEGIN IMMEDIATE`` transactions; evidence and optimization artifacts are append
only.  JSON columns hold structured, already-sanitized plugin data and are never
interpreted as executable instructions.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
import sqlite3
import stat
import threading
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from .paths import STORE_FILE

_SCHEMA_VERSION = 12
_CONNECTION_LOCK = threading.RLock()


def _now() -> float:
    return time.time()


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _decode(value: str | None, default: Any = None) -> Any:
    if not value:
        return {} if default is None else default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return {} if default is None else default


def _digest(value: Any) -> str:
    return sha256(_json(value).encode("utf-8")).hexdigest()


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


@contextmanager
def _migration_lock(db_path: Path):
    """Serialize non-idempotent DDL across WebUI and worker processes."""

    lock_path = db_path.with_name(f"{db_path.name}.migrate.lock")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise PermissionError("migration lock is not an owner-controlled file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, """
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS runtime_context_state (
      context_id TEXT PRIMARY KEY,
      state_json TEXT NOT NULL,
      revision INTEGER NOT NULL DEFAULT 0,
      updated_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence_events (
      event_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      event_json TEXT NOT NULL,
      content_digest TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_evidence_events_context_created
      ON evidence_events(context_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS samples (
      sample_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      objective_bucket TEXT NOT NULL,
      objective_signature TEXT NOT NULL DEFAULT '',
      payload_json TEXT NOT NULL,
      payload_digest TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_samples_context_bucket_created
      ON samples(context_id, objective_bucket, created_at DESC);

    CREATE TABLE IF NOT EXISTS sample_manifests (
      manifest_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      sample_ids_json TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      manifest_digest TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_manifests_context_kind_created
      ON sample_manifests(context_id, kind, created_at DESC);

    CREATE TABLE IF NOT EXISTS guidance_versions (
      guidance_version TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      objective_bucket TEXT NOT NULL,
      objective_signature TEXT NOT NULL DEFAULT '',
      guidance_text TEXT NOT NULL,
      metadata_json TEXT NOT NULL,
      artifact_digest TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_guidance_context_bucket_created
      ON guidance_versions(context_id, objective_bucket, created_at DESC);

    CREATE TABLE IF NOT EXISTS candidates (
      candidate_id TEXT PRIMARY KEY,
      run_id TEXT,
      context_id TEXT NOT NULL,
      objective_bucket TEXT NOT NULL,
      guidance_version TEXT,
      candidate_json TEXT NOT NULL,
      candidate_digest TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_candidates_context_bucket_created
      ON candidates(context_id, objective_bucket, created_at DESC);

    CREATE TABLE IF NOT EXISTS optimization_runs (
      run_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      status TEXT NOT NULL,
      run_json TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS evaluations (
      evaluation_id TEXT PRIMARY KEY,
      candidate_id TEXT NOT NULL,
      evaluation_json TEXT NOT NULL,
      evaluation_digest TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS replay_audits (
      audit_id TEXT PRIMARY KEY,
      candidate_id TEXT NOT NULL,
      manifest_id TEXT,
      audit_json TEXT NOT NULL,
      audit_digest TEXT NOT NULL,
      created_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS active_guidance (
      context_id TEXT NOT NULL,
      objective_bucket TEXT NOT NULL,
      guidance_version TEXT NOT NULL,
      revision INTEGER NOT NULL DEFAULT 0,
      updated_at REAL NOT NULL,
      PRIMARY KEY(context_id, objective_bucket),
      FOREIGN KEY(guidance_version) REFERENCES guidance_versions(guidance_version)
    );

    CREATE TABLE IF NOT EXISTS promotion_audits (
      promotion_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      objective_bucket TEXT NOT NULL,
      action TEXT NOT NULL,
      previous_guidance_version TEXT,
      guidance_version TEXT,
      expected_revision INTEGER,
      resulting_revision INTEGER,
      actor_id TEXT,
      detail_json TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_promotion_audits_context_bucket_created
      ON promotion_audits(context_id, objective_bucket, created_at DESC);

    CREATE TABLE IF NOT EXISTS jobs (
      job_key TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      status TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      max_retries INTEGER NOT NULL DEFAULT 2,
      payload_json TEXT NOT NULL,
      result_json TEXT,
      last_error TEXT,
      created_at REAL NOT NULL,
      updated_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at);

    CREATE TABLE IF NOT EXISTS job_leases (
      job_key TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      fencing_token INTEGER NOT NULL,
      expires_at REAL NOT NULL,
      updated_at REAL NOT NULL,
      FOREIGN KEY(job_key) REFERENCES jobs(job_key)
    );
    CREATE INDEX IF NOT EXISTS idx_job_leases_expiry ON job_leases(expires_at);

    CREATE TABLE IF NOT EXISTS worker_heartbeats (
      worker_id TEXT PRIMARY KEY,
      heartbeat_json TEXT NOT NULL,
      updated_at REAL NOT NULL,
      expires_at REAL NOT NULL
    );
    """),
    (2, """
    CREATE TABLE IF NOT EXISTS prompt_snapshots (
      snapshot_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      base_digest TEXT NOT NULL,
      components_json TEXT NOT NULL,
      protected_json TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_prompt_snapshots_context_created
      ON prompt_snapshots(context_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS prompt_artifacts (
      artifact_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      target_key TEXT NOT NULL,
      target_mode TEXT NOT NULL,
      activation_mode TEXT NOT NULL,
      base_digest TEXT NOT NULL,
      artifact_json TEXT NOT NULL,
      artifact_digest TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_prompt_artifacts_context_created
      ON prompt_artifacts(context_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS active_prompt_artifacts (
      context_id TEXT NOT NULL,
      target_key TEXT NOT NULL,
      artifact_id TEXT NOT NULL,
      baseline_snapshot_id TEXT NOT NULL,
      state TEXT NOT NULL,
      activation_mode TEXT NOT NULL,
      canary_percentage INTEGER NOT NULL,
      revision INTEGER NOT NULL DEFAULT 0,
      observations INTEGER NOT NULL DEFAULT 0,
      failures INTEGER NOT NULL DEFAULT 0,
      baseline_failure_rate REAL NOT NULL DEFAULT 0,
      updated_at REAL NOT NULL,
      PRIMARY KEY(context_id, target_key),
      FOREIGN KEY(artifact_id) REFERENCES prompt_artifacts(artifact_id),
      FOREIGN KEY(baseline_snapshot_id) REFERENCES prompt_snapshots(snapshot_id)
    );

    CREATE TABLE IF NOT EXISTS prompt_activation_audits (
      audit_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      target_key TEXT NOT NULL,
      artifact_id TEXT,
      action TEXT NOT NULL,
      previous_state TEXT,
      resulting_state TEXT NOT NULL,
      revision INTEGER NOT NULL,
      detail_json TEXT NOT NULL,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_prompt_activation_audits_context_created
      ON prompt_activation_audits(context_id, created_at DESC);
    """),
    (3, """
    CREATE TABLE IF NOT EXISTS autopilot_transitions (
      candidate_id TEXT PRIMARY KEY,
      context_id TEXT NOT NULL,
      objective_bucket TEXT NOT NULL,
      guidance_version TEXT NOT NULL,
      baseline_guidance_version TEXT,
      expected_active_revision INTEGER NOT NULL,
      state TEXT NOT NULL,
      canary_observations INTEGER NOT NULL DEFAULT 0,
      canary_failures INTEGER NOT NULL DEFAULT 0,
      monitor_observations INTEGER NOT NULL DEFAULT 0,
      monitor_failures INTEGER NOT NULL DEFAULT 0,
      reason_code TEXT NOT NULL,
      created_at REAL NOT NULL,
      updated_at REAL NOT NULL,
      FOREIGN KEY(guidance_version) REFERENCES guidance_versions(guidance_version)
    );
    CREATE INDEX IF NOT EXISTS idx_autopilot_transitions_scope_updated
      ON autopilot_transitions(context_id, objective_bucket, updated_at DESC);
    """),
    (4, """
    CREATE INDEX IF NOT EXISTS idx_autopilot_transitions_live_bucket
      ON autopilot_transitions(context_id, objective_bucket, created_at)
      WHERE state IN ('canary','monitoring');
    CREATE INDEX IF NOT EXISTS idx_autopilot_transitions_live_context
      ON autopilot_transitions(context_id, created_at)
      WHERE state IN ('canary','monitoring');
    """),
    (5, """
    CREATE TABLE IF NOT EXISTS active_guidance_revisions (
      context_id TEXT NOT NULL,
      objective_bucket TEXT NOT NULL,
      revision INTEGER NOT NULL,
      updated_at REAL NOT NULL,
      PRIMARY KEY(context_id,objective_bucket)
    );
    INSERT OR IGNORE INTO active_guidance_revisions(context_id,objective_bucket,revision,updated_at)
      SELECT context_id,objective_bucket,revision,updated_at FROM active_guidance;
    """),
    (6, """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_autopilot_transitions_one_live_bucket
      ON autopilot_transitions(context_id, objective_bucket)
      WHERE state IN ('canary','promoting','monitoring','rolling_back');
    """),
    (7, """
    ALTER TABLE autopilot_transitions ADD COLUMN policy_id TEXT;
    ALTER TABLE autopilot_transitions ADD COLUMN policy_digest TEXT;
    ALTER TABLE autopilot_transitions ADD COLUMN calibration_id TEXT;
    ALTER TABLE autopilot_transitions ADD COLUMN calibration_digest TEXT;
    """),
    (8, """
    ALTER TABLE autopilot_transitions ADD COLUMN canary_plan_id TEXT;
    ALTER TABLE autopilot_transitions ADD COLUMN canary_plan_digest TEXT;
    ALTER TABLE autopilot_transitions ADD COLUMN monitor_plan_id TEXT;
    ALTER TABLE autopilot_transitions ADD COLUMN monitor_plan_digest TEXT;
    ALTER TABLE autopilot_transitions ADD COLUMN canary_control_observations INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE autopilot_transitions ADD COLUMN canary_control_failures INTEGER NOT NULL DEFAULT 0;
    """),
    (9, """
    CREATE TABLE IF NOT EXISTS autopilot_candidate_approvals (
      candidate_id TEXT PRIMARY KEY,
      job_key TEXT NOT NULL,
      fencing_token INTEGER NOT NULL,
      candidate_digest TEXT NOT NULL,
      approved_at REAL NOT NULL,
      FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id)
    );
    CREATE TABLE IF NOT EXISTS autopilot_transition_outcomes (
      candidate_id TEXT NOT NULL,
      exposure_ref TEXT NOT NULL,
      transition_state TEXT NOT NULL,
      arm TEXT NOT NULL,
      success INTEGER NOT NULL,
      hard_failure INTEGER NOT NULL DEFAULT 0,
      created_at REAL NOT NULL,
      PRIMARY KEY(candidate_id, exposure_ref),
      FOREIGN KEY(candidate_id) REFERENCES autopilot_transitions(candidate_id)
    );
    CREATE TABLE IF NOT EXISTS autopilot_candidate_considerations (
      candidate_id TEXT PRIMARY KEY,
      result TEXT NOT NULL,
      considered_at REAL NOT NULL,
      FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id)
    );
    """),
    (10, """
    ALTER TABLE autopilot_candidate_approvals ADD COLUMN config_digest TEXT;
    CREATE TABLE IF NOT EXISTS job_fence_counters (
      job_key TEXT PRIMARY KEY,
      last_token INTEGER NOT NULL
    );
    INSERT OR REPLACE INTO job_fence_counters(job_key,last_token)
      SELECT j.job_key,
             MAX(j.attempts, COALESCE(l.fencing_token, 0))
        FROM jobs AS j
   LEFT JOIN job_leases AS l ON l.job_key=j.job_key;
    UPDATE autopilot_transitions
       SET state='recovery_required',
           reason_code='receipt_upgrade_required',
           updated_at=strftime('%s','now')
     WHERE state IN ('canary','promoting','monitoring','rolling_back');
    """),
    (11, """
    ALTER TABLE optimization_runs ADD COLUMN run_digest TEXT;
    UPDATE autopilot_transitions
       SET state='recovery_required',
           reason_code='run_digest_upgrade_required',
           updated_at=strftime('%s','now')
     WHERE state IN ('canary','promoting','monitoring','rolling_back');
    """),
    (12, """
    ALTER TABLE autopilot_transitions ADD COLUMN source_candidate_digest TEXT;
    UPDATE autopilot_transitions
       SET state='recovery_required',
           reason_code='publication_binding_upgrade_required',
           updated_at=strftime('%s','now')
     WHERE state IN ('canary','promoting','monitoring','rolling_back');
    """),
)


class Store:
    """SQLite repositories and transactions rooted at a caller-controlled path."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path is not None else STORE_FILE
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def migrate(self) -> None:
        with _CONNECTION_LOCK, _migration_lock(self.db_path), self._connect() as conn:
            self._prepare_legacy_schema(conn)
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS legacy_imports (source TEXT PRIMARY KEY, imported_at REAL NOT NULL)")
            applied = {int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations")}
            for version, sql in MIGRATIONS:
                if version not in applied:
                    # executescript commits an open transaction first, so include
                    # explicit boundaries in its script. A failed migration is not
                    # recorded and is rolled back before another process can retry.
                    try:
                        conn.executescript(
                            "BEGIN IMMEDIATE;\n"
                            + sql
                            + f"\nINSERT INTO schema_migrations(version, applied_at) VALUES ({version}, {_now()!r});\nCOMMIT;"
                        )
                    except Exception:
                        if conn.in_transaction:
                            conn.rollback()
                        raise
            self._backfill_run_digests(conn)
            self._import_legacy_rows(conn)

    @staticmethod
    def _backfill_run_digests(conn: sqlite3.Connection) -> None:
        """Bind pre-v11 run bodies to their canonical digest when decodable."""

        for row in conn.execute(
            "SELECT run_id,run_json FROM optimization_runs WHERE run_digest IS NULL"
        ):
            try:
                body = json.loads(row["run_json"])
            except (TypeError, ValueError):
                continue
            if not isinstance(body, dict):
                continue
            conn.execute(
                "UPDATE optimization_runs SET run_digest=? WHERE run_id=? AND run_digest IS NULL",
                (_digest(body), str(row["run_id"])),
            )

    @staticmethod
    def _table_columns(conn: sqlite3.Connection, name: str) -> set[str]:
        return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({name})")}

    def _prepare_legacy_schema(self, conn: sqlite3.Connection) -> None:
        """Make a non-versioned pre-Task-3 database safe for the new schema.

        The prior state facade used the same ``guidance_versions`` table name
        with a different primary key. Rename it before migration instead of
        dropping it, then import its rows below. Other old table names do not
        collide and remain readable migration sources.
        """
        names = {str(row["name"]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "guidance_versions" in names and "artifact_digest" not in self._table_columns(conn, "guidance_versions"):
            if "legacy_guidance_versions" not in names:
                conn.execute("ALTER TABLE guidance_versions RENAME TO legacy_guidance_versions")

    def _import_legacy_rows(self, conn: sqlite3.Connection) -> None:
        """Copy old state-facade rows once, without making JSON authoritative."""
        source = "state_facade_v1"
        if conn.execute("SELECT 1 FROM legacy_imports WHERE source=?", (source,)).fetchone():
            return
        names = {str(row["name"]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        now = _now()
        conn.execute("BEGIN IMMEDIATE")
        try:
            if "objective_samples" in names:
                for row in conn.execute("SELECT sample_id,objective_payload,created_at FROM objective_samples"):
                    body = _decode(row["objective_payload"])
                    if not isinstance(body, dict):
                        continue
                    conn.execute("INSERT OR IGNORE INTO samples(sample_id,context_id,objective_bucket,objective_signature,payload_json,payload_digest,created_at) VALUES(?,?,?,?,?,?,?)", (
                        str(row["sample_id"]), str(body.get("context_id") or ""), str(body.get("objective_bucket") or "reasoning"), str(body.get("objective_signature") or ""), _json(body), _digest(body), float(row["created_at"] or now)))
            if "optimization_jobs" in names:
                for row in conn.execute("SELECT job_key,context_id,status,attempts,max_retries,payload_json,result_json,last_error,created_at,updated_at FROM optimization_jobs"):
                    conn.execute("INSERT OR IGNORE INTO jobs(job_key,context_id,status,attempts,max_retries,payload_json,result_json,last_error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (
                        str(row["job_key"]), str(row["context_id"]), str(row["status"]), int(row["attempts"] or 0), int(row["max_retries"] or 2), row["payload_json"] or "{}", row["result_json"], row["last_error"], float(row["created_at"] or now), float(row["updated_at"] or now)))
            if "legacy_guidance_versions" in names:
                for row in conn.execute("SELECT context_id,objective_bucket,objective_signature,guidance_version,guidance_text,metadata_json,created_at FROM legacy_guidance_versions ORDER BY created_at"):
                    metadata = _decode(row["metadata_json"])
                    record = {"guidance_text": str(row["guidance_text"]), "metadata": metadata}
                    conn.execute("INSERT OR IGNORE INTO guidance_versions(guidance_version,context_id,objective_bucket,objective_signature,guidance_text,metadata_json,artifact_digest,created_at) VALUES(?,?,?,?,?,?,?,?)", (
                        str(row["guidance_version"]), str(row["context_id"]), str(row["objective_bucket"]), str(row["objective_signature"] or ""), str(row["guidance_text"]), _json(metadata), _digest(record), float(row["created_at"] or now)))
                    current = conn.execute("SELECT revision FROM active_guidance WHERE context_id=? AND objective_bucket=?", (str(row["context_id"]), str(row["objective_bucket"]))).fetchone()
                    revision = int(current["revision"]) + 1 if current else 1
                    conn.execute("INSERT INTO active_guidance(context_id,objective_bucket,guidance_version,revision,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(context_id,objective_bucket) DO UPDATE SET guidance_version=excluded.guidance_version,revision=excluded.revision,updated_at=excluded.updated_at", (
                        str(row["context_id"]), str(row["objective_bucket"]), str(row["guidance_version"]), revision, float(row["created_at"] or now)))
            conn.execute("INSERT INTO legacy_imports(source,imported_at) VALUES(?,?)", (source, now))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    @property
    def schema_version(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0) if row else 0

    # Runtime state ---------------------------------------------------------
    def get_context_state(self, context_id: str) -> tuple[dict[str, Any], int]:
        with self._connect() as conn:
            row = conn.execute("SELECT state_json, revision FROM runtime_context_state WHERE context_id=?", (str(context_id),)).fetchone()
        return (_decode(row["state_json"]), int(row["revision"])) if row else ({}, 0)

    def put_context_state(self, context_id: str, state: Mapping[str, Any], *, expected_revision: int | None = None) -> tuple[bool, int]:
        now = _now()
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT revision FROM runtime_context_state WHERE context_id=?", (str(context_id),)).fetchone()
            current = int(row["revision"]) if row else 0
            if expected_revision is not None and current != int(expected_revision):
                conn.execute("ROLLBACK")
                return False, current
            revision = current + 1
            conn.execute("""INSERT INTO runtime_context_state(context_id,state_json,revision,updated_at) VALUES(?,?,?,?)
                ON CONFLICT(context_id) DO UPDATE SET state_json=excluded.state_json,revision=excluded.revision,updated_at=excluded.updated_at""",
                (str(context_id), _json(dict(state)), revision, now))
            conn.execute("COMMIT")
        return True, revision

    # Immutable evidence and artifacts -------------------------------------
    def append_evidence(self, event_id: str, context_id: str, event_type: str, event: Mapping[str, Any], *, created_at: float | None = None) -> str:
        payload = dict(event)
        digest = _digest(payload)
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO evidence_events(event_id,context_id,event_type,event_json,content_digest,created_at) VALUES(?,?,?,?,?,?)",
                (str(event_id), str(context_id), str(event_type), _json(payload), digest, float(created_at or _now())))
        return str(event_id)

    def append_sample(self, sample_id: str, sample: Mapping[str, Any], *, created_at: float | None = None) -> str:
        payload = dict(sample)
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO samples(sample_id,context_id,objective_bucket,objective_signature,payload_json,payload_digest,created_at) VALUES(?,?,?,?,?,?,?)",
                (str(sample_id), str(payload.get("context_id") or ""), str(payload.get("objective_bucket") or "reasoning"), str(payload.get("objective_signature") or ""), _json(payload), _digest(payload), float(created_at or payload.get("created_at") or _now())))
        return str(sample_id)

    def get_sample(self, sample_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT payload_json FROM samples WHERE sample_id=?", (str(sample_id),)).fetchone()
        return _decode(row["payload_json"]) if row else None

    def list_samples(self, context_id: str, bucket: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        sql, params = "SELECT payload_json FROM samples WHERE context_id=?", [str(context_id)]
        if bucket:
            sql += " AND objective_bucket=?"; params.append(str(bucket))
        sql += " ORDER BY created_at DESC LIMIT ?"; params.append(max(0, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [value for row in rows if isinstance((value := _decode(row["payload_json"])), dict)]

    def count_samples(self, context_id: str, bucket: str | None = None) -> int:
        sql, params = "SELECT COUNT(*) FROM samples WHERE context_id=?", [str(context_id)]
        if bucket:
            sql += " AND objective_bucket=?"; params.append(str(bucket))
        with self._connect() as conn:
            return int(conn.execute(sql, params).fetchone()[0])

    def append_manifest(self, manifest_id: str, context_id: str, kind: str, sample_ids: Iterable[str], payload: Mapping[str, Any] | None = None) -> str:
        ids = [str(item) for item in sample_ids]
        body = dict(payload or {})
        record = {"context_id": str(context_id), "kind": str(kind), "sample_ids": ids, "payload": body}
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO sample_manifests(manifest_id,context_id,kind,sample_ids_json,payload_json,manifest_digest,created_at) VALUES(?,?,?,?,?,?,?)",
                (str(manifest_id), str(context_id), str(kind), _json(ids), _json(body), _digest(record), _now()))
        return str(manifest_id)

    def append_candidate(self, candidate_id: str, context_id: str, objective_bucket: str, candidate: Mapping[str, Any], *, run_id: str | None = None, guidance_version: str | None = None) -> str:
        body = dict(candidate)
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO candidates(candidate_id,run_id,context_id,objective_bucket,guidance_version,candidate_json,candidate_digest,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (str(candidate_id), run_id, str(context_id), str(objective_bucket), guidance_version, _json(body), _digest(body), _now()))
        return str(candidate_id)

    @staticmethod
    def _candidate_envelope(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["candidate"] = _decode(item.pop("candidate_json"))
        return item

    def get_candidate(
        self, candidate_id: str, *, context_id: str | None = None
    ) -> dict[str, Any] | None:
        """Return one immutable candidate envelope by exact identity."""

        sql = """SELECT candidate_id,run_id,context_id,objective_bucket,
                        guidance_version,candidate_json,candidate_digest,created_at
                 FROM candidates WHERE candidate_id=?"""
        params: list[Any] = [str(candidate_id)]
        if context_id is not None:
            sql += " AND context_id=?"
            params.append(str(context_id))
        with self._connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return None if row is None else self._candidate_envelope(row)

    def list_candidates(
        self,
        context_id: str,
        *,
        after: tuple[float, str] | None = None,
        limit: int = 128,
    ) -> list[dict[str, Any]]:
        """Return one bounded page of immutable candidate envelopes, oldest first."""

        bounded_limit = max(1, min(int(limit), 512))
        sql = """SELECT candidate_id,run_id,context_id,objective_bucket,
                        guidance_version,candidate_json,candidate_digest,created_at
                 FROM candidates WHERE context_id=?"""
        params: list[Any] = [str(context_id)]
        if after is not None:
            created_at, candidate_id = after
            sql += " AND (created_at>? OR (created_at=? AND candidate_id>?))"
            params.extend((float(created_at), float(created_at), str(candidate_id)))
        sql += " ORDER BY created_at,candidate_id LIMIT ?"
        params.append(bounded_limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._candidate_envelope(row) for row in rows]

    def append_guidance_version(self, guidance_version: str, context_id: str, objective_bucket: str, objective_signature: str, guidance_text: str, metadata: Mapping[str, Any] | None = None) -> str:
        record = {"guidance_text": str(guidance_text), "metadata": dict(metadata or {})}
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO guidance_versions(guidance_version,context_id,objective_bucket,objective_signature,guidance_text,metadata_json,artifact_digest,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (str(guidance_version), str(context_id), str(objective_bucket), str(objective_signature), str(guidance_text), _json(record["metadata"]), _digest(record), _now()))
        return str(guidance_version)

    def get_guidance_version(self, guidance_version: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM guidance_versions WHERE guidance_version=?", (str(guidance_version),)).fetchone()
        result = _row(row)
        if result:
            result["metadata"] = _decode(result.pop("metadata_json"))
        return result

    # Active guidance CAS, promotion and rollback --------------------------
    def get_active_guidance(self, context_id: str, objective_bucket: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("""SELECT a.guidance_version,
                       MAX(a.revision,COALESCE(r.revision,a.revision)) AS revision,
                       a.updated_at,g.objective_signature,g.guidance_text,g.metadata_json
                FROM active_guidance a JOIN guidance_versions g ON g.guidance_version=a.guidance_version
                LEFT JOIN active_guidance_revisions r ON r.context_id=a.context_id AND r.objective_bucket=a.objective_bucket
                WHERE a.context_id=? AND a.objective_bucket=?""", (str(context_id), str(objective_bucket))).fetchone()
        result = _row(row)
        if result:
            result["metadata"] = _decode(result.pop("metadata_json"))
            result["created_at"] = result["updated_at"]
        return result

    def get_active_guidance_revision(self, context_id: str, objective_bucket: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT revision FROM active_guidance_revisions WHERE context_id=? AND objective_bucket=?",
                (str(context_id), str(objective_bucket)),
            ).fetchone()
            if row is not None:
                return int(row["revision"])
            active = conn.execute(
                "SELECT revision FROM active_guidance WHERE context_id=? AND objective_bucket=?",
                (str(context_id), str(objective_bucket)),
            ).fetchone()
        return max(
            int(row["revision"]) if row is not None else 0,
            int(active["revision"]) if active is not None else 0,
        )

    def compare_and_swap_active_guidance(self, context_id: str, objective_bucket: str, guidance_version: str, *, expected_revision: int | None, actor_id: str | None = None, detail: Mapping[str, Any] | None = None, action: str = "promote") -> tuple[bool, int]:
        now = _now()
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            candidate = conn.execute("SELECT 1 FROM guidance_versions WHERE guidance_version=? AND context_id=? AND objective_bucket=?", (str(guidance_version), str(context_id), str(objective_bucket))).fetchone()
            if not candidate:
                conn.execute("ROLLBACK")
                raise ValueError("guidance version does not belong to the active scope")
            active = conn.execute("SELECT guidance_version,revision FROM active_guidance WHERE context_id=? AND objective_bucket=?", (str(context_id), str(objective_bucket))).fetchone()
            slot = conn.execute("SELECT revision FROM active_guidance_revisions WHERE context_id=? AND objective_bucket=?", (str(context_id), str(objective_bucket))).fetchone()
            slot_revision = int(slot["revision"]) if slot else 0
            active_revision = int(active["revision"]) if active else 0
            revision = max(slot_revision, active_revision)
            previous = active["guidance_version"] if active else None
            if expected_revision is not None and revision != int(expected_revision):
                if revision != slot_revision:
                    conn.execute("INSERT INTO active_guidance_revisions(context_id,objective_bucket,revision,updated_at) VALUES(?,?,?,?) ON CONFLICT(context_id,objective_bucket) DO UPDATE SET revision=excluded.revision,updated_at=excluded.updated_at", (str(context_id), str(objective_bucket), revision, now))
                    conn.execute("COMMIT")
                else:
                    conn.execute("ROLLBACK")
                return False, revision
            next_revision = revision + 1
            conn.execute("INSERT INTO active_guidance(context_id,objective_bucket,guidance_version,revision,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(context_id,objective_bucket) DO UPDATE SET guidance_version=excluded.guidance_version,revision=excluded.revision,updated_at=excluded.updated_at", (str(context_id), str(objective_bucket), str(guidance_version), next_revision, now))
            conn.execute("INSERT INTO active_guidance_revisions(context_id,objective_bucket,revision,updated_at) VALUES(?,?,?,?) ON CONFLICT(context_id,objective_bucket) DO UPDATE SET revision=excluded.revision,updated_at=excluded.updated_at", (str(context_id), str(objective_bucket), next_revision, now))
            conn.execute("INSERT INTO promotion_audits(promotion_id,context_id,objective_bucket,action,previous_guidance_version,guidance_version,expected_revision,resulting_revision,actor_id,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (_digest([context_id, objective_bucket, guidance_version, next_revision, now]), str(context_id), str(objective_bucket), str(action), previous, str(guidance_version), expected_revision, next_revision, actor_id, _json(dict(detail or {})), now))
            conn.execute("COMMIT")
        return True, next_revision

    def rollback_active_guidance(self, context_id: str, objective_bucket: str, guidance_version: str, *, expected_revision: int | None, actor_id: str | None = None, detail: Mapping[str, Any] | None = None) -> tuple[bool, int]:
        return self.compare_and_swap_active_guidance(context_id, objective_bucket, guidance_version, expected_revision=expected_revision, actor_id=actor_id, detail=detail, action="rollback")

    def clear_active_guidance(self, context_id: str, objective_bucket: str, *, expected_revision: int, actor_id: str | None = None, detail: Mapping[str, Any] | None = None) -> tuple[bool, int]:
        """CAS an active guidance slot back to the implicit Null baseline."""
        now = _now()
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active = conn.execute(
                "SELECT guidance_version,revision FROM active_guidance WHERE context_id=? AND objective_bucket=?",
                (str(context_id), str(objective_bucket)),
            ).fetchone()
            slot = conn.execute("SELECT revision FROM active_guidance_revisions WHERE context_id=? AND objective_bucket=?", (str(context_id), str(objective_bucket))).fetchone()
            slot_revision = int(slot["revision"]) if slot else 0
            active_revision = int(active["revision"]) if active else 0
            revision = max(slot_revision, active_revision)
            if active is None or revision != int(expected_revision):
                if revision != slot_revision:
                    conn.execute("INSERT INTO active_guidance_revisions(context_id,objective_bucket,revision,updated_at) VALUES(?,?,?,?) ON CONFLICT(context_id,objective_bucket) DO UPDATE SET revision=excluded.revision,updated_at=excluded.updated_at", (str(context_id), str(objective_bucket), revision, now))
                    conn.execute("COMMIT")
                else:
                    conn.execute("ROLLBACK")
                return False, revision
            next_revision = revision + 1
            previous = str(active["guidance_version"])
            conn.execute(
                "DELETE FROM active_guidance WHERE context_id=? AND objective_bucket=?",
                (str(context_id), str(objective_bucket)),
            )
            conn.execute(
                "INSERT INTO active_guidance_revisions(context_id,objective_bucket,revision,updated_at) VALUES(?,?,?,?) ON CONFLICT(context_id,objective_bucket) DO UPDATE SET revision=excluded.revision,updated_at=excluded.updated_at",
                (str(context_id), str(objective_bucket), next_revision, now),
            )
            conn.execute(
                "INSERT INTO promotion_audits(promotion_id,context_id,objective_bucket,action,previous_guidance_version,guidance_version,expected_revision,resulting_revision,actor_id,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (_digest([context_id, objective_bucket, "null", next_revision, now]), str(context_id), str(objective_bucket), "rollback", previous, "", expected_revision, next_revision, actor_id, _json(dict(detail or {})), now),
            )
            conn.execute("COMMIT")
        return True, next_revision

    # Runs/evaluations/replay records --------------------------------------
    def append_run(self, run_id: str, context_id: str, status: str, run: Mapping[str, Any]) -> str:
        body = dict(run)
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO optimization_runs(run_id,context_id,status,run_json,run_digest,created_at) VALUES(?,?,?,?,?,?)",
                (
                    str(run_id), str(context_id), str(status), _json(body),
                    _digest(body), _now(),
                ),
            )
        return str(run_id)

    def append_evaluation(self, evaluation_id: str, candidate_id: str, evaluation: Mapping[str, Any]) -> str:
        body = dict(evaluation)
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO evaluations(evaluation_id,candidate_id,evaluation_json,evaluation_digest,created_at) VALUES(?,?,?,?,?)", (str(evaluation_id), str(candidate_id), _json(body), _digest(body), _now()))
        return str(evaluation_id)

    def append_replay_audit(self, audit_id: str, candidate_id: str, audit: Mapping[str, Any], *, manifest_id: str | None = None) -> str:
        body = dict(audit)
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO replay_audits(audit_id,candidate_id,manifest_id,audit_json,audit_digest,created_at) VALUES(?,?,?,?,?,?)", (str(audit_id), str(candidate_id), manifest_id, _json(body), _digest(body), _now()))
        return str(audit_id)

    # Local multiprocess jobs, leases and heartbeats -----------------------
    def enqueue_job(self, job_key: str, context_id: str, payload: Mapping[str, Any], *, max_retries: int = 2, force: bool = False) -> tuple[str, bool]:
        now = _now()
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT status FROM jobs WHERE job_key=?", (str(job_key),)).fetchone()
            if existing:
                # A force enqueue must never replace work leased by another worker.
                leased = conn.execute("SELECT 1 FROM job_leases WHERE job_key=? AND expires_at>?", (str(job_key), now)).fetchone()
                if not force or leased:
                    conn.execute("ROLLBACK")
                    return str(job_key), False
                conn.execute("DELETE FROM jobs WHERE job_key=?", (str(job_key),))
            conn.execute("INSERT INTO jobs(job_key,context_id,status,attempts,max_retries,payload_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (str(job_key), str(context_id), "pending", 0, max(0, int(max_retries)), _json(dict(payload)), now, now))
            conn.execute("COMMIT")
        return str(job_key), True

    def claim_job(self, worker_id: str, lease_ttl_seconds: int, *, context_id: str | None = None, max_retries: int | None = None) -> dict[str, Any] | None:
        now, expiry = _now(), _now() + max(1, int(lease_ttl_seconds))
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM job_leases WHERE expires_at<=?", (now,))
            sql, args = "SELECT * FROM jobs WHERE status='pending'", []
            if context_id:
                sql += " AND context_id=?"; args.append(str(context_id))
            sql += " ORDER BY created_at LIMIT 1"
            row = conn.execute(sql, args).fetchone()
            if not row:
                conn.execute("COMMIT"); return None
            limit = int(max_retries) if max_retries is not None else int(row["max_retries"])
            if int(row["attempts"]) >= limit:
                conn.execute("UPDATE jobs SET status='failed',last_error=?,updated_at=? WHERE job_key=?", ("retry limit exceeded", now, row["job_key"]))
                conn.execute("COMMIT"); return None
            previous = conn.execute(
                "SELECT last_token FROM job_fence_counters WHERE job_key=?",
                (row["job_key"],),
            ).fetchone()
            token = int(previous["last_token"]) + 1 if previous else 1
            cursor = conn.execute("UPDATE jobs SET status='running',attempts=attempts+1,last_error=NULL,updated_at=? WHERE job_key=? AND status='pending'", (now, row["job_key"]))
            if not cursor.rowcount:
                conn.execute("ROLLBACK"); return None
            conn.execute(
                "INSERT INTO job_fence_counters(job_key,last_token) VALUES(?,?) ON CONFLICT(job_key) DO UPDATE SET last_token=excluded.last_token",
                (row["job_key"], token),
            )
            conn.execute("INSERT INTO job_leases(job_key,owner_id,fencing_token,expires_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(job_key) DO UPDATE SET owner_id=excluded.owner_id,fencing_token=excluded.fencing_token,expires_at=excluded.expires_at,updated_at=excluded.updated_at", (row["job_key"], str(worker_id), token, expiry, now))
            claimed = conn.execute("SELECT * FROM jobs WHERE job_key=?", (row["job_key"],)).fetchone()
            conn.execute("COMMIT")
        result = _row(claimed) or {}
        result["payload"] = _decode(result.pop("payload_json", "{}"))
        result["result"] = _decode(result.pop("result_json", None), None)
        result.update({"lease_owner": str(worker_id), "lease_expires_at": expiry, "fencing_token": token})
        return result

    def heartbeat_job(self, job_key: str, worker_id: str, fencing_token: int, lease_ttl_seconds: int) -> bool:
        now = _now()
        with _CONNECTION_LOCK, self._connect() as conn:
            cursor = conn.execute("UPDATE job_leases SET expires_at=?,updated_at=? WHERE job_key=? AND owner_id=? AND fencing_token=? AND expires_at>?", (now + max(1, int(lease_ttl_seconds)), now, str(job_key), str(worker_id), int(fencing_token), now))
        return bool(cursor.rowcount)

    def complete_job(self, job_key: str, worker_id: str | None, fencing_token: int | None, result: Mapping[str, Any] | None = None, *, status: str = "succeeded", error: str | None = None) -> bool:
        now = _now()
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            job = conn.execute(
                "SELECT context_id,payload_json FROM jobs WHERE job_key=?", (str(job_key),)
            ).fetchone()
            if job is None:
                conn.execute("ROLLBACK")
                return False
            if worker_id is not None and fencing_token is not None:
                lease = conn.execute("SELECT 1 FROM job_leases WHERE job_key=? AND owner_id=? AND fencing_token=? AND expires_at>?", (str(job_key), str(worker_id), int(fencing_token), now)).fetchone()
                if not lease:
                    conn.execute("ROLLBACK"); return False
            body = dict(result or {})
            job_payload = _decode(job["payload_json"])
            trusted_config_digest = job_payload.get("autopilot_config_digest")
            cursor = conn.execute("UPDATE jobs SET status=?,result_json=?,last_error=?,updated_at=? WHERE job_key=?", (str(status), _json(body) if result is not None else None, error, now, str(job_key)))
            if (
                cursor.rowcount
                and status == "candidate"
                and body.get("automatic_transition_state") == "pending_coordinator"
                and type(body.get("autopilot_config_digest")) is str
                and len(body["autopilot_config_digest"]) == 64
                and body["autopilot_config_digest"] == trusted_config_digest
                and type(body.get("candidate_id")) is str
                and body["candidate_id"]
                and worker_id is not None
                and fencing_token is not None
            ):
                candidate = conn.execute(
                    "SELECT context_id,candidate_digest FROM candidates WHERE candidate_id=?",
                    (body["candidate_id"],),
                ).fetchone()
                if (
                    candidate is None
                    or candidate["context_id"] != job["context_id"]
                    or body.get("candidate_digest") != candidate["candidate_digest"]
                ):
                    conn.execute("ROLLBACK")
                    return False
                conn.execute(
                    "INSERT OR IGNORE INTO autopilot_candidate_approvals(candidate_id,job_key,fencing_token,candidate_digest,approved_at,config_digest) VALUES(?,?,?,?,?,?)",
                    (
                        body["candidate_id"], str(job_key), int(fencing_token),
                        str(candidate["candidate_digest"]), now,
                        trusted_config_digest,
                    ),
                )
            conn.execute("DELETE FROM job_leases WHERE job_key=?", (str(job_key),))
            conn.execute("COMMIT")
        return bool(cursor.rowcount)

    def reclaim_expired_jobs(self) -> int:
        now = _now()
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("SELECT j.job_key,j.attempts,j.max_retries FROM jobs j JOIN job_leases l ON l.job_key=j.job_key WHERE j.status='running' AND l.expires_at<=?", (now,)).fetchall()
            for row in rows:
                status = "failed" if int(row["attempts"]) >= int(row["max_retries"]) else "pending"
                conn.execute("UPDATE jobs SET status=?,last_error=?,updated_at=? WHERE job_key=?", (status, "lease expired", now, row["job_key"]))
                conn.execute("DELETE FROM job_leases WHERE job_key=?", (row["job_key"],))
            conn.execute("COMMIT")
        return len(rows)

    def heartbeat_worker(self, worker_id: str, heartbeat: Mapping[str, Any] | None = None, *, ttl_seconds: int = 30) -> None:
        now = _now()
        with _CONNECTION_LOCK, self._connect() as conn:
            conn.execute("INSERT INTO worker_heartbeats(worker_id,heartbeat_json,updated_at,expires_at) VALUES(?,?,?,?) ON CONFLICT(worker_id) DO UPDATE SET heartbeat_json=excluded.heartbeat_json,updated_at=excluded.updated_at,expires_at=excluded.expires_at", (str(worker_id), _json(dict(heartbeat or {})), now, now + max(1, int(ttl_seconds))))

    def active_workers(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT worker_id,heartbeat_json,updated_at,expires_at FROM worker_heartbeats WHERE expires_at>? ORDER BY worker_id", (_now(),)).fetchall()
        return [{"worker_id": row["worker_id"], "heartbeat": _decode(row["heartbeat_json"]), "updated_at": row["updated_at"], "expires_at": row["expires_at"]} for row in rows]

    def remove_workers(self, worker_ids: list[str]) -> int:
        normalized = sorted({str(worker_id).strip() for worker_id in worker_ids if str(worker_id).strip()})
        if not normalized:
            return 0
        placeholders = ",".join("?" for _ in normalized)
        with _CONNECTION_LOCK, self._connect() as conn:
            cursor = conn.execute(f"DELETE FROM worker_heartbeats WHERE worker_id IN ({placeholders})", normalized)
        return int(cursor.rowcount or 0)


# Explicit repository aliases keep call sites focused on their bounded domain.
EvidenceRepository = Store
SampleRepository = Store
GuidanceRepository = Store
JobRepository = Store
