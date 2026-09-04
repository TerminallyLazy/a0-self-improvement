"""Public-contract coverage for Task 3's durable SQLite repositories."""
from __future__ import annotations

import json
import multiprocessing
import sqlite3

import pytest

from usr.plugins.dspy_rlm.helpers.store import Store
import usr.plugins.dspy_rlm.helpers.store as store_module


def _store(tmp_path) -> Store:
    return Store(tmp_path / "dspy-rlm.sqlite3")


def _status(store: Store, job_key: str) -> str:
    with store._connect() as conn:  # The public repository deliberately has no job-read API.
        return str(
            conn.execute(
                "SELECT status FROM jobs WHERE job_key=?", (job_key,)
            ).fetchone()[0]
        )


def _open_store_after_barrier(path: str, barrier, results) -> None:
    barrier.wait()
    try:
        Store(path)
    except Exception as error:
        results.put(f"{type(error).__name__}:{error}")
    else:
        results.put("ok")


def test_migrate_imports_legacy_rows_once_and_exposes_current_schema(tmp_path):
    db = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE objective_samples (
              sample_id TEXT PRIMARY KEY, objective_payload TEXT, created_at REAL
            );
            CREATE TABLE optimization_jobs (
              job_key TEXT PRIMARY KEY, context_id TEXT, status TEXT, attempts INTEGER,
              max_retries INTEGER, payload_json TEXT, result_json TEXT, last_error TEXT,
              created_at REAL, updated_at REAL
            );
            CREATE TABLE guidance_versions (
              context_id TEXT, objective_bucket TEXT, objective_signature TEXT,
              guidance_version TEXT PRIMARY KEY, guidance_text TEXT, metadata_json TEXT,
              created_at REAL
            );
            INSERT INTO objective_samples VALUES ('sample-1', '{"context_id":"ctx","objective_bucket":"reasoning"}', 11);
            INSERT INTO optimization_jobs VALUES ('job-1','ctx','pending',0,2,'{"work":1}',NULL,NULL,12,12);
            INSERT INTO guidance_versions VALUES ('ctx','reasoning','sig','guide-1','be concise','{"source":"legacy"}',13);
            """
        )

    store = Store(db)
    assert store.schema_version == len(store_module.MIGRATIONS)
    assert store.get_sample("sample-1") == {"context_id": "ctx", "objective_bucket": "reasoning"}
    assert store.get_active_guidance("ctx", "reasoning")["guidance_version"] == "guide-1"

    # A second open must not re-import and advance the migrated active revision.
    assert Store(db).get_active_guidance("ctx", "reasoning")["revision"] == 1
    with sqlite3.connect(db) as conn:
        assert (
            conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
            == len(store_module.MIGRATIONS)
        )
        assert conn.execute("SELECT COUNT(*) FROM jobs WHERE job_key='job-1'").fetchone()[0] == 1


def test_append_only_artifacts_preserve_first_payload(tmp_path):
    store = _store(tmp_path)

    assert store.append_sample("sample", {"context_id": "ctx", "objective_bucket": "a", "value": "first"}) == "sample"
    store.append_sample("sample", {"context_id": "other", "objective_bucket": "b", "value": "replacement"})
    assert store.get_sample("sample") == {"context_id": "ctx", "objective_bucket": "a", "value": "first"}

    store.append_guidance_version("guide", "ctx", "a", "sig", "first", {"rank": 1})
    store.append_guidance_version("guide", "ctx", "a", "other", "replacement", {"rank": 2})
    version = store.get_guidance_version("guide")
    assert version["guidance_text"] == "first"
    assert version["metadata"] == {"rank": 1}

    store.append_evidence("event", "ctx", "tool", {"safe": "first"}, created_at=1)
    store.append_evidence("event", "ctx", "turn", {"safe": "replacement"}, created_at=2)
    with store._connect() as conn:
        row = conn.execute("SELECT context_id,event_type,event_json FROM evidence_events WHERE event_id='event'").fetchone()
    assert tuple(row) == ("ctx", "tool", '{"safe":"first"}')


def test_fence_counter_migration_backfills_existing_attempt_and_lease(tmp_path):
    db = tmp_path / "v9.sqlite3"
    Store(db)
    with sqlite3.connect(db) as connection:
        connection.execute(
            "INSERT INTO jobs(job_key,context_id,status,attempts,max_retries,payload_json,created_at,updated_at) VALUES('job','ctx','running',5,9,'{}',1,1)"
        )
        connection.execute(
            "INSERT INTO job_leases(job_key,owner_id,fencing_token,expires_at,updated_at) VALUES('job','worker',7,9999999999,1)"
        )
        connection.execute(
            "ALTER TABLE autopilot_candidate_approvals DROP COLUMN config_digest"
        )
        connection.execute("DELETE FROM schema_migrations WHERE version=10")
        connection.execute("DROP TABLE job_fence_counters")
    Store(db)
    with sqlite3.connect(db) as connection:
        assert connection.execute(
            "SELECT last_token FROM job_fence_counters WHERE job_key='job'"
        ).fetchone()[0] == 7


def test_run_digest_migration_backfills_canonical_body_and_quarantines_live_transition(
    tmp_path,
):
    db = tmp_path / "v10.sqlite3"
    store = Store(db)
    store.append_run("run", "ctx", "candidate", {"candidate_id": "candidate"})
    with sqlite3.connect(db) as connection:
        connection.execute(
            "INSERT INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,expected_active_revision,state,reason_code,created_at,updated_at) VALUES('candidate','ctx','reasoning','guide',0,'canary','candidate_admitted',1,1)"
        )
        connection.execute("UPDATE optimization_runs SET run_digest=NULL")
        connection.execute("ALTER TABLE optimization_runs DROP COLUMN run_digest")
        connection.execute("DELETE FROM schema_migrations WHERE version=11")
    Store(db)
    with sqlite3.connect(db) as connection:
        run_json, run_digest = connection.execute(
            "SELECT run_json,run_digest FROM optimization_runs WHERE run_id='run'"
        ).fetchone()
        assert run_digest == store_module._digest(json.loads(run_json))
        assert connection.execute(
            "SELECT state,reason_code FROM autopilot_transitions WHERE candidate_id='candidate'"
        ).fetchone() == ("recovery_required", "run_digest_upgrade_required")


def test_publication_binding_migration_quarantines_unbound_live_transition(tmp_path):
    db = tmp_path / "v11.sqlite3"
    Store(db)
    with sqlite3.connect(db) as connection:
        connection.execute(
            "INSERT INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,expected_active_revision,state,reason_code,created_at,updated_at) VALUES('candidate','ctx','reasoning','guide',0,'canary','candidate_admitted',1,1)"
        )
        connection.execute(
            "ALTER TABLE autopilot_transitions DROP COLUMN source_candidate_digest"
        )
        connection.execute("DELETE FROM schema_migrations WHERE version=12")
    Store(db)
    with sqlite3.connect(db) as connection:
        assert connection.execute(
            "SELECT source_candidate_digest,state,reason_code FROM autopilot_transitions WHERE candidate_id='candidate'"
        ).fetchone() == (
            None,
            "recovery_required",
            "publication_binding_upgrade_required",
        )


def test_migrations_are_serialized_across_worker_processes(tmp_path):
    db = tmp_path / "v2.sqlite3"
    with sqlite3.connect(db) as connection:
        for version, sql in store_module.MIGRATIONS[:2]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)",
                (version, 1),
            )
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(3)
    results = context.Queue()
    processes = [
        context.Process(
            target=_open_store_after_barrier,
            args=(str(db), barrier, results),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    barrier.wait()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert sorted(results.get(timeout=2) for _ in processes) == ["ok", "ok"]
    with sqlite3.connect(db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0] == len(store_module.MIGRATIONS)


def test_active_guidance_cas_rejects_stale_writes_and_rolls_back(tmp_path):
    store = _store(tmp_path)
    store.append_guidance_version("v1", "ctx", "reasoning", "sig", "first")
    store.append_guidance_version("v2", "ctx", "reasoning", "sig", "second")

    assert store.compare_and_swap_active_guidance("ctx", "reasoning", "v1", expected_revision=0, actor_id="worker") == (True, 1)
    assert store.compare_and_swap_active_guidance("ctx", "reasoning", "v2", expected_revision=0) == (False, 1)
    assert store.compare_and_swap_active_guidance("ctx", "reasoning", "v2", expected_revision=1) == (True, 2)
    assert store.rollback_active_guidance("ctx", "reasoning", "v1", expected_revision=2, detail={"why": "regression"}) == (True, 3)
    assert store.get_active_guidance("ctx", "reasoning")["guidance_version"] == "v1"

    with store._connect() as conn:
        actions = [row[0] for row in conn.execute("SELECT action FROM promotion_audits ORDER BY created_at")]
    assert actions == ["promote", "promote", "rollback"]
    with pytest.raises(ValueError, match="does not belong"):
        store.compare_and_swap_active_guidance("other", "reasoning", "v1", expected_revision=0)


def test_new_cas_rejects_a_newer_legacy_writer_revision(tmp_path):
    store = _store(tmp_path)
    for version in ("v1", "v2", "v3"):
        store.append_guidance_version(version, "ctx", "reasoning", "sig", version)
    assert store.compare_and_swap_active_guidance(
        "ctx", "reasoning", "v1", expected_revision=0
    ) == (True, 1)
    with store._connect() as connection:
        connection.execute(
            "UPDATE active_guidance SET guidance_version='v2',revision=2 WHERE context_id='ctx' AND objective_bucket='reasoning'"
        )

    assert store.compare_and_swap_active_guidance(
        "ctx", "reasoning", "v3", expected_revision=1
    ) == (False, 2)
    assert store.get_active_guidance("ctx", "reasoning")["guidance_version"] == "v2"
    assert store.get_active_guidance_revision("ctx", "reasoning") == 2


def test_jobs_use_leases_fencing_reclaim_and_worker_heartbeats(tmp_path, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(store_module, "_now", lambda: now[0])
    store = _store(tmp_path)

    assert store.enqueue_job("job", "ctx", {"work": 1}, max_retries=2) == ("job", True)
    first = store.claim_job("worker-a", 5)
    assert first["fencing_token"] == 1
    assert first["payload"] == {"work": 1}
    assert not store.heartbeat_job("job", "worker-a", 99, 5)
    assert store.heartbeat_job("job", "worker-a", 1, 5)

    now[0] = 106.0
    assert store.reclaim_expired_jobs() == 1
    assert _status(store, "job") == "pending"
    second = store.claim_job("worker-b", 5)
    assert second["fencing_token"] == 2
    assert not store.complete_job("job", "worker-a", 1, {"stale": True})
    assert store.complete_job("job", "worker-b", 2, {"done": True})
    assert _status(store, "job") == "succeeded"

    store.heartbeat_worker("worker-b", {"queues": 1}, ttl_seconds=5)
    assert store.active_workers()[0]["heartbeat"] == {"queues": 1}
    now[0] = 112.0
    assert store.active_workers() == []
