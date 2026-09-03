from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import sqlite3

import pytest

from usr.plugins.dspy_rlm.helpers.guidance import GuidanceArtifact, render_guidance_artifact
from usr.plugins.dspy_rlm.helpers.store import Store
import usr.plugins.dspy_rlm.helpers.store as store_module
from usr.plugins.dspy_rlm.helpers.v3.migration_decoder import (
    LegacyJSONError,
    LegacySchemaError,
    decode_legacy_snapshot,
    inspect_legacy_schema,
    strict_legacy_json_loads,
)


AS_OF = datetime(2026, 8, 26, tzinfo=timezone.utc)


def _v1_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
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
        """
    )
    return connection


def _readonly(path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only=ON")
    return connection


def _v2_store(path) -> Store:
    """Build the exact frozen v2 layout without migrating it to the current schema."""

    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE legacy_imports (source TEXT PRIMARY KEY, imported_at REAL NOT NULL)"
        )
        for version, sql in store_module.MIGRATIONS[:2]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)",
                (version, 1.0),
            )
    store = object.__new__(Store)
    store.db_path = path
    return store


def _prompt_digest(value) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()


def _insert_active_guidance(store: Store, *, active: bool, expired: bool = False) -> GuidanceArtifact:
    issued_at = "2026-07-20T00:00:00Z" if expired else "2026-08-20T00:00:00Z"
    expires_at = "2026-08-10T00:00:00Z" if expired else "2026-09-10T00:00:00Z"
    artifact = GuidanceArtifact.create(
        artifact_id="guide-1",
        context_id="ctx",
        objective_bucket="reasoning",
        rules=[{"type": "retry_after_failure", "max_retries": 1}],
        source_manifest_hashes=["sha256:" + "a" * 64],
        source_finding_hashes=["sha256:" + "b" * 64],
        issued_at=issued_at,
        expires_at=expires_at,
        engine_kind="heuristic",
        engine_version="legacy-1",
    )
    render_at = datetime(2026, 8, 1, tzinfo=timezone.utc) if expired else AS_OF
    guidance_text = render_guidance_artifact(artifact, now=render_at)
    metadata = {"guidance_artifact": artifact.to_mapping()}
    with store._connect() as writer:
        writer.execute(
            "INSERT INTO guidance_versions VALUES (?,?,?,?,?,?,?,?)",
            (
                artifact.artifact_id,
                artifact.context_id,
                artifact.objective_bucket,
                "sig",
                guidance_text,
                json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                store_module._digest({"guidance_text": guidance_text, "metadata": metadata}),
                1.0,
            ),
        )
        if active:
            writer.execute(
                "INSERT INTO active_guidance VALUES (?,?,?,?,?)",
                ("ctx", "reasoning", artifact.artifact_id, 1, 1.0),
            )
    return artifact


@pytest.mark.parametrize("legacy_version", [1, 2])
def test_exact_schema_and_historical_digest_rules(tmp_path, legacy_version: int) -> None:
    if legacy_version == 1:
        connection = _v1_connection()
        connection.execute(
            "INSERT INTO objective_samples VALUES (?,?,?)",
            ("sample-1", '{"objective_bucket":"reasoning"}', 1.0),
        )
        connection.execute("PRAGMA query_only=ON")
        result = decode_legacy_snapshot(connection, as_of=AS_OF)
        assert inspect_legacy_schema(connection).variant == "v1"
        assert [(item.disposition, item.reason_code) for item in result.dispositions] == [
            ("quarantined", "legacy_objective_content")
        ]
        connection.close()
        return

    path = tmp_path / "legacy-v2.sqlite3"
    store = _v2_store(path)
    store.append_sample("sample-1", {"context_id": "ctx", "objective_bucket": "reasoning"})
    body = "ordinary prompt segment"
    source_digest = "sha256:" + sha256(body.encode("utf-8")).hexdigest()
    component = {
        "component_id": f"segment:00:{source_digest.split(':', 1)[1][:12]}",
        "ordinal": 0,
        "source_digest": source_digest,
        "body": body,
        "char_count": len(body),
        "protected": False,
        "protection_reason": "",
    }
    base_digest = _prompt_digest([source_digest])
    with store._connect() as writer:
        writer.execute(
            "INSERT INTO prompt_snapshots VALUES (?,?,?,?,?,?)",
            (
                "prompt-snapshot-" + base_digest.split(":", 1)[1][:24],
                "ctx",
                base_digest,
                json.dumps([component], ensure_ascii=True, sort_keys=True, separators=(",", ":")),
                "[]",
                1.0,
            ),
        )
    with _readonly(path) as connection:
        result = decode_legacy_snapshot(connection, as_of=AS_OF)
        assert result.fingerprint.variant == "v2"
        by_table = {item.source_table: item for item in result.dispositions if item.source_table in {"samples", "prompt_snapshots"}}
        assert by_table["samples"].disposition == "quarantined"
        assert by_table["prompt_snapshots"].reason_code == "legacy_prompt_snapshot"
        assert not [item for item in result.dispositions if item.disposition == "invalid"]


def test_mixed_v2_rows_receive_safe_dispositions_without_content_leakage(tmp_path) -> None:
    path = tmp_path / "mixed.sqlite3"
    store = _v2_store(path)
    _insert_active_guidance(store, active=True)
    raw_marker = "RAW-PROMPT-SECRET-MARKER"
    store.append_sample("sample-1", {"context_id": "ctx", "prompt": raw_marker})
    with store._connect() as writer:
        writer.execute(
            "INSERT INTO candidates VALUES (?,?,?,?,?,?,?,?)",
            ("bad", None, "ctx", "reasoning", None, '{"candidate":"raw"}', "0" * 64, 1.0),
        )
    with _readonly(path) as connection:
        result = decode_legacy_snapshot(connection, as_of=AS_OF)

    assert {item.disposition for item in result.dispositions} == {
        "projected", "quarantined", "unsupported", "invalid"
    }
    assert len(result.compatibility_members) == 1
    member = result.compatibility_members[0]
    assert member.engine_profile_id == "a0.generate.guidance.deterministic_rules.v1"
    assert member.rules[0].rule_type == "retry_after_failure"
    assert raw_marker not in repr(result)
    assert "DSPy RLM reliability guidance" not in repr(result)


@pytest.mark.parametrize(
    ("active", "expired", "expected_members", "reason"),
    [
        (True, False, 1, "compatibility_guidance_member"),
        (False, False, 0, "inactive_guidance_artifact"),
        (True, True, 0, "active_guidance_expired"),
    ],
)
def test_only_exact_active_nonexpired_guidance_is_eligible(
    tmp_path, active: bool, expired: bool, expected_members: int, reason: str
) -> None:
    path = tmp_path / f"eligible-{active}-{expired}.sqlite3"
    store = _v2_store(path)
    _insert_active_guidance(store, active=active, expired=expired)
    with _readonly(path) as connection:
        result = decode_legacy_snapshot(connection, as_of=AS_OF)
    assert len(result.compatibility_members) == expected_members
    assert reason in {item.reason_code for item in result.dispositions}


def test_unknown_schema_and_ambiguous_json_fail_closed(tmp_path) -> None:
    unknown = _v1_connection()
    unknown.execute("CREATE TABLE surprise (value TEXT)")
    unknown.execute("PRAGMA query_only=ON")
    with pytest.raises(LegacySchemaError, match="unknown legacy tables or columns"):
        decode_legacy_snapshot(unknown, as_of=AS_OF)

    with pytest.raises(LegacyJSONError, match="duplicate key"):
        strict_legacy_json_loads('{"x":1,"x":2}')
    with pytest.raises(LegacyJSONError, match="non-finite"):
        strict_legacy_json_loads('{"x":1e999}')

    current_path = tmp_path / "current.sqlite3"
    Store(current_path)
    with _readonly(current_path) as connection, pytest.raises(
        LegacySchemaError, match="unknown legacy tables or columns"
    ):
        decode_legacy_snapshot(connection, as_of=AS_OF)

    path = tmp_path / "future.sqlite3"
    store = _v2_store(path)
    with store._connect() as writer:
        writer.execute("UPDATE schema_migrations SET version=3 WHERE version=1")
    with _readonly(path) as connection, pytest.raises(LegacySchemaError, match="schema version"):
        decode_legacy_snapshot(connection, as_of=AS_OF)


def test_matching_column_names_with_different_constraints_are_rejected() -> None:
    connection = _v1_connection()
    connection.execute("ALTER TABLE objective_samples RENAME TO old_objective_samples")
    connection.execute(
        "CREATE TABLE objective_samples ("
        "sample_id TEXT PRIMARY KEY, objective_payload TEXT NOT NULL, created_at REAL)"
    )
    connection.execute("DROP TABLE old_objective_samples")
    connection.execute("PRAGMA query_only=ON")

    with pytest.raises(LegacySchemaError, match="constraints differ"):
        inspect_legacy_schema(connection)
