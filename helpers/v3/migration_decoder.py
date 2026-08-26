"""Pure, fail-closed readers for frozen v1/v2 plugin snapshots.

The migration authority supplies an already snapshotted, read-only SQLite
connection.  This module never opens a path, creates a table, repairs a row, or
writes a cache.  It recognizes only the two submitted legacy layouts and emits
content-free dispositions.  Raw legacy values are inspected only long enough
to validate their exact historical digests and decide their disposition.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import re
import sqlite3
from typing import Any, Literal, Mapping, Sequence

from ..guidance import (
    GuidanceArtifact,
    GuidanceValidationError,
    render_guidance_artifact,
    validate_guidance_artifact,
)


class LegacyDecodeError(ValueError):
    """Base class for a frozen legacy-reader failure."""


class LegacySchemaError(LegacyDecodeError):
    """Raised when a snapshot is not one exact admitted legacy schema."""


class LegacyJSONError(LegacyDecodeError):
    """Raised for malformed, duplicate-key, or non-finite legacy JSON."""


Disposition = Literal["projected", "quarantined", "unsupported", "invalid"]


_V1_TABLES: dict[str, tuple[str, ...]] = {
    "objective_samples": ("sample_id", "objective_payload", "created_at"),
    "optimization_jobs": (
        "job_key", "context_id", "status", "attempts", "max_retries",
        "payload_json", "result_json", "last_error", "created_at", "updated_at",
    ),
    "guidance_versions": (
        "context_id", "objective_bucket", "objective_signature", "guidance_version",
        "guidance_text", "metadata_json", "created_at",
    ),
}

_V2_TABLES: dict[str, tuple[str, ...]] = {
    "schema_migrations": ("version", "applied_at"),
    "legacy_imports": ("source", "imported_at"),
    "runtime_context_state": ("context_id", "state_json", "revision", "updated_at"),
    "evidence_events": (
        "event_id", "context_id", "event_type", "event_json", "content_digest", "created_at",
    ),
    "samples": (
        "sample_id", "context_id", "objective_bucket", "objective_signature",
        "payload_json", "payload_digest", "created_at",
    ),
    "sample_manifests": (
        "manifest_id", "context_id", "kind", "sample_ids_json", "payload_json",
        "manifest_digest", "created_at",
    ),
    "guidance_versions": (
        "guidance_version", "context_id", "objective_bucket", "objective_signature",
        "guidance_text", "metadata_json", "artifact_digest", "created_at",
    ),
    "candidates": (
        "candidate_id", "run_id", "context_id", "objective_bucket", "guidance_version",
        "candidate_json", "candidate_digest", "created_at",
    ),
    "optimization_runs": ("run_id", "context_id", "status", "run_json", "created_at"),
    "evaluations": (
        "evaluation_id", "candidate_id", "evaluation_json", "evaluation_digest", "created_at",
    ),
    "replay_audits": (
        "audit_id", "candidate_id", "manifest_id", "audit_json", "audit_digest", "created_at",
    ),
    "active_guidance": (
        "context_id", "objective_bucket", "guidance_version", "revision", "updated_at",
    ),
    "promotion_audits": (
        "promotion_id", "context_id", "objective_bucket", "action",
        "previous_guidance_version", "guidance_version", "expected_revision",
        "resulting_revision", "actor_id", "detail_json", "created_at",
    ),
    "jobs": (
        "job_key", "context_id", "status", "attempts", "max_retries", "payload_json",
        "result_json", "last_error", "created_at", "updated_at",
    ),
    "job_leases": ("job_key", "owner_id", "fencing_token", "expires_at", "updated_at"),
    "worker_heartbeats": ("worker_id", "heartbeat_json", "updated_at", "expires_at"),
    "prompt_snapshots": (
        "snapshot_id", "context_id", "base_digest", "components_json", "protected_json", "created_at",
    ),
    "prompt_artifacts": (
        "artifact_id", "context_id", "target_key", "target_mode", "activation_mode",
        "base_digest", "artifact_json", "artifact_digest", "status", "created_at",
    ),
    "active_prompt_artifacts": (
        "context_id", "target_key", "artifact_id", "baseline_snapshot_id", "state",
        "activation_mode", "canary_percentage", "revision", "observations", "failures",
        "baseline_failure_rate", "updated_at",
    ),
    "prompt_activation_audits": (
        "audit_id", "context_id", "target_key", "artifact_id", "action", "previous_state",
        "resulting_state", "revision", "detail_json", "created_at",
    ),
}

_RETAINED_V1_TABLES: dict[str, tuple[str, ...]] = {
    "objective_samples": _V1_TABLES["objective_samples"],
    "optimization_jobs": _V1_TABLES["optimization_jobs"],
    "legacy_guidance_versions": _V1_TABLES["guidance_versions"],
}

_ORDER_BY: dict[str, tuple[str, ...]] = {
    name: (columns[0],) for name, columns in {**_V1_TABLES, **_V2_TABLES}.items()
}
_ORDER_BY["active_guidance"] = ("context_id", "objective_bucket")
_ORDER_BY["active_prompt_artifacts"] = ("context_id", "target_key")
_ORDER_BY["legacy_guidance_versions"] = ("guidance_version",)

_STORE_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PROMPT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROMPT_ARTIFACT_KEYS = frozenset(
    {
        "artifact_id", "context_id", "target_key", "target_mode", "activation_mode",
        "base_snapshot_id", "base_digest", "replacements", "validation", "provenance",
        "artifact_digest",
    }
)
_PROMPT_COMPONENT_KEYS = frozenset(
    {
        "component_id", "ordinal", "source_digest", "body", "char_count", "protected",
        "protection_reason",
    }
)
_PROMPT_REPLACEMENT_KEYS = frozenset({"component_id", "source_digest", "text"})
_ENGINE_IDS = {
    "heuristic": "a0.generate.guidance.deterministic_rules.v1",
    "gepa": "a0.generate.guidance.legacy_rule_agreement_gepa.v1",
}
_SEMANTIC_SCHEMA_DIGESTS = {
    "v1": "6aafcfeb2e6c2db99600406f436de0bb89069dbe55720730c31bcb3f73697e35",
    "v2": "ea33f963f0eef08c3bf7d99c5b248d91ab951931d1749a7d9283db135a6180b4",
    "v2-retained-v1": "07afcd2438f5cd09745c53ff3f0e958b3d2427987dc1ed2775aa8ca9e5854d90",
}


@dataclass(frozen=True)
class LegacySchemaFingerprint:
    version: Literal[1, 2]
    variant: Literal["v1", "v2", "v2-retained-v1"]
    tables: tuple[tuple[str, tuple[str, ...]], ...]
    semantic_digest: str


@dataclass(frozen=True)
class CompatibilityGuidanceRule:
    rule_type: str
    max_retries: int | None


@dataclass(frozen=True)
class CompatibilityGuidanceMember:
    """The safe structured subset required for frozen guidance.v1 behavior."""

    artifact_id: str
    context_id: str
    objective_bucket: str
    artifact_digest: str
    rules: tuple[CompatibilityGuidanceRule, ...]
    source_manifest_hashes: tuple[str, ...]
    source_finding_hashes: tuple[str, ...]
    issued_at: str
    expires_at: str
    engine_profile_id: str
    engine_version: str
    render_target: Literal["system_prompt"] = "system_prompt"
    legacy_schema: Literal["guidance.v1"] = "guidance.v1"


@dataclass(frozen=True)
class LegacyRowDisposition:
    source_table: str
    source_ordinal: int
    disposition: Disposition
    reason_code: str
    compatibility_member: CompatibilityGuidanceMember | None = None


@dataclass(frozen=True)
class LegacyDecodeResult:
    fingerprint: LegacySchemaFingerprint
    dispositions: tuple[LegacyRowDisposition, ...]

    @property
    def compatibility_members(self) -> tuple[CompatibilityGuidanceMember, ...]:
        return tuple(
            item.compatibility_member
            for item in self.dispositions
            if item.compatibility_member is not None
        )

    @property
    def counts(self) -> Mapping[str, int]:
        return {
            kind: sum(item.disposition == kind for item in self.dispositions)
            for kind in ("projected", "quarantined", "unsupported", "invalid")
        }


@dataclass(frozen=True)
class _GuidanceRead:
    disposition: Disposition
    reason_code: str
    artifact: GuidanceArtifact | None = None
    member: CompatibilityGuidanceMember | None = None


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise LegacyJSONError("legacy JSON contains a non-finite number")
    return parsed


def strict_legacy_json_loads(encoded: Any) -> Any:
    """Decode historical JSON while rejecting duplicate keys and non-finite values."""

    if type(encoded) is bytes:
        try:
            text = encoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LegacyJSONError("legacy JSON is not UTF-8") from exc
    elif type(encoded) is str:
        text = encoded
    else:
        raise LegacyJSONError("legacy JSON must be text or bytes")

    def object_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise LegacyJSONError(f"legacy JSON contains duplicate key {key!r}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise LegacyJSONError(f"legacy JSON contains non-finite constant {value!r}")

    def validate(value: Any) -> None:
        if value is None or type(value) in {bool, int}:
            return
        if type(value) is float:
            if not math.isfinite(value):
                raise LegacyJSONError("legacy JSON contains a non-finite number")
            return
        if type(value) is str:
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise LegacyJSONError("legacy JSON contains an invalid Unicode scalar") from exc
            return
        if type(value) is list:
            for item in value:
                validate(item)
            return
        if type(value) is dict:
            for key, item in value.items():
                validate(key)
                validate(item)
            return
        raise LegacyJSONError("legacy JSON contains an unsupported value")

    try:
        value = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=invalid_constant,
            parse_float=_finite_float,
        )
        validate(value)
        return value
    except LegacyJSONError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise LegacyJSONError("legacy JSON is malformed") from exc


def _quoted(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _require_read_only(connection: sqlite3.Connection) -> None:
    row = connection.execute("PRAGMA query_only").fetchone()
    if row is None or int(row[0]) != 1:
        raise LegacySchemaError("legacy decoder requires a caller-provided query-only snapshot")


def _table_shape(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({_quoted(table)})"))


def _semantic_schema_digest(
    connection: sqlite3.Connection, tables: Sequence[str]
) -> str:
    """Bind declared types, nullability, defaults, PKs, and foreign keys."""

    semantic: list[list[Any]] = []
    for table in sorted(tables):
        columns = [
            list(row)
            for row in connection.execute(f"PRAGMA table_info({_quoted(table)})")
        ]
        foreign_keys = [
            list(row)
            for row in connection.execute(f"PRAGMA foreign_key_list({_quoted(table)})")
        ]
        semantic.append([table, columns, foreign_keys])
    encoded = json.dumps(
        semantic, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def inspect_legacy_schema(connection: sqlite3.Connection) -> LegacySchemaFingerprint:
    """Recognize one exact legacy table/column fingerprint without changing it."""

    _require_read_only(connection)
    names = tuple(
        sorted(
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
    )
    actual = {name: _table_shape(connection, name) for name in names}
    admitted: tuple[
        tuple[Literal[1, 2], Literal["v1", "v2", "v2-retained-v1"], dict[str, tuple[str, ...]]], ...
    ] = (
        (1, "v1", _V1_TABLES),
        (2, "v2", _V2_TABLES),
        (2, "v2-retained-v1", {**_V2_TABLES, **_RETAINED_V1_TABLES}),
    )
    for version, variant, expected in admitted:
        if actual == expected:
            semantic_digest = _semantic_schema_digest(connection, names)
            if semantic_digest != _SEMANTIC_SCHEMA_DIGESTS[variant]:
                raise LegacySchemaError(
                    "legacy schema constraints differ from the frozen fingerprint"
                )
            return LegacySchemaFingerprint(
                version=version,
                variant=variant,
                tables=tuple((name, columns) for name, columns in sorted(expected.items())),
                semantic_digest=semantic_digest,
            )
    raise LegacySchemaError("unknown legacy tables or columns; migration is blocked")


def _read_table(
    connection: sqlite3.Connection,
    table: str,
    columns: tuple[str, ...],
) -> list[dict[str, Any]]:
    selected = ",".join(_quoted(column) for column in columns)
    order = ",".join(_quoted(column) for column in _ORDER_BY[table])
    cursor = connection.execute(
        f"SELECT {selected} FROM {_quoted(table)} ORDER BY {order}"
    )
    return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def _store_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value if value is not None else {},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _store_digest(value: Any) -> str:
    return sha256(_store_json_bytes(value)).hexdigest()


def _prompt_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _prompt_digest(value: Any) -> str:
    return "sha256:" + sha256(_prompt_json_bytes(value)).hexdigest()


def _prompt_body_digest(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _valid_store_digest(value: Any, supplied: Any) -> bool:
    return type(supplied) is str and _STORE_DIGEST_RE.fullmatch(supplied) is not None and supplied == _store_digest(value)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _compatibility_member(artifact: GuidanceArtifact) -> CompatibilityGuidanceMember:
    return CompatibilityGuidanceMember(
        artifact_id=artifact.artifact_id,
        context_id=artifact.context_id,
        objective_bucket=artifact.objective_bucket,
        artifact_digest=artifact.artifact_digest,
        rules=tuple(
            CompatibilityGuidanceRule(rule_type=rule_type, max_retries=max_retries)
            for rule_type, max_retries in artifact.rules
        ),
        source_manifest_hashes=artifact.source_manifest_hashes,
        source_finding_hashes=artifact.source_finding_hashes,
        issued_at=_iso_utc(artifact.issued_at),
        expires_at=_iso_utc(artifact.expires_at),
        engine_profile_id=_ENGINE_IDS[artifact.engine_kind],
        engine_version=artifact.engine_version,
    )


def _decode_guidance_row(row: Mapping[str, Any], *, as_of: datetime, has_outer_digest: bool) -> _GuidanceRead:
    try:
        metadata = strict_legacy_json_loads(row["metadata_json"])
    except LegacyJSONError:
        return _GuidanceRead("invalid", "invalid_guidance_metadata_json")
    if type(metadata) is not dict:
        return _GuidanceRead("invalid", "invalid_guidance_metadata_shape")
    if has_outer_digest:
        record = {"guidance_text": str(row["guidance_text"]), "metadata": metadata}
        if not _valid_store_digest(record, row["artifact_digest"]):
            return _GuidanceRead("invalid", "guidance_store_digest_mismatch")
    serialized = metadata.get("guidance_artifact")
    if type(serialized) is not dict:
        return _GuidanceRead("quarantined", "legacy_free_form_guidance")
    if serialized.get("schema_version") != "guidance.v1":
        return _GuidanceRead("unsupported", "unsupported_guidance_schema")
    engine = serialized.get("engine")
    if type(engine) is dict and engine.get("kind") not in _ENGINE_IDS:
        return _GuidanceRead("unsupported", "unsupported_guidance_engine")
    try:
        artifact = validate_guidance_artifact(serialized)
    except (GuidanceValidationError, TypeError, ValueError):
        return _GuidanceRead("invalid", "invalid_guidance_artifact")
    if (
        artifact.artifact_id != str(row["guidance_version"])
        or artifact.context_id != str(row["context_id"])
        or artifact.objective_bucket != str(row["objective_bucket"])
    ):
        return _GuidanceRead("invalid", "guidance_scope_mismatch")
    if artifact.is_expired(as_of):
        return _GuidanceRead("quarantined", "expired_guidance_artifact", artifact=artifact)
    try:
        rendered = render_guidance_artifact(artifact, now=as_of)
    except (GuidanceValidationError, TypeError, ValueError):
        return _GuidanceRead("invalid", "invalid_guidance_render")
    if rendered != row["guidance_text"]:
        return _GuidanceRead("invalid", "guidance_render_mismatch")
    return _GuidanceRead(
        "quarantined",
        "inactive_guidance_artifact",
        artifact=artifact,
        member=_compatibility_member(artifact),
    )


def _decode_prompt_snapshot(row: Mapping[str, Any]) -> tuple[bool, str, Mapping[str, Any] | None]:
    try:
        components = strict_legacy_json_loads(row["components_json"])
        protected = strict_legacy_json_loads(row["protected_json"])
    except LegacyJSONError:
        return False, "invalid_prompt_snapshot_json", None
    if type(components) is not list or type(protected) is not list:
        return False, "invalid_prompt_snapshot_shape", None
    component_by_id: dict[str, Mapping[str, Any]] = {}
    for component in components:
        if type(component) is not dict or frozenset(component) != _PROMPT_COMPONENT_KEYS:
            return False, "invalid_prompt_component_shape", None
        ordinal = component["ordinal"]
        body = component["body"]
        source_digest = component["source_digest"]
        if type(ordinal) is not int or type(ordinal) is bool or ordinal < 0 or type(body) is not str:
            return False, "invalid_prompt_component_value", None
        if (
            type(source_digest) is not str
            or _PROMPT_DIGEST_RE.fullmatch(source_digest) is None
            or source_digest != _prompt_body_digest(body)
            or component["component_id"] != f"segment:{ordinal:02d}:{source_digest.split(':', 1)[1][:12]}"
            or component["char_count"] != len(body)
            or type(component["protected"]) is not bool
            or type(component["protection_reason"]) is not str
        ):
            return False, "prompt_component_digest_mismatch", None
        if component["component_id"] in component_by_id:
            return False, "duplicate_prompt_component", None
        component_by_id[component["component_id"]] = component
    expected_base = _prompt_digest([component["source_digest"] for component in components])
    if (
        type(row["base_digest"]) is not str
        or row["base_digest"] != expected_base
        or row["snapshot_id"] != "prompt-snapshot-" + expected_base.split(":", 1)[1][:24]
        or any(type(item) is not str or item not in component_by_id for item in protected)
        or protected != [component["component_id"] for component in components if component["protected"]]
    ):
        return False, "prompt_snapshot_digest_mismatch", None
    return True, "legacy_prompt_snapshot", {
        "snapshot_id": row["snapshot_id"],
        "context_id": row["context_id"],
        "base_digest": expected_base,
        "components": component_by_id,
    }


def _decode_prompt_artifact(
    row: Mapping[str, Any],
    snapshots: Mapping[str, Mapping[str, Any]],
) -> tuple[bool, str]:
    try:
        body = strict_legacy_json_loads(row["artifact_json"])
    except LegacyJSONError:
        return False, "invalid_prompt_artifact_json"
    if type(body) is not dict or frozenset(body) != _PROMPT_ARTIFACT_KEYS:
        return False, "invalid_prompt_artifact_shape"
    supplied = body.get("artifact_digest")
    unsigned = {key: value for key, value in body.items() if key != "artifact_digest"}
    if (
        type(supplied) is not str
        or _PROMPT_DIGEST_RE.fullmatch(supplied) is None
        or supplied != _prompt_digest(unsigned)
        or row["artifact_digest"] != supplied
    ):
        return False, "prompt_artifact_digest_mismatch"
    row_matches = (
        row["artifact_id"] == body["artifact_id"]
        and row["context_id"] == body["context_id"]
        and row["target_key"] == body["target_key"] == "agent_zero.system_prompt"
        and row["target_mode"] == body["target_mode"]
        and row["activation_mode"] == body["activation_mode"]
        and row["base_digest"] == body["base_digest"]
    )
    if not row_matches:
        return False, "prompt_artifact_row_mismatch"
    if body["target_mode"] not in {"selected_components", "assembled_prompt"}:
        return False, "invalid_prompt_target_mode"
    if body["activation_mode"] not in {"manual", "canary", "automatic"}:
        return False, "invalid_prompt_activation_mode"
    if type(body["validation"]) is not dict or type(body["provenance"]) is not dict:
        return False, "invalid_prompt_artifact_maps"
    snapshot = snapshots.get(str(body["base_snapshot_id"]))
    if (
        snapshot is None
        or snapshot["context_id"] != body["context_id"]
        or snapshot["base_digest"] != body["base_digest"]
    ):
        return False, "missing_prompt_baseline"
    replacements = body["replacements"]
    if type(replacements) is not list or not replacements:
        return False, "invalid_prompt_replacements"
    seen: set[str] = set()
    for replacement in replacements:
        if type(replacement) is not dict or frozenset(replacement) != _PROMPT_REPLACEMENT_KEYS:
            return False, "invalid_prompt_replacement_shape"
        component_id = replacement["component_id"]
        source = snapshot["components"].get(component_id)
        if (
            type(component_id) is not str
            or component_id in seen
            or source is None
            or replacement["source_digest"] != source["source_digest"]
            or source["protected"]
            or type(replacement["text"]) is not str
            or not replacement["text"].strip()
        ):
            return False, "invalid_prompt_replacement"
        seen.add(component_id)
    return True, "legacy_prompt_artifact"


def _simple_json_disposition(
    row: Mapping[str, Any],
    fields: Sequence[str],
    *,
    reason: str,
) -> tuple[Disposition, str]:
    try:
        for field in fields:
            if row[field] is not None:
                strict_legacy_json_loads(row[field])
    except LegacyJSONError:
        return "invalid", "invalid_legacy_json"
    return "quarantined", reason


def _digest_json_disposition(
    row: Mapping[str, Any],
    json_field: str,
    digest_field: str,
    *,
    reason: str,
) -> tuple[Disposition, str]:
    try:
        payload = strict_legacy_json_loads(row[json_field])
    except LegacyJSONError:
        return "invalid", "invalid_legacy_json"
    if not _valid_store_digest(payload, row[digest_field]):
        return "invalid", "legacy_digest_mismatch"
    return "quarantined", reason


def decode_legacy_snapshot(
    connection: sqlite3.Connection,
    *,
    as_of: datetime,
) -> LegacyDecodeResult:
    """Classify every row in one exact read-only legacy snapshot.

    ``as_of`` is mandatory so an interrupted migration retries the same expiry
    decision.  No raw row content is returned.
    """

    if not isinstance(as_of, datetime) or as_of.tzinfo is None:
        raise LegacyDecodeError("as_of must be a timezone-aware datetime")
    reference = as_of.astimezone(timezone.utc)
    fingerprint = inspect_legacy_schema(connection)
    expected = dict(fingerprint.tables)
    rows = {
        table: _read_table(connection, table, columns)
        for table, columns in expected.items()
    }
    if fingerprint.version == 2:
        versions = [row["version"] for row in rows["schema_migrations"]]
        if versions != [1, 2]:
            raise LegacySchemaError("unknown or incomplete legacy schema version history")

    dispositions: list[LegacyRowDisposition] = []

    def add(table: str, ordinal: int, disposition: Disposition, reason: str, member: CompatibilityGuidanceMember | None = None) -> None:
        dispositions.append(LegacyRowDisposition(table, ordinal, disposition, reason, member))

    if fingerprint.version == 1:
        for ordinal, row in enumerate(rows["objective_samples"]):
            disposition, reason = _simple_json_disposition(row, ("objective_payload",), reason="legacy_objective_content")
            add("objective_samples", ordinal, disposition, reason)
        for ordinal, row in enumerate(rows["optimization_jobs"]):
            disposition, reason = _simple_json_disposition(row, ("payload_json", "result_json"), reason="legacy_job_content")
            add("optimization_jobs", ordinal, disposition, reason)
        for ordinal, row in enumerate(rows["guidance_versions"]):
            read = _decode_guidance_row(row, as_of=reference, has_outer_digest=False)
            if read.disposition == "invalid" or read.disposition == "unsupported":
                add("guidance_versions", ordinal, read.disposition, read.reason_code)
            else:
                add("guidance_versions", ordinal, "quarantined", "guidance_has_no_active_pointer")
        return LegacyDecodeResult(fingerprint, tuple(dispositions))

    # Validate guidance independently, then let the snapshotted pointer be the
    # sole incumbency authority.
    guidance_reads: dict[str, _GuidanceRead] = {}
    guidance_ordinals: dict[str, int] = {}
    for ordinal, row in enumerate(rows["guidance_versions"]):
        version = str(row["guidance_version"])
        guidance_reads[version] = _decode_guidance_row(row, as_of=reference, has_outer_digest=True)
        guidance_ordinals[version] = ordinal

    active_versions: set[str] = set()
    for ordinal, row in enumerate(rows["active_guidance"]):
        version = str(row["guidance_version"])
        target = guidance_reads.get(version)
        if target is None:
            add("active_guidance", ordinal, "invalid", "active_guidance_target_missing")
            continue
        if (
            type(row["revision"]) is not int
            or type(row["revision"]) is bool
            or row["revision"] < 1
            or target.artifact is None
            or target.artifact.context_id != str(row["context_id"])
            or target.artifact.objective_bucket != str(row["objective_bucket"])
        ):
            add("active_guidance", ordinal, "invalid", "active_guidance_scope_mismatch")
            continue
        if target.disposition == "invalid":
            add("active_guidance", ordinal, "invalid", "active_guidance_target_invalid")
        elif target.disposition == "unsupported":
            add("active_guidance", ordinal, "unsupported", "active_guidance_target_unsupported")
        elif target.reason_code == "expired_guidance_artifact":
            add("active_guidance", ordinal, "unsupported", "active_guidance_expired")
        elif target.member is None:
            add("active_guidance", ordinal, "unsupported", "active_guidance_ineligible")
        else:
            active_versions.add(version)
            add("active_guidance", ordinal, "projected", "active_guidance_pointer")

    for version, ordinal in guidance_ordinals.items():
        read = guidance_reads[version]
        if version in active_versions and read.member is not None:
            add("guidance_versions", ordinal, "projected", "compatibility_guidance_member", read.member)
        elif read.reason_code in {"inactive_guidance_artifact", "expired_guidance_artifact"}:
            add("guidance_versions", ordinal, "unsupported", read.reason_code)
        else:
            add("guidance_versions", ordinal, read.disposition, read.reason_code)

    digest_tables = {
        "evidence_events": ("event_json", "content_digest", "legacy_evidence_content"),
        "samples": ("payload_json", "payload_digest", "legacy_sample_content"),
        "candidates": ("candidate_json", "candidate_digest", "legacy_candidate_content"),
        "evaluations": ("evaluation_json", "evaluation_digest", "legacy_evaluation_content"),
        "replay_audits": ("audit_json", "audit_digest", "legacy_replay_content"),
    }
    for table, (json_field, digest_field, reason) in digest_tables.items():
        for ordinal, row in enumerate(rows[table]):
            disposition, reason_code = _digest_json_disposition(row, json_field, digest_field, reason=reason)
            add(table, ordinal, disposition, reason_code)

    for ordinal, row in enumerate(rows["sample_manifests"]):
        try:
            sample_ids = strict_legacy_json_loads(row["sample_ids_json"])
            payload = strict_legacy_json_loads(row["payload_json"])
        except LegacyJSONError:
            add("sample_manifests", ordinal, "invalid", "invalid_legacy_json")
            continue
        record = {
            "context_id": str(row["context_id"]),
            "kind": str(row["kind"]),
            "sample_ids": sample_ids,
            "payload": payload,
        }
        if type(sample_ids) is not list or type(payload) is not dict or not _valid_store_digest(record, row["manifest_digest"]):
            add("sample_manifests", ordinal, "invalid", "legacy_manifest_digest_mismatch")
        else:
            add("sample_manifests", ordinal, "quarantined", "legacy_manifest_content")

    simple_tables = {
        "runtime_context_state": (("state_json",), "legacy_runtime_state"),
        "optimization_runs": (("run_json",), "legacy_optimization_content"),
        "promotion_audits": (("detail_json",), "legacy_promotion_content"),
        "jobs": (("payload_json", "result_json"), "legacy_job_content"),
        "worker_heartbeats": (("heartbeat_json",), "legacy_worker_content"),
        "prompt_activation_audits": (("detail_json",), "legacy_prompt_audit_content"),
    }
    for table, (json_fields, reason) in simple_tables.items():
        for ordinal, row in enumerate(rows[table]):
            disposition, reason_code = _simple_json_disposition(row, json_fields, reason=reason)
            add(table, ordinal, disposition, reason_code)

    for ordinal, _row in enumerate(rows["job_leases"]):
        add("job_leases", ordinal, "unsupported", "legacy_job_lease")

    snapshots: dict[str, Mapping[str, Any]] = {}
    for ordinal, row in enumerate(rows["prompt_snapshots"]):
        valid, reason, decoded = _decode_prompt_snapshot(row)
        add("prompt_snapshots", ordinal, "quarantined" if valid else "invalid", reason)
        if valid and decoded is not None:
            snapshots[str(row["snapshot_id"])] = decoded

    prompt_validity: dict[str, bool] = {}
    for ordinal, row in enumerate(rows["prompt_artifacts"]):
        valid, reason = _decode_prompt_artifact(row, snapshots)
        prompt_validity[str(row["artifact_id"])] = valid
        add("prompt_artifacts", ordinal, "quarantined" if valid else "invalid", reason)

    for ordinal, row in enumerate(rows["active_prompt_artifacts"]):
        if not prompt_validity.get(str(row["artifact_id"]), False):
            add("active_prompt_artifacts", ordinal, "invalid", "active_prompt_target_invalid")
        elif str(row["baseline_snapshot_id"]) not in snapshots:
            add("active_prompt_artifacts", ordinal, "invalid", "active_prompt_baseline_missing")
        else:
            add("active_prompt_artifacts", ordinal, "unsupported", "legacy_prompt_activation")

    for ordinal, _row in enumerate(rows["schema_migrations"]):
        add("schema_migrations", ordinal, "unsupported", "legacy_schema_metadata")
    for ordinal, _row in enumerate(rows["legacy_imports"]):
        add("legacy_imports", ordinal, "unsupported", "legacy_import_metadata")

    if fingerprint.variant == "v2-retained-v1":
        for ordinal, row in enumerate(rows["objective_samples"]):
            disposition, reason = _simple_json_disposition(row, ("objective_payload",), reason="retained_legacy_objective_content")
            add("objective_samples", ordinal, disposition, reason)
        for ordinal, row in enumerate(rows["optimization_jobs"]):
            disposition, reason = _simple_json_disposition(row, ("payload_json", "result_json"), reason="retained_legacy_job_content")
            add("optimization_jobs", ordinal, disposition, reason)
        for ordinal, row in enumerate(rows["legacy_guidance_versions"]):
            read = _decode_guidance_row(row, as_of=reference, has_outer_digest=False)
            if read.disposition in {"invalid", "unsupported"}:
                add("legacy_guidance_versions", ordinal, read.disposition, read.reason_code)
            else:
                add("legacy_guidance_versions", ordinal, "quarantined", "retained_guidance_has_no_active_pointer")

    return LegacyDecodeResult(fingerprint, tuple(dispositions))


__all__ = [
    "CompatibilityGuidanceMember",
    "CompatibilityGuidanceRule",
    "LegacyDecodeError",
    "LegacyDecodeResult",
    "LegacyJSONError",
    "LegacyRowDisposition",
    "LegacySchemaError",
    "LegacySchemaFingerprint",
    "decode_legacy_snapshot",
    "inspect_legacy_schema",
    "strict_legacy_json_loads",
]
