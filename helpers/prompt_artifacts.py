"""Versioned prompt-component snapshots, overlays, canaries, and rollback.

This module never rewrites Agent Zero prompt files. Runtime changes are exact-
digest replacements applied to the already assembled ``list[str]`` supplied to
the plugin extension seam. Any drift, corruption, or protected-component change
returns the original prompt unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import time
from typing import Any, Mapping, Sequence


TARGET_MODES = frozenset({"guidance_overlay", "selected_components", "assembled_prompt"})
ACTIVATION_MODES = frozenset({"manual", "canary", "automatic"})
TARGET_KEY = "agent_zero.system_prompt"
PROTECTED_INVENTORY = (
    {"id": "framework.response_contract", "label": "Response and break-loop contract", "reason": "Required for valid Agent Zero loop completion."},
    {"id": "framework.tool_contracts", "label": "Tool schemas and execution contracts", "reason": "Required for safe and valid tool calls."},
    {"id": "framework.security", "label": "Security, authentication, and secret handling", "reason": "Cannot be weakened by optimization."},
    {"id": "plugin.control_block", "label": "Self-improvement control guidance", "reason": "The optimizer cannot optimize its own control block."},
)
_PROTECTED_MARKERS = (
    ("break_loop", "framework.response_contract"),
    ("response tool", "framework.response_contract"),
    ("tool schema", "framework.tool_contracts"),
    ("tool contract", "framework.tool_contracts"),
    ("authentication", "framework.security"),
    ("csrf", "framework.security"),
    ("api key", "framework.security"),
    ("secret", "framework.security"),
    ("do not reveal", "framework.security"),
    ("optimization guidance", "plugin.control_block"),
    ("a0 self-improvement", "plugin.control_block"),
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _digest(value: Any) -> str:
    return "sha256:" + sha256(_canonical(value).encode("utf-8")).hexdigest()


def _body_digest(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _store():
    from . import state
    return state._store_for_root().store


def _protected_reason(body: str) -> str:
    lowered = body.lower()
    for marker, reason in _PROTECTED_MARKERS:
        if marker in lowered:
            return reason
    return ""


def discover_components(system_prompt: Sequence[str], *, max_chars: int = 60_000) -> list[dict[str, Any]]:
    remaining = max(1_000, min(250_000, int(max_chars)))
    components: list[dict[str, Any]] = []
    for ordinal, raw in enumerate(system_prompt):
        body = str(raw or "")
        if not body or remaining <= 0:
            continue
        body = body[:remaining]
        remaining -= len(body)
        digest = _body_digest(body)
        reason = _protected_reason(body)
        components.append({
            "component_id": f"segment:{ordinal:02d}:{digest.split(':', 1)[1][:12]}",
            "ordinal": ordinal,
            "source_digest": digest,
            "body": body,
            "char_count": len(body),
            "protected": bool(reason),
            "protection_reason": reason,
        })
    return components


def capture_snapshot(context_id: str, system_prompt: Sequence[str], *, max_chars: int = 60_000) -> dict[str, Any] | None:
    if not context_id:
        return None
    components = discover_components(system_prompt, max_chars=max_chars)
    if not components:
        return None
    base_digest = _digest([item["source_digest"] for item in components])
    snapshot_id = "prompt-snapshot-" + base_digest.split(":", 1)[1][:24]
    protected = [item["component_id"] for item in components if item["protected"]]
    with _store()._connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO prompt_snapshots(snapshot_id,context_id,base_digest,components_json,protected_json,created_at) VALUES(?,?,?,?,?,?)",
            (snapshot_id, str(context_id), base_digest, _canonical(components), _canonical(protected), time.time()),
        )
    return {"snapshot_id": snapshot_id, "context_id": str(context_id), "base_digest": base_digest, "components": components, "protected_components": protected}


def latest_snapshot(context_id: str) -> dict[str, Any] | None:
    with _store()._connect() as conn:
        row = conn.execute(
            "SELECT * FROM prompt_snapshots WHERE context_id=? ORDER BY created_at DESC LIMIT 1", (str(context_id),)
        ).fetchone()
    if not row:
        return None
    result = dict(row)
    try:
        result["components"] = json.loads(result.pop("components_json"))
        result["protected_components"] = json.loads(result.pop("protected_json"))
    except (TypeError, ValueError):
        return None
    return result


@dataclass(frozen=True)
class PromptArtifact:
    artifact_id: str
    context_id: str
    target_mode: str
    activation_mode: str
    base_snapshot_id: str
    base_digest: str
    replacements: tuple[Mapping[str, str], ...]
    validation: Mapping[str, Any]
    provenance: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.target_mode not in TARGET_MODES or self.target_mode == "guidance_overlay":
            raise ValueError("prompt artifact requires a direct prompt target mode")
        if self.activation_mode not in ACTIVATION_MODES:
            raise ValueError("invalid activation mode")
        if not self.artifact_id or not self.context_id or not self.base_digest.startswith("sha256:"):
            raise ValueError("invalid prompt artifact identity")
        if not self.replacements:
            raise ValueError("prompt artifact requires replacements")
        for replacement in self.replacements:
            if not str(replacement.get("component_id") or "").startswith("segment:"):
                raise ValueError("invalid prompt component id")
            if not str(replacement.get("source_digest") or "").startswith("sha256:"):
                raise ValueError("invalid prompt component digest")
            if not isinstance(replacement.get("text"), str) or not str(replacement.get("text")).strip():
                raise ValueError("replacement text is required")

    def to_mapping(self) -> dict[str, Any]:
        body = {
            "artifact_id": self.artifact_id,
            "context_id": self.context_id,
            "target_key": TARGET_KEY,
            "target_mode": self.target_mode,
            "activation_mode": self.activation_mode,
            "base_snapshot_id": self.base_snapshot_id,
            "base_digest": self.base_digest,
            "replacements": [dict(item) for item in self.replacements],
            "validation": dict(self.validation),
            "provenance": dict(self.provenance),
        }
        body["artifact_digest"] = _digest(body)
        return body

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PromptArtifact":
        return cls(
            artifact_id=str(value.get("artifact_id") or ""), context_id=str(value.get("context_id") or ""),
            target_mode=str(value.get("target_mode") or ""), activation_mode=str(value.get("activation_mode") or ""),
            base_snapshot_id=str(value.get("base_snapshot_id") or ""), base_digest=str(value.get("base_digest") or ""),
            replacements=tuple(dict(item) for item in value.get("replacements", ()) if isinstance(item, Mapping)),
            validation=dict(value.get("validation") or {}), provenance=dict(value.get("provenance") or {}),
        )


def stage_artifact(artifact: PromptArtifact) -> dict[str, Any]:
    body = artifact.to_mapping()
    with _store()._connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO prompt_artifacts(artifact_id,context_id,target_key,target_mode,activation_mode,base_digest,artifact_json,artifact_digest,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (artifact.artifact_id, artifact.context_id, TARGET_KEY, artifact.target_mode, artifact.activation_mode,
             artifact.base_digest, _canonical(body), body["artifact_digest"], "staged", time.time()),
        )
    return body


def get_artifact(artifact_id: str) -> PromptArtifact | None:
    with _store()._connect() as conn:
        row = conn.execute("SELECT artifact_json FROM prompt_artifacts WHERE artifact_id=?", (str(artifact_id),)).fetchone()
    if not row:
        return None
    try:
        return PromptArtifact.from_mapping(json.loads(row["artifact_json"]))
    except (TypeError, ValueError):
        return None


def _audit(conn: Any, *, context_id: str, artifact_id: str | None, action: str, previous: str, resulting: str, revision: int, detail: Mapping[str, Any] | None = None) -> None:
    now = time.time()
    audit_id = _digest([context_id, TARGET_KEY, artifact_id, action, revision, now])
    conn.execute(
        "INSERT INTO prompt_activation_audits(audit_id,context_id,target_key,artifact_id,action,previous_state,resulting_state,revision,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (audit_id, context_id, TARGET_KEY, artifact_id, action, previous, resulting, revision, _canonical(dict(detail or {})), now),
    )


def activate(artifact_id: str, *, expected_revision: int | None = None, state: str = "active", canary_percentage: int = 100, baseline_failure_rate: float = 0.0) -> dict[str, Any]:
    artifact = get_artifact(artifact_id)
    if artifact is None:
        raise ValueError("prompt artifact not found")
    now = time.time()
    store = _store()
    with store._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute("SELECT state,revision FROM active_prompt_artifacts WHERE context_id=? AND target_key=?", (artifact.context_id, TARGET_KEY)).fetchone()
        revision = int(current["revision"]) if current else 0
        previous = str(current["state"]) if current else "baseline"
        if expected_revision is not None and revision != int(expected_revision):
            conn.execute("ROLLBACK")
            return {"applied": False, "reason": "active_revision_conflict", "revision": revision, "state": previous}
        next_revision = revision + 1
        conn.execute(
            "INSERT INTO active_prompt_artifacts(context_id,target_key,artifact_id,baseline_snapshot_id,state,activation_mode,canary_percentage,revision,observations,failures,baseline_failure_rate,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(context_id,target_key) DO UPDATE SET artifact_id=excluded.artifact_id,baseline_snapshot_id=excluded.baseline_snapshot_id,state=excluded.state,activation_mode=excluded.activation_mode,canary_percentage=excluded.canary_percentage,revision=excluded.revision,observations=0,failures=0,baseline_failure_rate=excluded.baseline_failure_rate,updated_at=excluded.updated_at",
            (artifact.context_id, TARGET_KEY, artifact.artifact_id, artifact.base_snapshot_id, state, artifact.activation_mode,
             max(1, min(100, int(canary_percentage))), next_revision, 0, 0, max(0.0, min(1.0, float(baseline_failure_rate))), now),
        )
        conn.execute("UPDATE prompt_artifacts SET status=? WHERE artifact_id=?", (state, artifact.artifact_id))
        _audit(conn, context_id=artifact.context_id, artifact_id=artifact.artifact_id, action="activate", previous=previous, resulting=state, revision=next_revision)
        conn.execute("COMMIT")
    return {"applied": True, "artifact_id": artifact.artifact_id, "revision": next_revision, "state": state}


def begin_activation(artifact: PromptArtifact, cfg: Mapping[str, Any]) -> dict[str, Any]:
    settings = cfg.get("prompt_optimization") if isinstance(cfg.get("prompt_optimization"), Mapping) else {}
    if artifact.activation_mode == "manual":
        return {"applied": False, "artifact_id": artifact.artifact_id, "state": "staged", "reason": "manual_promotion_required"}
    baseline_failure = float(artifact.validation.get("baseline_failure_rate", 0.0) or 0.0)
    return activate(
        artifact.artifact_id, state="canary", canary_percentage=int(settings.get("canary_percentage", 10) or 10),
        baseline_failure_rate=baseline_failure,
    )


def active_status(context_id: str) -> dict[str, Any]:
    with _store()._connect() as conn:
        row = conn.execute(
            "SELECT * FROM active_prompt_artifacts WHERE context_id=? AND target_key=?", (str(context_id), TARGET_KEY)
        ).fetchone()
    return dict(row) if row else {}


def active_artifact(context_id: str) -> tuple[PromptArtifact | None, dict[str, Any]]:
    status = active_status(context_id)
    return (get_artifact(str(status.get("artifact_id") or "")) if status else None, status)


def should_apply(status: Mapping[str, Any], *, context_id: str, attempt: int = 0) -> bool:
    state = str(status.get("state") or "")
    if state == "active":
        return True
    if state not in {"canary", "awaiting_manual"}:
        return False
    percentage = max(1, min(100, int(status.get("canary_percentage", 10) or 10)))
    token = f"{context_id}|{status.get('artifact_id')}|{attempt}"
    return int(sha256(token.encode("utf-8")).hexdigest()[:8], 16) % 100 < percentage


def apply_artifact(system_prompt: list[str], artifact: PromptArtifact) -> tuple[bool, list[str]]:
    original = list(system_prompt)
    by_ordinal = {item["ordinal"]: item for item in discover_components(original, max_chars=250_000)}
    replacements = {str(item["component_id"]): item for item in artifact.replacements}
    changed = False
    for ordinal, component in by_ordinal.items():
        replacement = replacements.get(str(component["component_id"]))
        if replacement is None:
            continue
        if component["protected"] or component["source_digest"] != replacement.get("source_digest"):
            return False, original
        text = str(replacement.get("text") or "")
        if not text.strip():
            return False, original
        system_prompt[ordinal] = text
        changed = True
    if not changed or len(replacements) != sum(1 for item in replacements if any(c["component_id"] == item for c in by_ordinal.values())):
        system_prompt[:] = original
        return False, original
    return True, original


def promote(artifact_id: str, *, expected_revision: int | None = None) -> dict[str, Any]:
    return activate(artifact_id, expected_revision=expected_revision, state="active", canary_percentage=100)


def rollback(context_id: str, *, expected_revision: int | None = None, reason: str = "operator") -> dict[str, Any]:
    store = _store()
    with store._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute("SELECT * FROM active_prompt_artifacts WHERE context_id=? AND target_key=?", (str(context_id), TARGET_KEY)).fetchone()
        if not current:
            conn.execute("ROLLBACK")
            return {"applied": False, "reason": "no_active_prompt_artifact", "revision": 0}
        revision = int(current["revision"])
        if expected_revision is not None and revision != int(expected_revision):
            conn.execute("ROLLBACK")
            return {"applied": False, "reason": "active_revision_conflict", "revision": revision}
        next_revision = revision + 1
        conn.execute("UPDATE active_prompt_artifacts SET state='rolled_back',revision=?,updated_at=? WHERE context_id=? AND target_key=?", (next_revision, time.time(), str(context_id), TARGET_KEY))
        _audit(conn, context_id=str(context_id), artifact_id=str(current["artifact_id"]), action="rollback", previous=str(current["state"]), resulting="rolled_back", revision=next_revision, detail={"reason": reason})
        conn.execute("COMMIT")
    return {"applied": True, "state": "rolled_back", "revision": next_revision}


def record_observation(context_id: str, artifact_id: str, *, success: bool, cfg: Mapping[str, Any]) -> dict[str, Any]:
    settings = cfg.get("prompt_optimization") if isinstance(cfg.get("prompt_optimization"), Mapping) else {}
    rollback_cfg = settings.get("rollback") if isinstance(settings.get("rollback"), Mapping) else {}
    store = _store()
    with store._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM active_prompt_artifacts WHERE context_id=? AND target_key=? AND artifact_id=?", (str(context_id), TARGET_KEY, str(artifact_id))).fetchone()
        if not row or str(row["state"]) not in {"canary", "awaiting_manual"}:
            conn.execute("ROLLBACK")
            return {}
        observations = int(row["observations"]) + 1
        failures = int(row["failures"]) + int(not success)
        resulting = str(row["state"])
        minimum = max(3, int(settings.get("canary_min_observations", 10) or 10))
        maximum = max(minimum, int(settings.get("canary_max_observations", 40) or 40))
        failure_rate = failures / max(1, observations)
        success_rate = 1.0 - failure_rate
        baseline_failure_rate = float(row["baseline_failure_rate"])
        baseline_score = 1.0 - baseline_failure_rate
        allowed = baseline_failure_rate + float(rollback_cfg.get("maximum_failure_rate_increase", 0.05) or 0.05)
        minimum_score = max(0.0, baseline_score - float(rollback_cfg.get("maximum_score_regression", 0.05) or 0.05))
        has_regressed = failure_rate > allowed or success_rate < minimum_score
        if bool(rollback_cfg.get("enabled", True)) and observations >= minimum and has_regressed:
            resulting = "rolled_back"
        elif observations >= minimum and str(row["activation_mode"]) == "automatic" and not has_regressed:
            resulting = "active"
        elif observations >= maximum and str(row["activation_mode"]) == "canary":
            resulting = "awaiting_manual"
        revision = int(row["revision"]) + int(resulting != str(row["state"]))
        canary_percentage = 100 if resulting == "active" else int(row["canary_percentage"])
        conn.execute("UPDATE active_prompt_artifacts SET state=?,canary_percentage=?,revision=?,observations=?,failures=?,updated_at=? WHERE context_id=? AND target_key=?", (resulting, canary_percentage, revision, observations, failures, time.time(), str(context_id), TARGET_KEY))
        if resulting != str(row["state"]):
            _audit(conn, context_id=str(context_id), artifact_id=str(artifact_id), action="canary_decision", previous=str(row["state"]), resulting=resulting, revision=revision, detail={"observations": observations, "failure_rate": failure_rate, "success_rate": success_rate, "allowed_failure_rate": allowed, "minimum_score": minimum_score})
        conn.execute("COMMIT")
    return {"state": resulting, "revision": revision, "observations": observations, "failures": failures, "failure_rate": failure_rate, "success_rate": success_rate, "allowed_failure_rate": allowed, "minimum_score": minimum_score}


def public_status(context_id: str) -> dict[str, Any]:
    status = active_status(context_id)
    snapshot = latest_snapshot(context_id)
    return {
        "state": str(status.get("state") or "inactive"),
        "activation_mode": str(status.get("activation_mode") or "manual"),
        "artifact_id": str(status.get("artifact_id") or "")[:128],
        "revision": int(status.get("revision", 0) or 0),
        "canary_percentage": int(status.get("canary_percentage", 0) or 0),
        "observations": int(status.get("observations", 0) or 0),
        "failures": int(status.get("failures", 0) or 0),
        "snapshot_ready": bool(snapshot),
        "available_components": [
            {"component_id": str(item.get("component_id") or ""), "ordinal": int(item.get("ordinal", 0)), "char_count": int(item.get("char_count", 0)), "protected": bool(item.get("protected")), "protection_reason": str(item.get("protection_reason") or "")}
            for item in ((snapshot or {}).get("components") or [])
        ],
    }


__all__ = ["ACTIVATION_MODES", "PROTECTED_INVENTORY", "PromptArtifact", "TARGET_KEY", "TARGET_MODES", "active_artifact", "active_status", "apply_artifact", "begin_activation", "capture_snapshot", "discover_components", "get_artifact", "latest_snapshot", "promote", "public_status", "record_observation", "rollback", "should_apply", "stage_artifact"]
