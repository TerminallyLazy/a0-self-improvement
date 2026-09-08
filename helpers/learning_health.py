"""Bounded, read-only learning diagnostics. Never returns conversation content."""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Mapping

from . import paths

WINDOW = 20
MAX_RESULT_CHARS = 262_144
REASONS = frozenset({
    "no_actionable_rlm_findings", "not_enough_objectives", "no_objective_samples",
    "cooldown_not_elapsed", "optimization_already_running", "validation_failed",
    "deterministic_evidence_missing", "missing_candidate", "gepa_unavailable",
    "model_config_ref_required", "worker_environment_not_ready",
    "compile_runtime_budget_exceeded", "compile_cost_budget_exceeded",
    "candidate_staged_coordinator_promotion_required", "cancelled_while_executing",
})


@contextmanager
def _reader():
    connection = sqlite3.connect(paths.STORE_FILE.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.5)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        yield connection
    finally:
        connection.close()


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, str) or len(value) > MAX_RESULT_CHARS:
        return {}
    try:
        result = json.loads(value)
        return result if type(result) is dict else {}
    except ValueError:
        return {}


def job_outcome(status: str, raw_result: object) -> tuple[str, str]:
    """Separate queue completion from useful work; expose only fixed reasons."""
    result = _object(raw_result)
    result_status = result.get("status")
    if status in {"pending", "queued", "running", "cancelled", "failed"}:
        outcome = status
    elif result_status == "skipped":
        outcome = "skipped"
    elif status == "rejected" or result_status in {"candidate_rejected", "rejected", "failed", "error"}:
        outcome = "failed" if result_status in {"failed", "error"} else "rejected"
    elif result_status in {"candidate", "review_only"} and result.get("candidate_id"):
        outcome = "candidate"
    else:
        outcome = "completed_without_candidate"
    reason = result.get("reason")
    reason = reason.replace(" ", "_") if type(reason) is str else ""
    return outcome, reason if reason in REASONS else "details_unavailable"


def read_learning_health(context_ref: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "state": "empty", "window": WINDOW, "recorded_jobs": 0,
        "outcomes": {}, "last_outcome": "none", "last_reason": "none",
    }
    if not paths.STORE_FILE.is_file():
        return result
    try:
        with _reader() as connection:
            rows = connection.execute(
                """SELECT status, CASE WHEN length(result_json)<=? THEN result_json END AS result_json
                   FROM jobs WHERE context_id=? ORDER BY updated_at DESC,job_key DESC LIMIT ?""",
                (MAX_RESULT_CHARS, context_ref, WINDOW),
            ).fetchall()
        outcomes = [job_outcome(str(row["status"]), row["result_json"]) for row in rows]
        result.update(state="ready", recorded_jobs=len(rows), outcomes=dict(Counter(item[0] for item in outcomes)))
        if outcomes:
            result.update(last_outcome=outcomes[0][0], last_reason=outcomes[0][1])
    except (OSError, sqlite3.Error, ValueError):
        result["state"] = "unavailable"
    return result


def read_progress_inputs(
    context_ref: str, config: Mapping[str, Any], *, now: datetime | None = None,
) -> tuple[int, dict[str, Any]]:
    """Read existing counters without Store construction, migrations or repair."""
    if not paths.STORE_FILE.is_file():
        return 0, {}
    capture = config.get("trace_capture")
    capture = capture if isinstance(capture, Mapping) else {}
    ttl = max(60, int(capture.get("event_ttl_seconds", 604800)))
    reference = (now or datetime.now(timezone.utc)).timestamp()
    try:
        with _reader() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM evidence_events WHERE context_id=? AND event_type='loop' AND created_at>=?",
                (context_ref, reference - ttl),
            ).fetchone()[0]
            row = connection.execute(
                "SELECT CASE WHEN length(state_json)<=? THEN state_json END FROM runtime_context_state WHERE context_id=?",
                (MAX_RESULT_CHARS, context_ref),
            ).fetchone()
        return int(count), _object(row[0]) if row else {}
    except sqlite3.Error as exc:
        raise ValueError("learning_progress_unavailable") from exc


def next_action(health: Mapping[str, Any], *, enabled: bool, mode: str, generation: list, promotion: list) -> str:
    if not enabled:
        return "enable_plugin"
    if mode == "observe":
        return "choose_review"
    for gate in generation:
        if gate["state"] != "ready":
            return str(gate["reason_code"])
    if health.get("state") == "unavailable":
        return "learning_store_unavailable"
    reason = health.get("last_reason")
    if reason in {"no_actionable_rlm_findings", "not_enough_objectives", "no_objective_samples"}:
        return "collect_evidence"
    if health.get("last_outcome") in {"failed", "rejected"}:
        return "inspect_candidate_evidence"
    if mode == "autopilot":
        for gate in promotion:
            if gate["state"] != "ready":
                return str(gate["reason_code"])
    return "review_candidates" if health.get("outcomes", {}).get("candidate", 0) else "continue_working"
