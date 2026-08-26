"""Live, content-free observability for operator-selected automation."""
from __future__ import annotations

from datetime import datetime, timezone
import re
import sqlite3
from typing import Any, Mapping

from agent import AgentContext
from helpers.api import ApiHandler, Request, Response

from usr.plugins.dspy_rlm.helpers import config as config_module
from usr.plugins.dspy_rlm.helpers import autopilot, dependencies, paths, worker_supervisor
from usr.plugins.dspy_rlm.helpers.autopilot import settings_from_config
from usr.plugins.dspy_rlm.helpers.v3.automatic_genesis import project_context_refs
from usr.plugins.dspy_rlm.helpers.v3.operator_repository import (
    OperatorRepositoryAdapter,
    SafeStoreOperatorReader,
)
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_reader


AUTOPILOT_STATUS_SCHEMA = "a0.autopilot-status.v1"
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_JOB_STATES = frozenset(
    {"pending", "queued", "running", "candidate", "promoted", "rejected", "succeeded", "failed", "cancelled"}
)
_ACTIVITY = {
    "runtime_observation_fact": "observation_recorded",
    "improvement_candidate": "candidate_generated",
    "activation_disposition": "evidence_reduced",
    "canary_trial": "canary_started",
    "canary_conclusion": "canary_concluded",
    "activation_transition_receipt": "activation_changed",
    "post_promotion_monitor_conclusion": "monitor_concluded",
    "closed_loop_runner_receipt": "closed_loop_finished",
}


def _safe_ref(value: object, fallback: str = "unavailable") -> str:
    return value if type(value) is str and _SAFE_REF.fullmatch(value) else fallback


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _gate(gate_id: str, ready: bool, reason: str) -> dict[str, str]:
    return {
        "gate_id": gate_id,
        "state": "ready" if ready else "blocked",
        "reason_code": "ready" if ready else reason,
    }


def _legacy_runtime(context_refs: tuple[str, ...]) -> tuple[dict[str, int], list[dict[str, Any]]]:
    if not paths.STORE_FILE.is_file():
        return {}, []
    jobs: dict[str, int] = {}
    recent: list[dict[str, Any]] = []
    try:
        uri = f"file:{paths.STORE_FILE}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1.0) as connection:
            connection.row_factory = sqlite3.Row
            placeholders = ",".join("?" for _ in context_refs)
            rows = connection.execute(
                f"SELECT status,COUNT(*) AS count FROM jobs WHERE context_id IN ({placeholders}) GROUP BY status",
                context_refs,
            ).fetchall()
            jobs = {
                str(row["status"]): int(row["count"])
                for row in rows
                if str(row["status"]) in _JOB_STATES
            }
            job_rows = connection.execute(
                f"SELECT job_key,status,updated_at FROM jobs WHERE context_id IN ({placeholders}) ORDER BY updated_at DESC LIMIT 8",
                context_refs,
            ).fetchall()
            for row in job_rows:
                status = str(row["status"])
                job_ref = _safe_ref(str(row["job_key"]), "")
                if status not in _JOB_STATES or not job_ref:
                    continue
                stamp = datetime.fromtimestamp(
                    float(row["updated_at"]), timezone.utc
                ).isoformat(timespec="seconds").replace("+00:00", "Z")
                recent.append(
                    {
                        "activity_id": job_ref,
                        "kind": "candidate_work",
                        "state": status,
                        "observed_at": stamp,
                    }
                )
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return {}, []
    return jobs, recent


def _v3_runtime(context_refs: tuple[str, ...], *, selected_context_ref: str) -> dict[str, Any]:
    result = {
        "scope_ready": False,
        "observation_count": 0,
        "candidate_count": 0,
        "receipt_count": 0,
        "calibration_state": "unavailable",
        "activation_mode": "unavailable",
        "automatic_authority_state": "unavailable",
        "recent": [],
    }
    try:
        with open_runtime_reader(
            pre_cutover_path=paths.SAFE_STORE_FILE,
            manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
        ) as reader:
            facts = SafeStoreOperatorReader(reader)
            adapter = OperatorRepositoryAdapter(facts)
            records = []
            receipt_count = 0
            result["scope_ready"] = True
            for context_ref in context_refs:
                records.extend(facts.list_records(context_ref))
                result["scope_ready"] = (
                    result["scope_ready"]
                    and facts.get_activation_scope(context_ref) is not None
                )
                receipt_count += len(adapter.read_receipts_audit(context_ref).receipts)
            result["observation_count"] = sum(
                item.record.record_kind == "runtime_observation_fact" for item in records
            )
            result["candidate_count"] = sum(
                item.record.record_kind == "improvement_candidate" for item in records
            )
            policy = adapter.read_policy_capabilities(selected_context_ref)
            result["calibration_state"] = policy.calibration_state
            result["activation_mode"] = policy.activation_mode
            result["automatic_authority_state"] = policy.automatic_authority_state
            result["receipt_count"] = receipt_count
            activity: list[dict[str, str]] = []
            for item in sorted(records, key=lambda observed: observed.observed_at, reverse=True):
                kind = _ACTIVITY.get(item.record.record_kind)
                if kind is None:
                    continue
                activity.append(
                    {
                        "activity_id": _safe_ref(item.record.record_id),
                        "kind": kind,
                        "state": "completed",
                        "observed_at": item.observed_at,
                    }
                )
                if len(activity) == 8:
                    break
            result["recent"] = activity
    except Exception:
        pass
    return result


def _next_optimization(
    context_refs: tuple[str, ...],
    config: Mapping[str, Any],
    *,
    running: int,
    enabled: bool,
) -> dict[str, int | str]:
    if not enabled:
        return {
            "state": "disabled",
            "completed_loops": 0,
            "required_loops": 1,
            "remaining_loops": 1,
            "cooldown_remaining_seconds": 0,
        }
    progress = [autopilot.optimization_progress(ref, config) for ref in context_refs]
    rank = {"ready": 0, "cooldown": 1, "collecting": 2, "unavailable": 3}
    selected = min(
        progress,
        key=lambda item: (
            rank.get(item.state, 4),
            item.cooldown_remaining_seconds
            if item.state == "cooldown"
            else item.remaining_loops,
        ),
    )
    return {
        "state": "queued" if running else selected.state,
        "completed_loops": selected.completed_loops,
        "required_loops": selected.required_loops,
        "remaining_loops": selected.remaining_loops,
        "cooldown_remaining_seconds": selected.cooldown_remaining_seconds,
    }


def project_autopilot_status(
    *, context_ref: str, project_ref: str | None, config: Mapping[str, Any]
) -> dict[str, Any]:
    settings = settings_from_config(config)
    context_refs = (context_ref,)
    if settings.scope == "project" and project_ref:
        try:
            context_refs = project_context_refs(
                project_ref=project_ref,
                current_context_ref=context_ref,
            )
        except Exception:
            context_refs = (context_ref,)
    v3 = _v3_runtime(context_refs, selected_context_ref=context_ref)
    jobs, job_activity = _legacy_runtime(context_refs)
    dependency_ready = bool(dependencies.dependency_diagnostics().get("ready"))
    worker_state = worker_supervisor.snapshot(config)
    optimization = config.get("optimization")
    optimization = optimization if isinstance(optimization, Mapping) else {}
    prompt = config.get("prompt_optimization")
    prompt = prompt if isinstance(prompt, Mapping) else {}
    evaluator = config.get("evaluator")
    evaluator = evaluator if isinstance(evaluator, Mapping) else {}
    rlm = config.get("rlm")
    rlm = rlm if isinstance(rlm, Mapping) else {}

    generation_gates = (
        _gate("plugin_enabled", bool(config.get("enabled")), "plugin_disabled"),
        _gate("project_assigned", bool(project_ref), "project_required"),
        _gate("project_initialized", bool(v3["scope_ready"]), "project_setup_pending"),
        _gate("safe_observation", bool(config.get("instrumentation_enabled")), "observation_disabled"),
        _gate("rlm", bool(rlm.get("enabled")), "rlm_disabled"),
        _gate("gepa", bool(optimization.get("enable_dspy_optimizer")), "gepa_disabled"),
        _gate("worker_environment", dependency_ready, "worker_environment_not_ready"),
        _gate(
            "system_prompt_capture",
            not settings.capture_system_prompts or bool(prompt.get("allow_prompt_capture")),
            "system_prompt_capture_not_approved",
        ),
    )
    promotion_gates = (
        _gate(
            "certified_replay",
            settings.require_replay and bool(evaluator.get("enable_replay_audit")),
            "certified_replay_required",
        ),
        _gate("canary", settings.require_canary, "canary_required"),
        _gate("automatic_rollback", settings.automatic_rollback, "automatic_rollback_required"),
        _gate(
            "approved_calibration",
            v3["calibration_state"] == "approved",
            "approved_calibration_missing",
        ),
        _gate(
            "automatic_activation_policy",
            v3["activation_mode"] == "auto_after_canary",
            "automatic_activation_policy_missing",
        ),
        _gate(
            "automatic_activation_authority",
            v3["automatic_authority_state"] == "authorized",
            "automatic_activation_authority_missing",
        ),
        _gate(
            "automatic_transition_runner",
            False,
            "production_automation_not_available",
        ),
    )
    generation_ready = all(item["state"] == "ready" for item in generation_gates)
    promotion_ready = all(item["state"] == "ready" for item in promotion_gates)
    running = sum(jobs.get(name, 0) for name in ("pending", "queued", "running"))
    next_optimization = _next_optimization(
        context_refs,
        config,
        running=running,
        enabled=bool(config.get("enabled")) and settings.generates_candidates,
    )
    if not bool(config.get("enabled")):
        cycle_state = "disabled"
    elif settings.mode == "observe":
        cycle_state = "observing"
    elif running:
        cycle_state = "generating"
    elif not generation_ready:
        cycle_state = "blocked"
    elif not v3["observation_count"]:
        cycle_state = "collecting"
    elif settings.mode == "review":
        cycle_state = "review"
    elif not promotion_ready:
        cycle_state = "awaiting_authority"
    else:
        cycle_state = "ready"

    recent = sorted(
        [*v3["recent"], *job_activity],
        key=lambda item: item["observed_at"],
        reverse=True,
    )[:10]
    return {
        "schema": AUTOPILOT_STATUS_SCHEMA,
        "context_ref": context_ref,
        "observed_at": _now(),
        "mode": settings.mode,
        "scope": settings.scope,
        "context_count": len(context_refs),
        "risk_profile": settings.risk_profile,
        "cycle_state": cycle_state,
        "live_refresh_seconds": settings.live_refresh_seconds,
        "generation": {
            "state": "ready" if generation_ready else "blocked",
            "gates": list(generation_gates),
        },
        "promotion": {
            "state": "ready" if promotion_ready else "blocked",
            "gates": list(promotion_gates),
        },
        "counts": {
            "observations": int(v3["observation_count"]),
            "candidates": int(v3["candidate_count"]),
            "receipts": int(v3["receipt_count"]),
            "queued_work": running,
        },
        "workers": {
            "desired": int(worker_state.get("desired", 0) or 0),
            "running": int(worker_state.get("running", 0) or 0),
            "state": "ready" if dependency_ready else "blocked",
        },
        "next_optimization": next_optimization,
        "recent_activity": recent,
        "conversation_content": "excluded",
    }


class AutopilotStatus(ApiHandler):
    """Read live automation state without initializing storage or workers."""

    async def process(self, input: dict, request: Request) -> dict | Response:
        if type(input) is not dict or set(input) != {"context_id"}:
            return Response(status=400, response="context_id is required", mimetype="text/plain")
        context_ref = _safe_ref(input.get("context_id"), "")
        context = AgentContext.get(context_ref) if context_ref else None
        if context is None or str(getattr(context, "id", "")) != context_ref:
            return Response(status=404, response="context not found", mimetype="text/plain")
        agent = getattr(context, "agent0", None) or context
        config = config_module.load_config(agent=agent)
        config = config_module.normalize_config(config if isinstance(config, dict) else None)
        get_data = getattr(context, "get_data", None)
        project_ref = get_data("project") if callable(get_data) else None
        project_ref = project_ref if type(project_ref) is str and _SAFE_REF.fullmatch(project_ref) else None
        return project_autopilot_status(
            context_ref=context_ref,
            project_ref=project_ref,
            config=config,
        )


__all__ = ["AUTOPILOT_STATUS_SCHEMA", "AutopilotStatus", "project_autopilot_status"]
