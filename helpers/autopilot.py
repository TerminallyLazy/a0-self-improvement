"""Operator-selected automatic collection and candidate scheduling.

Autopilot is intentionally split at the v3 authority boundary. This module may
capture approved local system-prompt snapshots, append privacy-bounded metadata,
and enqueue candidate-generation work. It cannot write an Activation Scope,
declare replay or canary success, or promote a candidate. Automatic activation
continues to require the existing v3 calibration, evidence, canary, grant, CAS,
monitor, and rollback coordinators.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from . import prompt_artifacts, state, trace
from ._scheduler_coordinator import schedule_optimization_job
from .v3.automatic_genesis import project_context_refs


AUTOMATION_MODES = ("observe", "review", "autopilot")
AUTOMATION_SCOPES = ("current_chat", "project")
RISK_PROFILES = ("safe", "balanced", "aggressive")


@dataclass(frozen=True, slots=True)
class AutomationSettings:
    mode: str
    scope: str
    risk_profile: str
    live_refresh_seconds: int
    capture_system_prompts: bool
    require_replay: bool
    require_canary: bool
    automatic_rollback: bool

    @property
    def generates_candidates(self) -> bool:
        return self.mode in {"review", "autopilot"}

    @property
    def requests_automatic_activation(self) -> bool:
        return self.mode == "autopilot"


@dataclass(frozen=True, slots=True)
class OptimizationProgress:
    state: str
    total_loop_count: int
    completed_loops: int
    required_loops: int
    remaining_loops: int
    cooldown_remaining_seconds: int


def settings_from_config(config: Mapping[str, Any] | None) -> AutomationSettings:
    automation = (
        config.get("automation")
        if isinstance(config, Mapping) and isinstance(config.get("automation"), Mapping)
        else {}
    )
    mode = str(automation.get("mode") or "observe")
    scope = str(automation.get("scope") or "project")
    risk = str(automation.get("risk_profile") or "balanced")
    try:
        refresh = int(automation.get("live_refresh_seconds", 2) or 2)
    except (TypeError, ValueError):
        refresh = 2
    return AutomationSettings(
        mode=mode if mode in AUTOMATION_MODES else "observe",
        scope=scope if scope in AUTOMATION_SCOPES else "project",
        risk_profile=risk if risk in RISK_PROFILES else "balanced",
        live_refresh_seconds=max(1, min(30, refresh)),
        capture_system_prompts=bool(automation.get("capture_system_prompts", False)),
        require_replay=bool(automation.get("require_replay", True)),
        require_canary=bool(automation.get("require_canary", True)),
        automatic_rollback=bool(automation.get("automatic_rollback", True)),
    )


def capture_system_prompt(
    *, context_ref: str, system_prompt: Sequence[str], config: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Persist a local prompt snapshot only after the explicit capture opt-in."""

    settings = settings_from_config(config)
    if (
        not settings.generates_candidates
        or not settings.capture_system_prompts
        or not bool(config.get("enabled", False))
    ):
        return None
    prompt = config.get("prompt_optimization")
    prompt = prompt if isinstance(prompt, Mapping) else {}
    try:
        maximum = int(prompt.get("max_snapshot_chars", 60_000) or 60_000)
    except (TypeError, ValueError):
        maximum = 60_000
    return prompt_artifacts.capture_snapshot(
        context_ref,
        system_prompt,
        max_chars=max(1_000, min(250_000, maximum)),
    )


def record_tool_metadata(
    *,
    context_ref: str,
    tool_name: str,
    loop_iteration: int,
    terminal: bool,
    config: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Append bounded tool metadata without arguments, results, or error text."""

    settings = settings_from_config(config)
    if not settings.generates_candidates or not bool(config.get("enabled", False)):
        return None
    return trace.append_event(
        {
            "context_id": context_ref,
            "event_type": "tool",
            "agent_name": "agent_zero",
            "tool": tool_name or "unknown",
            "loop_iteration": loop_iteration,
            "success": True,
            "objective_bucket": "unknown",
            "response": "terminal" if terminal else "continuing",
        },
        policy=trace.policy_from_config(config),
    )


def observe_loop_and_schedule(
    *,
    agent: object,
    context_ref: str,
    message_ref: str,
    loop_iteration: int,
    config: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    """Record one opaque loop fact and enqueue eligible project work.

    The message identity supplies only a stable objective family; conversation
    text is not read, hashed, or persisted by this path.
    """

    settings = settings_from_config(config)
    if not settings.generates_candidates or not bool(config.get("enabled", False)):
        return ()
    trace.append_event(
        {
            "context_id": context_ref,
            "event_type": "loop",
            "agent_name": "agent_zero",
            "loop_iteration": loop_iteration,
            "success": True,
            "objective": f"message_ref:{message_ref}",
            "objective_bucket": "unknown",
            "response": "loop_completed",
        },
        policy=trace.policy_from_config(config),
    )
    if not _candidate_generation_enabled(config):
        return ()

    targets = _target_contexts(
        agent=agent,
        context_ref=context_ref,
        scope=settings.scope,
    )
    results: list[dict[str, Any]] = []
    for target in targets:
        result = _maybe_schedule_context(target, config)
        if result is not None:
            results.append(result)
    if any(item.get("dispatched") is True for item in results):
        # Process ownership remains in the explicit plugin supervisor. This
        # call reconciles only after durable work has been enqueued.
        from . import worker_supervisor

        worker_supervisor.reconcile(config)
    return tuple(results)


def _candidate_generation_enabled(config: Mapping[str, Any]) -> bool:
    optimization = config.get("optimization")
    optimization = optimization if isinstance(optimization, Mapping) else {}
    return bool(
        config.get("instrumentation_enabled", False)
        and optimization.get("enabled", False)
        and optimization.get("auto_optimize", False)
    )


def optimization_progress(
    context_ref: str,
    config: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> OptimizationProgress:
    """Project the next per-chat scheduling threshold without mutation."""

    optimization = config.get("optimization")
    optimization = optimization if isinstance(optimization, Mapping) else {}
    try:
        interval = max(1, int(optimization.get("auto_optimize_interval_messages", 12)))
        cooldown_hours = max(0, int(optimization.get("cooldown_hours", 6)))
    except (TypeError, ValueError):
        return OptimizationProgress("unavailable", 0, 0, 1, 1, 0)

    summary = trace.summarize_context(context_ref, limit=2_000_000)
    loop_count = max(0, int(summary.get("loop_count", 0) or 0))
    context_state = state.load_context_state(context_ref)
    last_trigger_count = max(
        0, int(context_state.get("autopilot_last_trigger_loop_count", 0) or 0)
    )
    loops_since_trigger = max(0, loop_count - last_trigger_count)
    completed = min(interval, loops_since_trigger)
    remaining = max(0, interval - loops_since_trigger)
    cooldown_remaining = 0

    last_trigger_at = context_state.get("autopilot_last_trigger_at")
    if remaining == 0 and cooldown_hours and isinstance(last_trigger_at, str):
        try:
            previous = datetime.fromisoformat(last_trigger_at.replace("Z", "+00:00"))
            if previous.tzinfo is None:
                previous = previous.replace(tzinfo=timezone.utc)
            deadline = previous.astimezone(timezone.utc) + timedelta(hours=cooldown_hours)
            seconds = (deadline - (now or datetime.now(timezone.utc))).total_seconds()
            cooldown_remaining = max(0, int(seconds + 0.999))
        except ValueError:
            cooldown_remaining = 0

    progress_state = (
        "collecting"
        if remaining
        else "cooldown" if cooldown_remaining else "ready"
    )
    return OptimizationProgress(
        state=progress_state,
        total_loop_count=loop_count,
        completed_loops=completed,
        required_loops=interval,
        remaining_loops=remaining,
        cooldown_remaining_seconds=cooldown_remaining,
    )


def _target_contexts(*, agent: object, context_ref: str, scope: str) -> tuple[str, ...]:
    if scope != "project":
        return (context_ref,)
    context = getattr(agent, "context", None)
    get_data = getattr(context, "get_data", None)
    project_ref = get_data("project") if callable(get_data) else None
    if type(project_ref) is not str or not project_ref:
        return (context_ref,)
    try:
        return project_context_refs(
            project_ref=project_ref,
            current_context_ref=context_ref,
        )
    except Exception:
        return (context_ref,)


def _maybe_schedule_context(
    context_ref: str, config: Mapping[str, Any]
) -> dict[str, Any] | None:
    progress = optimization_progress(context_ref, config)
    if progress.state != "ready":
        return None
    result = schedule_optimization_job(context_ref, dict(config), force=False)
    state._store_for_root().set_context_state(
        context_ref,
        {
            "autopilot_last_trigger_loop_count": progress.total_loop_count,
            "autopilot_last_trigger_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "autopilot_last_job_key": str(result.get("job_key") or ""),
            "autopilot_last_dispatch_state": str(result.get("status") or "unavailable"),
        },
    )
    return result


__all__ = [
    "AUTOMATION_MODES",
    "AUTOMATION_SCOPES",
    "RISK_PROFILES",
    "AutomationSettings",
    "OptimizationProgress",
    "capture_system_prompt",
    "observe_loop_and_schedule",
    "optimization_progress",
    "record_tool_metadata",
    "settings_from_config",
]
