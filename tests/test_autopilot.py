from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from usr.plugins.dspy_rlm.api import autopilot_status
from usr.plugins.dspy_rlm.helpers import autopilot, config


def test_autopilot_mode_is_one_switch_but_conversation_content_stays_excluded() -> None:
    configured = config.normalize_config(
        {
            "automation": {
                "mode": "autopilot",
                "capture_system_prompts": True,
                "include_conversation_content": True,
            }
        }
    )

    assert configured["automation"] == {
        "mode": "autopilot",
        "scope": "project",
        "risk_profile": "balanced",
        "live_refresh_seconds": 2,
        "capture_system_prompts": True,
        "include_conversation_content": False,
        "require_replay": True,
        "require_canary": True,
        "automatic_rollback": True,
    }
    assert configured["instrumentation_enabled"] is True
    assert configured["optimization"]["auto_optimize"] is True
    assert configured["optimization"]["auto_promote"] is True
    assert configured["optimization"]["enable_dspy_optimizer"] is True
    assert configured["rlm"]["enabled"] is True
    assert configured["prompt_optimization"]["allow_prompt_capture"] is True
    assert configured["prompt_optimization"]["activation_mode"] == "automatic"
    assert configured["prompt_optimization"]["automatic_requires_canary"] is True


def test_review_generates_candidates_without_requesting_automatic_promotion() -> None:
    configured = config.normalize_config({"automation": {"mode": "review"}})

    assert configured["optimization"]["auto_optimize"] is True
    assert configured["optimization"]["auto_promote"] is False
    assert configured["prompt_optimization"]["activation_mode"] == "manual"


def test_project_loop_schedules_each_eligible_chat_without_conversation_text(
    monkeypatch,
) -> None:
    events = []
    scheduled = []
    state_updates = []
    reconciled = []
    loop_counts = {"chat-main": 12, "chat-parallel": 24}

    monkeypatch.setattr(
        autopilot.trace,
        "append_event",
        lambda event, **_kwargs: events.append(dict(event)) or event,
    )
    monkeypatch.setattr(
        autopilot.trace,
        "summarize_context",
        lambda context_ref, **_kwargs: {"loop_count": loop_counts[context_ref]},
    )
    monkeypatch.setattr(
        autopilot,
        "project_context_refs",
        lambda **_kwargs: ("chat-main", "chat-parallel"),
    )
    monkeypatch.setattr(autopilot.state, "load_context_state", lambda _context: {})

    class Store:
        def set_context_state(self, context_ref, update):
            state_updates.append((context_ref, dict(update)))

    monkeypatch.setattr(autopilot.state, "_store_for_root", lambda: Store())
    monkeypatch.setattr(
        autopilot,
        "schedule_optimization_job",
        lambda context_ref, _cfg, force=False: scheduled.append((context_ref, force))
        or {"job_key": f"job:{context_ref}", "status": "queued", "dispatched": True},
    )
    from usr.plugins.dspy_rlm.helpers import worker_supervisor

    monkeypatch.setattr(
        worker_supervisor, "reconcile", lambda cfg: reconciled.append(cfg) or {}
    )
    agent = SimpleNamespace(
        context=SimpleNamespace(get_data=lambda key: "project-1" if key == "project" else None)
    )
    cfg = {
        "enabled": True,
        "instrumentation_enabled": True,
        "automation": {"mode": "autopilot", "scope": "project"},
        "optimization": {
            "enabled": True,
            "auto_optimize": True,
            "auto_optimize_interval_messages": 12,
            "cooldown_hours": 0,
        },
    }

    result = autopilot.observe_loop_and_schedule(
        agent=agent,
        context_ref="chat-main",
        message_ref="message-opaque-1",
        loop_iteration=4,
        config=cfg,
    )

    assert len(result) == 2
    assert scheduled == [("chat-main", False), ("chat-parallel", False)]
    assert [item[0] for item in state_updates] == ["chat-main", "chat-parallel"]
    assert len(reconciled) == 1
    assert events == [
        {
            "context_id": "chat-main",
            "event_type": "loop",
            "agent_name": "agent_zero",
            "loop_iteration": 4,
            "success": True,
            "objective": "message_ref:message-opaque-1",
            "objective_bucket": "unknown",
            "response": "loop_completed",
        }
    ]


def test_optimization_progress_reports_loops_remaining(monkeypatch) -> None:
    monkeypatch.setattr(
        autopilot.trace,
        "summarize_context",
        lambda _context, **_kwargs: {"loop_count": 20},
    )
    monkeypatch.setattr(
        autopilot.state,
        "load_context_state",
        lambda _context: {"autopilot_last_trigger_loop_count": 12},
    )

    progress = autopilot.optimization_progress(
        "chat-main",
        {
            "optimization": {
                "auto_optimize_interval_messages": 12,
                "cooldown_hours": 6,
            }
        },
        now=datetime(2026, 8, 26, tzinfo=timezone.utc),
    )

    assert progress.completed_loops == 8
    assert progress.required_loops == 12
    assert progress.remaining_loops == 4
    assert progress.state == "collecting"


def test_live_status_separates_generation_from_promotion_authority(monkeypatch) -> None:
    monkeypatch.setattr(
        autopilot_status,
        "_v3_runtime",
        lambda _contexts, **_kwargs: {
            "scope_ready": True,
            "observation_count": 14,
            "candidate_count": 2,
            "receipt_count": 7,
            "calibration_state": "approved",
            "activation_mode": "auto_after_canary",
            "automatic_authority_state": "unavailable",
            "recent": [],
        },
    )
    monkeypatch.setattr(autopilot_status, "_legacy_runtime", lambda _context: ({}, []))
    monkeypatch.setattr(
        autopilot_status.dependencies,
        "dependency_diagnostics",
        lambda: {"ready": True},
    )
    monkeypatch.setattr(
        autopilot_status.worker_supervisor,
        "snapshot",
        lambda _cfg: {"desired": 1, "running": 1},
    )
    monkeypatch.setattr(
        autopilot_status.autopilot,
        "optimization_progress",
        lambda _context, _cfg: autopilot.OptimizationProgress(
            "collecting", 8, 8, 12, 4, 0
        ),
    )
    configured = config.normalize_config(
        {
            "enabled": True,
            "automation": {"mode": "autopilot", "capture_system_prompts": True},
            "prompt_optimization": {"allow_prompt_capture": True},
        }
    )

    result = autopilot_status.project_autopilot_status(
        context_ref="chat-main", project_ref="project-1", config=configured
    )

    assert result["generation"]["state"] == "ready"
    assert result["promotion"]["state"] == "blocked"
    assert result["cycle_state"] == "awaiting_authority"
    assert result["context_count"] == 1
    assert result["conversation_content"] == "excluded"
    assert result["next_optimization"] == {
        "state": "collecting",
        "completed_loops": 8,
        "required_loops": 12,
        "remaining_loops": 4,
        "cooldown_remaining_seconds": 0,
    }
    blocked = {
        item["gate_id"]: item["reason_code"]
        for item in result["promotion"]["gates"]
        if item["state"] == "blocked"
    }
    assert blocked == {
        "automatic_activation_authority": "automatic_activation_authority_missing",
        "automatic_transition_runner": "production_automation_not_available",
    }
