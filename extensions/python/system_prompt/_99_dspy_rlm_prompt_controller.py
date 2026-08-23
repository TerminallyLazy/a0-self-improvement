"""Late prompt-component controller for opt-in GEPA prompt artifacts."""
from __future__ import annotations

from typing import Any

from helpers.extension import Extension

from usr.plugins.dspy_rlm.helpers import config as config_module
from usr.plugins.dspy_rlm.helpers import prompt_artifacts, state


class DspyRlmPromptController(Extension):
    async def execute(self, system_prompt: list[str] = [], **kwargs: Any) -> None:
        if not self.agent or not isinstance(system_prompt, list):
            return
        cfg = config_module.load_config(self.agent)
        settings = cfg.get("prompt_optimization") if isinstance(cfg, dict) else {}
        if not isinstance(settings, dict) or not bool(settings.get("enabled")):
            return
        if str(settings.get("target_mode") or "guidance_overlay") == "guidance_overlay":
            return
        if not bool(settings.get("allow_prompt_capture")):
            return
        context_id = str(getattr(self.agent.context, "id", "") or "")
        if not context_id:
            return
        snapshot = prompt_artifacts.capture_snapshot(
            context_id, system_prompt, max_chars=int(settings.get("max_snapshot_chars", 60_000) or 60_000)
        )
        if snapshot is None:
            return
        artifact, active = prompt_artifacts.active_artifact(context_id)
        context_state = state.load_context_state(context_id)
        attempt = int(context_state.get("attempts_total", 0) or 0)
        applied = False
        if artifact is not None and prompt_artifacts.should_apply(active, context_id=context_id, attempt=attempt):
            applied, _original = prompt_artifacts.apply_artifact(system_prompt, artifact)
        context_state.update({
            "prompt_artifact_applied": artifact.artifact_id if applied and artifact is not None else "",
            "prompt_baseline_digest": str(snapshot.get("base_digest") or ""),
            "prompt_target_mode": str(settings.get("target_mode") or "guidance_overlay"),
            "prompt_canary_state": str(active.get("state") or "inactive"),
        })
        state._store_for_root().set_context_state(context_id, context_state)
