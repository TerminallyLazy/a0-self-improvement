"""Ensure inert v3 Genesis for the active Agent Zero project."""
from __future__ import annotations

from typing import Any

from helpers.extension import Extension

from usr.plugins.dspy_rlm.helpers import config as config_module
from usr.plugins.dspy_rlm.helpers.v3.automatic_genesis import ensure_project_genesis


def _context_and_project(agent: object) -> tuple[str, str] | None:
    context = getattr(agent, "context", None)
    context_ref = getattr(context, "id", None)
    get_data = getattr(context, "get_data", None)
    if type(context_ref) is not str or not context_ref or not callable(get_data):
        return None
    if bool(get_data("dspy_rlm_offline_replay", recursive=False)):
        return None
    project_ref = get_data("project")
    if type(project_ref) is not str or not project_ref:
        return None
    return context_ref, project_ref


class DspyRlmProjectGenesis(Extension):
    """Enroll project chats before prompt composition; never block a chat."""

    async def execute(self, loop_data: Any = None, **kwargs: Any) -> None:
        try:
            agent = getattr(self, "agent", None)
            if agent is None:
                return
            cfg = config_module.load_config(agent)
            if (
                not isinstance(cfg, dict)
                or cfg.get("enabled") is not True
                or cfg.get("automatic_project_genesis") is not True
            ):
                return
            binding = _context_and_project(agent)
            if binding is None:
                return
            context_ref, project_ref = binding
            ensure_project_genesis(
                project_ref=project_ref,
                current_context_ref=context_ref,
            )
        except Exception:
            # Genesis enables improvement; it must never become availability
            # authority for the ordinary Agent Zero message loop.
            return
