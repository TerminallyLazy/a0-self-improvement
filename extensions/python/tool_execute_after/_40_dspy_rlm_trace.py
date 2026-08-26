"""Persist one content-free v3 fact after a certified tool response returns."""
from __future__ import annotations

from typing import Any

from helpers.extension import Extension
from helpers.tool import Response

from usr.plugins.dspy_rlm.helpers import config as config_module
from usr.plugins.dspy_rlm.helpers import paths
from usr.plugins.dspy_rlm.helpers.v3.observation import (
    RuntimeObservationRequest,
    record_runtime_observation,
)
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_repository


def _log_ref(value: object) -> str | None:
    ref = getattr(value, "id", None)
    return ref if type(ref) is str else None


def _occurrence_ref(loop_data: object, *, terminal: bool) -> str | None:
    current_tool = getattr(loop_data, "current_tool", None)
    ref = _log_ref(getattr(current_tool, "log", None))
    if ref is not None:
        return ref
    params = getattr(loop_data, "params_temporary", None)
    if terminal and type(params) is dict:
        return _log_ref(params.get("log_item_response"))
    return None


def _ordinary_context(agent: object) -> str | None:
    context = getattr(agent, "context", None)
    get_data = getattr(context, "get_data", None)
    context_ref = getattr(context, "id", None)
    if context is None or not callable(get_data) or type(context_ref) is not str:
        return None
    if bool(get_data("dspy_rlm_offline_replay", recursive=False)):
        return None
    return context_ref


class DspyRlmToolTrace(Extension):
    """Retained name; tool names, arguments, and result bodies remain transient."""

    async def execute(self, response: Any = None, **kwargs: Any) -> None:
        try:
            agent = getattr(self, "agent", None)
            context_ref = _ordinary_context(agent)
            if context_ref is None or type(response) is not Response:
                return
            cfg = config_module.load_config(agent)
            if not isinstance(cfg, dict) or cfg.get("enabled") is not True:
                return
            loop_data = getattr(agent, "loop_data", None)
            iteration = getattr(loop_data, "iteration", None)
            terminal = response.break_loop
            if type(iteration) is not int or iteration < -1 or type(terminal) is not bool:
                return
            occurrence_ref = _occurrence_ref(loop_data, terminal=terminal)
            if occurrence_ref is None:
                return
            request = RuntimeObservationRequest(
                context_ref=context_ref,
                occurrence_ref=occurrence_ref,
                observation_kind="tool_execute_after",
                outcome_code=(
                    "tool_returned_terminal" if terminal else "tool_returned_continuing"
                ),
                loop_iteration=iteration,
            )
            with open_runtime_repository(
                pre_cutover_path=paths.SAFE_STORE_FILE,
                manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
            ) as repository:
                record_runtime_observation(repository, request)
        except Exception:
            # Observation must never interfere with tool continuation or retain
            # tool/provider/error content through a diagnostic fallback.
            return
