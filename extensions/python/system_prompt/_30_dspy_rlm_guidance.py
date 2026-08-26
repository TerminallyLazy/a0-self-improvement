"""Compose the active v3 profile at Agent Zero's system-prompt seam."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any

from helpers.extension import Extension

from usr.plugins.dspy_rlm.helpers import config as config_module
from usr.plugins.dspy_rlm.helpers import paths
from usr.plugins.dspy_rlm.helpers.v3 import runtime_composer
from usr.plugins.dspy_rlm.helpers.v3.canary_runtime import (
    CANARY_ASSIGNMENT_KEY_ENV,
    CANARY_SELECTION_LOOP_KEY,
    CanaryRuntimeSelection,
    exposure_identity,
    select_canary_runtime,
)
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_reader


def _assignment_secret() -> bytes | None:
    value = os.environ.get(CANARY_ASSIGNMENT_KEY_ENV)
    return value.encode("utf-8") if type(value) is str and value else None


def _canary_identity(
    *, context_ref: str, loop_data: object
) -> tuple[object, dict[str, Any]] | None:
    params = getattr(loop_data, "params_temporary", None)
    message_ref = getattr(getattr(loop_data, "user_message", None), "id", None)
    iteration = getattr(loop_data, "iteration", None)
    if type(params) is not dict or type(message_ref) is not str or type(iteration) is not int:
        return None
    return (
        exposure_identity(
            context_ref=context_ref,
            message_ref=message_ref,
            loop_iteration=iteration,
        ),
        params,
    )


class DspyRlmGuidance(Extension):
    """Apply only a validated v3 Activation Profile through a pure reader."""

    async def execute(
        self,
        system_prompt: list[str] = [],
        loop_data: Any = None,
        **kwargs: Any,
    ) -> None:
        if not self.agent or not isinstance(system_prompt, list):
            return

        # These gates precede every safe-store operation. Configuration is the
        # plugin-wide authority gate; a prompt without a live context is never
        # eligible for context-scoped activation.
        cfg = config_module.load_config(self.agent)
        if not isinstance(cfg, dict) or cfg.get("enabled") is not True:
            return
        context = getattr(self.agent, "context", None)
        context_id = getattr(context, "id", None)
        if type(context_id) is not str or not context_id:
            return

        try:
            canary_identity = _canary_identity(
                context_ref=context_id,
                loop_data=loop_data,
            )
            params = canary_identity[1] if canary_identity is not None else None
            if params is not None:
                params.pop(CANARY_SELECTION_LOOP_KEY, None)
            get_data = getattr(context, "get_data", None)
            offline_replay = (
                bool(get_data("dspy_rlm_offline_replay", recursive=False))
                if callable(get_data)
                else True
            )
            reference_time = datetime.now(timezone.utc)
            with open_runtime_reader(
                pre_cutover_path=paths.SAFE_STORE_FILE,
                manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
            ) as reader:
                selection: CanaryRuntimeSelection | None = None
                if canary_identity is not None and not offline_replay:
                    selection = select_canary_runtime(
                        reader,
                        identity=canary_identity[0],
                        assignment_secret=_assignment_secret(),
                        now=reference_time,
                    )
                result = runtime_composer.compose_runtime(
                    reader,
                    context_ref=context_id,
                    system_prompt=system_prompt,
                    objective_bucket=str(
                        kwargs.get("objective_bucket")
                        or runtime_composer.LEGACY_DEFAULT_OBJECTIVE_BUCKET
                    ),
                    now=reference_time,
                    profile_selection=(
                        runtime_composer.ProfileSelection(
                            selection.selected_profile_id,
                            selection.selected_profile_digest,
                            selection.scope_revision,
                        )
                        if selection is not None
                        else None
                    ),
                )
                if selection is not None and (
                    not result.applied or result.profile_id != selection.selected_profile_id
                ):
                    selection = None
                    result = runtime_composer.compose_runtime(
                        reader,
                        context_ref=context_id,
                        system_prompt=system_prompt,
                        objective_bucket=str(
                            kwargs.get("objective_bucket")
                            or runtime_composer.LEGACY_DEFAULT_OBJECTIVE_BUCKET
                        ),
                        now=reference_time,
                    )
        except Exception:
            # Missing, corrupt, incompatible, or unreadable authority cannot
            # alter Agent Zero's original prompt or initialize/repair storage.
            return

        if not result.applied:
            return
        segments = list(result.segments)
        if any(type(segment) is not str for segment in segments):
            return
        if selection is not None and params is not None:
            params[CANARY_SELECTION_LOOP_KEY] = selection
        system_prompt[:] = segments
