"""Persist one content-free v3 fact at Agent Zero's message-loop-end seam."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any

from helpers.extension import Extension

from usr.plugins.dspy_rlm.helpers import config as config_module
from usr.plugins.dspy_rlm.helpers import autopilot
from usr.plugins.dspy_rlm.helpers import paths
from usr.plugins.dspy_rlm.helpers.autopilot_transition_runner import (
    ARTIFACT_LOOP_KEY as AUTOPILOT_ARTIFACT_LOOP_KEY,
    FRAMEWORK_HARD_FAILURE_KEY,
    FRAMEWORK_OUTCOME_KEY,
    SELECTION_LOOP_KEY as AUTOPILOT_SELECTION_LOOP_KEY,
    TERMINAL_OUTCOME_KEY,
    TransitionSelection,
    record_outcome,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_runtime import (
    CANARY_ASSIGNMENT_KEY_ENV,
    CANARY_SELECTION_LOOP_KEY,
    CanaryRuntimeSelection,
    commit_canary_runtime_observation,
    exposure_identity,
)
from usr.plugins.dspy_rlm.helpers.v3.observation import (
    RuntimeObservationRequest,
    record_runtime_observation,
)
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_repository


def _log_ref(value: object) -> str | None:
    ref = getattr(value, "id", None)
    return ref if type(ref) is str else None


def _assignment_secret() -> bytes | None:
    value = os.environ.get(CANARY_ASSIGNMENT_KEY_ENV)
    return value.encode("utf-8") if type(value) is str and value else None


def _ordinary_context(agent: object) -> tuple[object, str] | None:
    context = getattr(agent, "context", None)
    get_data = getattr(context, "get_data", None)
    context_ref = getattr(context, "id", None)
    if context is None or not callable(get_data) or type(context_ref) is not str:
        return None
    if bool(get_data("dspy_rlm_offline_replay", recursive=False)):
        return None
    return context, context_ref


class DspyRlmOptimizationScheduler(Extension):
    """Record safe facts and schedule operator-selected candidate generation."""

    async def execute(self, loop_data: Any = None, **kwargs: Any) -> None:
        try:
            agent = getattr(self, "agent", None)
            ordinary = _ordinary_context(agent)
            if ordinary is None:
                return
            _, context_ref = ordinary
            cfg = config_module.load_config(agent)
            if not isinstance(cfg, dict) or cfg.get("enabled") is not True:
                return
            iteration = getattr(loop_data, "iteration", None)
            params = getattr(loop_data, "params_temporary", None)
            persistent = getattr(loop_data, "params_persistent", None)
            if type(iteration) is not int or iteration < 0 or type(params) is not dict:
                return
            occurrence_ref = _log_ref(params.get("log_item_generating"))
            if occurrence_ref is None:
                return
            request = RuntimeObservationRequest(
                context_ref=context_ref,
                occurrence_ref=occurrence_ref,
                observation_kind="message_loop_end",
                outcome_code="message_loop_end_observed",
                loop_iteration=iteration,
            )
            with open_runtime_repository(
                pre_cutover_path=paths.SAFE_STORE_FILE,
                manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
            ) as repository:
                recorded = False
                selection = params.get(CANARY_SELECTION_LOOP_KEY)
                secret = _assignment_secret()
                if type(selection) is CanaryRuntimeSelection and secret is not None:
                    message_ref = getattr(getattr(loop_data, "user_message", None), "id", None)
                    identity = (
                        exposure_identity(
                            context_ref=context_ref,
                            message_ref=message_ref,
                            loop_iteration=iteration,
                        )
                        if type(message_ref) is str
                        else None
                    )
                    if (
                        identity is not None
                        and identity.exposure_unit_ref == selection.exposure_unit_ref
                        and identity.envelope_ref == selection.envelope_ref
                    ):
                        try:
                            commit_canary_runtime_observation(
                                repository,
                                selection=selection,
                                outcome_request=request,
                                assignment_secret=secret,
                                now=datetime.now(timezone.utc),
                            )
                            recorded = True
                        except Exception:
                            pass
                if not recorded:
                    record_runtime_observation(repository, request)
            transition = (
                persistent.get(AUTOPILOT_SELECTION_LOOP_KEY)
                if type(persistent) is dict
                else None
            )
            terminal_observed = (
                type(persistent) is dict
                and persistent.get(TERMINAL_OUTCOME_KEY) is True
            )
            if terminal_observed and type(transition) is TransitionSelection:
                record_outcome(
                    transition,
                    success=persistent.get(FRAMEWORK_OUTCOME_KEY),
                    config=cfg,
                    hard_failure=persistent.get(FRAMEWORK_HARD_FAILURE_KEY) is True,
                )
                for key in (
                    AUTOPILOT_SELECTION_LOOP_KEY,
                    AUTOPILOT_ARTIFACT_LOOP_KEY,
                    FRAMEWORK_OUTCOME_KEY,
                    FRAMEWORK_HARD_FAILURE_KEY,
                    TERMINAL_OUTCOME_KEY,
                ):
                    persistent.pop(key, None)
            message_ref = getattr(getattr(loop_data, "user_message", None), "id", None)
            if type(message_ref) is str and message_ref:
                autopilot.observe_loop_and_schedule(
                    agent=agent,
                    context_ref=context_ref,
                    message_ref=message_ref,
                    loop_iteration=iteration,
                    config=cfg,
                )
        except Exception:
            # Observation is optional to ordinary Agent Zero behavior. Missing,
            # stale, corrupt, or unsupported authority must remain inert and no
            # content or exception detail may enter another sink here.
            return
