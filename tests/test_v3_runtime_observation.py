from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from helpers.tool import Response
from usr.plugins.dspy_rlm.extensions.python.message_loop_end import (
    _90_dspy_rlm_optimize as loop_hook_module,
)
from usr.plugins.dspy_rlm.extensions.python.tool_execute_after import (
    _40_dspy_rlm_trace as tool_hook_module,
)
from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.observation import (
    OBSERVATION_REGISTRY,
    RuntimeObservationRequest,
    record_runtime_observation,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdentityCollision,
    V3Reader,
    V3Repository,
)


def _seed(path: Path, *, context_ref: str = "context-01") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="activation-profile-01",
        context_ref=context_ref,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="epoch-01",
    )
    with V3Repository.create(path, registry=OBSERVATION_REGISTRY) as repository:
        with repository.transaction() as transaction:
            transaction.insert_record(guidance)
            transaction.insert_record(prompt)
            transaction.insert_record(profile)
            transaction.initialize_activation_scope(
                context_ref=context_ref,
                profile_id=profile.record_id,
                profile_digest=profile.content_digest,
            )


def _opener(path: Path):
    def open_existing(**_kwargs: Any) -> V3Repository:
        return V3Repository.open(path, registry=OBSERVATION_REGISTRY)

    return open_existing


def _context(context_ref: str = "context-01", *, replay: bool = False) -> Any:
    return SimpleNamespace(
        id=context_ref,
        get_data=lambda key, recursive=False: replay
        if key == "dspy_rlm_offline_replay"
        else None,
    )


def test_observation_is_atomic_restart_idempotent_and_conflict_closed(
    tmp_path: Path,
) -> None:
    store = tmp_path / "safe.sqlite3"
    _seed(store)
    request = RuntimeObservationRequest(
        context_ref="context-01",
        occurrence_ref="tool-log-01",
        observation_kind="tool_execute_after",
        outcome_code="tool_returned_continuing",
        loop_iteration=2,
    )

    with V3Repository.open(store, registry=OBSERVATION_REGISTRY) as repository:
        first = record_runtime_observation(repository, request)
    with V3Repository.open(store, registry=OBSERVATION_REGISTRY) as repository:
        replay = record_runtime_observation(repository, request)
        assert first is not None and replay is not None
        assert first.replayed is False and replay.replayed is True
        assert replay.record == first.record
    with V3Reader.open(store, registry=OBSERVATION_REGISTRY) as reader:
        assert reader.count_domain_events_for_context("context-01") == 1
    with V3Repository.open(store, registry=OBSERVATION_REGISTRY) as repository:
        with pytest.raises(IdentityCollision):
            record_runtime_observation(
                repository,
                RuntimeObservationRequest(
                    context_ref="context-01",
                    occurrence_ref="tool-log-01",
                    observation_kind="tool_execute_after",
                    outcome_code="tool_returned_terminal",
                    loop_iteration=2,
                ),
            )
    with V3Reader.open(store, registry=OBSERVATION_REGISTRY) as reader:
        assert reader.count_domain_events_for_context("context-01") == 1


@pytest.mark.asyncio
async def test_hooks_persist_only_certified_content_free_facts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = tmp_path / "safe.sqlite3"
    _seed(store)
    monkeypatch.setattr(loop_hook_module.config_module, "load_config", lambda _agent: {"enabled": True})
    monkeypatch.setattr(loop_hook_module, "open_runtime_repository", _opener(store))
    monkeypatch.setattr(tool_hook_module, "open_runtime_repository", _opener(store))
    tool_log = SimpleNamespace(id="tool-log-02")
    loop_data = SimpleNamespace(
        iteration=3,
        current_tool=SimpleNamespace(log=tool_log),
        params_temporary={"log_item_generating": SimpleNamespace(id="model-log-02")},
    )
    agent = SimpleNamespace(context=_context(), loop_data=loop_data)
    response = Response(
        message="RAW_RESULT_SECRET_7f3b",
        break_loop=False,
        additional={"provider_id": "RAW_PROVIDER_SECRET_7f3b"},
    )

    tool_hook = tool_hook_module.DspyRlmToolTrace(agent=agent)
    loop_hook = loop_hook_module.DspyRlmOptimizationScheduler(agent=agent)
    for _ in range(2):
        await tool_hook.execute(
            response=response,
            tool_name="RAW_TOOL_SECRET_7f3b",
            tool_args={"path": "/RAW/PATH/SECRET_7f3b"},
        )
        await loop_hook.execute(
            loop_data=loop_data,
            raw_prompt="RAW_PROMPT_SECRET_7f3b",
            error="RAW_ERROR_SECRET_7f3b",
        )
    loop_data.current_tool = SimpleNamespace()
    loop_data.params_temporary["log_item_response"] = SimpleNamespace(
        id="response-log-02"
    )
    terminal = Response(message="RAW_TERMINAL_SECRET_7f3b", break_loop=True)
    for _ in range(2):
        await tool_hook.execute(response=terminal, tool_name="response")

    with V3Reader.open(store, registry=OBSERVATION_REGISTRY) as reader:
        records = [
            item.record
            for item in reader.list_records_for_context("context-01", maximum=8)
            if item.record.record_kind == "runtime_observation_fact"
        ]
        assert len(records) == 3
        assert {record.payload["outcome_code"] for record in records} == {
            "message_loop_end_observed",
            "tool_returned_continuing",
            "tool_returned_terminal",
        }
        assert all(record.payload["promotion_authority"] == "none" for record in records)
        assert all(record.payload["objective_bucket_state"] == "unbound" for record in records)
        assert reader.count_domain_events_for_context("context-01") == 3
    durable = store.read_bytes()
    for forbidden in (
        b"RAW_RESULT_SECRET_7f3b",
        b"RAW_PROVIDER_SECRET_7f3b",
        b"RAW_TOOL_SECRET_7f3b",
        b"RAW/PATH/SECRET_7f3b",
        b"RAW_PROMPT_SECRET_7f3b",
        b"RAW_ERROR_SECRET_7f3b",
        b"RAW_TERMINAL_SECRET_7f3b",
    ):
        assert forbidden not in durable


@pytest.mark.asyncio
async def test_disabled_replay_or_missing_hook_identity_is_inert_before_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(**_kwargs: Any) -> Any:
        pytest.fail("inert observation attempted to open authority")

    monkeypatch.setattr(loop_hook_module, "open_runtime_repository", forbidden)
    monkeypatch.setattr(tool_hook_module, "open_runtime_repository", forbidden)
    ordinary_agent = SimpleNamespace(context=_context(), loop_data=SimpleNamespace())
    monkeypatch.setattr(loop_hook_module.config_module, "load_config", lambda _agent: {"enabled": False})
    await loop_hook_module.DspyRlmOptimizationScheduler(agent=ordinary_agent).execute(
        loop_data=SimpleNamespace(
            iteration=0,
            params_temporary={"log_item_generating": SimpleNamespace(id="model-log-03")},
        )
    )

    replay_agent = SimpleNamespace(
        context=_context(replay=True),
        loop_data=SimpleNamespace(
            iteration=0,
            current_tool=SimpleNamespace(log=SimpleNamespace(id="tool-log-03")),
            params_temporary={},
        ),
    )
    monkeypatch.setattr(loop_hook_module.config_module, "load_config", lambda _agent: {"enabled": True})
    await tool_hook_module.DspyRlmToolTrace(agent=replay_agent).execute(
        response=Response(message="ignored", break_loop=False)
    )
    await loop_hook_module.DspyRlmOptimizationScheduler(agent=ordinary_agent).execute(
        loop_data=SimpleNamespace(iteration=0, params_temporary={})
    )
