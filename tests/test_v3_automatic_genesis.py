"""Focused acceptance checks for default-on, inert project Genesis."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from usr.plugins.dspy_rlm.extensions.python.message_loop_start._20_dspy_rlm_project_genesis import (
    DspyRlmProjectGenesis,
)
from usr.plugins.dspy_rlm.helpers import paths
from usr.plugins.dspy_rlm.helpers.v3.automatic_genesis import ensure_project_genesis
from usr.plugins.dspy_rlm.helpers.v3.runtime_composer import compose_runtime
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_reader


_SEAM = (
    "usr.plugins.dspy_rlm.extensions.python.message_loop_start."
    "_20_dspy_rlm_project_genesis"
)


def _chat(chats_dir: Path, context_ref: str, project_ref: str) -> None:
    directory = chats_dir / context_ref
    directory.mkdir(parents=True)
    (directory / "chat.json").write_text(
        json.dumps({"id": context_ref, "data": {"project": project_ref}}),
        encoding="utf-8",
    )


def test_project_enrollment_is_inert_grouped_and_idempotent(
    isolated_plugin_paths: Path,
) -> None:
    chats = isolated_plugin_paths / "chats"
    _chat(chats, "context-main", "project-one")
    _chat(chats, "context-parallel", "project-one")
    _chat(chats, "context-unrelated", "project-two")
    now = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)

    first = ensure_project_genesis(
        project_ref="project-one",
        current_context_ref="context-main",
        chats_dir=chats,
        now=now,
    )

    assert first.discovered_context_count == 2
    assert first.initialized_context_refs == ("context-main", "context-parallel")
    with open_runtime_reader(
        pre_cutover_path=paths.SAFE_STORE_FILE,
        manifest_path=paths.STORE_AUTHORITY_MANIFEST_FILE,
    ) as reader:
        for context_ref in first.initialized_context_refs:
            scope = reader.get_activation_scope(context_ref)
            assert scope is not None
            assert scope.scope_revision == 0
            assert scope.mode == "normal"
            original = ("core prompt", "exact trailing space ")
            composed = compose_runtime(
                reader,
                context_ref=context_ref,
                system_prompt=original,
                now=now,
            )
            assert composed.segments == original
            assert composed.reason_codes == ("null_profile_identity",)
        assert reader.get_activation_scope("context-unrelated") is None

    second = ensure_project_genesis(
        project_ref="project-one",
        current_context_ref="context-main",
        chats_dir=chats,
        now=now,
    )
    custody = paths.AUTHORITY_DIR / "automatic-project-genesis"

    assert second.initialized_context_refs == ()
    assert second.already_ready_count == 2
    assert len(tuple((custody / "grants").glob("*.json"))) == 2
    for private_file in (
        custody / "issuer-root.secret",
        custody / "issuer-profile.json",
        custody / "opaque-reference.key",
        custody / "coordinator.lock",
    ):
        assert stat.S_IMODE(private_file.stat().st_mode) == 0o600


@pytest.mark.asyncio
async def test_message_loop_start_obeys_gates_and_uses_exact_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, str]] = []
    monkeypatch.setattr(
        f"{_SEAM}.config_module.load_config",
        lambda _agent: {"enabled": True, "automatic_project_genesis": True},
    )
    monkeypatch.setattr(
        f"{_SEAM}.ensure_project_genesis",
        lambda **kwargs: calls.append(kwargs),
    )

    def get_data(key: str, **_kwargs: object) -> object:
        return {"project": "project-one", "dspy_rlm_offline_replay": False}.get(key)

    agent = SimpleNamespace(
        context=SimpleNamespace(id="context-main", get_data=get_data)
    )
    await DspyRlmProjectGenesis(agent=agent).execute()

    assert calls == [
        {"project_ref": "project-one", "current_context_ref": "context-main"}
    ]

    monkeypatch.setattr(
        f"{_SEAM}.config_module.load_config",
        lambda _agent: {"enabled": True, "automatic_project_genesis": False},
    )
    await DspyRlmProjectGenesis(agent=agent).execute()
    assert len(calls) == 1
