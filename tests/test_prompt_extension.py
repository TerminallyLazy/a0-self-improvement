"""Fail-closed tests for the unified v3 system-prompt seam."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from usr.plugins.dspy_rlm.extensions.python.system_prompt._30_dspy_rlm_guidance import (
    DspyRlmGuidance,
)
from usr.plugins.dspy_rlm.extensions.python.system_prompt._99_dspy_rlm_prompt_controller import (
    DspyRlmPromptController,
)
from usr.plugins.dspy_rlm.helpers import guidance, prompt_artifacts, state
from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Repository


_SEAM = "usr.plugins.dspy_rlm.extensions.python.system_prompt._30_dspy_rlm_guidance"


def _agent(context_id: str = "context-01") -> SimpleNamespace:
    return SimpleNamespace(context=SimpleNamespace(id=context_id))


def _snapshot(root: Path) -> dict[str, bytes | None]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): path.read_bytes() if path.is_file() else None
        for path in sorted(root.rglob("*"))
    }


def _poison_legacy_and_work(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("the v3 prompt seam invoked legacy state, capture, guidance, or work")

    monkeypatch.setattr(state, "load_context_state", forbidden)
    monkeypatch.setattr(state, "_store_for_root", forbidden)
    monkeypatch.setattr(prompt_artifacts, "capture_snapshot", forbidden)
    monkeypatch.setattr(prompt_artifacts, "active_artifact", forbidden)
    monkeypatch.setattr(prompt_artifacts, "apply_artifact", forbidden)
    monkeypatch.setattr(guidance, "select_active_guidance_artifact", forbidden)
    monkeypatch.setattr(guidance, "render_guidance_artifact", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)


def _configure(monkeypatch: pytest.MonkeyPatch, *, enabled: bool) -> None:
    monkeypatch.setattr(
        f"{_SEAM}.config_module.load_config",
        lambda _agent: {"enabled": enabled},
    )


def _create_null_genesis(path: Path, *, context_id: str = "context-01") -> None:
    path.parent.mkdir(parents=True)
    null_guidance = null_guidance_artifact()
    null_prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="activation-profile-01",
        context_ref=context_id,
        guidance_artifact=null_guidance,
        prompt_patch_artifact=null_prompt,
        key_epoch="epoch-01",
    )
    with V3Repository.create(path) as repository:
        with repository.transaction() as transaction:
            transaction.insert_record(null_guidance)
            transaction.insert_record(null_prompt)
            transaction.insert_record(profile)
            transaction.initialize_activation_scope(
                context_ref=context_id,
                profile_id=profile.record_id,
                profile_digest=profile.content_digest,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("enabled", "context_id"),
    [(False, "context-01"), (True, "")],
    ids=("disabled", "missing-context"),
)
async def test_inert_gates_stop_before_safe_store_access(
    monkeypatch: pytest.MonkeyPatch,
    isolated_plugin_paths: Path,
    enabled: bool,
    context_id: str,
) -> None:
    _configure(monkeypatch, enabled=enabled)
    _poison_legacy_and_work(monkeypatch)
    monkeypatch.setattr(f"{_SEAM}.open_runtime_reader", pytest.fail)
    prompt = ["core system prompt\n", "tool contract"]
    original = list(prompt)

    await DspyRlmGuidance(agent=_agent(context_id)).execute(system_prompt=prompt)

    assert prompt == original
    assert _snapshot(isolated_plugin_paths) == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "safe_store_state",
    ["missing", "corrupt", "uninitialized", "null-genesis"],
)
async def test_safe_store_reads_are_zero_write_and_prompt_byte_equivalent(
    monkeypatch: pytest.MonkeyPatch,
    isolated_plugin_paths: Path,
    safe_store_state: str,
) -> None:
    _configure(monkeypatch, enabled=True)
    _poison_legacy_and_work(monkeypatch)
    store = isolated_plugin_paths / "state" / "dspy_rlm_v3.sqlite"
    if safe_store_state == "corrupt":
        store.parent.mkdir(parents=True)
        store.write_bytes(b"not a sqlite authority")
    elif safe_store_state == "uninitialized":
        store.parent.mkdir(parents=True)
        with V3Repository.create(store):
            pass
    elif safe_store_state == "null-genesis":
        _create_null_genesis(store)

    before = _snapshot(isolated_plugin_paths)
    prompt = ["core\n\x00prompt", "exact trailing space "]
    original_bytes = "\x1f".join(prompt).encode()

    await DspyRlmGuidance(agent=_agent()).execute(system_prompt=prompt)

    assert "\x1f".join(prompt).encode() == original_bytes
    assert _snapshot(isolated_plugin_paths) == before
    assert not Path(f"{store}-wal").exists()
    assert not Path(f"{store}-shm").exists()


@pytest.mark.asyncio
async def test_late_controller_is_an_inert_compatibility_no_op(
    monkeypatch: pytest.MonkeyPatch,
    isolated_plugin_paths: Path,
) -> None:
    _poison_legacy_and_work(monkeypatch)
    prompt = ["core"]
    before = _snapshot(isolated_plugin_paths)

    await DspyRlmPromptController(agent=_agent()).execute(system_prompt=prompt)

    assert prompt == ["core"]
    assert _snapshot(isolated_plugin_paths) == before == {}
