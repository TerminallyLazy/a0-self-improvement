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
    assert first.context_refs == ("context-main", "context-parallel")
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
    from usr.plugins.dspy_rlm.extensions.python.message_loop_start import (
        _20_dspy_rlm_project_genesis as extension_module,
    )

    extension_module._RECONCILED_CONTEXTS.clear()
    extension_module._RECONCILIATION_FAILURES.clear()
    calls: list[dict[str, str]] = []
    sync_calls: list[dict[str, object]] = []
    provision_calls: list[dict[str, object]] = []
    reconcile_calls: list[dict[str, object]] = []
    legacy_store = object()
    repository = object()
    monkeypatch.setattr(
        f"{_SEAM}.config_module.load_config",
        lambda _agent: {
            "enabled": True,
            "automatic_project_genesis": True,
            "automation": {"mode": "autopilot", "authority_consent_revision": 1},
        },
    )
    monkeypatch.setattr(
        f"{_SEAM}.ensure_project_genesis",
        lambda **kwargs: (
            calls.append(kwargs)
            or SimpleNamespace(context_refs=("context-main", "context-parallel"))
        ),
    )
    monkeypatch.setattr(
        f"{_SEAM}.state_module._store_for_root",
        lambda: SimpleNamespace(store=legacy_store),
    )
    monkeypatch.setattr(
        f"{_SEAM}.sync_legacy_candidates",
        lambda **kwargs: sync_calls.append(kwargs),
    )
    class RepositoryContext:
        def __enter__(self):
            return repository

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(
        f"{_SEAM}.open_runtime_repository", lambda **_kwargs: RepositoryContext()
    )
    monkeypatch.setattr(
        f"{_SEAM}.provision_autopilot_control_plane",
        lambda repo, **kwargs: provision_calls.append(
            {"repository": repo, **kwargs}
        ),
    )
    monkeypatch.setattr(
        f"{_SEAM}.reconcile_candidates",
        lambda **kwargs: reconcile_calls.append(kwargs),
    )
    monkeypatch.setattr(
        f"{_SEAM}.resume_incomplete_transitions", lambda **_kwargs: None
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
    assert [item["context_ref"] for item in sync_calls] == [
        "context-main",
        "context-parallel",
    ]
    assert all(item["legacy_store"] is legacy_store for item in sync_calls)
    assert [item["context_ref"] for item in provision_calls] == [
        "context-main",
        "context-parallel",
    ]
    assert all(item["repository"] is repository for item in provision_calls)
    assert all(
        item["authority_root"] == paths.AUTHORITY_DIR / "autopilot-transition"
        for item in provision_calls
    )
    assert [item["context_ref"] for item in reconcile_calls] == [
        "context-main",
        "context-parallel",
    ]

    monkeypatch.setattr(
        f"{_SEAM}.config_module.load_config",
        lambda _agent: {"enabled": True, "automatic_project_genesis": False},
    )
    await DspyRlmProjectGenesis(agent=agent).execute()
    assert len(calls) == 1
    assert len(sync_calls) == 2
    assert len(provision_calls) == 2
    assert len(reconcile_calls) == 2


@pytest.mark.asyncio
async def test_reconciliation_retries_failures_and_success_cache_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from usr.plugins.dspy_rlm.extensions.python.message_loop_start import (
        _20_dspy_rlm_project_genesis as extension_module,
    )

    extension_module._RECONCILED_CONTEXTS.clear()
    extension_module._RECONCILIATION_FAILURES.clear()
    now = [100.0]
    sync_calls = []
    monkeypatch.setattr(extension_module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        extension_module.config_module,
        "load_config",
        lambda _agent: {
            "enabled": True,
            "automatic_project_genesis": True,
            "automation": {"mode": "autopilot", "authority_consent_revision": 1},
        },
    )
    monkeypatch.setattr(
        extension_module,
        "ensure_project_genesis",
        lambda **_kwargs: SimpleNamespace(context_refs=("context-main",)),
    )
    monkeypatch.setattr(
        extension_module.state_module,
        "_store_for_root",
        lambda: SimpleNamespace(store=object()),
    )

    def sync(**kwargs):
        sync_calls.append(kwargs)
        if len(sync_calls) == 1:
            raise RuntimeError("transient reconciliation failure")

    monkeypatch.setattr(extension_module, "sync_legacy_candidates", sync)
    monkeypatch.setattr(
        extension_module, "resume_incomplete_transitions", lambda **_kwargs: None
    )
    monkeypatch.setattr(
        extension_module, "provision_autopilot_control_plane", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(extension_module, "reconcile_candidates", lambda **_kwargs: None)

    class RepositoryContext:
        def __enter__(self):
            return object()

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(
        extension_module, "open_runtime_repository", lambda **_kwargs: RepositoryContext()
    )
    agent = SimpleNamespace(
        context=SimpleNamespace(
            id="context-main",
            get_data=lambda key, **_kwargs: {
                "project": "project-one", "dspy_rlm_offline_replay": False,
            }.get(key),
        )
    )
    hook = DspyRlmProjectGenesis(agent=agent)
    await hook.execute()
    await hook.execute()
    await hook.execute()
    assert len(sync_calls) == 1
    _, retry_at = next(iter(extension_module._RECONCILIATION_FAILURES.values()))
    now[0] = retry_at
    await hook.execute()
    assert len(sync_calls) == 2
    await hook.execute()
    assert len(sync_calls) == 2
    now[0] += 31
    await hook.execute()
    assert len(sync_calls) == 3


@pytest.mark.asyncio
async def test_reconciliation_cache_retries_provision_and_candidate_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from usr.plugins.dspy_rlm.extensions.python.message_loop_start import (
        _20_dspy_rlm_project_genesis as extension_module,
    )

    now = [100.0]
    monkeypatch.setattr(extension_module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        extension_module.config_module, "load_config",
        lambda _agent: {
            "enabled": True, "automatic_project_genesis": True,
            "automation": {"mode": "autopilot", "authority_consent_revision": 1},
        },
    )
    monkeypatch.setattr(
        extension_module, "ensure_project_genesis",
        lambda **_kwargs: SimpleNamespace(context_refs=("context-main",)),
    )
    monkeypatch.setattr(
        extension_module.state_module, "_store_for_root",
        lambda: SimpleNamespace(store=object()),
    )
    monkeypatch.setattr(extension_module, "sync_legacy_candidates", lambda **_kwargs: None)
    monkeypatch.setattr(extension_module, "resume_incomplete_transitions", lambda **_kwargs: None)

    class RepositoryContext:
        def __enter__(self):
            return object()

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(
        extension_module, "open_runtime_repository", lambda **_kwargs: RepositoryContext()
    )
    agent = SimpleNamespace(
        context=SimpleNamespace(
            id="context-main",
            get_data=lambda key, **_kwargs: {
                "project": "project-one", "dspy_rlm_offline_replay": False,
            }.get(key),
        )
    )
    for failing_seam in ("provision", "reconcile"):
        extension_module._RECONCILED_CONTEXTS.clear()
        extension_module._RECONCILIATION_FAILURES.clear()
        calls = {"provision": 0, "reconcile": 0}

        def provision(*_args, **_kwargs):
            calls["provision"] += 1
            if failing_seam == "provision" and calls["provision"] == 1:
                raise RuntimeError("transient provision failure")

        def reconcile(**_kwargs):
            calls["reconcile"] += 1
            if failing_seam == "reconcile" and calls["reconcile"] == 1:
                raise RuntimeError("transient candidate failure")

        monkeypatch.setattr(extension_module, "provision_autopilot_control_plane", provision)
        monkeypatch.setattr(extension_module, "reconcile_candidates", reconcile)
        hook = DspyRlmProjectGenesis(agent=agent)
        await hook.execute()
        await hook.execute()
        assert calls[failing_seam] == 1
        _, retry_at = next(iter(extension_module._RECONCILIATION_FAILURES.values()))
        now[0] = retry_at
        await hook.execute()
        assert calls[failing_seam] == 2


@pytest.mark.asyncio
async def test_transition_recovery_failure_is_backed_off_between_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from usr.plugins.dspy_rlm.extensions.python.message_loop_start import (
        _20_dspy_rlm_project_genesis as extension_module,
    )

    extension_module._RECONCILED_CONTEXTS.clear()
    extension_module._RECONCILIATION_FAILURES.clear()
    now = [100.0]
    recovery_calls: list[str] = []
    monkeypatch.setattr(extension_module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        extension_module.config_module,
        "load_config",
        lambda _agent: {
            "enabled": True,
            "automatic_project_genesis": True,
            "automation": {"mode": "autopilot", "authority_consent_revision": 1},
        },
    )

    def fail_recovery(**kwargs: object) -> None:
        recovery_calls.append(str(kwargs["context_ref"]))
        raise RuntimeError("persistent transition-store failure")

    monkeypatch.setattr(extension_module, "resume_incomplete_transitions", fail_recovery)
    agent = SimpleNamespace(
        context=SimpleNamespace(
            id="context-main",
            get_data=lambda key, **_kwargs: {
                "project": "project-one",
                "dspy_rlm_offline_replay": False,
            }.get(key),
        )
    )
    hook = DspyRlmProjectGenesis(agent=agent)

    await hook.execute()
    await hook.execute()
    await hook.execute()
    assert recovery_calls == ["context-main"]

    attempt, retry_at = next(iter(extension_module._RECONCILIATION_FAILURES.values()))
    assert attempt == 1
    now[0] = retry_at
    await hook.execute()
    assert recovery_calls == ["context-main", "context-main"]
    assert next(iter(extension_module._RECONCILIATION_FAILURES.values()))[0] == 2
