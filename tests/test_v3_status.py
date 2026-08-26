"""Slice 1 acceptance tests for the pure, content-free public status path."""
from __future__ import annotations

import json
import multiprocessing.process
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from usr.plugins.dspy_rlm.api import status
from usr.plugins.dspy_rlm.helpers import paths
from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Repository


_CLI = Path(__file__).resolve().parents[1] / "scripts" / "a0_local_authority.py"
_ROOT_KEYS = {
    "schema",
    "plugin",
    "context_ref",
    "plugin_state",
    "ordinary_runtime_state",
    "activation_scope",
    "policy",
    "capabilities",
    "candidates",
    "canary",
    "monitor",
    "evidence",
    "fixtures",
    "migration",
    "recent_receipts",
}
_INERT_AXES = {
    "policy",
    "capabilities",
    "candidates",
    "canary",
    "monitor",
    "evidence",
    "fixtures",
    "migration",
    "recent_receipts",
}
_AXIS_KEYS = {"state", "observed_at", "freshness", "reason_codes"}


def _run_local_cli(*arguments: str | Path) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(_CLI), *(str(value) for value in arguments)],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _write_project_chat(chats: Path, context_ref: str, project_ref: str) -> None:
    chat_dir = chats / context_ref
    chat_dir.mkdir(parents=True)
    (chat_dir / "chat.json").write_text(
        json.dumps({"id": context_ref, "data": {"project": project_ref}}),
        encoding="utf-8",
    )


def _snapshot(root: Path) -> dict[str, tuple[str, int, int]]:
    if not root.exists():
        return {}
    snapshot: dict[str, tuple[str, int, int]] = {}
    for item in sorted((root, *root.rglob("*"))):
        stat = item.stat()
        kind = "directory" if item.is_dir() else "file"
        snapshot[str(item.relative_to(root.parent))] = (
            kind,
            stat.st_size,
            stat.st_mtime_ns,
        )
    return snapshot


def _assert_strict_public_shape(result: dict[str, Any]) -> None:
    assert set(result) == _ROOT_KEYS
    assert result["schema"] == "a0.public-status.v1"
    assert result["plugin"] == "dspy_rlm"
    assert result["ordinary_runtime_state"] == "unaffected"
    assert result["plugin_state"] in {
        "disabled",
        "uninitialized",
        "ready",
        "blocked",
    }
    for name in _INERT_AXES:
        assert set(result[name]) == _AXIS_KEYS
        assert isinstance(result[name]["reason_codes"], list)


def _install_live_context(
    monkeypatch: pytest.MonkeyPatch, *, enabled: bool, context_ref: str = "context-1"
) -> None:
    context = SimpleNamespace(id=context_ref, agent0=object())
    calls: list[str] = []

    def get(candidate: str) -> object | None:
        calls.append(candidate)
        return context if candidate == context_ref else None

    monkeypatch.setattr(status.AgentContext, "get", staticmethod(get))
    monkeypatch.setattr(
        status.config_module,
        "load_config",
        lambda *, agent: {"enabled": enabled},
    )
    monkeypatch.setattr(
        multiprocessing.process.BaseProcess,
        "start",
        lambda *_args, **_kwargs: pytest.fail("status attempted to start a process"),
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("status attempted to start a subprocess"),
    )
    monkeypatch.setattr(
        threading.Thread,
        "start",
        lambda *_args, **_kwargs: pytest.fail("status attempted to start a thread"),
    )
    monkeypatch.setattr(status, "_context_get_calls", calls, raising=False)


async def _read_twice() -> tuple[dict[str, Any], dict[str, Any]]:
    handler = status.Status(None, None)
    first = await handler.process({"context_id": "context-1"}, None)
    second = await handler.process({"context_id": "context-1"}, None)
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    return first, second


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("enabled", "expected_state"),
    ((False, "disabled"), (True, "uninitialized")),
)
async def test_missing_store_reads_are_repeatable_and_create_nothing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    enabled: bool,
    expected_state: str,
) -> None:
    store = tmp_path / "absent" / "dspy_rlm_v3.sqlite"
    monkeypatch.setattr(paths, "SAFE_STORE_FILE", store)
    _install_live_context(monkeypatch, enabled=enabled)

    before = _snapshot(tmp_path)
    first, second = await _read_twice()
    after = _snapshot(tmp_path)

    assert first == second
    assert before == after
    assert not store.parent.exists()
    assert first["plugin_state"] == expected_state
    assert first["activation_scope"] == {
        "state": "uninitialized",
        "observed_at": None,
        "freshness": "not_observed",
        "reason_codes": ["safe_store_missing"],
    }
    assert status._context_get_calls == ["context-1", "context-1"]
    _assert_strict_public_shape(first)


@pytest.mark.asyncio
async def test_corrupt_store_is_blocked_without_exception_or_content_reflection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = tmp_path / "state" / "dspy_rlm_v3.sqlite"
    store.parent.mkdir()
    secret = "TOP_SECRET_exception_/private/operator/path"
    store.write_bytes(secret.encode("utf-8"))
    monkeypatch.setattr(paths, "SAFE_STORE_FILE", store)
    _install_live_context(monkeypatch, enabled=True)

    before = _snapshot(tmp_path)
    first, second = await _read_twice()
    after = _snapshot(tmp_path)

    assert first == second
    assert before == after
    assert first["plugin_state"] == "blocked"
    assert first["activation_scope"] == {
        "state": "blocked",
        "observed_at": None,
        "freshness": "not_observed",
        "reason_codes": ["safe_store_unreadable"],
    }
    assert secret not in repr(first)
    assert str(store) not in repr(first)
    assert not Path(f"{store}-wal").exists()
    assert not Path(f"{store}-shm").exists()
    _assert_strict_public_shape(first)


def _create_ready_store(store: Path, *, context_ref: str = "context-1") -> None:
    store.parent.mkdir(parents=True)
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile:context-1:genesis",
        context_ref=context_ref,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="system-v1",
    )
    with V3Repository.create(store) as repository:
        with repository.transaction() as transaction:
            transaction.insert_record(guidance)
            transaction.insert_record(prompt)
            transaction.insert_record(profile)
            transaction.initialize_activation_scope(
                context_ref=context_ref,
                profile_id=profile.record_id,
                profile_digest=profile.content_digest,
            )


@pytest.mark.asyncio
async def test_ready_store_reads_only_safe_activation_summary_and_never_mutates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = tmp_path / "state" / "dspy_rlm_v3.sqlite"
    _create_ready_store(store)
    monkeypatch.setattr(paths, "SAFE_STORE_FILE", store)
    _install_live_context(monkeypatch, enabled=True)

    before = _snapshot(tmp_path)
    first, second = await _read_twice()
    after = _snapshot(tmp_path)

    assert first == second
    assert before == after
    assert first["plugin_state"] == "ready"
    activation = first["activation_scope"]
    assert set(activation) == _AXIS_KEYS | {
        "profile_ref",
        "scope_revision",
        "mode",
        "rollback_eligibility",
        "slots",
    }
    assert activation["state"] == "active"
    assert activation["freshness"] == "current"
    assert activation["profile_ref"] == "profile:context-1:genesis"
    assert activation["scope_revision"] == 0
    assert activation["mode"] == "normal"
    assert activation["rollback_eligibility"] == "not_evaluated"
    assert activation["slots"] == [
        {
            "slot_kind": "structured_guidance",
            "artifact_ref": "system:a0-self-improvement:null-guidance:v1",
            "state": "active",
        },
        {
            "slot_kind": "prompt_patch",
            "artifact_ref": "system:a0-self-improvement:null-prompt-patch:v1",
            "state": "active",
        },
    ]
    assert not Path(f"{store}-wal").exists()
    assert not Path(f"{store}-shm").exists()
    _assert_strict_public_shape(first)


@pytest.mark.asyncio
async def test_disabled_status_remains_inspectable_without_hiding_activation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = tmp_path / "state" / "dspy_rlm_v3.sqlite"
    _create_ready_store(store)
    monkeypatch.setattr(paths, "SAFE_STORE_FILE", store)
    _install_live_context(monkeypatch, enabled=False)

    before = _snapshot(tmp_path)
    first, second = await _read_twice()
    after = _snapshot(tmp_path)

    assert first == second
    assert before == after
    assert first["plugin_state"] == "disabled"
    assert first["activation_scope"]["state"] == "active"
    assert first["ordinary_runtime_state"] == "unaffected"
    _assert_strict_public_shape(first)


def test_local_readiness_inspection_distinguishes_store_from_context_genesis(
    tmp_path: Path,
) -> None:
    store = tmp_path / "state" / "dspy_rlm_v3.sqlite"
    manifest = tmp_path / "state" / "store-authority-manifest.json"
    _create_ready_store(store)

    command = [
        "readiness-inspect",
        "--store",
        str(store),
        "--manifest",
        str(manifest),
        "--context",
    ]
    ready = _run_local_cli(*command, "context-1")
    missing_context = _run_local_cli(*command, "context-2")

    assert ready["state"] == "ready"
    assert ready["store_authority"] == {
        "source": "pre_cutover",
        "manifest_revision": 0,
        "generation_ref": "pre_cutover",
    }
    assert ready["activation_scope"]["scope_revision"] == 0
    assert missing_context["state"] == "uninitialized"
    assert missing_context["activation_scope"]["reason_codes"] == [
        "activation_scope_missing"
    ]


def test_project_readiness_reports_only_missing_contexts_in_selected_project(
    tmp_path: Path,
) -> None:
    store = tmp_path / "state" / "dspy_rlm_v3.sqlite"
    manifest = tmp_path / "state" / "store-authority-manifest.json"
    chats = tmp_path / "chats"
    _create_ready_store(store)
    for context_ref, project_ref in (
        ("context-1", "project-1"),
        ("context-2", "project-1"),
        ("context-3", "project-2"),
    ):
        _write_project_chat(chats, context_ref, project_ref)

    result = _run_local_cli(
        "project-readiness-inspect",
        "--store",
        store,
        "--manifest",
        manifest,
        "--chats-dir",
        chats,
        "--project",
        "project-1",
    )

    assert result["state"] == "incomplete"
    assert result["context_count"] == 2
    assert result["ready_count"] == 1
    assert result["missing_context_refs"] == ["context-2"]


def test_project_genesis_initializes_every_context_in_only_the_named_project(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    authority = state / "authority"
    grants = authority / "project-grants"
    chats = tmp_path / "chats"
    state.mkdir()
    authority.mkdir(mode=0o700)
    grants.mkdir(mode=0o700)
    for context_ref, project_ref in (
        ("context-1", "project-1"),
        ("context-2", "project-1"),
        ("context-3", "project-2"),
    ):
        _write_project_chat(chats, context_ref, project_ref)

    secret = authority / "issuer-root.secret"
    profile = authority / "issuer-profile.json"
    opaque_key = authority / "opaque-reference.key"
    _run_local_cli(
        "issuer-bootstrap",
        "--secret",
        secret,
        "--profile",
        profile,
        "--issuer",
        "issuer-1",
        "--key-epoch",
        "1",
        "--authority-class",
        "operator_authority_grant",
        "--confirm",
        "BOOTSTRAP_LOCAL_AUTHORITY",
    )
    _run_local_cli(
        "opaque-key-bootstrap",
        "--output",
        opaque_key,
        "--key-epoch",
        "opaque-1",
        "--confirm",
        "BOOTSTRAP_OPAQUE_REFERENCE_KEY",
    )

    result = _run_local_cli(
        "project-genesis",
        "--store",
        state / "dspy_rlm_v3.sqlite",
        "--manifest",
        state / "store-authority-manifest.json",
        "--chats-dir",
        chats,
        "--project",
        "project-1",
        "--secret",
        secret,
        "--profile",
        profile,
        "--opaque-key",
        opaque_key,
        "--opaque-key-epoch",
        "opaque-1",
        "--grant-dir",
        grants,
        "--subject",
        "operator-1",
        "--idempotency-prefix",
        "project-genesis-1",
        "--session-nonce-prefix",
        "project-session-1",
        "--authority-expires-at",
        "2030-01-01T00:15:00Z",
        "--now",
        "2030-01-01T00:00:00Z",
        "--confirm",
        "BOOTSTRAP_PROJECT_GENESIS",
        "--create-store",
    )

    assert result["state"] == "ready"
    assert result["context_count"] == 2
    assert result["initialized_context_refs"] == ["context-1", "context-2"]
    assert result["already_ready_count"] == 0
    assert len(result["activation_receipt_refs"]) == 2
    assert len(tuple(grants.glob("grant_*.json"))) == 2
