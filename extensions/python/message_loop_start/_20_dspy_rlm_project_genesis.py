"""Ensure inert v3 Genesis for the active Agent Zero project."""
from __future__ import annotations

from hashlib import sha256
import json
import time
from typing import Any

from helpers.extension import Extension

from usr.plugins.dspy_rlm.helpers import config as config_module
from usr.plugins.dspy_rlm.helpers import paths as paths_module
from usr.plugins.dspy_rlm.helpers import state as state_module
from usr.plugins.dspy_rlm.helpers.autopilot_transition_runner import (
    reconcile_candidates,
    resume_incomplete_transitions,
)
from usr.plugins.dspy_rlm.helpers.v3.automatic_genesis import ensure_project_genesis
from usr.plugins.dspy_rlm.helpers.v3.autopilot_control_plane import (
    AUTOPILOT_AUTHORITY_CONSENT_REVISION,
    provision_autopilot_control_plane,
)
from usr.plugins.dspy_rlm.helpers.v3.autopilot_publication import sync_legacy_candidates
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_repository


_RECONCILED_CONTEXTS: dict[tuple[str, str, str], float] = {}
_RECONCILIATION_FAILURES: dict[tuple[str, str, str], tuple[int, float]] = {}
_RECONCILIATION_TTL_SECONDS = 30.0
_RECONCILIATION_MAX_BACKOFF_SECONDS = 300.0


def _reconciliation_key(
    context_ref: str, project_ref: str, config: dict[str, Any]
) -> tuple[str, str, str]:
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":"), default=str)
    return context_ref, project_ref, sha256(encoded.encode()).hexdigest()


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


def _record_reconciliation_failure(
    key: tuple[str, str, str], reference: float,
) -> None:
    previous_attempt = _RECONCILIATION_FAILURES.get(key, (0, 0.0))[0]
    attempt = min(previous_attempt + 1, 16)
    base = min(
        _RECONCILIATION_MAX_BACKOFF_SECONDS,
        5.0 * (2 ** (attempt - 1)),
    )
    jitter_seed = int(sha256("\0".join(key).encode()).hexdigest()[:8], 16)
    jitter = base * 0.2 * (jitter_seed / 0xFFFFFFFF)
    _RECONCILIATION_FAILURES[key] = (attempt, reference + base + jitter)


class DspyRlmProjectGenesis(Extension):
    """Enroll project chats before prompt composition; never block a chat."""

    async def execute(self, loop_data: Any = None, **kwargs: Any) -> None:
        reconciliation_key: tuple[str, str, str] | None = None
        try:
            agent = getattr(self, "agent", None)
            if agent is None:
                return
            loaded = config_module.load_config(agent)
            cfg = config_module.normalize_config(
                loaded if isinstance(loaded, dict) else None
            )
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
            reconciliation_key = _reconciliation_key(context_ref, project_ref, cfg)
            reference = time.monotonic()
            for key, reconciled_at in tuple(_RECONCILED_CONTEXTS.items()):
                if reference - reconciled_at >= _RECONCILIATION_TTL_SECONDS:
                    _RECONCILED_CONTEXTS.pop(key, None)
            for key, (_attempt, retry_at) in tuple(_RECONCILIATION_FAILURES.items()):
                if reference >= retry_at + _RECONCILIATION_MAX_BACKOFF_SECONDS:
                    _RECONCILIATION_FAILURES.pop(key, None)
            if len(_RECONCILIATION_FAILURES) > 1024:
                for key, (_attempt, retry_at) in sorted(
                    _RECONCILIATION_FAILURES.items(), key=lambda item: item[1][1]
                )[: len(_RECONCILIATION_FAILURES) - 1024]:
                    _RECONCILIATION_FAILURES.pop(key, None)
            if len(_RECONCILED_CONTEXTS) > 1024:
                for key, _reconciled_at in sorted(
                    _RECONCILED_CONTEXTS.items(), key=lambda item: item[1]
                )[: len(_RECONCILED_CONTEXTS) - 1024]:
                    _RECONCILED_CONTEXTS.pop(key, None)
            last_reconciled = _RECONCILED_CONTEXTS.get(reconciliation_key)
            if (
                last_reconciled is not None
                and time.monotonic() - last_reconciled < _RECONCILIATION_TTL_SECONDS
            ):
                return
            failure = _RECONCILIATION_FAILURES.get(reconciliation_key)
            if failure is not None and reference < failure[1]:
                return
            resume_incomplete_transitions(context_ref=context_ref, config=cfg)
            genesis = ensure_project_genesis(
                project_ref=project_ref,
                current_context_ref=context_ref,
            )
            legacy_store = state_module._store_for_root().store
            fully_reconciled = True
            for discovered_context_ref in genesis.context_refs:
                try:
                    sync_legacy_candidates(
                        context_ref=discovered_context_ref,
                        legacy_store=legacy_store,
                        pre_cutover_path=paths_module.SAFE_STORE_FILE,
                        manifest_path=paths_module.STORE_AUTHORITY_MANIFEST_FILE,
                    )
                except Exception:
                    # One damaged historical candidate must not prevent
                    # another project chat from reconciling its valid work.
                    fully_reconciled = False
                    continue
            if (
                cfg.get("automation", {}).get("mode") == "autopilot"
                and cfg.get("automation", {}).get("authority_consent_revision")
                == AUTOPILOT_AUTHORITY_CONSENT_REVISION
            ):
                try:
                    with open_runtime_repository(
                        pre_cutover_path=paths_module.SAFE_STORE_FILE,
                        manifest_path=paths_module.STORE_AUTHORITY_MANIFEST_FILE,
                    ) as repository:
                        for discovered_context_ref in genesis.context_refs:
                            try:
                                provision_autopilot_control_plane(
                                    repository,
                                    context_ref=discovered_context_ref,
                                    config=cfg,
                                    authority_root=(
                                        paths_module.AUTHORITY_DIR
                                        / "autopilot-transition"
                                    ),
                                )
                                reconcile_candidates(
                                    context_ref=discovered_context_ref,
                                    config=cfg,
                                )
                            except Exception:
                                # Authority is independently scoped per chat.
                                # One damaged scope cannot block another scope
                                # or the ordinary message loop.
                                fully_reconciled = False
                                continue
                except Exception:
                    _record_reconciliation_failure(
                        reconciliation_key, time.monotonic()
                    )
                    return
            if fully_reconciled:
                _RECONCILED_CONTEXTS[reconciliation_key] = time.monotonic()
                _RECONCILIATION_FAILURES.pop(reconciliation_key, None)
            else:
                _record_reconciliation_failure(
                    reconciliation_key, time.monotonic()
                )
        except Exception:
            # Genesis enables improvement; it must never become availability
            # authority for the ordinary Agent Zero message loop.
            if reconciliation_key is not None:
                _record_reconciliation_failure(
                    reconciliation_key, time.monotonic()
                )
            return
