"""Small process supervisor for plugin-owned local optimization workers."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from contextlib import contextmanager
import fcntl
from pathlib import Path
from typing import Any, Iterator, Mapping

from usr.plugins.dspy_rlm.helpers import dependencies


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[2]
REGISTRY = PLUGIN_ROOT / "state" / "worker-processes.json"
WORKER_LOG = PLUGIN_ROOT / "state" / "workers.log"
REGISTRY_LOCK = PLUGIN_ROOT / "state" / "worker-processes.lock"


@contextmanager
def _registry_lock() -> Iterator[None]:
    REGISTRY_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with REGISTRY_LOCK.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _read_registry() -> list[dict[str, Any]]:
    try:
        value = json.loads(REGISTRY.read_text(encoding="utf-8"))
        return [dict(item) for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []
    except (OSError, ValueError, TypeError):
        return []


def _write_registry(rows: list[dict[str, Any]]) -> None:
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    temporary = REGISTRY.with_suffix(".tmp")
    temporary.write_text(json.dumps(rows, sort_keys=True), encoding="utf-8")
    os.replace(temporary, REGISTRY)


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _desired(cfg: Mapping[str, Any]) -> int:
    optimization = cfg.get("optimization") if isinstance(cfg.get("optimization"), Mapping) else {}
    scheduler = cfg.get("scheduler") if isinstance(cfg.get("scheduler"), Mapping) else {}
    if not bool(cfg.get("enabled", False)) or not bool(optimization.get("enabled", False)):
        return 0
    mode = str(scheduler.get("mode") or "single").lower()
    return 1 if mode == "single" else max(1, min(64, int(scheduler.get("max_workers", 1) or 1)))


def _unregister(rows: list[dict[str, Any]]) -> None:
    worker_ids = [str(row.get("worker_id") or "") for row in rows]
    if not any(worker_ids):
        return
    from usr.plugins.dspy_rlm.helpers.queue import LocalMultiprocessQueue
    LocalMultiprocessQueue(PLUGIN_ROOT).remove_workers(worker_ids)


def reconcile(cfg: Mapping[str, Any]) -> dict[str, Any]:
    """Match live worker processes to effective config without blocking on jobs."""
    with _registry_lock():
        desired = _desired(cfg)
        diagnostics = dependencies.dependency_diagnostics()
        if desired and not diagnostics["ready"]:
            return {"desired": desired, "running": 0, "started": 0, "stopped": 0, "reason": "worker_environment_not_ready"}

        rows = [row for row in _read_registry() if _alive(int(row.get("pid", 0) or 0))]
        stopped = 0
        removed: list[dict[str, Any]] = []
        while len(rows) > desired:
            row = rows.pop()
            removed.append(row)
            try:
                os.kill(int(row["pid"]), signal.SIGTERM)
                stopped += 1
            except OSError:
                pass
        _unregister(removed)

        started = 0
        if len(rows) < desired:
            REGISTRY.parent.mkdir(parents=True, exist_ok=True)
            with WORKER_LOG.open("a", encoding="utf-8") as output:
                while len(rows) < desired:
                    worker_id = f"managed-{os.getpid()}-{int(time.time() * 1000)}-{len(rows) + 1}"
                    process = subprocess.Popen(
                        [str(dependencies.WORKER_PYTHON), "-m", "usr.plugins.dspy_rlm.worker", "--serve", "--worker-id", worker_id],
                        cwd=str(REPOSITORY_ROOT), stdout=output, stderr=subprocess.STDOUT,
                        start_new_session=True, close_fds=True,
                    )
                    rows.append({"pid": process.pid, "worker_id": worker_id, "started_at": time.time()})
                    started += 1
        _write_registry(rows)
        return {"desired": desired, "running": len(rows), "started": started, "stopped": stopped, "reason": "ready"}


def stop_all() -> dict[str, int]:
    with _registry_lock():
        rows = _read_registry()
        stopped = 0
        for row in rows:
            try:
                os.kill(int(row.get("pid", 0) or 0), signal.SIGTERM)
                stopped += 1
            except OSError:
                pass
        _unregister(rows)
        _write_registry([])
        return {"stopped": stopped}


def snapshot(cfg: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Observe the managed pool without starting or stopping processes."""
    rows = [row for row in _read_registry() if _alive(int(row.get("pid", 0) or 0))]
    desired = _desired(cfg or {}) if cfg is not None else len(rows)
    diagnostics = dependencies.dependency_diagnostics()
    reason = "ready" if diagnostics["ready"] else "worker_environment_not_ready"
    return {
        "desired": desired,
        "running": len(rows),
        "reason": reason,
        "managed_workers": len(rows),
        "worker_ids": [str(row.get("worker_id") or "") for row in rows],
    }
