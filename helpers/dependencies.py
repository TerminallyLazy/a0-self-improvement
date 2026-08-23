"""Install and diagnose the isolated DSPy RLM/GEPA worker environment."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = PLUGIN_ROOT / "requirements.txt"
LOCK_MANIFEST = PLUGIN_ROOT / "requirements-gepa.lock"
STATE_DIR = PLUGIN_ROOT / "state"


def _worker_venv_path() -> Path:
    configured = str(os.environ.get("DSPY_RLM_WORKER_VENV") or "").strip()
    if configured:
        return Path(configured).expanduser()
    if Path("/.dockerenv").exists():
        return Path("/opt/dspy-rlm-worker-venv")
    return STATE_DIR / "worker-venv"


WORKER_VENV = _worker_venv_path()
WORKER_PYTHON = WORKER_VENV / "bin" / "python"
WORKER_SITE_PACKAGES = (
    WORKER_VENV / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
)
FRAMEWORK_BRIDGE = WORKER_SITE_PACKAGES / "agent_zero_framework.pth"
INSTALLER_LOCK = STATE_DIR / "worker-env-install.lock"
INSTALL_LOG = STATE_DIR / "worker-env-install.log"
INSTALL_MARKER = STATE_DIR / "worker-env.json"
EXPECTED = {"dspy": "3.3.1", "gepa": "0.1.4", "dspy-cli": "0.1.13"}


def locked_requirements() -> list[str]:
    if not LOCK_MANIFEST.is_file():
        return []
    return [line.strip() for line in LOCK_MANIFEST.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def _read_marker() -> dict[str, Any]:
    try:
        value = json.loads(INSTALL_MARKER.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def dependency_diagnostics() -> dict[str, Any]:
    requirements = locked_requirements()
    marker = _read_marker()
    versions = marker.get("versions") if isinstance(marker.get("versions"), dict) else {}
    ready = bool(WORKER_PYTHON.is_file() and FRAMEWORK_BRIDGE.is_file() and marker.get("ready") is True
                 and all(str(versions.get(name)) == version for name, version in EXPECTED.items()))
    return {
        "lock_manifest": str(LOCK_MANIFEST), "exact_requirements": requirements,
        "installed": list(requirements) if ready else [], "missing": [] if ready else list(requirements),
        "hash_complete": True, "diagnostics": [] if ready else ["isolated_worker_environment_not_ready"],
        "ready": ready, "worker_python": str(WORKER_PYTHON), "versions": versions,
    }


def manual_setup_plan() -> dict[str, Any]:
    uv = shutil.which("uv") or "uv"
    commands = [
        f"{sys.executable} -m venv --system-site-packages {WORKER_VENV}",
        f"{uv} pip install --python {WORKER_PYTHON} -r {REQUIREMENTS}",
        f"{WORKER_PYTHON} -c 'import dspy, gepa; assert hasattr(dspy, \"RLM\"); assert hasattr(dspy, \"GEPA\")'",
    ]
    return {
        "ok": dependency_diagnostics()["ready"], "mode": "isolated_worker_venv",
        "execution_performed": False, "lock_manifest": str(LOCK_MANIFEST),
        "exact_requirements": locked_requirements(), "isolated_worker_venv": str(WORKER_VENV),
        "installer_lock": str(INSTALLER_LOCK), "timeout_seconds": 115,
        "trusted_index_required": False, "hashes_required": False, "log_path": str(INSTALL_LOG),
        "commands_for_operator_review": commands, "blockers": [] if shutil.which("uv") else ["uv_not_available"],
    }


def _acquire_lock() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        return os.open(INSTALLER_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        try:
            if time.time() - INSTALLER_LOCK.stat().st_mtime > 900:
                INSTALLER_LOCK.unlink()
                return os.open(INSTALLER_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except OSError:
            pass
        raise RuntimeError("DSPy RLM worker environment installation is already running")


def _write_framework_bridge() -> None:
    framework_paths = []
    worker_root = WORKER_VENV.resolve()
    for raw_path in sys.path:
        candidate = Path(raw_path or ".").resolve()
        if "site-packages" not in candidate.parts or not candidate.is_dir():
            continue
        if candidate == worker_root or worker_root in candidate.parents:
            continue
        framework_paths.append(str(candidate))
    if not framework_paths:
        raise RuntimeError("Agent Zero framework site-packages could not be located")
    WORKER_SITE_PACKAGES.mkdir(parents=True, exist_ok=True)
    FRAMEWORK_BRIDGE.write_text("\n".join(dict.fromkeys(framework_paths)) + "\n", encoding="utf-8")


def install_worker_environment(timeout_seconds: int = 115) -> dict[str, Any]:
    current = dependency_diagnostics()
    if current["ready"]:
        return {"ok": True, "execution_performed": False, "diagnostics": current}
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("DSPy RLM requires 'uv' to install its isolated worker environment")
    lock_fd = _acquire_lock()
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with INSTALL_LOG.open("a", encoding="utf-8") as log:
            subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", str(WORKER_VENV)],
                           check=True, stdout=log, stderr=subprocess.STDOUT, timeout=timeout_seconds)
            _write_framework_bridge()
            subprocess.run([uv, "pip", "install", "--python", str(WORKER_PYTHON), "-r", str(REQUIREMENTS)],
                           check=True, cwd=str(PLUGIN_ROOT), stdout=log, stderr=subprocess.STDOUT,
                           timeout=timeout_seconds)
            probe = (
                "import json, importlib.metadata as m, dspy, gepa; "
                "from helpers.print_style import PrintStyle; "
                "assert hasattr(dspy, 'RLM') and hasattr(dspy, 'GEPA'); "
                "print(json.dumps({'dspy': m.version('dspy'), 'gepa': m.version('gepa'), "
                "'dspy-cli': m.version('dspy-cli')}))"
            )
            result = subprocess.run([str(WORKER_PYTHON), "-c", probe], check=True, capture_output=True,
                                    text=True, timeout=timeout_seconds)
        versions = json.loads(result.stdout.strip().splitlines()[-1])
        INSTALL_MARKER.write_text(json.dumps({"ready": True, "versions": versions, "installed_at": time.time()},
                                             sort_keys=True), encoding="utf-8")
        diagnostics = dependency_diagnostics()
        if not diagnostics["ready"]:
            raise RuntimeError(f"DSPy RLM worker dependency versions do not match pins: {versions}")
        return {"ok": True, "execution_performed": True, "diagnostics": diagnostics}
    finally:
        os.close(lock_fd)
        INSTALLER_LOCK.unlink(missing_ok=True)

