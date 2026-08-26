"""Install and diagnose the isolated DSPy RLM/GEPA worker environment."""
from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_REQUIREMENTS = PLUGIN_ROOT / "requirements.txt"
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
WORKER_PYVENV_CONFIG = WORKER_VENV / "pyvenv.cfg"
WORKER_SITE_PACKAGES = (
    WORKER_VENV / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
)
FRAMEWORK_BRIDGE = WORKER_SITE_PACKAGES / "agent_zero_framework.pth"
INSTALLER_LOCK = STATE_DIR / "worker-env-install.lock"
INSTALL_LOG = STATE_DIR / "worker-env-install.log"
INSTALL_MARKER = STATE_DIR / "worker-env.json"
EXPECTED = {"dspy": "3.3.1", "gepa": "0.1.4", "deno": "2.9.5"}


def locked_requirements() -> list[str]:
    if not LOCK_MANIFEST.is_file():
        return []
    return [
        line.removesuffix(" \\").strip()
        for line in LOCK_MANIFEST.read_text(encoding="utf-8").splitlines()
        if line and not line[0].isspace() and not line.startswith("#")
    ]


def lock_sha256() -> str:
    if not LOCK_MANIFEST.is_file():
        return ""
    return hashlib.sha256(LOCK_MANIFEST.read_bytes()).hexdigest()


def lock_hash_complete() -> bool:
    if not LOCK_MANIFEST.is_file():
        return False
    blocks: list[list[str]] = []
    for line in LOCK_MANIFEST.read_text(encoding="utf-8").splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    return bool(blocks) and all(any("--hash=sha256:" in line for line in block) for block in blocks)


def _read_marker() -> dict[str, Any]:
    try:
        value = json.loads(INSTALL_MARKER.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _venv_isolated() -> bool:
    try:
        entries = {
            key.strip().lower(): value.strip().lower()
            for line in WORKER_PYVENV_CONFIG.read_text(encoding="utf-8").splitlines()
            if "=" in line
            for key, value in (line.split("=", 1),)
        }
    except OSError:
        return False
    return entries.get("include-system-site-packages") == "false"


def _framework_bridge_is_narrow() -> bool:
    try:
        lines = [line for line in FRAMEWORK_BRIDGE.read_text(encoding="utf-8").splitlines() if line]
    except OSError:
        return False
    if len(lines) != 1:
        return False
    candidate = Path(lines[0])
    return bool(
        candidate.is_absolute()
        and (candidate / "agent.py").is_file()
        and (candidate / "helpers" / "print_style.py").is_file()
        and (candidate / "usr").is_dir()
    )


def dependency_diagnostics() -> dict[str, Any]:
    requirements = locked_requirements()
    marker = _read_marker()
    versions = marker.get("versions") if isinstance(marker.get("versions"), dict) else {}
    ready = bool(WORKER_PYTHON.is_file() and _venv_isolated() and _framework_bridge_is_narrow()
                 and marker.get("ready") is True
                 and marker.get("lock_sha256") == lock_sha256() and lock_hash_complete()
                 and all(str(versions.get(name)) == version for name, version in EXPECTED.items()))
    return {
        "lock_manifest": str(LOCK_MANIFEST), "exact_requirements": requirements,
        "installed": list(requirements) if ready else [], "missing": [] if ready else list(requirements),
        "hash_complete": lock_hash_complete(),
        "lock_sha256": lock_sha256(),
        "diagnostics": [] if ready else ["isolated_worker_environment_not_ready"],
        "ready": ready, "worker_python": str(WORKER_PYTHON), "versions": versions,
        "inherits_system_site_packages": not _venv_isolated(),
    }


def manual_setup_plan() -> dict[str, Any]:
    uv = shutil.which("uv") or "uv"
    commands = [
        f"{sys.executable} -m venv {WORKER_VENV}",
        f"{uv} pip install --require-hashes --python {WORKER_PYTHON} -r {LOCK_MANIFEST}",
        f"{WORKER_PYTHON} -c 'import dspy, gepa; assert hasattr(dspy, \"RLM\"); assert hasattr(dspy, \"GEPA\")'",
    ]
    return {
        "ok": dependency_diagnostics()["ready"], "mode": "isolated_worker_venv",
        "execution_performed": False, "lock_manifest": str(LOCK_MANIFEST),
        "exact_requirements": locked_requirements(), "isolated_worker_venv": str(WORKER_VENV),
        "installer_lock": str(INSTALLER_LOCK), "timeout_seconds": 115,
        "trusted_index_required": False, "hashes_required": True, "log_path": str(INSTALL_LOG),
        "inherits_system_site_packages": False,
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
    framework_roots: list[str] = []
    for raw_path in sys.path:
        candidate = Path(raw_path or ".").resolve()
        if not candidate.is_dir() or candidate == PLUGIN_ROOT:
            continue
        if (
            (candidate / "agent.py").is_file()
            and (candidate / "helpers" / "print_style.py").is_file()
            and (candidate / "usr").is_dir()
        ):
            framework_roots.append(str(candidate))
    if len(set(framework_roots)) != 1:
        raise RuntimeError("one exact Agent Zero framework source root is required")
    WORKER_SITE_PACKAGES.mkdir(parents=True, exist_ok=True)
    FRAMEWORK_BRIDGE.write_text(framework_roots[0] + "\n", encoding="utf-8")


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
            subprocess.run([sys.executable, "-m", "venv", str(WORKER_VENV)],
                           check=True, stdout=log, stderr=subprocess.STDOUT, timeout=timeout_seconds)
            _write_framework_bridge()
            subprocess.run([uv, "pip", "install", "--require-hashes", "--python", str(WORKER_PYTHON),
                            "-r", str(LOCK_MANIFEST)],
                           check=True, cwd=str(PLUGIN_ROOT), stdout=log, stderr=subprocess.STDOUT,
                           timeout=timeout_seconds)
            probe = (
                "import json, importlib.metadata as m, dspy, gepa; "
                "from helpers.print_style import PrintStyle; "
                "assert hasattr(dspy, 'RLM') and hasattr(dspy, 'GEPA'); "
                "print(json.dumps({'dspy': m.version('dspy'), 'gepa': m.version('gepa'), "
                "'deno': m.version('deno')}))"
            )
            result = subprocess.run([str(WORKER_PYTHON), "-c", probe], check=True, capture_output=True,
                                    text=True, timeout=timeout_seconds)
        versions = json.loads(result.stdout.strip().splitlines()[-1])
        INSTALL_MARKER.write_text(json.dumps({"ready": True, "versions": versions,
                                              "lock_sha256": lock_sha256(), "installed_at": time.time()},
                                             sort_keys=True), encoding="utf-8")
        diagnostics = dependency_diagnostics()
        if not diagnostics["ready"]:
            raise RuntimeError(f"DSPy RLM worker dependency versions do not match pins: {versions}")
        return {"ok": True, "execution_performed": True, "diagnostics": diagnostics}
    finally:
        os.close(lock_fd)
        INSTALLER_LOCK.unlink(missing_ok=True)
