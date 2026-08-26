from __future__ import annotations

from pathlib import Path
import tomllib

import yaml


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON_RANGE = ">=3.12,<3.15"
EXPECTED_TEST_DEPENDENCIES = {
    "PyYAML>=6,<7",
    "pytest>=8,<10",
    "pytest-asyncio>=0.24,<2",
}
PINNED_AGENT_ZERO_COMMIT = "b22a144bf59f15b1516084c9e7b88133ba92c8a9"


def _pyproject() -> dict:
    return tomllib.loads((PLUGIN_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_standalone_project_is_metadata_only() -> None:
    pyproject = _pyproject()
    project = pyproject["project"]

    assert project["name"] == "a0-self-improvement"
    assert project["requires-python"] == EXPECTED_PYTHON_RANGE
    assert project["dependencies"] == []
    assert set(project["optional-dependencies"]["test"]) == EXPECTED_TEST_DEPENDENCIES
    assert pyproject["tool"]["uv"]["package"] is False
    assert "build-system" not in pyproject


def test_project_and_plugin_versions_match() -> None:
    project = _pyproject()["project"]
    plugin = yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8"))

    assert plugin["name"] == "dspy_rlm"
    assert plugin["version"] == project["version"]


def test_worker_dependencies_are_not_framework_dependencies() -> None:
    project = _pyproject()["project"]
    worker_entrypoint = (PLUGIN_ROOT / "requirements.txt").read_text(encoding="utf-8")
    lock = tomllib.loads((PLUGIN_ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked_packages = {package["name"] for package in lock["package"]}
    root_package = next(package for package in lock["package"] if package["name"] == project["name"])

    assert project["dependencies"] == []
    assert "-r requirements-gepa.lock" not in worker_entrypoint
    assert not any(
        line.strip() and not line.lstrip().startswith("#")
        for line in worker_entrypoint.splitlines()
    )
    assert (PLUGIN_ROOT / "requirements-gepa.lock").is_file()
    assert lock["requires-python"].replace(" ", "") == EXPECTED_PYTHON_RANGE
    assert root_package["source"] == {"virtual": "."}
    assert locked_packages.isdisjoint({"dspy", "gepa", "dspy-cli", "litellm", "cryptography"})
    migration_lock = (PLUGIN_ROOT / "requirements-migration.lock").read_text(encoding="utf-8")
    assert "cryptography==50.0.0" in migration_lock


def test_ci_uses_frozen_uv_and_exact_compatibility_target() -> None:
    workflow_path = PLUGIN_ROOT / ".github" / "workflows" / "tests.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    job = workflow["jobs"]["pytest"]
    run_steps = [step["run"] for step in job["steps"] if "run" in step]

    assert job["strategy"]["matrix"]["python-version"] == ["3.12", "3.13", "3.14"]
    assert any("uv sync --frozen --extra test" in step for step in run_steps)
    assert any("--collect-only" in step for step in run_steps)
    assert any("python -m pytest" in step for step in run_steps)
    assert any("python -m compileall" in step for step in run_steps)
    assert any("tests/test_manifest_contract.py" in step for step in run_steps)
    assert any("scripts/scan_source_secrets.py" in step for step in run_steps)
    assert any("scripts/check_agent_zero_contract.py" in step for step in run_steps)
    assert PINNED_AGENT_ZERO_COMMIT in workflow_text
    assert "requirements-gepa.lock" not in "\n".join(run_steps)
