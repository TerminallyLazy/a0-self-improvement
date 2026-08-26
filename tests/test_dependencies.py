"""Isolated worker dependency setup contracts."""
from __future__ import annotations

from usr.plugins.dspy_rlm.helpers import dependencies


def test_current_worker_lock_is_hashed_and_excludes_dspy_cli() -> None:
    requirements = set(dependencies.locked_requirements())
    assert "dspy==3.3.1" in requirements
    assert "deno==2.9.5" in requirements
    assert "gepa==0.1.4" in requirements
    assert not any(requirement.startswith("dspy-cli==") for requirement in requirements)
    assert dependencies.lock_hash_complete() is True


def test_setup_plan_targets_only_the_isolated_worker() -> None:
    plan = dependencies.manual_setup_plan()
    assert plan["mode"] == "isolated_worker_venv"
    assert plan["execution_performed"] is False
    assert "worker-venv" in plan["isolated_worker_venv"]
    assert all("worker-venv" in command for command in plan["commands_for_operator_review"])
    assert plan["hashes_required"] is True
    assert "--system-site-packages" not in plan["commands_for_operator_review"][0]
    assert "--require-hashes" in plan["commands_for_operator_review"][1]
    assert "requirements-gepa.lock" in plan["commands_for_operator_review"][1]


def test_diagnostics_fail_closed_without_a_matching_marker(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(dependencies, "WORKER_VENV", tmp_path / "worker-venv")
    monkeypatch.setattr(dependencies, "WORKER_PYTHON", tmp_path / "worker-venv" / "bin" / "python")
    monkeypatch.setattr(dependencies, "INSTALL_MARKER", tmp_path / "worker-env.json")
    report = dependencies.dependency_diagnostics()
    assert report["ready"] is False
    assert report["missing"]


def test_framework_bridge_contains_only_one_exact_source_root(monkeypatch, tmp_path) -> None:
    framework = tmp_path / "agent-zero"
    (framework / "helpers").mkdir(parents=True)
    (framework / "usr").mkdir()
    (framework / "agent.py").write_text("", encoding="utf-8")
    (framework / "helpers" / "print_style.py").write_text("", encoding="utf-8")
    site_packages = tmp_path / "worker" / "site-packages"
    bridge = site_packages / "agent_zero_framework.pth"
    monkeypatch.setattr(dependencies.sys, "path", [str(framework)])
    monkeypatch.setattr(dependencies, "WORKER_SITE_PACKAGES", site_packages)
    monkeypatch.setattr(dependencies, "FRAMEWORK_BRIDGE", bridge)

    dependencies._write_framework_bridge()

    assert bridge.read_text(encoding="utf-8") == f"{framework.resolve()}\n"
    assert dependencies._framework_bridge_is_narrow() is True
