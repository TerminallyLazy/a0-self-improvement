from __future__ import annotations

import json
from pathlib import Path

import yaml

from usr.plugins.dspy_rlm.helpers import config as config_module


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def _checked_in_defaults() -> dict:
    return yaml.safe_load((PLUGIN_ROOT / "default_config.yaml").read_text(encoding="utf-8"))


def _assert_inert_v2_defaults(config: dict) -> None:
    assert config["config_version"] == 2
    assert config["enabled"] is False
    assert config["instrumentation_enabled"] is False
    assert config["optimization"]["enabled"] is False
    assert config["optimization"]["auto_optimize"] is False
    assert config["prompt"]["inject_guidance"] is False
    assert config["rlm"]["enabled"] is True
    assert config["prompt_optimization"]["enabled"] is False
    assert config["prompt_optimization"]["allow_prompt_capture"] is False
    assert config["prompt_optimization"]["automatic_requires_canary"] is True
    assert config["dependencies"]["install_mode"] == "isolated_worker"
    assert config["dependencies"]["ensure_at_startup"] is True
    assert config["engine"] == "heuristic"
    assert config["worker"]["backend"] == "sqlite_local"
    assert config["worker"]["max_workers"] == 1


def test_checked_in_default_config_is_inert_v2() -> None:
    defaults = _checked_in_defaults()

    _assert_inert_v2_defaults(defaults)


def test_checked_in_default_config_has_no_conflicting_legacy_aliases() -> None:
    defaults = _checked_in_defaults()

    forbidden_legacy_keys = {
        "auto_optimize_enabled",
        "optimization_interval_messages",
        "optimization_min_samples",
        "optimization_trace_window",
        "optimization_cooldown_hours",
        "enable_dspy_optimizer",
        "gepa_steps",
        "gepa_threads",
        "trace_enabled",
        "trace_retention_limit",
        "auto_optimize",
        "scheduler_max_workers",
    }
    assert forbidden_legacy_keys.isdisjoint(defaults)


def test_settings_switches_bridge_stable_controls_to_canonical_optimization_keys() -> None:
    markup = (PLUGIN_ROOT / "webui" / "config.html").read_text(encoding="utf-8")

    for binding in (
        'x-model="config.auto_optimize_enabled"',
        'x-model="config.enable_dspy_optimizer"',
        'x-model="config.enable_replay_audit"',
    ):
        assert binding in markup

    for unsafe_nested_watcher in (
        "$watch(() => config.optimization.auto_optimize",
        "$watch(() => config.optimization.enable_dspy_optimizer",
        "$watch(() => config.optimization.enable_replay_audit",
    ):
        assert unsafe_nested_watcher not in markup

    for bridge in (
        "$watch(() => config.auto_optimize_enabled",
        "$watch(() => config.enable_dspy_optimizer",
        "$watch(() => config.enable_replay_audit",
        "optimizationSection.auto_optimize = enabled;",
        "optimizationSection.enable_dspy_optimizer = enabled;",
        "optimizationSection.enable_replay_audit = toBool(value, false);",
        "config.auto_optimize_enabled = enabled;",
        "config.auto_optimize = enabled;",
        "config.auto_enqueue = enabled;",
        "config.enable_dspy_optimizer = enabled;",
    ):
        assert bridge in markup


def test_enabled_optimization_switches_survive_json_round_trip() -> None:
    settings = config_module.normalize_config({})
    settings["optimization"].update(
        auto_optimize=True,
        enable_dspy_optimizer=True,
        enable_replay_audit=True,
    )
    settings.update(
        auto_optimize_enabled=True,
        auto_optimize=True,
        auto_enqueue=True,
        enable_dspy_optimizer=True,
    )

    reloaded = config_module.normalize_config(json.loads(json.dumps(settings)))

    assert reloaded["optimization"]["auto_optimize"] is True
    assert reloaded["optimization"]["enable_dspy_optimizer"] is True
    assert reloaded["optimization"]["enable_replay_audit"] is True
    assert not any("conflicting legacy aliases" in item for item in reloaded["diagnostics"])
