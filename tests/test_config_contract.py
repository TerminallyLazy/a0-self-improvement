from __future__ import annotations

import json
from pathlib import Path
import re

import yaml

from usr.plugins.dspy_rlm.helpers import config as config_module


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def _checked_in_defaults() -> dict:
    return yaml.safe_load((PLUGIN_ROOT / "default_config.yaml").read_text(encoding="utf-8"))


def _assert_inert_v2_defaults(config: dict) -> None:
    assert config["config_version"] == 2
    assert config["enabled"] is False
    assert config["automatic_project_genesis"] is True
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
        'x-model="config.automatic_project_genesis"',
        'x-model="config.auto_optimize_enabled"',
        'x-model="config.enable_dspy_optimizer"',
        'x-model="config.enable_replay_audit"',
    ):
        assert binding in markup

    for unsafe_nested_watcher in (
        "$watch(() => config.optimization.auto_optimize",
        "$watch(() => config.optimization.enable_dspy_optimizer",
        "$watch(() => config.optimization.enable_replay_audit",
        "$watch(() => config.trace_capture.max_events_per_context",
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

    assert "config.automatic_project_genesis = toBool(config.automatic_project_genesis, true);" in markup
    assert "Set up project chats automatically" in markup
    assert "Set up project Genesis automatically" not in markup


def test_automatic_project_genesis_persists_and_falls_closed_without_defaults(
    monkeypatch,
) -> None:
    enabled = config_module.normalize_config({"automatic_project_genesis": True})
    disabled = config_module.normalize_config({"automatic_project_genesis": False})

    assert enabled["automatic_project_genesis"] is True
    assert disabled["automatic_project_genesis"] is False

    monkeypatch.setattr(config_module, "_load_default", lambda: {})
    assert config_module.normalize_config(None)["automatic_project_genesis"] is False


def test_operating_profile_highlight_follows_the_selected_preset() -> None:
    markup = (PLUGIN_ROOT / "webui" / "config.html").read_text(encoding="utf-8")

    assert "selectedPreset: 'balanced'" in markup
    assert "this.selectedPreset = level;" in markup
    for profile in ("safe", "balanced", "aggressive"):
        assert f":class=\"{{ 'is-strong': selectedPreset === '{profile}' }}\"" in markup

    assert 'class="dspy-btn is-strong"' not in markup


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


def test_every_flat_editable_compatibility_field_has_a_canonical_sync_watcher() -> None:
    markup = (PLUGIN_ROOT / "webui" / "config.html").read_text(encoding="utf-8")
    flat_bindings = set(
        re.findall(r'x-model(?:\.number)?="config\.([A-Za-z0-9_]+)"', markup)
    )
    direct_fields = {
        "automatic_project_genesis",
        "enabled",
        "status_refresh_seconds",
    }
    watched_fields = set(
        re.findall(r"\$watch\(\(\) => config\.([A-Za-z0-9_]+)", markup)
    )

    assert flat_bindings - direct_fields <= watched_fields


def test_all_editable_compatibility_fields_survive_one_save_reload_transaction() -> None:
    settings = config_module.normalize_config({"automation": {"mode": "observe"}})
    settings.update(
        instrumentation_enabled=True,
        trace_enabled=True,
        auto_optimize_enabled=True,
        auto_optimize=True,
        auto_enqueue=True,
        optimization_interval_messages=7,
        optimization_min_samples=4,
        optimization_cooldown_hours=1,
        optimization_trace_window=1900,
        optimization_preview_limit=23,
        enable_dspy_optimizer=True,
        gepa_steps=4,
        ge_pa_steps=4,
        gepa_threads=3,
        ge_pa_threads=3,
        replay_set_size=7,
        replay_tolerable_regression=0.12,
        enable_replay_audit=True,
        scheduler_mode="single",
        scheduler_max_workers=2,
        scheduler_poll_interval_seconds=4,
        scheduler_job_lease_seconds=50,
        scheduler_max_retries=3,
        scheduler_heartbeat_seconds=9,
        scheduler_stale_worker_seconds=190,
        scheduler_lock_ttl_seconds=35,
        scheduler_backoff_base_seconds=3,
        scheduler_enforce_single_tenant_per_context=True,
    )
    settings["trace_capture"]["max_events_per_context"] = 1900
    settings["optimization"].update(
        auto_optimize=True,
        auto_optimize_interval_messages=7,
        min_samples_for_promotion=4,
        cooldown_hours=1,
        optimization_preview_limit=23,
        enable_dspy_optimizer=True,
        ge_pa_steps=4,
        gepa_steps=4,
        ge_pa_threads=3,
        gepa_threads=3,
        replay_set_size=7,
        replay_tolerable_regression=0.12,
        enable_replay_audit=True,
    )
    settings["scheduler"].update(
        mode="single",
        max_workers=2,
        poll_interval_seconds=4,
        job_lease_seconds=50,
        max_retries=3,
        heartbeat_seconds=9,
        stale_worker_seconds=190,
        scheduler_lock_ttl_seconds=35,
        backoff_base_seconds=3,
        enforce_single_tenant_per_context=True,
    )

    reloaded = config_module.normalize_config(json.loads(json.dumps(settings)))

    assert reloaded["instrumentation_enabled"] is True
    assert reloaded["trace_capture"]["max_events_per_context"] == 1900
    assert reloaded["optimization"]["auto_optimize_interval_messages"] == 7
    assert reloaded["optimization"]["min_samples_for_promotion"] == 4
    assert reloaded["optimization"]["cooldown_hours"] == 1
    assert reloaded["optimization_cooldown_hours"] == 1
    assert reloaded["optimization"]["optimization_preview_limit"] == 23
    assert reloaded["optimization"]["replay_set_size"] == 7
    assert reloaded["optimization"]["replay_tolerable_regression"] == 0.12
    assert reloaded["optimization"]["enable_dspy_optimizer"] is True
    assert reloaded["optimization"]["enable_replay_audit"] is True
    assert reloaded["optimization"]["ge_pa_steps"] == 4
    assert reloaded["optimization"]["ge_pa_threads"] == 3
    assert reloaded["scheduler"]["mode"] == "single"
    assert reloaded["scheduler"]["max_workers"] == 2
    assert reloaded["scheduler"]["poll_interval_seconds"] == 4
    assert reloaded["scheduler"]["job_lease_seconds"] == 50
    assert reloaded["scheduler"]["max_retries"] == 3
    assert reloaded["scheduler"]["heartbeat_seconds"] == 9
    assert reloaded["scheduler"]["stale_worker_seconds"] == 190
    assert reloaded["scheduler"]["scheduler_lock_ttl_seconds"] == 35
    assert reloaded["scheduler"]["backoff_base_seconds"] == 3
    assert reloaded["scheduler"]["enforce_single_tenant_per_context"] is True
    assert not any("conflicting legacy aliases" in item for item in reloaded["diagnostics"])


def test_every_nested_field_bound_in_settings_survives_save_and_reload() -> None:
    markup = (PLUGIN_ROOT / "webui" / "config.html").read_text(encoding="utf-8")
    paths = sorted(
        {
            match
            for match in re.findall(
                r'x-model(?:\.number)?="config\.([A-Za-z0-9_.]+)"', markup
            )
            if "." in match
        }
    )
    enum_values = {
        "automation.scope": "current_chat",
        "dependencies.install_mode": "isolated_worker",
        "prompt_optimization.activation_mode": "canary",
        "prompt_optimization.target_mode": "assembled_prompt",
    }

    def read_path(config: dict, path: str):
        value = config
        for part in path.split("."):
            value = value[part]
        return value

    def write_path(config: dict, path: str, value) -> None:
        target = config
        parts = path.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value

    def alternate(path: str, value):
        if path in enum_values:
            return enum_values[path]
        if isinstance(value, bool):
            return not value
        if isinstance(value, int):
            return value + 1
        if isinstance(value, float):
            return 0.37 if 0.0 <= value <= 1.0 and value != 0.37 else value + 1.0
        if isinstance(value, str):
            return "persist-check"
        raise AssertionError(f"unsupported editable field type for {path}: {type(value)}")

    baseline = config_module.normalize_config({"automation": {"mode": "observe"}})
    for path in paths:
        settings = json.loads(json.dumps(baseline))
        expected = alternate(path, read_path(settings, path))
        write_path(settings, path, expected)
        if path == "trace_capture.max_events_per_context":
            settings["optimization_trace_window"] = expected

        reloaded = config_module.normalize_config(json.loads(json.dumps(settings)))

        assert read_path(reloaded, path) == expected, path

    selected_components = json.loads(json.dumps(baseline))
    selected_components["prompt_optimization"]["selected_components"] = [
        "segment:persist-check"
    ]
    reloaded = config_module.normalize_config(selected_components)
    assert reloaded["prompt_optimization"]["selected_components"] == [
        "segment:persist-check"
    ]


def test_mode_owned_fields_are_not_presented_as_editable() -> None:
    markup = (PLUGIN_ROOT / "webui" / "config.html").read_text(encoding="utf-8")

    assert "Review and Autopilot lock the capabilities they require." in markup
    assert markup.count(':disabled="selectedAutomation !== \'observe\'"') >= 7
    assert ':disabled="selectedAutomation === \'autopilot\'"' in markup
