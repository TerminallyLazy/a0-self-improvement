from __future__ import annotations

from usr.plugins.dspy_rlm.helpers import config, prompt_artifacts, state


def _use_store(monkeypatch, tmp_path):
    store = state.StateStore(tmp_path)
    monkeypatch.setattr(prompt_artifacts, "_store", lambda: store.store)
    return store


def test_prompt_optimization_config_is_inert_and_automatic_keeps_canary() -> None:
    defaults = config.normalize_config({})["prompt_optimization"]
    assert defaults["enabled"] is False
    assert defaults["target_mode"] == "guidance_overlay"
    configured = config.normalize_config({"prompt_optimization": {"enabled": True, "allow_prompt_capture": True, "target_mode": "assembled_prompt", "activation_mode": "automatic", "automatic_requires_canary": False}})["prompt_optimization"]
    assert configured["activation_mode"] == "automatic"
    assert configured["automatic_requires_canary"] is True


def test_protected_components_cannot_be_replaced(monkeypatch, tmp_path) -> None:
    _use_store(monkeypatch, tmp_path)
    prompt = ["General response style", "Always use the response tool with break_loop"]
    snapshot = prompt_artifacts.capture_snapshot("ctx", prompt)
    assert snapshot is not None
    assert snapshot["components"][0]["protected"] is False
    assert snapshot["components"][1]["protected"] is True
    replacement = snapshot["components"][0]
    artifact = prompt_artifacts.PromptArtifact(
        artifact_id="artifact-1", context_id="ctx", target_mode="selected_components", activation_mode="manual",
        base_snapshot_id=snapshot["snapshot_id"], base_digest=snapshot["base_digest"],
        replacements=({"component_id": replacement["component_id"], "source_digest": replacement["source_digest"], "text": "Be concise and verify claims."},),
        validation={"passed": True}, provenance={"engine": "test"},
    )
    applied, original = prompt_artifacts.apply_artifact(prompt, artifact)
    assert applied is True
    assert prompt == ["Be concise and verify claims.", "Always use the response tool with break_loop"]
    assert original[0] == "General response style"


def test_automatic_activation_enters_canary_then_promotes(monkeypatch, tmp_path) -> None:
    _use_store(monkeypatch, tmp_path)
    snapshot = prompt_artifacts.capture_snapshot("ctx", ["General response style"])
    component = snapshot["components"][0]
    artifact = prompt_artifacts.PromptArtifact(
        artifact_id="artifact-auto", context_id="ctx", target_mode="selected_components", activation_mode="automatic",
        base_snapshot_id=snapshot["snapshot_id"], base_digest=snapshot["base_digest"],
        replacements=({"component_id": component["component_id"], "source_digest": component["source_digest"], "text": "Use concise verified responses."},),
        validation={"passed": True, "baseline_failure_rate": 0.0}, provenance={"engine": "test"},
    )
    prompt_artifacts.stage_artifact(artifact)
    started = prompt_artifacts.begin_activation(artifact, {"prompt_optimization": {"canary_percentage": 100}})
    assert started["state"] == "canary"
    cfg = {"prompt_optimization": {"canary_min_observations": 3, "canary_max_observations": 4, "rollback": {"enabled": True, "maximum_failure_rate_increase": 0.1}}}
    prompt_artifacts.record_observation("ctx", artifact.artifact_id, success=True, cfg=cfg)
    prompt_artifacts.record_observation("ctx", artifact.artifact_id, success=True, cfg=cfg)
    result = prompt_artifacts.record_observation("ctx", artifact.artifact_id, success=True, cfg=cfg)
    assert result["state"] == "active"


def test_automatic_activation_rolls_back_on_score_regression(monkeypatch, tmp_path) -> None:
    _use_store(monkeypatch, tmp_path)
    snapshot = prompt_artifacts.capture_snapshot("ctx", ["General response style"])
    component = snapshot["components"][0]
    artifact = prompt_artifacts.PromptArtifact(
        artifact_id="artifact-regression", context_id="ctx", target_mode="selected_components", activation_mode="automatic",
        base_snapshot_id=snapshot["snapshot_id"], base_digest=snapshot["base_digest"],
        replacements=({"component_id": component["component_id"], "source_digest": component["source_digest"], "text": "Use concise verified responses."},),
        validation={"passed": True, "baseline_failure_rate": 0.0}, provenance={"engine": "test"},
    )
    prompt_artifacts.stage_artifact(artifact)
    prompt_artifacts.begin_activation(artifact, {"prompt_optimization": {"canary_percentage": 100}})
    cfg = {"prompt_optimization": {"canary_min_observations": 3, "canary_max_observations": 4, "rollback": {"enabled": True, "maximum_failure_rate_increase": 1.0, "maximum_score_regression": 0.05}}}
    prompt_artifacts.record_observation("ctx", artifact.artifact_id, success=True, cfg=cfg)
    prompt_artifacts.record_observation("ctx", artifact.artifact_id, success=True, cfg=cfg)
    result = prompt_artifacts.record_observation("ctx", artifact.artifact_id, success=False, cfg=cfg)
    assert result["state"] == "rolled_back"
    assert result["failure_rate"] == 1 / 3
    assert abs(result["success_rate"] - (2 / 3)) < 1e-12
