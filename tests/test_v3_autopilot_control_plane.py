from __future__ import annotations

from pathlib import Path

from usr.plugins.dspy_rlm.helpers import config as config_module
from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.autopilot_control_plane import (
    autopilot_transition_runtime_ready,
    issue_automatic_transition_grant,
    provision_autopilot_control_plane,
)
from usr.plugins.dspy_rlm.helpers.v3 import autopilot_control_plane
from usr.plugins.dspy_rlm.helpers.v3.operator_repository import (
    OperatorRepositoryAdapter,
    SafeStoreOperatorReader,
)
from usr.plugins.dspy_rlm.helpers.v3.registry import V3_REGISTRY
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Reader, V3Repository


CONTEXT = "context:autopilot-control"


def _repository(path: Path) -> V3Repository:
    repository = V3Repository.create(path, registry=V3_REGISTRY)
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile:autopilot-control",
        context_ref=CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="test-v1",
    )
    with repository.transaction() as transaction:
        for record in (guidance, prompt, profile):
            transaction.insert_record(record)
        transaction.initialize_activation_scope(
            context_ref=CONTEXT,
            profile_id=profile.record_id,
            profile_digest=profile.content_digest,
        )
    return repository


def test_autopilot_provisions_one_standing_calibration_and_replays(tmp_path: Path) -> None:
    store = tmp_path / "safe-store.sqlite3"
    authority = tmp_path / "authority"
    config = config_module.normalize_config(
        {
            "enabled": True,
            "automation": {"mode": "autopilot", "authority_consent_revision": 1},
        }
    )
    with _repository(store) as repository:
        first = provision_autopilot_control_plane(
            repository,
            context_ref=CONTEXT,
            config=config,
            authority_root=authority,
        )
        replay = provision_autopilot_control_plane(
            repository,
            context_ref=CONTEXT,
            config=config,
            authority_root=authority,
        )

    assert first.state == "authorized"
    assert replay.state == "authorized"
    assert replay.policy == first.policy
    assert replay.calibration == first.calibration
    assert replay.replayed is True
    with V3Reader.open(store, registry=V3_REGISTRY) as reader:
        plan = reader.get_record(
            reader.get_record(first.calibration.record_id).payload["canary_plan_id"]
        )
    assert [item["bucket_ref"] for item in plan.payload["buckets"]] == ["reasoning"]
    horizon = plan.payload["horizon_exposures"]
    assert autopilot_control_plane._binomial_below_minimum_probability(
        horizon, 10, 0.10
    ) <= 0.005
    assert autopilot_control_plane._binomial_below_minimum_probability(
        horizon, 10, 0.90
    ) <= 0.005
    with V3Reader.open(store, registry=V3_REGISTRY) as reader:
        projected = OperatorRepositoryAdapter(
            SafeStoreOperatorReader(reader)
        ).read_policy_capabilities(CONTEXT)
    assert projected.calibration_state == "approved"
    assert projected.activation_mode == "auto_after_canary"
    assert projected.automatic_authority_state == "authorized"
    grant = issue_automatic_transition_grant(
        authority_root=authority,
        context_ref=CONTEXT,
        action="activate",
        target_ref="candidate:auto",
        target_revision=0,
    )
    assert grant.authority_class == "automatic_transition_grant"
    assert grant.purpose == "automatic_promotion"
    assert autopilot_transition_runtime_ready(authority) is True
    (authority / "canary-assignment.key").chmod(0o644)
    assert autopilot_transition_runtime_ready(authority) is False


def test_canary_horizon_bounds_combined_shortfall_at_extreme_allocations() -> None:
    for percentage in (1, 99):
        horizon = autopilot_control_plane._reliable_canary_horizon(
            minimum=3, maximum=40, candidate_percentage=percentage,
        )
        probability = percentage / 100
        assert autopilot_control_plane._binomial_below_minimum_probability(
            horizon, 3, probability
        ) <= 0.005
        assert autopilot_control_plane._binomial_below_minimum_probability(
            horizon, 3, 1 - probability
        ) <= 0.005


def test_non_autopilot_mode_never_provisions_authority(tmp_path: Path) -> None:
    store = tmp_path / "safe-store.sqlite3"
    config = config_module.normalize_config(
        {"enabled": True, "automation": {"mode": "review"}}
    )
    with _repository(store) as repository:
        result = provision_autopilot_control_plane(
            repository,
            context_ref=CONTEXT,
            config=config,
            authority_root=tmp_path / "authority",
        )

    assert result.state == "not_authorized"
    assert not (tmp_path / "authority").exists()
    assert autopilot_transition_runtime_ready(tmp_path / "authority") is False
    with V3Reader.open(store, registry=V3_REGISTRY) as reader:
        assert reader.count_records_for_context(CONTEXT) == 1


def test_legacy_autopilot_setting_requires_explicit_current_consent(tmp_path: Path) -> None:
    store = tmp_path / "safe-store.sqlite3"
    config = config_module.normalize_config(
        {"enabled": True, "automation": {"mode": "autopilot"}}
    )
    assert config["automation"]["authority_consent_revision"] == 0
    with _repository(store) as repository:
        result = provision_autopilot_control_plane(
            repository,
            context_ref=CONTEXT,
            config=config,
            authority_root=tmp_path / "authority",
        )
    assert result.state == "not_authorized"
    assert not (tmp_path / "authority").exists()


def test_control_plane_identities_are_scoped_per_context(tmp_path: Path) -> None:
    store = tmp_path / "safe-store.sqlite3"
    authority = tmp_path / "authority"
    other = "context:autopilot-control-other"
    config = config_module.normalize_config(
        {
            "enabled": True,
            "automation": {"mode": "autopilot", "authority_consent_revision": 1},
        }
    )
    with _repository(store) as repository:
        guidance = null_guidance_artifact()
        prompt = null_prompt_patch_artifact()
        profile = activation_profile(
            record_id="profile:autopilot-control-other",
            context_ref=other,
            guidance_artifact=guidance,
            prompt_patch_artifact=prompt,
            key_epoch="test-v1",
        )
        with repository.transaction() as transaction:
            transaction.insert_record(profile)
            transaction.initialize_activation_scope(
                context_ref=other,
                profile_id=profile.record_id,
                profile_digest=profile.content_digest,
            )
        first = provision_autopilot_control_plane(
            repository,
            context_ref=CONTEXT,
            config=config,
            authority_root=authority,
        )
        second = provision_autopilot_control_plane(
            repository,
            context_ref=other,
            config=config,
            authority_root=authority,
        )

    assert first.policy is not None and second.policy is not None
    assert first.calibration is not None and second.calibration is not None
    assert first.policy.record_id != second.policy.record_id
    assert first.calibration.record_id != second.calibration.record_id


def test_reverted_settings_mint_a_new_monotonic_policy_occurrence(
    tmp_path: Path,
) -> None:
    store = tmp_path / "safe-store.sqlite3"
    authority = tmp_path / "authority"
    config_a = config_module.normalize_config(
        {
            "enabled": True,
            "automation": {"mode": "autopilot", "authority_consent_revision": 1},
            "prompt_optimization": {"canary_percentage": 10},
        }
    )
    config_b = config_module.normalize_config(
        {
            "enabled": True,
            "automation": {"mode": "autopilot", "authority_consent_revision": 1},
            "prompt_optimization": {"canary_percentage": 25},
        }
    )
    with _repository(store) as repository:
        first_a = provision_autopilot_control_plane(
            repository, context_ref=CONTEXT, config=config_a,
            authority_root=authority,
        )
        second_b = provision_autopilot_control_plane(
            repository, context_ref=CONTEXT, config=config_b,
            authority_root=authority,
        )
        third_a = provision_autopilot_control_plane(
            repository, context_ref=CONTEXT, config=config_a,
            authority_root=authority,
        )
        revisions = [
            repository.get_record(result.policy.record_id).payload["policy_revision"]
            for result in (first_a, second_b, third_a)
            if result.policy is not None
        ]

    assert first_a.policy is not None
    assert second_b.policy is not None
    assert third_a.policy is not None
    assert revisions == [1, 2, 3]
    assert third_a.policy.record_id.startswith(f"{first_a.policy.record_id}:")
    assert third_a.policy.record_id != first_a.policy.record_id
    with V3Reader.open(store, registry=V3_REGISTRY) as reader:
        capability = OperatorRepositoryAdapter(
            SafeStoreOperatorReader(reader)
        ).read_policy_capabilities(CONTEXT)
    assert capability.policy_ref == third_a.policy.record_id
    assert capability.automatic_authority_state == "authorized"
