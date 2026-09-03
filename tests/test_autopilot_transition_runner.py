from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from usr.plugins.dspy_rlm.helpers import autopilot_transition_runner as runner
from usr.plugins.dspy_rlm.helpers.guidance import GuidanceArtifact, render_guidance_artifact
from usr.plugins.dspy_rlm.helpers.state import StateStore
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    Rational,
    activation_policy,
    canary_plan,
    monitor_plan,
    policy_calibration,
)


def _config() -> dict:
    return {
        "enabled": True,
        "automation": {"mode": "autopilot", "authority_consent_revision": 1},
    }


def _binding(context_ref: str) -> runner._AuthorityBinding:
    policy = activation_policy(
        record_id="policy", context_ref=context_ref, policy_revision=1,
        activation_mode="auto_after_canary", key_epoch="test-v1",
    )
    canary = canary_plan(
        record_id="canary-plan", context_ref=context_ref, horizon_exposures=6,
        expiry_seconds=3600, candidate_allocation=Rational(1, 2),
        assignment_key_commitment="a" * 64, hard_veto_failure_limit=0,
        buckets=(BucketCalibration("reasoning", 3, Rational(1, 20), Rational(0, 1)),),
        key_epoch="test-v1",
    )
    monitor = monitor_plan(
        record_id="monitor-plan", context_ref=context_ref, horizon_exposures=3,
        look_interval_exposures=1,
        ordinary_regression_boundary=Rational(-1, 20),
        hard_veto_failure_limit=0, key_epoch="test-v1",
    )
    calibration = policy_calibration(
        record_id="calibration", context_ref=context_ref, status="approved",
        environment_ref="agent-zero:local-production", policy=policy,
        canary_plan_record=canary, monitor_plan_record=monitor,
        activation_authorities=("automatic", "manual"),
        soft_rollback_authorized=True, key_epoch="test-v1",
    )
    return runner._AuthorityBinding(policy, calibration, canary, monitor)


def _seed_candidate(
    state_store: StateStore, *, candidate_id: str, artifact: GuidanceArtifact,
    replay: dict,
) -> None:
    state_store.store.append_guidance_version(
        artifact.artifact_id,
        artifact.context_id,
        artifact.objective_bucket,
        "objective-1",
        render_guidance_artifact(artifact),
        {"guidance_artifact": artifact.to_mapping()},
    )
    audit_id = f"audit-{candidate_id}"
    state_store.store.append_candidate(
        candidate_id,
        artifact.context_id,
        artifact.objective_bucket,
        {
            "candidate_id": candidate_id,
            "guidance_version": artifact.artifact_id,
            "guidance_artifact": artifact.to_mapping(),
            "validation": {"passed": True},
            "replay_audit_id": audit_id,
        },
        guidance_version=artifact.artifact_id,
    )
    state_store.store.append_replay_audit(audit_id, candidate_id, replay)


def _artifact(
    context_ref: str, artifact_id: str = "guide-auto-1", *, expired: bool = False,
) -> GuidanceArtifact:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at = now - timedelta(days=2) if expired else now
    expires_at = now - timedelta(days=1) if expired else now + timedelta(days=1)
    return GuidanceArtifact.create(
        artifact_id=artifact_id,
        context_id=context_ref,
        objective_bucket="reasoning",
        rules=({"type": "verify_tool_contract"},),
        source_manifest_hashes=("sha256:" + "1" * 64,),
        source_finding_hashes=("sha256:" + "2" * 64,),
        issued_at=issued_at.isoformat().replace("+00:00", "Z"),
        expires_at=expires_at.isoformat().replace("+00:00", "Z"),
        engine_kind="gepa",
        engine_version="gepa-v1",
    )


def test_pointer_fence_revalidates_current_scope_and_candidate_publication() -> None:
    context_ref = "context-auto"
    binding = _binding(context_ref)
    source_digest = "b" * 64
    record_id = "autopilot_candidate_" + runner.sha256(
        runner.canonical_json([context_ref, source_digest])
    ).hexdigest()
    scope = SimpleNamespace(
        scope_revision=2,
        current_profile_id="profile-current",
        current_profile_digest="c" * 64,
    )
    publication = SimpleNamespace(
        schema_id="a0.autopilot-review-candidate.v1",
        context_ref=context_ref,
        payload={
            "source_candidate_digest": source_digest,
            "objective_bucket": "reasoning",
            "review_disposition": "review_only",
            "observed_scope_revision": 2,
            "incumbent_profile_id": "profile-current",
            "incumbent_profile_digest": "c" * 64,
        },
    )
    records = {
        item.record_id: item
        for item in (
            binding.policy,
            binding.calibration,
            binding.canary_plan,
            binding.monitor_plan,
        )
    }
    records[record_id] = publication

    class Connection:
        def execute(self, *_args, **_kwargs):
            rows = [
                {"record_id": binding.policy.record_id},
                {"record_id": binding.calibration.record_id},
            ]
            return SimpleNamespace(fetchall=lambda: rows)

    transaction = SimpleNamespace(
        _connection=Connection(),
        get_record=lambda identity: records.get(identity),
        get_activation_scope=lambda _context_ref: scope,
    )
    transition = {
        "source_candidate_digest": source_digest,
        "objective_bucket": "reasoning",
    }

    runner._require_current_binding(
        transaction,
        context_ref=context_ref,
        binding=binding,
        transition=transition,
    )
    scope.scope_revision = 3
    with pytest.raises(PermissionError, match="publication authority changed"):
        runner._require_current_binding(
            transaction,
            context_ref=context_ref,
            binding=binding,
            transition=transition,
        )


def test_runner_compares_both_canary_arms_then_promotes_and_rolls_back(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_automatic_grant", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "_published_candidate_matches", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_coordinator_candidate_approved", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_candidate_evidence_matches", lambda **_kwargs: True)
    monkeypatch.setattr(
        runner, "_authorized_pointer_mutation",
        lambda *, mutate, **_kwargs: mutate(),
    )
    from usr.plugins.dspy_rlm.helpers.v3 import autopilot_control_plane
    monkeypatch.setattr(
        autopilot_control_plane,
        "canary_assignment_value",
        lambda **kwargs: 0 if kwargs["exposure_ref"].startswith("candidate") else 99,
    )
    artifact = _artifact(context_ref)
    _seed_candidate(
        state_store,
        candidate_id="candidate-auto-1",
        artifact=artifact,
        replay={"decision": "review_only", "reason": "missing_baseline"},
    )
    assert runner.consider_candidate(
        context_ref=context_ref,
        candidate_id="candidate-auto-1",
        objective_bucket="reasoning",
        guidance_version=artifact.artifact_id,
        config=_config(),
    ) == "canary"

    result = "canary"
    for arm in ("candidate", "incumbent"):
        for index in range(3):
            selection, selected = runner.select_guidance(
                context_ref=context_ref,
                objective_bucket="reasoning",
                exposure_ref=f"{arm}-{index}",
                config=_config(),
            )
            assert selection is not None and selection.arm == arm
            assert selected == artifact if arm == "candidate" else selected is None
            result = runner.record_outcome(selection, success=True, config=_config())
    assert result == "monitoring"
    active = state_store.store.get_active_guidance(context_ref, "reasoning")
    assert active is not None and active["guidance_version"] == artifact.artifact_id

    monitoring, selected = runner.select_guidance(
        context_ref=context_ref,
        objective_bucket="reasoning",
        exposure_ref="monitor-1",
        config=_config(),
    )
    assert monitoring is not None and monitoring.state == "monitoring"
    assert selected == artifact
    assert runner.record_outcome(
        monitoring, success=False, config=_config()
    ) == "rolled_back"
    assert state_store.store.get_active_guidance(context_ref, "reasoning") is None


def test_runner_rejects_digest_tampering_and_cross_bucket_fallback(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_automatic_grant", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "_published_candidate_matches", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_coordinator_candidate_approved", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_candidate_evidence_matches", lambda **_kwargs: True)
    artifact = _artifact(context_ref)
    _seed_candidate(
        state_store,
        candidate_id="candidate-auto-2",
        artifact=artifact,
        replay={"decision": "promotion_ready", "reason": "passed"},
    )
    with state_store.store._connect() as connection:
        connection.execute(
            "UPDATE replay_audits SET audit_json=? WHERE audit_id=?",
            ('{"decision":"promotion_ready","reason":"tampered"}', "audit-candidate-auto-2"),
        )
    assert runner.consider_candidate(
        context_ref=context_ref,
        candidate_id="candidate-auto-2",
        objective_bucket="reasoning",
        guidance_version=artifact.artifact_id,
        config=_config(),
    ) == "rejected"
    _seed_candidate(
        state_store,
        candidate_id="candidate-valid-scope",
        artifact=artifact,
        replay={"decision": "review_only", "reason": "missing_baseline"},
    )
    assert runner.consider_candidate(
        context_ref=context_ref,
        candidate_id="candidate-valid-scope",
        objective_bucket="reasoning",
        guidance_version=artifact.artifact_id,
        config=_config(),
    ) == "canary"
    assert runner.select_guidance(
        context_ref=context_ref,
        objective_bucket="shell",
        exposure_ref="shell-1",
        config=_config(),
    ) == (None, None)


def test_activation_scope_drift_stops_an_admitted_canary(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_automatic_grant", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "_coordinator_candidate_approved", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_candidate_evidence_matches", lambda **_kwargs: True)
    publication_current = [True, False]
    monkeypatch.setattr(
        runner, "_published_candidate_matches",
        lambda **_kwargs: publication_current.pop(0),
    )
    artifact = _artifact(context_ref, "guide-scope-drift")
    _seed_candidate(
        state_store,
        candidate_id="candidate-scope-drift",
        artifact=artifact,
        replay={"decision": "review_only", "reason": "missing_baseline"},
    )
    assert runner.consider_candidate(
        context_ref=context_ref,
        candidate_id="candidate-scope-drift",
        objective_bucket="reasoning",
        guidance_version=artifact.artifact_id,
        config=_config(),
    ) == "canary"

    assert runner.select_guidance(
        context_ref=context_ref,
        objective_bucket="reasoning",
        exposure_ref="message-after-scope-change",
        config=_config(),
    ) == (None, None)
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT state,reason_code FROM autopilot_transitions WHERE candidate_id=?",
            ("candidate-scope-drift",),
        ).fetchone()
    assert tuple(row) == ("recovery_required", "authority_drift")


def test_calibrated_hard_failure_prevents_promotion(tmp_path, monkeypatch) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_automatic_grant", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "_published_candidate_matches", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_coordinator_candidate_approved", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_candidate_evidence_matches", lambda **_kwargs: True)
    artifact = _artifact(context_ref)
    _seed_candidate(
        state_store,
        candidate_id="candidate-hard-failure",
        artifact=artifact,
        replay={"decision": "review_only", "reason": "missing_baseline"},
    )
    assert runner.consider_candidate(
        context_ref=context_ref,
        candidate_id="candidate-hard-failure",
        objective_bucket="reasoning",
        guidance_version=artifact.artifact_id,
        config=_config(),
    ) == "canary"
    result = runner.record_outcome(
        runner.TransitionSelection(
            "candidate-hard-failure", context_ref, "reasoning",
            artifact.artifact_id, "canary", "candidate", "hard-exposure",
        ),
        success=False,
        config=_config(),
        hard_failure=True,
    )
    assert result == "rejected"
    assert state_store.store.get_active_guidance(context_ref, "reasoning") is None


def test_ordinary_failure_uses_rate_margin_and_duplicate_exposure_is_inert(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_automatic_grant", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "_published_candidate_matches", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_coordinator_candidate_approved", lambda **_kwargs: True)
    monkeypatch.setattr(runner, "_candidate_evidence_matches", lambda **_kwargs: True)
    artifact = _artifact(context_ref, "guide-ordinary-failure")
    _seed_candidate(
        state_store,
        candidate_id="candidate-ordinary-failure",
        artifact=artifact,
        replay={"decision": "review_only", "reason": "missing_baseline"},
    )
    assert runner.consider_candidate(
        context_ref=context_ref,
        candidate_id="candidate-ordinary-failure",
        objective_bucket="reasoning",
        guidance_version=artifact.artifact_id,
        config=_config(),
    ) == "canary"
    selection = runner.TransitionSelection(
        "candidate-ordinary-failure", context_ref, "reasoning",
        artifact.artifact_id, "canary", "candidate", "exposure-1",
    )
    assert runner.record_outcome(
        selection, success=False, config=_config()
    ) == "canary"
    assert runner.record_outcome(
        selection, success=False, config=_config()
    ) == "duplicate_outcome"
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT canary_observations,canary_failures,state FROM autopilot_transitions WHERE candidate_id=?",
            ("candidate-ordinary-failure",),
        ).fetchone()
        receipts = connection.execute(
            "SELECT COUNT(*) AS count FROM autopilot_transition_outcomes WHERE candidate_id=?",
            ("candidate-ordinary-failure",),
        ).fetchone()["count"]
    assert dict(row) == {
        "canary_observations": 1, "canary_failures": 1, "state": "canary"
    }
    assert receipts == 1


def test_expired_canary_is_terminal_before_prompt_exposure(tmp_path, monkeypatch) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_transition_binding_matches", lambda *_args: True)
    artifact = _artifact(context_ref, "guide-expired")
    state_store.store.append_guidance_version(
        artifact.artifact_id, context_ref, "reasoning", "objective",
        render_guidance_artifact(artifact), {"guidance_artifact": artifact.to_mapping()},
    )
    now = datetime.now(timezone.utc).timestamp()
    with state_store.store._connect() as connection:
        connection.execute(
            "INSERT INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,expected_active_revision,state,reason_code,created_at,updated_at,policy_id,policy_digest,calibration_id,calibration_digest,canary_plan_id,canary_plan_digest,monitor_plan_id,monitor_plan_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "candidate-expired", context_ref, "reasoning", artifact.artifact_id,
                0, "canary", "candidate_admitted", now - 3601, now - 3601,
                *binding.identities(),
            ),
        )
    assert runner.select_guidance(
        context_ref=context_ref, objective_bucket="reasoning",
        exposure_ref="late-exposure", config=_config(),
    ) == (None, None)
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT state,reason_code FROM autopilot_transitions WHERE candidate_id='candidate-expired'"
        ).fetchone()
    assert tuple(row) == ("rejected", "canary_expired")


def test_reconciliation_retries_when_publication_authority_is_unavailable(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_automatic_grant", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "_candidate_evidence_matches", lambda **_kwargs: True)
    artifact = _artifact(context_ref, "guide-retry-publication")
    _seed_candidate(
        state_store, candidate_id="candidate-retry-publication", artifact=artifact,
        replay={"decision": "review_only", "reason": "missing_baseline"},
    )
    candidate = state_store.store.get_candidate(
        "candidate-retry-publication", context_id=context_ref
    )
    with state_store.store._connect() as connection:
        connection.execute(
            "INSERT INTO autopilot_candidate_approvals(candidate_id,job_key,fencing_token,candidate_digest,approved_at,config_digest) VALUES(?,?,?,?,?,?)",
            (
                "candidate-retry-publication", "job-retry", 1,
                candidate["candidate_digest"], datetime.now(timezone.utc).timestamp(),
                __import__(
                    "usr.plugins.dspy_rlm.helpers.v3.autopilot_control_plane",
                    fromlist=["effective_config_digest"],
                ).effective_config_digest(_config()),
            ),
        )
    availability = [None, True]
    monkeypatch.setattr(
        runner, "_published_candidate_matches", lambda **_kwargs: availability.pop(0)
    )
    assert runner.reconcile_candidates(
        context_ref=context_ref, config=_config()
    ) == "authority_unavailable"
    with state_store.store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM autopilot_candidate_considerations"
        ).fetchone()[0] == 0
    assert runner.reconcile_candidates(
        context_ref=context_ref, config=_config()
    ) == "canary"


def test_restart_retries_decided_pointer_mutation_without_new_evidence(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_transition_binding_matches", lambda *_args: True)
    monkeypatch.setattr(
        runner, "_authorized_pointer_mutation",
        lambda *, mutate, **_kwargs: mutate(),
    )
    artifact = _artifact(context_ref, "guide-restart")
    state_store.store.append_guidance_version(
        artifact.artifact_id, context_ref, "reasoning", "objective",
        render_guidance_artifact(artifact), {"guidance_artifact": artifact.to_mapping()},
    )
    now = datetime.now(timezone.utc).timestamp()
    with state_store.store._connect() as connection:
        connection.execute(
            "INSERT INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,expected_active_revision,state,reason_code,created_at,updated_at,policy_id,policy_digest,calibration_id,calibration_digest,canary_plan_id,canary_plan_digest,monitor_plan_id,monitor_plan_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "candidate-restart", context_ref, "reasoning", artifact.artifact_id,
                0, "promoting", "canary_passed", now, now, *binding.identities(),
            ),
        )
    runner.resume_incomplete_transitions(context_ref=context_ref, config=_config())
    active = state_store.store.get_active_guidance(context_ref, "reasoning")
    assert active is not None and active["guidance_version"] == artifact.artifact_id
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT state,expected_active_revision FROM autopilot_transitions WHERE candidate_id='candidate-restart'"
        ).fetchone()
        assert connection.execute(
            "SELECT COUNT(*) FROM autopilot_transition_outcomes"
        ).fetchone()[0] == 0
    assert tuple(row) == ("monitoring", 1)
    with state_store.store._connect() as connection:
        connection.execute(
            "UPDATE autopilot_transitions SET state='rolling_back',reason_code='monitor_regression' WHERE candidate_id='candidate-restart'"
        )
    runner.resume_incomplete_transitions(context_ref=context_ref, config=_config())
    assert state_store.store.get_active_guidance(context_ref, "reasoning") is None
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT state FROM autopilot_transitions WHERE candidate_id='candidate-restart'"
        ).fetchone()
    assert row["state"] == "rolled_back"


def test_restart_recovers_lost_promotion_ack_without_second_cas(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    artifact = _artifact(context_ref, "guide-lost-promotion-ack")
    state_store.store.append_guidance_version(
        artifact.artifact_id, context_ref, "reasoning", "objective",
        render_guidance_artifact(artifact), {"guidance_artifact": artifact.to_mapping()},
    )
    assert state_store.store.compare_and_swap_active_guidance(
        context_ref, "reasoning", artifact.artifact_id, expected_revision=0,
    ) == (True, 1)
    now = datetime.now(timezone.utc).timestamp()
    with state_store.store._connect() as connection:
        connection.execute(
            "INSERT INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,expected_active_revision,state,reason_code,created_at,updated_at,policy_id,policy_digest,calibration_id,calibration_digest,canary_plan_id,canary_plan_digest,monitor_plan_id,monitor_plan_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "candidate-lost-promotion-ack", context_ref, "reasoning",
                artifact.artifact_id, 0, "promoting", "canary_passed", now, now,
                *binding.identities(),
            ),
        )
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_transition_binding_matches", lambda *_args: True)
    monkeypatch.setattr(
        runner, "_authorized_pointer_mutation",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("CAS must not repeat")),
    )

    runner.resume_incomplete_transitions(context_ref=context_ref, config=_config())
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT state,reason_code,expected_active_revision FROM autopilot_transitions WHERE candidate_id=?",
            ("candidate-lost-promotion-ack",),
        ).fetchone()
    assert tuple(row) == ("monitoring", "promotion_recovered", 1)


def test_restart_recovers_lost_rollback_ack_without_second_cas(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    artifact = _artifact(context_ref, "guide-lost-rollback-ack")
    state_store.store.append_guidance_version(
        artifact.artifact_id, context_ref, "reasoning", "objective",
        render_guidance_artifact(artifact), {"guidance_artifact": artifact.to_mapping()},
    )
    assert state_store.store.compare_and_swap_active_guidance(
        context_ref, "reasoning", artifact.artifact_id, expected_revision=0,
    ) == (True, 1)
    assert state_store.store.clear_active_guidance(
        context_ref, "reasoning", expected_revision=1,
    ) == (True, 2)
    now = datetime.now(timezone.utc).timestamp()
    with state_store.store._connect() as connection:
        connection.execute(
            "INSERT INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,expected_active_revision,state,reason_code,created_at,updated_at,policy_id,policy_digest,calibration_id,calibration_digest,canary_plan_id,canary_plan_digest,monitor_plan_id,monitor_plan_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "candidate-lost-rollback-ack", context_ref, "reasoning",
                artifact.artifact_id, 1, "rolling_back", "monitor_regression", now,
                now, *binding.identities(),
            ),
        )
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_transition_binding_matches", lambda *_args: True)
    monkeypatch.setattr(
        runner, "_authorized_pointer_mutation",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("CAS must not repeat")),
    )

    runner.resume_incomplete_transitions(context_ref=context_ref, config=_config())
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT state,reason_code FROM autopilot_transitions WHERE candidate_id=?",
            ("candidate-lost-rollback-ack",),
        ).fetchone()
    assert tuple(row) == ("rolled_back", "rollback_recovered")


def test_restart_rejects_expired_candidate_before_unapplied_promotion(
    tmp_path, monkeypatch,
) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_transition_binding_matches", lambda *_args: True)
    monkeypatch.setattr(
        runner,
        "_authorized_pointer_mutation",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("CAS must not run")),
    )
    artifact = _artifact(context_ref, "guide-expired-promotion", expired=True)
    state_store.store.append_guidance_version(
        artifact.artifact_id, context_ref, "reasoning", "objective",
        "Expired candidate fixture", {"guidance_artifact": artifact.to_mapping()},
    )
    now = datetime.now(timezone.utc).timestamp()
    with state_store.store._connect() as connection:
        connection.execute(
            "INSERT INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,expected_active_revision,state,reason_code,created_at,updated_at,policy_id,policy_digest,calibration_id,calibration_digest,canary_plan_id,canary_plan_digest,monitor_plan_id,monitor_plan_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "candidate-expired-promotion", context_ref, "reasoning",
                artifact.artifact_id, 0, "promoting", "canary_passed", now, now,
                *binding.identities(),
            ),
        )
    runner.resume_incomplete_transitions(context_ref=context_ref, config=_config())
    assert state_store.store.get_active_guidance(context_ref, "reasoning") is None
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT state,reason_code FROM autopilot_transitions WHERE candidate_id=?",
            ("candidate-expired-promotion",),
        ).fetchone()
    assert tuple(row) == ("rejected", "candidate_artifact_unavailable")


def test_unknown_outcome_never_advances_canary(tmp_path, monkeypatch) -> None:
    state_store = StateStore(tmp_path)
    context_ref = "context-auto"
    binding = _binding(context_ref)
    monkeypatch.setattr(runner.state, "_store_for_root", lambda: state_store)
    monkeypatch.setattr(runner, "_authority_binding", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(runner, "_transition_binding_matches", lambda *_args: True)
    artifact = _artifact(context_ref, "guide")
    state_store.store.append_guidance_version(
        artifact.artifact_id,
        context_ref,
        "reasoning",
        "objective",
        render_guidance_artifact(artifact),
        {"guidance_artifact": artifact.to_mapping()},
    )
    now = datetime.now(timezone.utc).timestamp()
    with state_store.store._connect() as connection:
        connection.execute(
            "INSERT INTO autopilot_transitions(candidate_id,context_id,objective_bucket,guidance_version,expected_active_revision,state,reason_code,created_at,updated_at,policy_id,policy_digest,calibration_id,calibration_digest,canary_plan_id,canary_plan_digest,monitor_plan_id,monitor_plan_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "candidate", context_ref, "reasoning", "guide", 0, "canary",
                "candidate_admitted", now, now, *binding.identities(),
            ),
        )
    selection = runner.TransitionSelection(
        "candidate", context_ref, "reasoning", "guide", "canary", "candidate",
        "unknown-exposure",
    )
    assert runner.record_outcome(
        selection, success=None, config=_config()
    ) == "outcome_unknown"
    with state_store.store._connect() as connection:
        row = connection.execute(
            "SELECT canary_observations FROM autopilot_transitions WHERE candidate_id='candidate'"
        ).fetchone()
    assert row["canary_observations"] == 0
