"""Task 7 contract coverage for coordinator-owned guidance promotion."""
from __future__ import annotations

import json

import pytest

from usr.plugins.dspy_rlm.helpers.promotion import PromotionCoordinator
from usr.plugins.dspy_rlm.helpers.state import StateStore


@pytest.fixture
def coordinator(tmp_path) -> PromotionCoordinator:
    return PromotionCoordinator(state_store=StateStore(tmp_path), coordinator_id="test-coordinator")


def test_stage_is_immutable_and_does_not_change_the_active_pointer(coordinator: PromotionCoordinator) -> None:
    version = coordinator.stage("ctx-1", "reasoning", "Use concise steps.", objective_signature="sig-1", metadata={"source": "worker"})

    staged = coordinator.store.get_guidance_version(version)
    assert staged is not None
    assert staged["guidance_text"] == "Use concise steps."
    assert staged["metadata"] == {"source": "worker"}
    assert coordinator.current("ctx-1", "reasoning") is None

    # Re-staging a caller-supplied immutable ID must not replace its artifact.
    assert coordinator.stage("ctx-1", "reasoning", "Replacement", guidance_version=version) == version
    assert coordinator.store.get_guidance_version(version)["guidance_text"] == "Use concise steps."


def test_coordinator_refuses_unevaluated_first_promotion(coordinator: PromotionCoordinator) -> None:
    version = coordinator.stage("ctx-1", "reasoning", "First")

    decision = coordinator.promote("ctx-1", "reasoning", version, expected_revision=0)

    assert not decision.applied
    assert decision.reason == "missing_active_baseline"
    assert coordinator.current("ctx-1", "reasoning") is None

    with coordinator.store._connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM promotion_audits").fetchone()[0]
    assert count == 0


def test_null_baseline_evidence_chain_is_complete_and_digest_verified(
    coordinator: PromotionCoordinator,
) -> None:
    ids = {
        "run_id": "run-1",
        "candidate_id": "candidate-1",
        "evaluation_id": "evaluation-1",
        "replay_audit_id": "audit-1",
        "replay_manifest_id": "replay-manifest-1",
        "training_manifest_id": "training-manifest-1",
    }
    metadata = {"persistence": ids}
    version = coordinator.stage(
        "ctx-1", "reasoning", "Candidate", guidance_version="guide-1",
        metadata=metadata,
    )
    replay_manifest = {
        "manifest_id": ids["replay_manifest_id"], "digest": "a" * 64,
    }
    coordinator.store.append_manifest(
        ids["training_manifest_id"], "ctx-1", "optimization_training", [],
        {"objective_bucket": "reasoning"},
    )
    coordinator.store.append_manifest(
        ids["replay_manifest_id"], "ctx-1", "paired_replay", [], replay_manifest,
    )
    coordinator.store.append_run(
        ids["run_id"], "ctx-1", "candidate",
        {
            **ids, "guidance_version": version,
            "objective_bucket": "reasoning",
        },
    )
    candidate = {
        "candidate_id": ids["candidate_id"], "run_id": ids["run_id"],
        "guidance_version": version, "guidance_metadata": metadata,
        "validation": {"passed": True},
        "replay_audit_id": ids["replay_audit_id"],
        "replay_manifest_id": ids["replay_manifest_id"],
    }
    coordinator.store.append_candidate(
        ids["candidate_id"], "ctx-1", "reasoning", candidate,
        run_id=ids["run_id"], guidance_version=version,
    )
    coordinator.store.append_evaluation(
        ids["evaluation_id"], ids["candidate_id"],
        {
            "run_id": ids["run_id"], "validation": {"passed": True},
            "replay_manifest_id": ids["replay_manifest_id"],
        },
    )
    coordinator.store.append_replay_audit(
        ids["replay_audit_id"], ids["candidate_id"],
        {
            "decision": "review_only", "reason": "missing_baseline",
            "promotion_ready": False, "passed": False,
            "manifest_id": ids["replay_manifest_id"],
            "manifest_digest": replay_manifest["digest"],
            "provenance": {"candidate_guidance_version": version},
        },
        manifest_id=ids["replay_manifest_id"],
    )
    evidence, reason = coordinator.verified_evidence_chain(
        "ctx-1", "reasoning", version, None, allow_missing_baseline=True
    )
    assert evidence is not None and reason == ""
    evidence, reason = coordinator.verified_evidence_chain(
        "ctx-1", "reasoning", version, None, allow_missing_baseline=True,
        expected_candidate_id="candidate-other",
    )
    assert evidence is None and reason == "promotion_evidence_linkage_mismatch"
    with coordinator.store._connect() as connection:
        original_run = connection.execute(
            "SELECT run_json FROM optimization_runs WHERE run_id=?", (ids["run_id"],)
        ).fetchone()["run_json"]
        connection.execute(
            "UPDATE optimization_runs SET run_json='{\"tampered\":true}' WHERE run_id=?",
            (ids["run_id"],),
        )
    evidence, reason = coordinator.verified_evidence_chain(
        "ctx-1", "reasoning", version, None, allow_missing_baseline=True
    )
    assert evidence is None and reason == "persisted_evidence_digest_mismatch"
    with coordinator.store._connect() as connection:
        connection.execute(
            "UPDATE optimization_runs SET run_json=? WHERE run_id=?",
            (original_run, ids["run_id"]),
        )
    with coordinator.store._connect() as connection:
        connection.execute(
            "UPDATE evaluations SET evaluation_json='{\"tampered\":true}' WHERE evaluation_id=?",
            (ids["evaluation_id"],),
        )
    evidence, reason = coordinator.verified_evidence_chain(
        "ctx-1", "reasoning", version, None, allow_missing_baseline=True
    )
    assert evidence is None and reason == "persisted_evidence_digest_mismatch"


def test_rollback_is_cas_protected_and_keeps_audit_history(coordinator: PromotionCoordinator) -> None:
    v1 = coordinator.stage("ctx-1", "reasoning", "Known-good")
    v2 = coordinator.stage("ctx-1", "reasoning", "Regression")
    # An existing promoted version is a fixture precondition. New versions must
    # use the evidence-gated promote path and cannot bootstrap themselves.
    applied, revision = coordinator.store.compare_and_swap_active_guidance(
        "ctx-1", "reasoning", v2, expected_revision=0,
        actor_id="fixture", detail={"fixture": True}, action="fixture",
    )
    assert applied and revision == 1

    conflict = coordinator.rollback("ctx-1", "reasoning", v1, expected_revision=0)
    assert not conflict.applied
    assert conflict.reason == "active_revision_conflict"

    restored = coordinator.rollback("ctx-1", "reasoning", v1, expected_revision=1, detail={"why": "regression"})
    assert restored.applied
    assert restored.action == "rollback"
    assert restored.previous_guidance_version == v2
    assert restored.resulting_revision == 2
    active = coordinator.current("ctx-1", "reasoning")
    assert active is not None
    assert active["guidance_version"] == v1
    assert active["revision"] == 2

    with coordinator.store._connect() as conn:
        audit = conn.execute(
            "SELECT action,previous_guidance_version,guidance_version,expected_revision,resulting_revision,actor_id,detail_json "
            "FROM promotion_audits WHERE action='rollback'"
        ).fetchone()
    assert tuple(audit[0:6]) == ("rollback", v2, v1, 1, 2, "coordinator:test-coordinator")
    assert json.loads(audit[6]) == {"authority": "coordinator", "why": "regression"}
