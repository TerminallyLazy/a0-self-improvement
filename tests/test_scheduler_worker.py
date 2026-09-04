from __future__ import annotations

from types import SimpleNamespace

import pytest

from usr.plugins.dspy_rlm.helpers.scheduler import worker


def test_worker_optimizer_defers_unfenced_context_state(monkeypatch) -> None:
    captured = []
    monkeypatch.setattr(
        worker.optimizer, "run_optimization_sync",
        lambda context_id, cfg, **kwargs: captured.append(
            (context_id, cfg, kwargs)
        ) or {"status": "candidate"},
    )
    assert worker._run_without_promotion("ctx", {"enabled": True}, False) == {
        "status": "candidate"
    }
    assert captured == [
        (
            "ctx", {"enabled": True},
            {"force": False, "manage_context_state": False},
        )
    ]


def test_fenced_worker_ignores_only_the_queue_owned_running_marker(monkeypatch) -> None:
    monkeypatch.setattr(worker.optimizer.config_module, "normalize_config", lambda cfg: cfg)
    monkeypatch.setattr(
        worker.optimizer.RuntimePolicy, "from_config",
        lambda _cfg: SimpleNamespace(reasons_for=lambda *_args, **_kwargs: ()),
    )
    monkeypatch.setattr(
        worker.optimizer.state_module, "load_context_state",
        lambda _context: {"optimization_running": True},
    )
    monkeypatch.setattr(worker.optimizer.trace, "summarize_context", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(worker.optimizer, "_collect_objectives", lambda *_args, **_kwargs: [])

    result = worker.optimizer.run_optimization_sync(
        "ctx", {"optimization": {"min_samples_for_promotion": 10}},
        force=False, manage_context_state=False,
    )

    assert result["reason"] == "not_enough_objectives"


def test_worker_copy_preserves_complete_manifest_evidence_chain(monkeypatch) -> None:
    identifiers = {
        "run_id": "run-1",
        "candidate_id": "candidate-1",
        "evaluation_id": "evaluation-1",
        "replay_audit_id": "audit-1",
        "training_manifest_id": "training-1",
        "replay_manifest_id": "replay-1",
    }
    artifact = SimpleNamespace(
        artifact_id="guide-1",
        objective_bucket="reasoning",
        to_mapping=lambda: {"artifact_id": "guide-1"},
    )
    result = {
        **identifiers,
        "status": "candidate",
        "guidance": "fixed guidance",
        "guidance_version": "guide-1",
        "guidance_metadata": {"guidance_artifact": {"artifact_id": "guide-1"}},
        "objective_rows": [],
        "replay_manifest": {"manifest_id": "replay-1", "cases": []},
        "validation": {"passed": True},
        "replay_audit": {},
    }
    captured_runs: list[dict[str, object]] = []

    class FakeStore:
        def append_manifest(self, *_args, **_kwargs):
            return None

        def append_run(self, _run_id, _context_id, _status, body):
            captured_runs.append(dict(body))

        def append_candidate(
            self, candidate_id, context_id, objective_bucket, body, **kwargs
        ):
            self.persisted = {
                "candidate_id": candidate_id,
                "context_id": context_id,
                "objective_bucket": objective_bucket,
                "guidance_version": kwargs["guidance_version"],
                "candidate": dict(body),
                "candidate_digest": "digest-1",
            }

        def append_evaluation(self, *_args, **_kwargs):
            return None

        def append_replay_audit(self, *_args, **_kwargs):
            return None

        def get_candidate(self, *_args, **_kwargs):
            return self.persisted

    store = FakeStore()
    queue = SimpleNamespace(
        state=SimpleNamespace(store=store),
        store=store,
        is_cancelled=lambda _job: False,
        heartbeat=lambda _lease, _seconds: True,
        heartbeat_worker=lambda *_args, **_kwargs: None,
    )
    lease = SimpleNamespace(job_key="job-1", worker_id="worker-1", fencing_token=1)
    monkeypatch.setattr(worker, "_run_without_promotion", lambda *_args, **_kwargs: dict(result))
    monkeypatch.setattr(worker, "validate_guidance_artifact", lambda _value: artifact)
    monkeypatch.setattr(
        worker, "PromotionCoordinator",
        lambda **_kwargs: SimpleNamespace(stage=lambda *_args, **_kwargs: "guide-1"),
    )
    monkeypatch.setattr(worker.config_module, "normalize_config", lambda cfg: cfg)

    copied, terminal = worker._execute_job(
        queue,
        {
            "lease": lease,
            "context_id": "ctx",
            "attempts": 1,
            "objective_bucket": "reasoning",
            "payload": {"config": {}},
        },
        {},
        {"lease": 45, "heartbeat": 8, "worker_ttl": 180},
    )

    assert terminal == "candidate"
    assert copied["candidate_id"] == "candidate-1"
    assert captured_runs == [
        {
            "run_id": "run-1",
            "candidate_id": "candidate-1",
            "guidance_version": "guide-1",
            "objective_bucket": "reasoning",
            "validation": {"passed": True},
            "training_manifest_id": "training-1",
            "replay_manifest_id": "replay-1",
            "replay_audit_id": "audit-1",
        }
    ]


@pytest.mark.parametrize(
    ("terminal", "job_status", "expected_running"),
    (("candidate", "cancelled", False), ("lost_lease", "pending", True)),
)
def test_worker_reconciles_context_cache_when_final_fence_is_rejected(
    monkeypatch, terminal: str, job_status: str, expected_running: bool,
) -> None:
    updates = []

    class FakeState:
        def __init__(self, _plugin_dir):
            self.store = self

        def set_context_state(self, context_id, update):
            updates.append((context_id, dict(update)))

    class FakeQueue:
        def __init__(self, *, state_store):
            self.state = state_store
            self.claimed = False

        def reclaim_expired(self):
            return 0

        def heartbeat_worker(self, *_args, **_kwargs):
            return None

        def claim(self, *_args, **_kwargs):
            if self.claimed:
                return None
            self.claimed = True
            return {
                "context_id": "ctx", "attempts": 1,
                "lease": SimpleNamespace(job_key="job", worker_id="worker", fencing_token=1),
            }

        def complete(self, *_args, **_kwargs):
            return False

        def get(self, _job_key):
            return {"status": job_status, "last_error": "fenced"}

    monkeypatch.setattr(worker.state_module, "StateStore", FakeState)
    monkeypatch.setattr(worker, "LocalMultiprocessQueue", FakeQueue)
    monkeypatch.setattr(worker.config_module, "load_config", lambda _agent: {})
    monkeypatch.setattr(worker.config_module, "normalize_config", lambda cfg: cfg)
    monkeypatch.setattr(
        worker, "_execute_job", lambda *_args, **_kwargs: ({}, terminal)
    )
    assert worker.worker_loop("plugin", "worker", once=True) == 1
    assert updates[-1][0] == "ctx"
    assert updates[-1][1]["optimization_status"] == job_status
    assert updates[-1][1]["optimization_running"] is expected_running
