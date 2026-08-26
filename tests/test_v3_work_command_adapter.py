from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from usr.plugins.dspy_rlm.helpers.v3 import V3Repository, null_guidance_artifact
from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant, digest_idempotency_key
from usr.plugins.dspy_rlm.helpers.v3.work_authority import (
    ClaimConditions,
    FinalizationConditions,
    LeaseIdentity,
    PublicationWriteSet,
    StaleFence,
    WORK_AUTHORITY_REGISTRY,
    WorkCoordinator,
)
from usr.plugins.dspy_rlm.helpers.v3.work_command_adapter import (
    SafeWorkCommandAdapter,
    WorkPolicyFacts,
)


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
CONTEXT = "context.work"
SESSION = "browser.session.000000000000000001"


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _store(tmp_path: Path):
    repository = V3Repository.create(
        tmp_path / "safe.sqlite3", registry=WORK_AUTHORITY_REGISTRY
    )
    input_record = null_guidance_artifact()
    with repository.transaction() as transaction:
        transaction.insert_record(input_record)
    return repository, input_record


def _optimize(input_record, *, work_id: str = "work.optimize.1") -> dict[str, object]:
    return {
        "schema": "a0.command.optimize.v1",
        "action": "optimize",
        "context_ref": CONTEXT,
        "target_ref": work_id,
        "expected_revision": 0,
        "idempotency_key": "work-key-1",
        "authority_grant_id": "grant.optimize.1",
        "policy_ref": "policy.work.v1",
        "operator_reason_code": "operator_requested",
        "work_id": work_id,
        "operation_kind": "candidate_search",
        "input_record": {
            "record_id": input_record.record_id,
            "digest": input_record.content_digest,
        },
        "budget_ledger_id": None,
        "max_attempts": 2,
        "available_at": _timestamp(NOW),
        "deadline_at": _timestamp(NOW + timedelta(hours=1)),
        "created_at": _timestamp(NOW),
    }


def _grant(payload: dict[str, object], *, now: datetime) -> VerifiedGrant:
    return VerifiedGrant(
        grant_id=payload["authority_grant_id"],  # type: ignore[arg-type]
        authority_class="operator_authority_grant",
        issuer_id="issuer.local",
        key_epoch=1,
        subject_ref="operator.local",
        context_ref=payload["context_ref"],  # type: ignore[arg-type]
        action=payload["action"],  # type: ignore[arg-type]
        purpose="operator_mutation",
        target_ref=payload["target_ref"],  # type: ignore[arg-type]
        target_revision=payload["expected_revision"],  # type: ignore[arg-type]
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=10),
        idempotency_key_digest=digest_idempotency_key(
            payload["idempotency_key"]  # type: ignore[arg-type]
        ),
        session_nonce=SESSION,
    )


def _handle(adapter, payload, *, now=NOW, policy=lambda _facts: True):
    return adapter.handle(
        payload,
        bound_context_ref=CONTEXT,
        bound_session_nonce=SESSION,
        now=now,
        revalidate_grant=lambda: _grant(payload, now=now),
        revalidate_policy=policy,
    )


def test_closed_schema_and_explicit_policy_fail_before_work_state(tmp_path: Path) -> None:
    repository, input_record = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        adapter = SafeWorkCommandAdapter(coordinator)
        malformed = {**_optimize(input_record), "force": True}
        calls: list[tuple[WorkPolicyFacts, bool]] = []

        syntax = _handle(adapter, malformed)
        denied = _handle(
            adapter,
            _optimize(input_record),
            policy=lambda facts: calls.append(
                (facts, repository._connection.in_transaction)
            )
            is None
            and False,
        )

        assert syntax.status_code == 400
        assert denied.status_code == 422
        assert calls[0][0].max_attempts == 2
        assert calls[0][0].budget_ledger_id is None
        assert calls[0][0].command_at == NOW
        assert calls[0][0].cancellation_identity is None
        assert calls[0][1] is True
        assert coordinator.get("work.optimize.1") is None


def test_optimize_only_enqueues_and_exact_replay_is_200(tmp_path: Path) -> None:
    repository, input_record = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        adapter = SafeWorkCommandAdapter(coordinator)
        payload = _optimize(input_record)

        accepted = _handle(adapter, payload)
        replay = _handle(adapter, payload)

        assert accepted.status_code == 202
        assert accepted.body["work_state"] == "queued"
        assert accepted.body["receipt_ref"] == replay.body["receipt_ref"]
        assert accepted.body["observed_revision"] == 0
        assert accepted.body["resulting_revision"] == 0
        assert accepted.body["policy_ref"] == "policy.work.v1"
        assert accepted.body["replayed"] is False
        assert replay.status_code == 200
        assert replay.body["reason_codes"] == ["exact_replay"]
        assert coordinator.get("work.optimize.1").attempt_count == 0


def test_optimize_same_key_with_different_frozen_target_is_conflict(tmp_path: Path) -> None:
    repository, input_record = _store(tmp_path)
    with repository:
        adapter = SafeWorkCommandAdapter(WorkCoordinator(repository))
        assert _handle(adapter, _optimize(input_record)).status_code == 202
        before = repository._connection.execute(
            "SELECT COUNT(*) FROM typed_records WHERE schema_id = ?",
            ("a0.work-mutation-receipt.v1",),
        ).fetchone()[0]

        conflict = _optimize(input_record, work_id="work.optimize.2")
        conflict["authority_grant_id"] = "grant.optimize.2"
        result = _handle(adapter, conflict)

        assert result.status_code == 409
        assert result.body["reason_codes"] == ["work_command_conflict"]
        assert result.body["receipt_ref"] is None
        after = repository._connection.execute(
            "SELECT COUNT(*) FROM typed_records WHERE schema_id = ?",
            ("a0.work-mutation-receipt.v1",),
        ).fetchone()[0]
        assert after == before


def test_cancel_advances_fence_blocks_late_publication_and_completes_cleanup(
    tmp_path: Path,
) -> None:
    repository, input_record = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        adapter = SafeWorkCommandAdapter(coordinator)
        optimize = _optimize(input_record)
        assert _handle(adapter, optimize).status_code == 202
        lease = coordinator.claim(
            work_id="work.optimize.1",
            attempt_id="attempt.1",
            owner_id="owner.1",
            process_nonce="process.nonce.1",
            process_start_identity="process.start.1",
            now=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
            conditions=ClaimConditions(True, True, True, True),
        )
        identity = LeaseIdentity(
            lease.work_id,
            lease.attempt_id,
            lease.owner_id,
            lease.fence_token,
            lease.process_nonce,
            lease.process_start_identity,
        )
        requested_at = NOW + timedelta(minutes=2)
        request = {
            "schema": "a0.command.work-cancel.v1",
            "action": "work_cancel",
            "context_ref": CONTEXT,
            "target_ref": "work.optimize.1",
            "expected_revision": identity.fence_token,
            "idempotency_key": "cancel-request-key-1",
            "authority_grant_id": "grant.cancel.request.1",
            "policy_ref": "policy.work.v1",
            "operator_reason_code": "operator_requested",
            "phase": "request",
            "work_id": "work.optimize.1",
            "now": _timestamp(requested_at),
        }

        cancellation = _handle(adapter, request, now=requested_at)

        assert cancellation.status_code == 202
        assert cancellation.body["fence_revision"] == identity.fence_token + 1
        assert cancellation.body["receipt_ref"] is not None
        with pytest.raises(StaleFence):
            coordinator.finalize(
                identity=identity,
                now=NOW + timedelta(minutes=3),
                authority_revalidator=lambda *_args: FinalizationConditions(
                    True, True, True, True, True, True, True
                ),
                publication_planner=lambda: PublicationWriteSet((), ()),
            )

        completed_at = NOW + timedelta(minutes=3)
        complete = {
            "schema": "a0.command.work-cancel.v1",
            "action": "work_cancel",
            "context_ref": CONTEXT,
            "target_ref": "work.optimize.1",
            "expected_revision": identity.fence_token + 1,
            "idempotency_key": "cancel-complete-key-1",
            "authority_grant_id": "grant.cancel.complete.1",
            "policy_ref": "policy.work.v1",
            "operator_reason_code": "operator_requested",
            "phase": "complete",
            "work_id": "work.optimize.1",
            "now": _timestamp(completed_at),
            "expired_identity": {
                "work_id": identity.work_id,
                "attempt_id": identity.attempt_id,
                "owner_id": identity.owner_id,
                "fence_token": identity.fence_token,
                "process_nonce": identity.process_nonce,
                "process_start_identity": identity.process_start_identity,
            },
            "cleanup": {
                "cleanup_confirmed": True,
                "process_identity_verified": True,
                "staging_cleanup_verified": True,
            },
        }
        terminal = _handle(adapter, complete, now=completed_at)

        assert terminal.status_code == 200
        assert terminal.body["work_state"] == "cancelled"
        assert coordinator.get("work.optimize.1").state == "cancelled"
