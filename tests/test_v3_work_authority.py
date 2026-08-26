from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from usr.plugins.dspy_rlm.helpers.v3 import (
    DomainEvent,
    V3Repository,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.work_authority import (
    BudgetBroker,
    BudgetExceeded,
    ClaimConditions,
    DeadlineExceeded,
    FinalizationConditions,
    LeaseIdentity,
    PublicationWriteSet,
    RecoveryConditions,
    StaleFence,
    WORK_AUTHORITY_REGISTRY,
    WorkCoordinator,
    WorkEnqueue,
    WorkMutationAuthority,
    WorkStateConflict,
)


NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
ALL_CLAIM = ClaimConditions(True, True, True, True)
ALL_FINAL = FinalizationConditions(True, True, True, True, True, True, True)
ALL_RECOVERY = RecoveryConditions(True, True, True, True, True, True, True)


def _authorize_final(_transaction, _item, _identity):
    return ALL_FINAL


def _store(tmp_path: Path):
    repository = V3Repository.create(
        tmp_path / "safe.sqlite3", registry=WORK_AUTHORITY_REGISTRY
    )
    guidance = null_guidance_artifact()
    with repository.transaction() as transaction:
        transaction.insert_record(guidance)
    return repository, guidance


def _enqueue(
    coordinator: WorkCoordinator,
    guidance,
    *,
    work_id: str = "work-1",
    key: str = "key-1",
    ledger_id: str | None = None,
    max_attempts: int = 2,
):
    key_digest = sha256(key.encode()).hexdigest()
    authority = _mutation_authority(
        action="optimize",
        phase="enqueue",
        target_ref=work_id,
        revision=0,
        key_digest=key_digest,
        at=NOW,
    )
    return coordinator.enqueue(
        WorkEnqueue(
            work_id=work_id,
            idempotency_key_digest=key_digest,
            context_ref="context-1",
            operation_kind="candidate_search",
            input_record_id=guidance.record_id,
            input_digest=guidance.content_digest,
            budget_ledger_id=ledger_id,
            max_attempts=max_attempts,
            available_at=NOW,
            deadline_at=NOW + timedelta(hours=1),
            created_at=NOW,
        ),
        authority=authority,
        authority_revalidator=lambda _transaction: _grant(authority),
    )


def _mutation_authority(
    *,
    action: str,
    phase: str,
    target_ref: str,
    revision: int,
    key_digest: str,
    at: datetime,
) -> WorkMutationAuthority:
    request_digest = sha256(
        f"{action}:{phase}:{target_ref}:{revision}:{key_digest}:{at.isoformat()}".encode()
    ).hexdigest()
    return WorkMutationAuthority(
        action=action,  # type: ignore[arg-type]
        phase=phase,  # type: ignore[arg-type]
        authority_grant_id=f"grant:{request_digest[:24]}",
        policy_ref="policy.work.v1",
        context_ref="context-1",
        target_ref=target_ref,
        target_revision=revision,
        idempotency_key_digest=key_digest,
        request_digest=request_digest,
        session_nonce="session.1",
        admitted_at=at,
    )


def _grant(authority: WorkMutationAuthority) -> VerifiedGrant:
    return VerifiedGrant(
        grant_id=authority.authority_grant_id,
        authority_class="operator_authority_grant",
        issuer_id="issuer.local",
        key_epoch=1,
        subject_ref="operator.local",
        context_ref=authority.context_ref,
        action=authority.action,
        purpose="operator_mutation",
        target_ref=authority.target_ref,
        target_revision=authority.target_revision,
        issued_at=authority.admitted_at - timedelta(seconds=1),
        expires_at=authority.admitted_at + timedelta(minutes=10),
        idempotency_key_digest=authority.idempotency_key_digest,
        session_nonce=authority.session_nonce,
    )


def _claim(
    coordinator: WorkCoordinator,
    *,
    work_id: str = "work-1",
    attempt: str = "a1",
    claimed_at: datetime = NOW + timedelta(minutes=1),
):
    lease = coordinator.claim(
        work_id=work_id,
        attempt_id=attempt,
        owner_id="owner-1",
        process_nonce=f"nonce-{attempt}",
        process_start_identity=f"pid-start-{attempt}",
        now=claimed_at,
        expires_at=claimed_at + timedelta(minutes=9),
        conditions=ALL_CLAIM,
    )
    return lease, LeaseIdentity(
        lease.work_id,
        lease.attempt_id,
        lease.owner_id,
        lease.fence_token,
        lease.process_nonce,
        lease.process_start_identity,
    )


def _ledger(broker: BudgetBroker):
    return broker.create_ledger(
        ledger_id="ledger-1",
        run_ref="run-1",
        budget_profile_ref="profile-1",
        budget_profile_digest=sha256(b"profile").hexdigest(),
        dimensions={"calls": 4, "tokens": 100},
        created_at=NOW,
    )


def test_enqueue_claim_and_fenced_finalize_publish_atomically(tmp_path: Path) -> None:
    repository, guidance = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        admission = _enqueue(coordinator, guidance)
        replay = _enqueue(coordinator, guidance)
        assert admission.replayed is False
        assert replay.replayed is True

        lease, identity = _claim(coordinator)
        assert lease.fence_token == 1
        prompt = null_prompt_patch_artifact()
        event = DomainEvent(
            event_id="work-1:completed",
            subject_id="work-1",
            subject_kind="work_item",
            sequence=0,
            event_type="publication_completed",
            payload_record_id=prompt.record_id,
            actor_authority_ref="coordinator-1",
            fence_token=identity.fence_token,
        )
        completed = coordinator.finalize(
            identity=identity,
            now=NOW + timedelta(minutes=2),
            authority_revalidator=_authorize_final,
            publication_planner=lambda: PublicationWriteSet((prompt,), (event,)),
        )
        assert completed.state == "completed"
        assert repository.get_record(prompt.record_id) == prompt


def test_cancellation_advances_fence_and_denies_late_publication(tmp_path: Path) -> None:
    repository, guidance = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        _enqueue(coordinator, guidance)
        _, identity = _claim(coordinator)
        requested_at = NOW + timedelta(minutes=2)
        request_authority = _mutation_authority(
            action="work_cancel",
            phase="request",
            target_ref="work-1",
            revision=identity.fence_token,
            key_digest=sha256(b"cancel-request-1").hexdigest(),
            at=requested_at,
        )
        cancellation_admission = coordinator.request_cancellation(
            work_id="work-1", expected_fence=identity.fence_token,
            now=requested_at,
            authority=request_authority,
            authority_revalidator=lambda _transaction: _grant(request_authority),
        )
        cancellation = cancellation_admission.item
        assert cancellation.fence_token == identity.fence_token + 1

        late = null_prompt_patch_artifact()
        with pytest.raises(StaleFence):
            coordinator.finalize(
                identity=identity,
                now=NOW + timedelta(minutes=3),
                authority_revalidator=_authorize_final,
                publication_planner=lambda: PublicationWriteSet((late,), ()),
            )
        assert repository.get_record(late.record_id) is None
        completed_at = NOW + timedelta(minutes=3)
        complete_authority = _mutation_authority(
            action="work_cancel",
            phase="complete",
            target_ref="work-1",
            revision=cancellation.fence_token,
            key_digest=sha256(b"cancel-complete-1").hexdigest(),
            at=completed_at,
        )
        terminal = coordinator.complete_cancellation(
            expired_identity=identity,
            cancellation_fence=cancellation.fence_token,
            now=completed_at,
            cleanup_confirmed=True,
            process_identity_verified=True,
            staging_cleanup_verified=True,
            authority=complete_authority,
            authority_revalidator=lambda _transaction: _grant(complete_authority),
        ).item
        assert terminal.state == "cancelled"

        queued = _enqueue(
            coordinator, guidance, work_id="work-queued", key="queued-cancel"
        ).item
        queued_at = NOW + timedelta(minutes=4)
        queued_authority = _mutation_authority(
            action="work_cancel",
            phase="request",
            target_ref=queued.work_id,
            revision=queued.fence_token,
            key_digest=sha256(b"cancel-request-queued").hexdigest(),
            at=queued_at,
        )
        queued_terminal = coordinator.request_cancellation(
            work_id=queued.work_id,
            expected_fence=queued.fence_token,
            now=queued_at,
            authority=queued_authority,
            authority_revalidator=lambda _transaction: _grant(queued_authority),
        ).item
        assert queued_terminal.state == "cancelled"


def test_expired_lease_requires_two_phase_cleanup_before_retry(tmp_path: Path) -> None:
    repository, guidance = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        _enqueue(coordinator, guidance)
        _, first_identity = _claim(coordinator)
        recovery = coordinator.begin_expired_lease_recovery(
            identity=first_identity, now=NOW + timedelta(minutes=10)
        )
        assert recovery.state == "recovery_required"
        assert recovery.fence_token == first_identity.fence_token + 1
        with pytest.raises(WorkStateConflict):
            _claim(coordinator, attempt="replacement-too-early")

        queued = coordinator.complete_recovery(
            expired_identity=first_identity,
            recovery_fence=recovery.fence_token,
            now=NOW + timedelta(minutes=11),
            retry_available_at=NOW + timedelta(minutes=11),
            conditions=ALL_RECOVERY,
        )
        assert queued.state == "queued"
        second, _ = _claim(
            coordinator, attempt="a2", claimed_at=NOW + timedelta(minutes=11)
        )
        assert second.fence_token > recovery.fence_token


def test_recovery_cannot_retry_without_each_explicit_condition(tmp_path: Path) -> None:
    repository, guidance = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        _enqueue(coordinator, guidance)
        _, identity = _claim(coordinator)
        recovery = coordinator.begin_expired_lease_recovery(
            identity=identity, now=NOW + timedelta(minutes=10)
        )
        failed = coordinator.complete_recovery(
            expired_identity=identity,
            recovery_fence=recovery.fence_token,
            now=NOW + timedelta(minutes=11),
            retry_available_at=NOW + timedelta(minutes=11),
            conditions=RecoveryConditions(True, True, True, True, False, True, True),
        )
        assert failed.state == "failed"


def test_budget_reservation_reconciles_actual_and_known_unused_only(tmp_path: Path) -> None:
    repository, guidance = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        broker = BudgetBroker(repository)
        _ledger(broker)
        _enqueue(coordinator, guidance, ledger_id="ledger-1")
        _, identity = _claim(coordinator)
        reservation = broker.reserve(
            reservation_id="reservation-1",
            identity=identity,
            ledger_id="ledger-1",
            amounts={"calls": 2, "tokens": 60},
            created_at=NOW + timedelta(minutes=2),
        )
        assert reservation.replayed is False
        assert broker.reserve(
            reservation_id="reservation-1",
            identity=identity,
            ledger_id="ledger-1",
            amounts={"calls": 2, "tokens": 60},
            created_at=NOW + timedelta(minutes=2),
        ).replayed is True
        snapshot = broker.reconcile(
            reservation_id="reservation-1",
            identity=identity,
            actual_amounts={"calls": 1, "tokens": 45},
            created_at=NOW + timedelta(minutes=3),
        )
        assert snapshot.dimensions["calls"] == (4, 0, 1, 0)
        assert snapshot.dimensions["tokens"] == (100, 0, 45, 0)


def test_unknown_crash_usage_remains_blocking_capacity(tmp_path: Path) -> None:
    repository, guidance = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        broker = BudgetBroker(repository)
        _ledger(broker)
        _enqueue(coordinator, guidance, ledger_id="ledger-1")
        _, identity = _claim(coordinator)
        broker.reserve(
            reservation_id="reservation-1",
            identity=identity,
            ledger_id="ledger-1",
            amounts={"calls": 3, "tokens": 80},
            created_at=NOW + timedelta(minutes=2),
        )
        snapshot = broker.mark_unreconciled(
            reservation_id="reservation-1",
            expired_identity=identity,
            created_at=NOW + timedelta(minutes=10),
        )
        assert snapshot.dimensions["calls"] == (4, 0, 0, 3)
        assert snapshot.dimensions["tokens"] == (100, 0, 0, 80)
        _enqueue(
            coordinator, guidance, work_id="work-2", key="key-2", ledger_id="ledger-1"
        )
        _, second_identity = _claim(
            coordinator,
            work_id="work-2",
            attempt="work-2-a1",
            claimed_at=NOW + timedelta(minutes=11),
        )
        with pytest.raises(BudgetExceeded):
            broker.reserve(
                reservation_id="reservation-2",
                identity=second_identity,
                ledger_id="ledger-1",
                amounts={"calls": 2, "tokens": 30},
                created_at=NOW + timedelta(minutes=12),
            )


def test_expired_deadline_rejects_publication_without_discovery(tmp_path: Path) -> None:
    repository, guidance = _store(tmp_path)
    with repository:
        coordinator = WorkCoordinator(repository)
        _enqueue(coordinator, guidance)
        _, identity = _claim(coordinator)
        late = null_prompt_patch_artifact()
        with pytest.raises(DeadlineExceeded):
            coordinator.finalize(
                identity=identity,
                now=NOW + timedelta(minutes=10),
                authority_revalidator=_authorize_final,
                publication_planner=lambda: PublicationWriteSet((late,), ()),
            )
        assert repository.get_record(late.record_id) is None
