from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256

from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.closed_loop import (
    MONITOR_CONCLUSION_SCHEMA_ID,
    STAGES,
    STAGE_CONTRACTS,
    ClosedLoopPlan,
    ExactAuthority,
    ExactTypedRecord,
    StageAuthorities,
)
from usr.plugins.dspy_rlm.helpers.v3.closed_loop_repository import (
    CLOSED_LOOP_REPOSITORY_REGISTRY,
    RepositoryClosedLoopServices,
    RepositoryStageResult,
)
from usr.plugins.dspy_rlm.helpers.v3.closed_loop_runner import (
    CLOSED_LOOP_RUNNER_REGISTRY,
    ClosedLoopRunRequest,
    LeaseRenewal,
    RepositoryClosedLoopRunner,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Repository
from usr.plugins.dspy_rlm.helpers.v3.schemas import (
    RecordSchema,
    SchemaRegistry,
    build_typed_record,
    merge_schema_registries,
    strict_object,
    strict_string,
    validate_links,
)
from usr.plugins.dspy_rlm.helpers.v3.work_authority import (
    ClaimConditions,
    FinalizationConditions,
    WORK_AUTHORITY_REGISTRY,
    WorkCoordinator,
    WorkEnqueue,
    WorkMutationAuthority,
)


NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
CONTEXT = "context:runner"
INPUT_SCHEMA = "test.runner-input.v1"
AUTHORITY_SCHEMA = "test.runner-authority.v1"
KEY_EPOCH = "runner-test-v1"
ALL_CLAIM = ClaimConditions(True, True, True, True)
ALL_FINAL = FinalizationConditions(True, True, True, True, True, True, True)

_FACT = strict_object(
    {"fact_type": strict_string(maximum=128), "links": validate_links}
)
_FACT_SCHEMAS = {
    INPUT_SCHEMA: "runner_test_input",
    AUTHORITY_SCHEMA: "runner_test_authority",
}
for _contract in STAGE_CONTRACTS.values():
    if _contract.output_schema_id != MONITOR_CONCLUSION_SCHEMA_ID:
        _FACT_SCHEMAS.setdefault(
            _contract.output_schema_id, _contract.output_record_kind
        )

TEST_REGISTRY = merge_schema_registries(
    WORK_AUTHORITY_REGISTRY,
    CLOSED_LOOP_REPOSITORY_REGISTRY,
    CLOSED_LOOP_RUNNER_REGISTRY,
    SchemaRegistry(
        RecordSchema(schema_id, kind, _FACT)
        for schema_id, kind in _FACT_SCHEMAS.items()
    ),
)


def _record(record_id: str, schema_id: str, record_kind: str):
    return build_typed_record(
        record_id=record_id,
        context_ref=CONTEXT,
        record_kind=record_kind,
        schema_id=schema_id,
        payload={"fact_type": record_kind, "links": []},
        key_epoch=KEY_EPOCH,
        registry=TEST_REGISTRY,
    )


def _authority(action: str, phase: str, target: str, revision: int, key: str):
    key_digest = sha256(key.encode()).hexdigest()
    request_digest = sha256(
        f"{action}:{phase}:{target}:{revision}:{key_digest}".encode()
    ).hexdigest()
    return WorkMutationAuthority(
        action=action,  # type: ignore[arg-type]
        phase=phase,  # type: ignore[arg-type]
        authority_grant_id=f"grant:{request_digest[:24]}",
        policy_ref="policy.runner.v1",
        context_ref=CONTEXT,
        target_ref=target,
        target_revision=revision,
        idempotency_key_digest=key_digest,
        request_digest=request_digest,
        session_nonce="session.runner",
        admitted_at=NOW,
    )


def _grant(authority: WorkMutationAuthority):
    return VerifiedGrant(
        grant_id=authority.authority_grant_id,
        authority_class="operator_authority_grant",
        issuer_id="issuer.local",
        key_epoch=1,
        subject_ref="operator.local",
        context_ref=CONTEXT,
        action=authority.action,
        purpose="operator_mutation",
        target_ref=authority.target_ref,
        target_revision=authority.target_revision,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        idempotency_key_digest=authority.idempotency_key_digest,
        session_nonce=authority.session_nonce,
    )


def _seed(tmp_path):
    path = tmp_path / "runner.sqlite3"
    repository = V3Repository.create(path, registry=TEST_REGISTRY)
    initial = _record("input:runner", INPUT_SCHEMA, "runner_test_input")
    authorities = {
        stage: _record(
            f"authority:{stage}", AUTHORITY_SCHEMA, "runner_test_authority"
        )
        for stage in STAGES
    }
    with repository.transaction() as transaction:
        transaction.insert_record(initial)
        for authority in authorities.values():
            transaction.insert_record(authority)
    plan = ClosedLoopPlan(
        run_ref="run:runner",
        context_ref=CONTEXT,
        key_epoch=KEY_EPOCH,
        admitted_input=ExactTypedRecord.of(initial),
        stage_authorities=tuple(
            StageAuthorities(
                stage,
                (
                    ExactAuthority(
                        authorities[stage].record_id,
                        authorities[stage].content_digest,
                    ),
                ),
            )
            for stage in STAGES
        ),
    )
    coordinator = WorkCoordinator(repository)
    enqueue_authority = _authority("optimize", "enqueue", "work:runner", 0, "enqueue")
    coordinator.enqueue(
        WorkEnqueue(
            work_id="work:runner",
            idempotency_key_digest=enqueue_authority.idempotency_key_digest,
            context_ref=CONTEXT,
            operation_kind="candidate_search",
            input_record_id=initial.record_id,
            input_digest=initial.content_digest,
            budget_ledger_id=None,
            max_attempts=2,
            available_at=NOW,
            deadline_at=NOW + timedelta(hours=1),
            created_at=NOW,
        ),
        authority=enqueue_authority,
        authority_revalidator=lambda _transaction: _grant(enqueue_authority),
    )
    return repository, path, plan


def _request():
    claim = NOW + timedelta(minutes=1)
    claim_expiry = claim + timedelta(minutes=1)
    renewals = tuple(
        LeaseRenewal(
            stage,
            claim + timedelta(seconds=index + 1),
            claim_expiry + timedelta(minutes=index + 1),
        )
        for index, stage in enumerate(STAGES)
    )
    return ClosedLoopRunRequest(
        runner_ref="runner:primary",
        work_id="work:runner",
        attempt_id="attempt:1",
        owner_id="owner:runner",
        process_nonce="nonce:runner",
        process_start_identity="process:runner",
        runner_authority_ref="authority:runner",
        claim_at=claim,
        claim_expires_at=claim_expiry,
        stage_renewals=renewals,
        finalization_renewal=LeaseRenewal(
            STAGES[-1],
            claim + timedelta(seconds=30),
            renewals[-1].expires_at + timedelta(minutes=1),
        ),
    )


def _services(calls, *, fail_stage=None):
    services = {}
    for stage in STAGES:

        def execute(_transaction, invocation, expected=stage):
            assert invocation.stage == expected
            calls.append(expected)
            if expected == fail_stage:
                raise RuntimeError("untrusted detail must not persist")
            contract = STAGE_CONTRACTS[expected]
            decision = "review_only" if expected == "evidence_reduction" else contract.decision
            return RepositoryStageResult(
                contract.owner,
                decision,
                _record(
                    f"output:{invocation.sequence}:{expected}",
                    contract.output_schema_id,
                    contract.output_record_kind,
                ),
            )

        services[stage] = execute
    return RepositoryClosedLoopServices(**services)


def _run(runner, request, plan, services):
    return runner.run(
        request,
        plan=plan,
        services=services,
        claim_conditions=ALL_CLAIM,
        finalization_revalidator=lambda _transaction, _item, _identity: ALL_FINAL,
        failure_classifier=lambda _exc: "provider_unavailable",
    )


def test_runner_fences_terminal_and_restart_replays_without_services(tmp_path):
    repository, path, plan = _seed(tmp_path)
    request = _request()
    calls = []
    result = _run(
        RepositoryClosedLoopRunner(repository), request, plan, _services(calls)
    )
    assert result.work.state == "completed"
    assert result.receipt.payload["status"] == "completed"
    assert result.receipt.payload["terminal_state"] == "review_only"
    assert calls == list(STAGES[:6])
    repository.close()

    calls.clear()
    with V3Repository.open(path, registry=TEST_REGISTRY) as reopened:
        replay = _run(
            RepositoryClosedLoopRunner(reopened), request, plan, _services(calls)
        )
        assert replay.replayed is True
        assert replay.work.state == "completed"
        assert replay.closed_loop_terminal == result.closed_loop_terminal
        assert calls == []


def test_runner_failure_is_exact_durable_and_never_publishes_work(tmp_path):
    repository, path, plan = _seed(tmp_path)
    request = _request()
    calls = []
    result = _run(
        RepositoryClosedLoopRunner(repository),
        request,
        plan,
        _services(calls, fail_stage="analysis_attempt"),
    )
    assert result.work.state == "leased"
    assert result.receipt.payload["status"] == "failed"
    assert result.receipt.payload["reason_code"] == "provider_unavailable"
    assert result.receipt.payload["failure_stage"] == "analysis_attempt"
    assert b"untrusted detail" not in result.receipt.canonical_bytes
    assert calls == list(STAGES[:3])
    repository.close()

    calls.clear()
    with V3Repository.open(path, registry=TEST_REGISTRY) as reopened:
        replay = _run(
            RepositoryClosedLoopRunner(reopened), request, plan, _services(calls)
        )
        assert replay.replayed is True
        assert replay.work.state == "leased"
        assert calls == []


def test_preclaimed_cancellation_never_invokes_a_stage(tmp_path):
    repository, _path, plan = _seed(tmp_path)
    cancel = _authority("work_cancel", "request", "work:runner", 0, "cancel")
    WorkCoordinator(repository).request_cancellation(
        work_id="work:runner",
        expected_fence=0,
        now=NOW + timedelta(seconds=1),
        authority=cancel,
        authority_revalidator=lambda _transaction: _grant(cancel),
    )
    calls = []
    result = _run(
        RepositoryClosedLoopRunner(repository), _request(), plan, _services(calls)
    )
    assert result.work.state == "cancelled"
    assert result.receipt.payload["status"] == "cancelled"
    assert result.receipt.payload["reason_code"] == "cancellation_requested"
    assert calls == []
    repository.close()
