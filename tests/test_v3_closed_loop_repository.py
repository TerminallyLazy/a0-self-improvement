from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.artifacts import ACTIVATION_PROFILE_SCHEMA_ID
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    ACTIVATION_POLICY_SCHEMA_ID,
    POST_PROMOTION_MONITOR_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.closed_loop import (
    MONITOR_CONCLUSION_SCHEMA_ID,
    STAGES,
    STAGE_CONTRACTS,
    ClosedLoopError,
    ClosedLoopPlan,
    ExactAuthority,
    ExactTypedRecord,
    StageAuthorities,
)
from usr.plugins.dspy_rlm.helpers.v3.closed_loop_repository import (
    CLOSED_LOOP_REPOSITORY_REGISTRY,
    RepositoryClosedLoopCoordinator,
    RepositoryClosedLoopServices,
    RepositoryStageResult,
    build_monitor_conclusion,
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


CONTEXT = "context:durable-closed-loop"
RUN = "closed-loop:durable-run"
KEY_EPOCH = "closed-loop-test-v1"
INPUT_SCHEMA_ID = "test.closed-loop-input.v1"
AUTHORITY_SCHEMA_ID = "test.closed-loop-authority.v1"


_FACT_PAYLOAD = strict_object(
    {"fact_type": strict_string(maximum=128), "links": validate_links}
)
_FACT_SCHEMAS: dict[str, str] = {
    INPUT_SCHEMA_ID: "closed_loop_test_input",
    AUTHORITY_SCHEMA_ID: "closed_loop_test_authority",
    POST_PROMOTION_MONITOR_SCHEMA_ID: "post_promotion_monitor",
    ACTIVATION_PROFILE_SCHEMA_ID: "activation_profile",
    ACTIVATION_POLICY_SCHEMA_ID: "activation_policy",
}
for _contract in STAGE_CONTRACTS.values():
    if _contract.output_schema_id != MONITOR_CONCLUSION_SCHEMA_ID:
        previous = _FACT_SCHEMAS.setdefault(
            _contract.output_schema_id, _contract.output_record_kind
        )
        assert previous == _contract.output_record_kind

TEST_REGISTRY = merge_schema_registries(
    CLOSED_LOOP_REPOSITORY_REGISTRY,
    SchemaRegistry(
        RecordSchema(schema_id, record_kind, _FACT_PAYLOAD)
        for schema_id, record_kind in _FACT_SCHEMAS.items()
    ),
)


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _record(
    record_id: str,
    schema_id: str,
    record_kind: str,
    *,
    context_ref: str = CONTEXT,
):
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind=record_kind,
        schema_id=schema_id,
        payload={"fact_type": record_kind, "links": []},
        key_epoch=KEY_EPOCH,
        registry=TEST_REGISTRY,
    )


def _seed(tmp_path, *, run_ref: str = RUN):
    repository = V3Repository.create(
        tmp_path / "closed-loop.sqlite3", registry=TEST_REGISTRY
    )
    admitted_input = _record(
        "input:fixtures", INPUT_SCHEMA_ID, "closed_loop_test_input"
    )
    authority_records = {
        stage: _record(
            f"authority:{stage}",
            AUTHORITY_SCHEMA_ID,
            "closed_loop_test_authority",
        )
        for stage in STAGES
    }
    monitor_inputs = {
        "monitor": _record(
            "monitor:active",
            POST_PROMOTION_MONITOR_SCHEMA_ID,
            "post_promotion_monitor",
        ),
        "profile": _record(
            "profile:active", ACTIVATION_PROFILE_SCHEMA_ID, "activation_profile"
        ),
        "policy": _record(
            "policy:active", ACTIVATION_POLICY_SCHEMA_ID, "activation_policy"
        ),
    }
    with repository.transaction() as transaction:
        transaction.insert_record(admitted_input)
        for record in (*authority_records.values(), *monitor_inputs.values()):
            transaction.insert_record(record)
    plan = ClosedLoopPlan(
        run_ref=run_ref,
        context_ref=CONTEXT,
        key_epoch=KEY_EPOCH,
        admitted_input=ExactTypedRecord.of(admitted_input),
        stage_authorities=tuple(
            StageAuthorities(
                stage,
                (
                    ExactAuthority(
                        authority_records[stage].record_id,
                        authority_records[stage].content_digest,
                    ),
                ),
            )
            for stage in STAGES
        ),
    )
    return repository, plan, monitor_inputs


def _services(
    plan: ClosedLoopPlan,
    monitor_inputs,
    *,
    decisions: dict[str, str] | None = None,
    calls: list[str] | None = None,
    mutate=None,
) -> RepositoryClosedLoopServices:
    decisions = decisions or {}
    calls = calls if calls is not None else []
    services = {}
    for stage in STAGES:

        def execute(transaction, invocation, expected=stage):
            assert invocation.stage == expected
            assert transaction.get_record(plan.admitted_input.record_id) is not None
            calls.append(expected)
            decision = decisions.get(expected, STAGE_CONTRACTS[expected].decision)
            contract = STAGE_CONTRACTS[expected]
            if expected == "monitor_conclusion":
                output = build_monitor_conclusion(
                    record_id=f"output:{invocation.sequence}:{expected}:{decision}",
                    context_ref=plan.context_ref,
                    key_epoch=plan.key_epoch,
                    decision=decision,
                    monitor=ExactTypedRecord.of(monitor_inputs["monitor"]),
                    active_profile=ExactTypedRecord.of(monitor_inputs["profile"]),
                    policy=ExactTypedRecord.of(monitor_inputs["policy"]),
                )
            else:
                output = _record(
                    f"output:{invocation.sequence}:{expected}:{decision}",
                    contract.output_schema_id,
                    contract.output_record_kind,
                )
            result = RepositoryStageResult(contract.owner, decision, output)
            return mutate(expected, result) if mutate is not None else result

        services[stage] = execute
    return RepositoryClosedLoopServices(**services)


def test_full_rollback_is_durable_atomic_and_exactly_replayable(tmp_path):
    repository, plan, monitor_inputs = _seed(tmp_path)
    calls: list[str] = []
    services = _services(plan, monitor_inputs, calls=calls)
    coordinator = RepositoryClosedLoopCoordinator(repository)

    result = coordinator.run(plan, services)

    assert result.replayed is False
    assert tuple(receipt.payload["stage"] for receipt in result.receipts) == STAGES
    assert result.terminal.payload["terminal_state"] == "rolled_back"
    assert all(
        receipt.payload["worker_activation_authority"] == "none"
        for receipt in result.receipts
    )
    with repository.transaction() as transaction:
        assert transaction.next_domain_event_sequence(result.run.record_id) == len(STAGES)
        assert transaction.get_domain_event(result.terminal.record_id, 0).event_type == (
            "closed_loop_terminal_reached"
        )
        assert all(
            transaction.get_record(output.record_id) == output for output in result.outputs
        )

    replay = coordinator.run(plan, services)
    assert replay.replayed is True
    assert replay.terminal == result.terminal
    assert calls == list(STAGES)
    repository.close()


@pytest.mark.parametrize(
    ("decisions", "terminal_state", "completed"),
    (
        ({"evidence_reduction": "rejected"}, "evidence_rejected", STAGES[:6]),
        ({"evidence_reduction": "review_only"}, "review_only", STAGES[:6]),
        (
            {"canary_conclusion": "authoritative_canary_failed"},
            "canary_failed",
            STAGES[:8],
        ),
        (
            {"canary_conclusion": "authoritative_canary_inconclusive"},
            "canary_inconclusive",
            STAGES[:8],
        ),
        (
            {"canary_conclusion": "authoritative_canary_stopped"},
            "canary_stopped",
            STAGES[:8],
        ),
        ({"monitor_conclusion": "retain"}, "retained", STAGES[:10]),
    ),
)
def test_terminal_branches_never_invoke_downstream_stages(
    tmp_path, decisions, terminal_state, completed
):
    repository, plan, monitor_inputs = _seed(tmp_path)
    calls: list[str] = []

    result = RepositoryClosedLoopCoordinator(repository).run(
        plan,
        _services(plan, monitor_inputs, decisions=decisions, calls=calls),
    )

    assert result.terminal.payload["terminal_state"] == terminal_state
    assert tuple(calls) == completed
    assert tuple(result.terminal.payload["completed_stages"]) == completed
    repository.close()


def test_lost_ack_replays_one_step_and_restart_resumes_from_receipt(tmp_path):
    repository, plan, monitor_inputs = _seed(tmp_path)
    calls: list[str] = []
    services = _services(
        plan,
        monitor_inputs,
        decisions={"evidence_reduction": "review_only"},
        calls=calls,
    )
    coordinator = RepositoryClosedLoopCoordinator(repository)

    first = coordinator.execute_stage(plan, expected_sequence=0, services=services)
    replay = coordinator.execute_stage(plan, expected_sequence=0, services=services)
    assert replay.replayed is True
    assert replay.receipt == first.receipt
    assert calls == ["observation"]

    path = repository.path
    repository.close()
    reopened = V3Repository.open(path, registry=TEST_REGISTRY)
    resumed = RepositoryClosedLoopCoordinator(reopened).run(plan, services)
    assert resumed.terminal.payload["terminal_state"] == "review_only"
    assert calls == list(STAGES[:6])
    assert RepositoryClosedLoopCoordinator(reopened).run(plan, services).replayed is True
    reopened.close()


@pytest.mark.parametrize("violation", ("owner", "schema", "context", "branch"))
def test_refuses_invalid_service_or_frozen_plan_without_partial_step(
    tmp_path, violation
):
    repository, plan, monitor_inputs = _seed(tmp_path)

    def mutate(stage, result):
        if stage != "observation":
            return result
        if violation == "owner":
            return replace(result, owner="analysis_worker")
        if violation == "branch":
            return replace(result, decision="retain")
        if violation == "context":
            return replace(
                result,
                output=_record(
                    "output:wrong-context",
                    result.output.schema_id,
                    result.output.record_kind,
                    context_ref="context:wrong",
                ),
            )
        wrong = STAGE_CONTRACTS["safe_analysis_view"]
        return replace(
            result,
            output=_record(
                "output:wrong-schema",
                wrong.output_schema_id,
                wrong.output_record_kind,
            ),
        )

    with pytest.raises(ClosedLoopError):
        RepositoryClosedLoopCoordinator(repository).execute_stage(
            plan,
            expected_sequence=0,
            services=_services(plan, monitor_inputs, mutate=mutate),
        )
    run_record = RepositoryClosedLoopCoordinator(repository).start(plan)
    with repository.transaction() as transaction:
        assert transaction.next_domain_event_sequence(run_record.record_id) == 0

    bad_authorities = list(plan.stage_authorities)
    bad_authorities[0] = StageAuthorities(
        STAGES[0], (ExactAuthority("authority:missing", _digest("missing")),)
    )
    with pytest.raises(ClosedLoopError):
        RepositoryClosedLoopCoordinator(repository).start(
            replace(plan, run_ref="closed-loop:bad-authority", stage_authorities=tuple(bad_authorities))
        )

    alternate_input = _record(
        "input:other", INPUT_SCHEMA_ID, "closed_loop_test_input"
    )
    with repository.transaction() as transaction:
        transaction.insert_record(alternate_input)
    with pytest.raises(ClosedLoopError, match="different plan"):
        RepositoryClosedLoopCoordinator(repository).start(
            replace(plan, admitted_input=ExactTypedRecord.of(alternate_input))
        )
    repository.close()
