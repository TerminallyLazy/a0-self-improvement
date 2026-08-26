from __future__ import annotations

from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.closed_loop import (
    STAGES,
    STAGE_CONTRACTS,
    ClosedLoopError,
    ClosedLoopPlan,
    ClosedLoopServices,
    DeterministicClosedLoopCoordinator,
    ExactAuthority,
    ExactTypedRecord,
    StageAuthorities,
    StageResult,
)


CONTEXT = "context:closed-loop"
RUN = "closed-loop:run-1"


def digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def typed_record(
    label: str, *, schema_id: str, record_kind: str, context_ref: str = CONTEXT
) -> ExactTypedRecord:
    return ExactTypedRecord(
        record_id=f"record:{label}",
        digest=digest(label),
        schema_id=schema_id,
        record_kind=record_kind,
        context_ref=context_ref,
    )


def plan() -> ClosedLoopPlan:
    return ClosedLoopPlan(
        run_ref=RUN,
        context_ref=CONTEXT,
        key_epoch="closed-loop-test-v1",
        admitted_input=typed_record(
            "admitted-fixtures",
            schema_id="a0.fixture-manifest.v1",
            record_kind="fixture_manifest",
        ),
        stage_authorities=tuple(
            StageAuthorities(
                stage,
                (ExactAuthority(f"authority:{stage}", digest(f"authority:{stage}")),),
            )
            for stage in STAGES
        ),
    )


class FakeProvider:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def certified_replay(self, invocation):
        self.calls.append(invocation.stage)
        return exact_result(invocation)


def exact_result(invocation, **changes) -> StageResult:
    contract = STAGE_CONTRACTS[invocation.stage]
    values = {
        "stage": invocation.stage,
        "run_ref": invocation.run_ref,
        "context_ref": invocation.context_ref,
        "predecessor": invocation.predecessor,
        "authorities": invocation.authorities,
        "owner": contract.owner,
        "decision": contract.decision,
        "output": typed_record(
            f"{invocation.sequence}:{invocation.stage}",
            schema_id=contract.output_schema_id,
            record_kind=contract.output_record_kind,
        ),
        "committed": contract.committed,
    }
    values.update(changes)
    return StageResult(**values)


def services(*, fake_provider: FakeProvider, override=None, calls=None) -> ClosedLoopServices:
    calls = calls if calls is not None else []
    stage_services = {}
    for stage in STAGES:
        if override is not None and stage == override[0]:
            stage_services[stage] = override[1]
        elif stage == "certified_replay":
            stage_services[stage] = fake_provider.certified_replay
        else:
            def execute(invocation, expected=stage):
                assert invocation.stage == expected
                calls.append(expected)
                return exact_result(invocation)

            stage_services[stage] = execute
    return ClosedLoopServices(**stage_services)


def test_fake_provider_closed_loop_runs_exact_sequence_through_rollback():
    provider = FakeProvider()
    calls: list[str] = []
    result = DeterministicClosedLoopCoordinator(
        services(fake_provider=provider, calls=calls)
    ).run(plan())

    assert tuple(item.stage for item in result.stage_results) == STAGES
    assert calls == [stage for stage in STAGES if stage != "certified_replay"]
    assert provider.calls == ["certified_replay"]
    assert result.completion.payload["terminal_state"] == "rolled_back"
    assert result.completion.payload["completed_stages"] == list(STAGES)
    assert result.completion.payload["worker_activation_observed"] is False
    assert result.stage_results[-1].decision == "predecessor_restored"
    assert result.stage_results[-1].owner == "activation_coordinator"
    assert all(
        receipt.payload["worker_activation_authority"] == "none"
        for receipt in result.stage_receipts
    )
    for previous, current in zip(result.stage_results, result.stage_results[1:]):
        assert current.predecessor == previous.output


def test_activation_cannot_be_returned_under_worker_authority():
    provider = FakeProvider()

    def worker_activates(invocation):
        return exact_result(invocation, owner="analysis_worker")

    coordinator = DeterministicClosedLoopCoordinator(
        services(
            fake_provider=provider,
            override=("activation", worker_activates),
        )
    )
    with pytest.raises(ClosedLoopError, match="wrong authority owner"):
        coordinator.run(plan())


def test_non_promotion_disposition_stops_without_fallback_to_canary():
    provider = FakeProvider()
    reached_canary = False

    def review_only(invocation):
        return exact_result(invocation, decision="review_only")

    def canary_must_not_run(invocation):
        nonlocal reached_canary
        reached_canary = True
        return exact_result(invocation)

    stage_services = services(
        fake_provider=provider,
        override=("evidence_reduction", review_only),
    )
    stage_services = ClosedLoopServices(
        **{
            stage: (
                canary_must_not_run
                if stage == "canary_start"
                else getattr(stage_services, stage)
            )
            for stage in STAGES
        }
    )
    with pytest.raises(ClosedLoopError, match="exact gate"):
        DeterministicClosedLoopCoordinator(stage_services).run(plan())
    assert reached_canary is False
