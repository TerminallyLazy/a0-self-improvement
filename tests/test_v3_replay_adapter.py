from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from typing import Any

import pytest

from usr.plugins.dspy_rlm.helpers.v3.fixtures import (
    ASSESSMENT_PROFILE_SCHEMA_ID,
    EXECUTION_PROFILE_SCHEMA_ID,
    FIXTURE_ADMISSION_SCHEMA_ID,
    FIXTURE_DRAFT_SCHEMA_ID,
    FIXTURE_ELIGIBILITY_SCHEMA_ID,
    FIXTURE_FAMILY_SCHEMA_ID,
    FIXTURE_MANIFEST_SCHEMA_ID,
    FixtureAdmission,
    FixtureDraft,
    _record,
)
from usr.plugins.dspy_rlm.helpers.v3.replay_adapter import (
    ExactIdentity,
    LockedCandidateIdentity,
    ProviderArmReport,
    ReplayArmUsage,
    ReplayBindings,
    ReplayBounds,
    ReplayCapabilityIdentity,
    ReplayContractError,
    ReplayObservedCounters,
    ReplayPairOrchestrator,
    ReplayPairRequest,
    fixture_argument_digest,
    replay_request_digest,
)
from usr.plugins.dspy_rlm.helpers.v3.replay_repository import (
    REPLAY_REPOSITORY_REGISTRY,
    ReplayAttemptIncomplete,
    RepositoryReplayCoordinator,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
    V3Repository,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import (
    RecordSchema,
    SchemaRegistry,
    build_typed_record,
    canonical_json,
    merge_schema_registries,
    schema_digest,
    strict_literal,
    strict_object,
    strict_string,
    validate_links,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64

_TEST_REPLAY_ANCHOR_SCHEMA = "test.replay-anchor.v1"
_TEST_REPLAY_REGISTRY = merge_schema_registries(
    REPLAY_REPOSITORY_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                _TEST_REPLAY_ANCHOR_SCHEMA,
                "test_replay_anchor",
                strict_object(
                    {
                        "record_type": strict_literal("test_replay_anchor"),
                        "label": strict_string(maximum=128),
                        "links": validate_links,
                    }
                ),
            ),
        )
    ),
)


class FakeProvider:
    def __init__(self, behavior: str = "completed") -> None:
        self.behavior = behavior
        self.invocations: list[Any] = []
        self.observed: dict[str, ReplayObservedCounters] = {}

    def execute_arm(self, invocation, fixture_tools):
        self.invocations.append(invocation)
        usage = _usage()
        live = 0
        hosted = 0
        if self.behavior == "over_budget":
            usage = replace(usage, tokens=101)
        if self.behavior == "live_and_hosted":
            live = int(invocation.arm == "candidate")
            hosted = int(invocation.arm == "incumbent")
        if self.behavior == "hidden_hosted":
            hosted = 1
        self.observed[invocation.fresh_state_ref] = _observed(
            usage, live=live, hosted=hosted
        )
        if self.behavior == "live_and_hosted":
            if invocation.arm == "candidate":
                fixture_tools.dispatch_live_tool("forbidden")
            return ProviderArmReport(
                invocation.arm,
                invocation.subject,
                "completed",
                "completed",
                _usage(),
                provider_hosted_tool_executions=1,
            )
        if self.behavior == "over_budget":
            return ProviderArmReport(
                invocation.arm,
                invocation.subject,
                "completed",
                "completed",
                usage,
            )
        if self.behavior == "unavailable":
            return ProviderArmReport(
                invocation.arm,
                invocation.subject,
                "availability_failure",
                "provider_unavailable",
                _usage(),
            )
        fixture_tools.continue_fixture_tool(
            tool_contract_ref="fixture-tool.v1", arguments={"query": "opaque"}
        )
        return ProviderArmReport(
            invocation.arm,
            invocation.subject,
            "completed",
            "completed",
            replace(_usage(), fixture_calls=1),
        )

    def read_counters(self, invocation):
        return self.observed[invocation.fresh_state_ref]


def _usage() -> ReplayArmUsage:
    return ReplayArmUsage(
        wall_time_ms=0,
        model_calls=1,
        turns=1,
        fixture_calls=0,
        tokens=10,
        output_bytes=12,
        cost_microunits=7,
    )


def _observed(
    usage: ReplayArmUsage, *, live: int = 0, hosted: int = 0
) -> ReplayObservedCounters:
    return ReplayObservedCounters(
        usage.model_calls,
        usage.turns,
        usage.tokens,
        usage.output_bytes,
        usage.cost_microunits,
        live,
        hosted,
    )


def _fixture_content() -> dict[str, Any]:
    return {
        "schema": "a0.replay-case-content.v1",
        "input_message": "TOP_SECRET_INPUT",
        "initial_state": ["TOP_SECRET_STATE"],
        "tool_steps": [
            {
                "ordinal": 0,
                "tool_contract_ref": "fixture-tool.v1",
                "argument_matcher_digest": fixture_argument_digest(
                    "fixture-tool.v1", {"query": "opaque"}
                ),
                "response_digest": DIGEST_E,
                "state_transition_ref": "transition-1",
            }
        ],
        "expected_outcome": ["TOP_SECRET_EXPECTATION"],
        "execution_bounds": {
            "max_turns": 5,
            "max_tool_steps": 1,
            "max_output_bytes": 1024,
        },
    }


def _bound_fixture() -> tuple[ReplayBindings, dict[str, Any]]:
    content = _fixture_content()
    content_bytes = canonical_json(content)
    content_digest = schema_digest(
        "fixture-content", "a0.replay-case-content.v1", content_bytes
    )
    family = _record(
        "fixture_family",
        FIXTURE_FAMILY_SCHEMA_ID,
        {
            "record_type": "fixture_family",
            "family_ref": "family-1",
            "source_lineage_digest": DIGEST_A,
            "partition_policy_ref": "partition-policy-1",
            "partition_weights": {
                "training": 1,
                "tuning": 1,
                "certification_holdout": 1,
            },
            "partition": "training",
            "links": [],
        },
        "fixture-v1",
    )
    draft = _record(
        "fixture_draft",
        FIXTURE_DRAFT_SCHEMA_ID,
        {
            "record_type": "fixture_draft",
            "fixture_ref": "fixture-1",
            "revision": 1,
            "author_ref": "author-1",
            "origin_class": "system_curated",
            "source_attestation_digest": DIGEST_B,
            "content_schema_id": "a0.replay-case-content.v1",
            "content_digest": content_digest,
            "content_size": len(content_bytes),
            "vault_ref": "vault-1",
            "encryption_profile_ref": "encryption-1",
            "ciphertext_digest": DIGEST_C,
            "family_ref": "family-1",
            "partition": "training",
            "protected": False,
            "release_receipt_ref": None,
            "release_receipt_digest": None,
            "links": [],
        },
        "fixture-v1",
    )
    fixture = FixtureDraft(family, (family, family), draft)
    admission_receipt = _record(
        "fixture_admission_receipt",
        FIXTURE_ADMISSION_SCHEMA_ID,
        {
            "record_type": "fixture_admission_receipt",
            "draft_id": draft.record_id,
            "draft_digest": draft.content_digest,
            "review_id": "review-1",
            "review_digest": DIGEST_A,
            "family_id": family.record_id,
            "family_digest": family.content_digest,
            "partition": "training",
            "fixture_use_grant_id": "grant-1",
            "admitted_at": "2026-08-26T12:00:00.000000Z",
            "release_receipt_ref": None,
            "release_receipt_digest": None,
            "links": [],
        },
        "fixture-v1",
    )
    eligibility = _record(
        "fixture_eligibility_event",
        FIXTURE_ELIGIBILITY_SCHEMA_ID,
        {
            "record_type": "fixture_eligibility_event",
            "fixture_id": draft.record_id,
            "fixture_digest": draft.content_digest,
            "state": "admitted",
            "effective_at": "2026-08-26T12:00:00.000000Z",
            "authority_ref": "grant-1",
            "reason_code": "admission_complete",
            "links": [],
        },
        "fixture-v1",
    )
    admission = FixtureAdmission(family, admission_receipt, eligibility, None)  # type: ignore[arg-type]
    execution = _record(
        "execution_profile",
        EXECUTION_PROFILE_SCHEMA_ID,
        {
            "record_type": "execution_profile",
            "runtime_digest": DIGEST_A,
            "model_configuration_digest": DIGEST_B,
            "replay_adapter_digest": DIGEST_C,
            "behavior_configuration_digest": DIGEST_D,
            "links": [],
        },
        "fixture-v1",
    )
    assessment = _record(
        "assessment_profile",
        ASSESSMENT_PROFILE_SCHEMA_ID,
        {
            "record_type": "assessment_profile",
            "validator_profile_digest": DIGEST_A,
            "activation_policy_digest": DIGEST_B,
            "threshold_profile_digest": DIGEST_C,
            "freshness_policy_digest": DIGEST_D,
            "replay_seed": 7,
            "required_buckets": ["reasoning"],
            "links": [],
        },
        "fixture-v1",
    )
    manifest = _record(
        "fixture_manifest",
        FIXTURE_MANIFEST_SCHEMA_ID,
        {
            "record_type": "fixture_manifest",
            "selection_policy_ref": "selection-1",
            "execution_profile_id": execution.record_id,
            "execution_profile_digest": execution.content_digest,
            "assessment_profile_id": assessment.record_id,
            "assessment_profile_digest": assessment.content_digest,
            "entries": [
                {
                    "ordinal": 0,
                    "draft_id": draft.record_id,
                    "draft_digest": draft.content_digest,
                    "admission_id": admission_receipt.record_id,
                    "admission_digest": admission_receipt.content_digest,
                    "family_id": family.record_id,
                    "family_digest": family.content_digest,
                    "partition": "training",
                }
            ],
            "links": [],
        },
        "fixture-v1",
    )
    bindings = ReplayBindings(
        fixture=fixture,
        admission=admission,
        manifest=manifest,
        execution_profile=execution,
        assessment_profile=assessment,
        candidate=LockedCandidateIdentity(
            ExactIdentity("candidate-1", DIGEST_A),
            ExactIdentity("candidate-lock-1", DIGEST_B),
        ),
        incumbent=ExactIdentity("incumbent-1", DIGEST_C),
        capability=ReplayCapabilityIdentity(
            ExactIdentity("capability-1", DIGEST_D), DIGEST_A, DIGEST_C
        ),
    )
    return bindings, content


def _request(
    *, pair_ref: str = "pair-1", retry_of: ExactIdentity | None = None
) -> ReplayPairRequest:
    bindings, content = _bound_fixture()
    return ReplayPairRequest(
        issuer_ref="issuer-replay-1",
        subject_ref="operator-replay-1",
        context_ref="context-opaque-1",
        pair_attempt_ref=pair_ref,
        idempotency_key_digest=hashlib.sha256(
            ("idempotency:" + pair_ref).encode()
        ).hexdigest(),
        bindings=bindings,
        fixture_content=content,
        bounds=ReplayBounds(5000, 2, 5, 1, 100, 1024, 100),
        retry_of=retry_of,
    )


def _anchor(label: str):
    return build_typed_record(
        record_id="test-replay-anchor:" + label,
        context_ref="context-opaque-1",
        record_kind="test_replay_anchor",
        schema_id=_TEST_REPLAY_ANCHOR_SCHEMA,
        payload={"record_type": "test_replay_anchor", "label": label, "links": []},
        key_epoch="test-v1",
        registry=_TEST_REPLAY_REGISTRY,
    )


def _repository_request():
    request = _request()
    anchors = tuple(
        _anchor(label) for label in ("candidate", "candidate-lock", "incumbent", "capability")
    )
    candidate, candidate_lock, incumbent, capability = anchors
    bindings = replace(
        request.bindings,
        candidate=LockedCandidateIdentity(
            ExactIdentity(candidate.record_id, candidate.content_digest),
            ExactIdentity(candidate_lock.record_id, candidate_lock.content_digest),
        ),
        incumbent=ExactIdentity(incumbent.record_id, incumbent.content_digest),
        capability=ReplayCapabilityIdentity(
            ExactIdentity(capability.record_id, capability.content_digest),
            request.bindings.execution_profile.payload["runtime_digest"],
            request.bindings.execution_profile.payload["replay_adapter_digest"],
        ),
    )
    return replace(request, bindings=bindings), anchors


def _seed_replay_bindings(repository, request, anchors) -> None:
    bindings = request.bindings
    records = (
        bindings.fixture.family,
        bindings.fixture.record,
        bindings.admission.receipt,
        bindings.admission.eligibility,
        bindings.execution_profile,
        bindings.assessment_profile,
        bindings.manifest,
        *anchors,
    )
    with repository.transaction() as transaction:
        for record in records:
            transaction.insert_record(record)


def test_pair_uses_one_snapshot_distinct_fresh_state_and_content_free_receipt() -> None:
    provider = FakeProvider()
    nonces = iter(("state-candidate", "state-incumbent"))
    result = ReplayPairOrchestrator(provider, counter_reader=provider.read_counters, nonce_factory=lambda: next(nonces)).run_pair(
        _request()
    )

    assert len(provider.invocations) == 2
    assert provider.invocations[0].frozen_snapshot == provider.invocations[1].frozen_snapshot
    assert provider.invocations[0].fresh_state_ref != provider.invocations[1].fresh_state_ref
    assert all(not item.provider_hosted_tools_enabled for item in provider.invocations)
    assert result.receipt.payload["activation_evidence_eligible"] is True
    receipt_bytes = result.receipt.canonical_bytes
    assert b"TOP_SECRET_INPUT" not in receipt_bytes
    assert b"TOP_SECRET_STATE" not in receipt_bytes
    assert b"TOP_SECRET_EXPECTATION" not in receipt_bytes
    assert {link.role for link in result.receipt.links} >= {
        "fixture_admission",
        "fixture_manifest",
        "execution_profile",
        "assessment_profile",
        "candidate_artifact",
        "candidate_lock_receipt",
        "incumbent_artifact",
        "replay_capability",
    }


def test_exact_profile_and_capability_drift_blocks_before_provider_dispatch() -> None:
    provider = FakeProvider()
    request = _request()
    drifted = replace(
        request,
        bindings=replace(
            request.bindings,
            capability=ReplayCapabilityIdentity(
                request.bindings.capability.certificate, DIGEST_B, DIGEST_C
            ),
        ),
    )

    with pytest.raises(ReplayContractError, match="capability"):
        ReplayPairOrchestrator(provider, counter_reader=provider.read_counters).run_pair(drifted)
    assert provider.invocations == []


def test_live_and_provider_hosted_tool_attempts_make_pair_non_authoritative() -> None:
    provider = FakeProvider("live_and_hosted")
    result = ReplayPairOrchestrator(
        provider,
        counter_reader=provider.read_counters,
        nonce_factory=iter(("fresh-1", "fresh-2")).__next__,
    ).run_pair(_request())

    assert result.candidate.outcome == "harness_failure"
    assert result.candidate.reason_code == "live_tool_dispatch_denied"
    assert result.incumbent.outcome == "harness_failure"
    assert result.incumbent.reason_code == "provider_hosted_tool_execution_denied"
    assert result.receipt.payload["activation_evidence_eligible"] is False

    hidden = FakeProvider("hidden_hosted")
    hidden_result = ReplayPairOrchestrator(
        hidden,
        counter_reader=hidden.read_counters,
        nonce_factory=iter(("hidden-1", "hidden-2")).__next__,
    ).run_pair(_request(pair_ref="pair-hidden"))
    assert hidden_result.candidate.reason_code == "provider_hosted_tool_execution_denied"
    assert hidden_result.receipt.payload["activation_evidence_eligible"] is False


def test_each_integer_budget_dimension_is_enforced_without_candidate_harm() -> None:
    provider = FakeProvider("over_budget")
    result = ReplayPairOrchestrator(
        provider,
        counter_reader=provider.read_counters,
        nonce_factory=iter(("fresh-1", "fresh-2")).__next__,
    ).run_pair(_request())

    assert result.candidate.outcome == "harness_failure"
    assert result.candidate.reason_code == "budget_exhausted"
    assert result.incumbent.reason_code == "budget_exhausted"
    with pytest.raises(ReplayContractError, match="bounded integer"):
        ReplayBounds(5000, 2, 5, 1, True, 1024, 100)  # type: ignore[arg-type]


def test_retry_runs_a_fresh_whole_pair_and_never_resumes_one_arm() -> None:
    provider = FakeProvider("unavailable")
    nonces = iter(("s1", "s2", "s3", "s4"))
    orchestrator = ReplayPairOrchestrator(
        provider, counter_reader=provider.read_counters, nonce_factory=lambda: next(nonces)
    )
    first = orchestrator.run_pair(_request())
    prior = ExactIdentity(first.receipt.record_id, first.receipt.content_digest)
    second = orchestrator.retry_pair(first.receipt, _request(pair_ref="pair-2", retry_of=prior))

    assert len(provider.invocations) == 4
    assert {item.fresh_state_ref for item in provider.invocations} == {"s1", "s2", "s3", "s4"}
    assert [item.arm for item in provider.invocations] == [
        "candidate",
        "incumbent",
        "candidate",
        "incumbent",
    ]
    assert second.receipt.payload["retry_of_receipt_ref"] == first.receipt.record_id


def test_repository_replays_completed_pair_after_reopen_without_plaintext(
    tmp_path: Path,
) -> None:
    request, anchors = _repository_request()
    path = tmp_path / "durable-replay.sqlite3"
    provider = FakeProvider()
    executor = ReplayPairOrchestrator(
        provider,
        counter_reader=provider.read_counters,
        nonce_factory=iter(("repository-candidate", "repository-incumbent")).__next__,
    )
    with V3Repository.create(path, registry=_TEST_REPLAY_REGISTRY) as repository:
        _seed_replay_bindings(repository, request, anchors)
        first = RepositoryReplayCoordinator(repository, executor).run_pair(request)

    class NeverExecute:
        def run_pair(self, _request):
            raise AssertionError("provider replay was dispatched")

    with V3Repository.open(path, registry=_TEST_REPLAY_REGISTRY) as repository:
        replay = RepositoryReplayCoordinator(repository, NeverExecute()).run_pair(request)
        with pytest.raises(IdempotencyConflict):
            RepositoryReplayCoordinator(repository, NeverExecute()).run_pair(
                replace(request, pair_attempt_ref="pair-conflict")
            )

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.result.receipt == first.result.receipt
    assert len(provider.invocations) == 2
    assert b"TOP_SECRET_INPUT" not in path.read_bytes()
    assert b"TOP_SECRET_STATE" not in path.read_bytes()


def test_claim_without_receipt_never_redispatches_or_fabricates_result(
    tmp_path: Path,
) -> None:
    request, anchors = _repository_request()
    path = tmp_path / "incomplete-replay.sqlite3"

    class Interrupted:
        def __init__(self) -> None:
            self.calls = 0

        def run_pair(self, _request):
            self.calls += 1
            raise RuntimeError("lost provider completion")

    interrupted = Interrupted()
    with V3Repository.create(path, registry=_TEST_REPLAY_REGISTRY) as repository:
        _seed_replay_bindings(repository, request, anchors)
        with pytest.raises(RuntimeError, match="lost provider completion"):
            RepositoryReplayCoordinator(repository, interrupted).run_pair(request)
        with pytest.raises(ReplayAttemptIncomplete):
            RepositoryReplayCoordinator(repository, interrupted).run_pair(request)
        with pytest.raises(IdempotencyConflict):
            RepositoryReplayCoordinator(repository, interrupted).run_pair(
                replace(request, pair_attempt_ref="different-pair")
            )
        assert (
            repository.get_record(
                "replay_pair_receipt_" + replay_request_digest(request)
            )
            is None
        )

    assert interrupted.calls == 1
