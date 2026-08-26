from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_runtime import (
    CANARY_RUNTIME_OBSERVATION_KIND,
    CANARY_RUNTIME_OBSERVATION_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.deterministic_analysis import ExactIdentity
from usr.plugins.dspy_rlm.helpers.v3.observation import (
    RuntimeObservationRequest,
    record_runtime_observation,
)
from usr.plugins.dspy_rlm.helpers.v3.observation_bridge import (
    OBSERVATION_BRIDGE_REGISTRY,
    BridgeInput,
    CanaryOutcomeAuthorityRequired,
    ObservationBridgeConflict,
    ObservationBridgeError,
    ObservationBridgeRequest,
    OutcomeMapping,
    bridge_runtime_observations,
    build_analysis_window,
    build_certified_canary_outcome,
    build_evidence_authority,
    build_observation_bridge_policy,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Reader, V3Repository
from usr.plugins.dspy_rlm.helpers.v3.schemas import build_typed_record


CONTEXT = "context-bridge-01"
EPOCH = "bridge-epoch-01"


def _exact(record: object) -> ExactIdentity:
    return ExactIdentity(record.record_id, record.content_digest)


def _seed(
    path: Path, mappings: tuple[OutcomeMapping, ...]
) -> tuple[object, object, object, object]:
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile-bridge-current",
        context_ref=CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch=EPOCH,
    )
    window = build_analysis_window(
        record_id="window-bridge-01",
        context_ref=CONTEXT,
        window_revision=4,
        key_epoch=EPOCH,
    )
    evidence = build_evidence_authority(
        record_id="evidence-authority-bridge-01",
        context_ref=CONTEXT,
        authority_revision=7,
        key_epoch=EPOCH,
    )
    policy = build_observation_bridge_policy(
        record_id="bridge-policy-01",
        context_ref=CONTEXT,
        policy_revision=3,
        current_profile=profile,
        analysis_window=window,
        evidence_authority=evidence,
        mappings=mappings,
        output_key_epoch=EPOCH,
    )
    with V3Repository.create(path, registry=OBSERVATION_BRIDGE_REGISTRY) as repository:
        with repository.transaction() as transaction:
            for record in (guidance, prompt, profile, window, evidence, policy):
                transaction.insert_record(record)
            transaction.initialize_activation_scope(
                context_ref=CONTEXT,
                profile_id=profile.record_id,
                profile_digest=profile.content_digest,
            )
    return profile, window, evidence, policy


def _observe(path: Path, occurrence: str, outcome: str = "tool_returned_continuing"):
    with V3Repository.open(path, registry=OBSERVATION_BRIDGE_REGISTRY) as repository:
        result = record_runtime_observation(
            repository,
            RuntimeObservationRequest(
                context_ref=CONTEXT,
                occurrence_ref=occurrence,
                observation_kind="tool_execute_after",
                outcome_code=outcome,
                loop_iteration=2,
            ),
        )
        assert result is not None
        return result.record


def _request(
    *,
    key: str,
    profile: object,
    window: object,
    evidence: object,
    policy: object,
    inputs: tuple[BridgeInput, ...],
    epoch: str = EPOCH,
) -> ObservationBridgeRequest:
    return ObservationBridgeRequest(
        context_ref=CONTEXT,
        idempotency_key=key,
        policy=_exact(policy),
        current_profile=_exact(profile),
        analysis_window=_exact(window),
        evidence_authority=_exact(evidence),
        output_key_epoch=epoch,
        inputs=inputs,
    )


def test_explicit_mapping_aggregates_content_free_facts_and_replays_after_restart(
    tmp_path: Path,
) -> None:
    store = tmp_path / "safe.sqlite3"
    profile, window, evidence, policy = _seed(
        store,
        (
            OutcomeMapping(
                "runtime_observation",
                "tool_execute_after",
                "tool_returned_continuing",
                "tool_retrieval",
            ),
        ),
    )
    first_observation = _observe(store, "tool-log-bridge-01")
    second_observation = _observe(store, "tool-log-bridge-02")
    request = _request(
        key="bridge-key-01",
        profile=profile,
        window=window,
        evidence=evidence,
        policy=policy,
        inputs=tuple(
            sorted(
                (
                    BridgeInput(_exact(first_observation)),
                    BridgeInput(_exact(second_observation)),
                ),
                key=lambda item: item.observation.ref,
            )
        ),
    )

    with V3Repository.open(store, registry=OBSERVATION_BRIDGE_REGISTRY) as repository:
        first = bridge_runtime_observations(repository, request)
    with V3Repository.open(store, registry=OBSERVATION_BRIDGE_REGISTRY) as repository:
        replay = bridge_runtime_observations(repository, request)

    assert first.replayed is False and replay.replayed is True
    assert replay.receipt == first.receipt
    assert replay.facts == first.facts
    assert len(first.facts) == 1
    fact = first.facts[0]
    assert fact.payload["bucket_ref"] == "tool_retrieval"
    assert fact.payload["outcome_code"] == "tool_returned_continuing"
    assert fact.payload["occurrences"] == 2
    assert fact.payload["source_profile_ref"] == profile.record_id
    assert first.receipt.payload["promotion_authority"] == "none"
    assert "bridge-key-01" not in first.receipt.canonical_bytes.decode()
    with V3Reader.open(store, registry=OBSERVATION_BRIDGE_REGISTRY) as reader:
        assert reader.count_domain_events_for_context(CONTEXT) == 3


def test_unmapped_or_stale_runtime_input_rolls_back_without_receipt(tmp_path: Path) -> None:
    store = tmp_path / "safe.sqlite3"
    profile, window, evidence, policy = _seed(
        store,
        (
            OutcomeMapping(
                "runtime_observation",
                "tool_execute_after",
                "tool_returned_terminal",
                "shell",
            ),
        ),
    )
    observation = _observe(store, "tool-log-unmapped")
    request = _request(
        key="bridge-key-unmapped",
        profile=profile,
        window=window,
        evidence=evidence,
        policy=policy,
        inputs=(BridgeInput(_exact(observation)),),
    )

    with V3Repository.open(store, registry=OBSERVATION_BRIDGE_REGISTRY) as repository:
        with pytest.raises(ObservationBridgeError, match="no explicit bucket mapping"):
            bridge_runtime_observations(repository, request)
    with V3Reader.open(store, registry=OBSERVATION_BRIDGE_REGISTRY) as reader:
        kinds = [
            item.record.record_kind
            for item in reader.list_records_for_context(CONTEXT, maximum=32)
        ]
        assert "observation_bridge_receipt" not in kinds
        assert "analysis_observation_fact" not in kinds


def test_changed_request_reusing_idempotency_key_conflicts_before_writes(
    tmp_path: Path,
) -> None:
    store = tmp_path / "safe.sqlite3"
    profile, window, evidence, policy = _seed(
        store,
        (
            OutcomeMapping(
                "runtime_observation",
                "tool_execute_after",
                "tool_returned_continuing",
                "reasoning",
            ),
        ),
    )
    observation = _observe(store, "tool-log-conflict")
    request = _request(
        key="bridge-key-conflict",
        profile=profile,
        window=window,
        evidence=evidence,
        policy=policy,
        inputs=(BridgeInput(_exact(observation)),),
    )
    changed = _request(
        key="bridge-key-conflict",
        profile=profile,
        window=window,
        evidence=evidence,
        policy=policy,
        inputs=(BridgeInput(_exact(observation)),),
        epoch="changed-epoch",
    )

    with V3Repository.open(store, registry=OBSERVATION_BRIDGE_REGISTRY) as repository:
        first = bridge_runtime_observations(repository, request)
        with pytest.raises(ObservationBridgeConflict):
            bridge_runtime_observations(repository, changed)
    with V3Reader.open(store, registry=OBSERVATION_BRIDGE_REGISTRY) as reader:
        receipts = [
            item.record
            for item in reader.list_records_for_context(CONTEXT, maximum=32)
            if item.record.record_kind == "observation_bridge_receipt"
        ]
        assert receipts == [first.receipt]
        assert reader.count_domain_events_for_context(CONTEXT) == 2


def test_canary_exposure_requires_separate_certified_outcome_authority(
    tmp_path: Path,
) -> None:
    store = tmp_path / "safe.sqlite3"
    mappings = (
        OutcomeMapping(
            "certified_canary_outcome",
            "canary_runtime_observation",
            "task_completed",
            "reasoning",
        ),
    )
    profile, window, evidence, policy = _seed(store, mappings)
    runtime = _observe(store, "canary-outcome-occurrence")
    canary_payload = {
        "fact_type": CANARY_RUNTIME_OBSERVATION_KIND,
        "context_ref": CONTEXT,
        "trial_id": window.record_id,
        "trial_digest": window.content_digest,
        "exposure_receipt_id": evidence.record_id,
        "exposure_receipt_digest": evidence.content_digest,
        "runtime_observation_id": runtime.record_id,
        "runtime_observation_digest": runtime.content_digest,
        "exposure_unit_ref": "canary-exposure-unit-01",
        "envelope_ref": "canary-envelope-01",
        "outcome_occurrence_ref": runtime.payload["occurrence_ref"],
        "arm": "incumbent",
        "selected_profile_id": profile.record_id,
        "selected_profile_digest": profile.content_digest,
        "scope_revision": 0,
        "assignment_digest": sha256(b"assignment").hexdigest(),
        "outcome_code": "message_loop_end_observed",
        "outcome_authority": "exposure_only",
        "promotion_authority": "none",
        "objective_bucket_state": "unbound",
        "contains_raw_content": False,
        "contains_provider_identifier": False,
        "contains_error_detail": False,
        "contains_path": False,
        "links": [
            {
                "role": "canary_trial",
                "ordinal": 0,
                "target_id": window.record_id,
                "target_digest": window.content_digest,
            },
            {
                "role": "exposure_receipt",
                "ordinal": 0,
                "target_id": evidence.record_id,
                "target_digest": evidence.content_digest,
            },
            {
                "role": "runtime_observation",
                "ordinal": 0,
                "target_id": runtime.record_id,
                "target_digest": runtime.content_digest,
            },
            {
                "role": "selected_profile",
                "ordinal": 0,
                "target_id": profile.record_id,
                "target_digest": profile.content_digest,
            },
        ],
    }
    canary = build_typed_record(
        record_id="canary-runtime-observation-bridge-01",
        context_ref=CONTEXT,
        record_kind=CANARY_RUNTIME_OBSERVATION_KIND,
        schema_id=CANARY_RUNTIME_OBSERVATION_SCHEMA_ID,
        payload=canary_payload,
        key_epoch=EPOCH,
        registry=OBSERVATION_BRIDGE_REGISTRY,
    )
    authority = build_certified_canary_outcome(
        record_id="certified-canary-outcome-01",
        context_ref=CONTEXT,
        canary_observation=canary,
        certified_outcome_code="task_completed",
        source_profile=profile,
        current_profile=profile,
        observed_scope_revision=0,
        analysis_window=window,
        evidence_authority=evidence,
        key_epoch=EPOCH,
    )
    with V3Repository.open(store, registry=OBSERVATION_BRIDGE_REGISTRY) as repository:
        with repository.transaction() as transaction:
            transaction.insert_record(canary)
            transaction.insert_record(authority)
        without_authority = _request(
            key="canary-bridge-without-authority",
            profile=profile,
            window=window,
            evidence=evidence,
            policy=policy,
            inputs=(BridgeInput(_exact(canary)),),
        )
        with pytest.raises(CanaryOutcomeAuthorityRequired):
            bridge_runtime_observations(repository, without_authority)
        admitted = bridge_runtime_observations(
            repository,
            _request(
                key="canary-bridge-certified",
                profile=profile,
                window=window,
                evidence=evidence,
                policy=policy,
                inputs=(BridgeInput(_exact(canary), _exact(authority)),),
            ),
        )

    assert admitted.facts[0].payload["outcome_code"] == "task_completed"
    assert admitted.facts[0].payload["bucket_ref"] == "reasoning"
    assert canary.payload["outcome_authority"] == "exposure_only"
    assert canary.payload["outcome_code"] == "message_loop_end_observed"
