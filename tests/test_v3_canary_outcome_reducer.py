from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    CanaryCoordinator,
    CanaryStartRequest,
    Rational,
    RecordIdentity,
    activation_policy,
    canary_plan,
    monitor_plan,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_command_adapter import (
    ExactRecord,
    SlotBinding,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_outcome_reducer import (
    CANARY_OUTCOME_REDUCER_REGISTRY,
    CanaryBucketValue,
    CanaryOutcomeReductionError,
    CanaryOutcomeReductionRequest,
    RepositoryCanaryOutcomeReducer,
    build_canary_attributable_outcome,
    build_canary_outcome_fact_authority,
    build_canary_outcome_reducer_profile,
    build_canary_outcome_window,
    digest_canary_outcome_reduction_request,
)
from usr.plugins.dspy_rlm.helpers.v3.calibration_authority import (
    CalibrationApprovalRequest,
    CalibrationWithdrawalRequest,
    ExactRecord as CalibrationExactRecord,
    approve_policy_calibration,
    withdraw_policy_calibration,
)
from usr.plugins.dspy_rlm.helpers.v3.candidate_publication import (
    IMPROVEMENT_CANDIDATE_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
    IntegrityFailure,
    V3Repository,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import (
    RecordSchema,
    SchemaRegistry,
    build_typed_record,
    merge_schema_registries,
    strict_literal,
    strict_object,
    validate_links,
)


CONTEXT = "context:canary-outcome-reducer"
KEY_EPOCH = "test-v1"
SECRET = b"explicit-canary-reducer-test-key"
TEST_EXACT_SCHEMA_ID = "test.canary-outcome-producer.v1"
TEST_REGISTRY = merge_schema_registries(
    CANARY_OUTCOME_REDUCER_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                TEST_EXACT_SCHEMA_ID,
                "test_exact",
                strict_object(
                    {
                        "fact_type": strict_literal("test_exact"),
                        "links": validate_links,
                    }
                ),
            ),
        )
    ),
)


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _link(role: str, target) -> dict[str, object]:
    return {
        "role": role,
        "ordinal": 0,
        "target_id": target.record_id,
        "target_digest": target.content_digest,
    }


def _test_exact(record_id: str):
    return build_typed_record(
        record_id=record_id,
        context_ref=CONTEXT,
        record_kind="test_exact",
        schema_id=TEST_EXACT_SCHEMA_ID,
        payload={"fact_type": "test_exact", "links": []},
        key_epoch=KEY_EPOCH,
        registry=TEST_REGISTRY,
    )


def _candidate(incumbent, successor, artifact, anchor):
    return build_typed_record(
        record_id="candidate:1",
        context_ref=CONTEXT,
        record_kind="improvement_candidate",
        schema_id=IMPROVEMENT_CANDIDATE_SCHEMA_ID,
        payload={
            "record_type": "improvement_candidate",
            "change_kind": "replace_structured_guidance",
            "artifact_slot": "structured_guidance",
            "artifact_id": artifact.record_id,
            "artifact_digest": artifact.content_digest,
            "incumbent_profile_id": incumbent.record_id,
            "incumbent_profile_digest": incumbent.content_digest,
            "successor_profile_id": successor.record_id,
            "successor_profile_digest": successor.content_digest,
            "activation_scope_ref": CONTEXT,
            "observed_scope_revision": 0,
            "lineage_id": anchor.record_id,
            "lineage_digest": anchor.content_digest,
            "benefit_claim": {
                "kind": "outcome",
                "bucket": "shell",
                "claim_ref": "claim:1",
                "claim_digest": _digest("claim:1"),
            },
            "risk_tier": "standard",
            "engine_semantic_id": "a0.generate.guidance.deterministic_rules.v1",
            "engine_profile_id": anchor.record_id,
            "engine_profile_digest": anchor.content_digest,
            "artifact_generation_receipt_id": anchor.record_id,
            "artifact_generation_receipt_digest": anchor.content_digest,
            "links": [
                _link("artifact", artifact),
                _link("incumbent_profile", incumbent),
                _link("successor_profile", successor),
                _link("lineage", anchor),
                _link("engine_profile", anchor),
                _link("artifact_generation_receipt", anchor),
            ],
        },
        key_epoch=KEY_EPOCH,
        registry=TEST_REGISTRY,
    )


def _grant(binding):
    now = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
    return VerifiedGrant(
        grant_id=f"grant:{binding.operation}",
        authority_class=binding.authority_class,
        issuer_id=binding.issuer_ref,
        key_epoch=1,
        subject_ref=binding.subject_ref,
        context_ref=binding.context_ref,
        action=binding.action,
        purpose=binding.purpose,
        target_ref=binding.target_ref,
        target_revision=binding.target_revision,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        idempotency_key_digest=binding.idempotency_key_digest,
        session_nonce=binding.session_nonce,
    )


def _seed(tmp_path, *, diagnostic: bool = False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    incumbent = activation_profile(
        record_id="profile:incumbent",
        context_ref=CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch=KEY_EPOCH,
    )
    successor = activation_profile(
        record_id="profile:successor",
        context_ref=CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch=KEY_EPOCH,
    )
    candidate = _candidate(incumbent, successor, guidance, prompt)
    producer = _test_exact("producer:outcome-reducer")
    policy = activation_policy(
        record_id="policy:1",
        context_ref=CONTEXT,
        policy_revision=1,
        activation_mode="canary_required",
        key_epoch=KEY_EPOCH,
    )
    plan = canary_plan(
        record_id="plan:1",
        context_ref=CONTEXT,
        horizon_exposures=2,
        expiry_seconds=900,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=sha256(
            b"a0-canary-assignment-key\0" + SECRET
        ).hexdigest(),
        hard_veto_failure_limit=0,
        buckets=(BucketCalibration("shell", 1, Rational(0, 1), Rational(0, 1)),),
        key_epoch=KEY_EPOCH,
    )
    monitoring = monitor_plan(
        record_id="monitor:1",
        context_ref=CONTEXT,
        horizon_exposures=4,
        look_interval_exposures=2,
        ordinary_regression_boundary=Rational(0, 1),
        hard_veto_failure_limit=0,
        key_epoch=KEY_EPOCH,
    )
    repository = V3Repository.create(
        tmp_path / "canary-outcome.sqlite3", registry=TEST_REGISTRY
    )
    with repository.transaction() as transaction:
        for record in (
            guidance,
            prompt,
            incumbent,
            successor,
            candidate,
            producer,
            policy,
            plan,
            monitoring,
        ):
            transaction.insert_record(record)
        transaction.initialize_activation_scope(
            context_ref=CONTEXT,
            profile_id=incumbent.record_id,
            profile_digest=incumbent.content_digest,
        )
    calibration = approve_policy_calibration(
        repository,
        request=CalibrationApprovalRequest(
            calibration_id="calibration:1",
            receipt_id="calibration-approval-receipt:1",
            context_ref=CONTEXT,
            expected_policy_revision=1,
            environment_ref="environment:test",
            policy=CalibrationExactRecord.of(policy),
            canary_plan=CalibrationExactRecord.of(plan),
            monitor_plan=CalibrationExactRecord.of(monitoring),
            activation_authorities=("manual",),
            soft_rollback_authorized=False,
            issuer_ref="issuer:calibration",
            subject_ref="subject:calibration",
            idempotency_key_digest=_digest("calibration-approve"),
            session_nonce="session:calibration",
            reason_code="calibration_approved",
            key_epoch=KEY_EPOCH,
        ),
        revalidate_grant=_grant,
    ).calibration
    trial = CanaryCoordinator(key_epoch=KEY_EPOCH).plan_start(
        CanaryStartRequest(
            record_id="trial:1",
            context_ref=CONTEXT,
            canary_kind="diagnostic" if diagnostic else "authoritative",
            disposition="review_only" if diagnostic else "promotion_ready",
            disposition_ref=RecordIdentity.of(prompt),
            candidate=RecordIdentity.of(candidate),
            incumbent_profile=RecordIdentity.of(incumbent),
            expected_scope_revision=0,
            observed_scope_revision=0,
            environment_ref="environment:test",
            policy=policy,
            calibration=calibration,
            plan=plan,
            authority_grant=RecordIdentity.of(prompt),
            authority_purpose=(
                "diagnostic_canary" if diagnostic else "authoritative_canary"
            ),
            occupied_canary_ref=None,
        )
    )
    coordinator = CanaryCoordinator(key_epoch=KEY_EPOCH)
    by_arm = {}
    for index in range(128):
        receipt = coordinator.plan_exposure(
            record_id=f"exposure:{index:03d}",
            trial=trial,
            active_trial=RecordIdentity.of(trial),
            observed_scope_revision=0,
            exposure_unit_ref=f"unit:{index:03d}",
            envelope_ref=f"envelope:{index:03d}",
            eligible=True,
            already_receipted=False,
            assignment_secret=SECRET,
            frozen_plan=plan,
        )
        by_arm.setdefault(receipt.payload["arm"], receipt)
        if set(by_arm) == {"candidate", "incumbent"}:
            break
    exposures = tuple(sorted(by_arm.values(), key=lambda item: item.record_id))
    assert len(exposures) == 2
    with repository.transaction() as transaction:
        transaction.insert_record(trial)
        for exposure in exposures:
            transaction.insert_record(exposure)
        slot = transaction.claim_empty_operation_slot(
            context_ref=CONTEXT,
            operation_kind="canary",
            expected_revision=0,
            expected_scope_revision=0,
            operation_id=trial.record_id,
            operation_digest=trial.content_digest,
        )
    profile = build_canary_outcome_reducer_profile(
        record_id="reducer-profile:1",
        context_ref=CONTEXT,
        profile_revision=1,
        producer=producer,
        canary_plan=plan,
        policy_calibration=calibration,
        key_epoch=KEY_EPOCH,
    )
    window = build_canary_outcome_window(
        record_id="outcome-window:1",
        context_ref=CONTEXT,
        window_revision=1,
        trial=trial,
        canary_plan=plan,
        reducer_profile=profile,
        exposure_receipts=exposures,
        key_epoch=KEY_EPOCH,
    )
    authority = build_canary_outcome_fact_authority(
        record_id="outcome-authority:1",
        context_ref=CONTEXT,
        authority_revision=1,
        trial=trial,
        candidate=candidate,
        producer=producer,
        reducer_profile=profile,
        canary_plan=plan,
        policy_calibration=calibration,
        key_epoch=KEY_EPOCH,
    )
    facts = []
    for exposure in exposures:
        candidate_arm = exposure.payload["arm"] == "candidate"
        facts.append(
            build_canary_attributable_outcome(
                record_id=f"outcome:{exposure.record_id}",
                context_ref=CONTEXT,
                trial=trial,
                canary_plan=plan,
                outcome_window=window,
                exposure_receipt=exposure,
                candidate=candidate,
                selected_profile=successor if candidate_arm else incumbent,
                outcome_authority=authority,
                outcome_occurrence_ref=f"occurrence:{exposure.record_id}",
                bucket_values=(
                    CanaryBucketValue(
                        "shell", True, Rational(3, 1) if candidate_arm else Rational(1, 1)
                    ),
                ),
                hard_failure=False,
                shared_failure=False,
                identity_drift=False,
                boundary_uncertain=False,
                key_epoch=KEY_EPOCH,
            )
        )
    facts = tuple(sorted(facts, key=lambda item: item.record_id))
    with repository.transaction() as transaction:
        for record in (profile, window, authority, *facts):
            transaction.insert_record(record)
    return {
        "repository": repository,
        "incumbent": incumbent,
        "successor": successor,
        "candidate": candidate,
        "producer": producer,
        "policy": policy,
        "plan": plan,
        "monitor": monitoring,
        "calibration": calibration,
        "trial": trial,
        "slot": slot,
        "profile": profile,
        "window": window,
        "authority": authority,
        "exposures": exposures,
        "facts": facts,
    }


def _request(seed, **changes):
    request = CanaryOutcomeReductionRequest(
        context_ref=CONTEXT,
        expected_scope_revision=0,
        slot=SlotBinding(seed["slot"].operation_revision, ExactRecord.of(seed["trial"])),
        trial=ExactRecord.of(seed["trial"]),
        canary_plan=ExactRecord.of(seed["plan"]),
        activation_policy=ExactRecord.of(seed["policy"]),
        policy_calibration=ExactRecord.of(seed["calibration"]),
        producer=ExactRecord.of(seed["producer"]),
        reducer_profile=ExactRecord.of(seed["profile"]),
        outcome_authority=ExactRecord.of(seed["authority"]),
        outcome_window=ExactRecord.of(seed["window"]),
        exposure_receipts=tuple(ExactRecord.of(item) for item in seed["exposures"]),
        outcome_facts=tuple(ExactRecord.of(item) for item in seed["facts"]),
        reduction_record_id="reduction:1",
        certified_authority_record_id="certified-reducer-authority:1",
        conclusion_record_id="conclusion:1",
        idempotency_key_digest=_digest("reduce:1"),
        request_digest="0" * 64,
        key_epoch=KEY_EPOCH,
    )
    request = replace(request, **changes)
    return replace(
        request,
        request_digest=digest_canary_outcome_reduction_request(request),
    )


def test_fixed_horizon_reduction_is_content_free_durable_and_exact(tmp_path):
    seed = _seed(tmp_path)
    request = _request(seed)
    result = RepositoryCanaryOutcomeReducer(seed["repository"]).reduce(request)

    assert result.replayed is False
    assert result.conclusion_request.eligible_exposure_count == 2
    assert result.conclusion_request.bucket_outcomes[0].candidate_delta == Rational(2, 1)
    assert result.conclusion_request.bucket_outcomes[0].comparable_count == 1
    assert result.certified_reducer_authority.payload["reducer_profile"] == ExactRecord.of(
        seed["profile"]
    ).payload()
    assert result.reduction.payload["threshold_authority"] == "exact_canary_plan_only"
    assert result.event.event_type == "canary_outcome_reduced"
    durable = seed["repository"].path.read_bytes()
    assert b"contains_raw_content\":false" in durable
    seed["repository"].close()

    reopened = V3Repository.open(
        tmp_path / "canary-outcome.sqlite3", registry=TEST_REGISTRY
    )
    replay = RepositoryCanaryOutcomeReducer(reopened).reduce(request)
    assert replay.replayed is True
    assert replay.receipt == result.receipt
    assert replay.conclusion_request == result.conclusion_request
    reopened.close()


def test_exposure_only_or_missing_outcome_never_reduces(tmp_path):
    seed = _seed(tmp_path)
    reducer = RepositoryCanaryOutcomeReducer(seed["repository"])
    request = _request(seed, outcome_facts=(_request(seed).outcome_facts[0],))
    before = seed["repository"].path.read_bytes()
    with pytest.raises(CanaryOutcomeReductionError, match="every exposure"):
        reducer.reduce(request)
    assert seed["repository"].path.read_bytes() == before

    exposure_only = _request(
        seed,
        outcome_facts=tuple(ExactRecord.of(item) for item in seed["exposures"]),
    )
    with pytest.raises(IntegrityFailure, match="exact record binding"):
        reducer.reduce(exposure_only)
    seed["repository"].close()


def test_mixed_window_profile_and_plan_are_rejected(tmp_path):
    seed = _seed(tmp_path)
    wrong_profile = replace(
        ExactRecord.of(seed["profile"]), digest=_digest("wrong-profile")
    )
    request = _request(seed, reducer_profile=wrong_profile)
    with pytest.raises(IntegrityFailure):
        RepositoryCanaryOutcomeReducer(seed["repository"]).reduce(request)
    seed["repository"].close()


def test_withdrawn_calibration_and_diagnostic_authority_fail_closed(tmp_path):
    seed = _seed(tmp_path / "withdrawn")
    withdraw_policy_calibration(
        seed["repository"],
        request=CalibrationWithdrawalRequest(
            receipt_id="calibration-withdrawal-receipt:1",
            context_ref=CONTEXT,
            expected_policy_revision=1,
            environment_ref="environment:test",
            calibration=CalibrationExactRecord.of(seed["calibration"]),
            issuer_ref="issuer:calibration",
            subject_ref="subject:calibration",
            idempotency_key_digest=_digest("calibration-withdraw"),
            session_nonce="session:calibration",
            reason_code="calibration_withdrawn",
            key_epoch=KEY_EPOCH,
        ),
        revalidate_grant=_grant,
    )
    with pytest.raises(IntegrityFailure, match="withdrawn"):
        RepositoryCanaryOutcomeReducer(seed["repository"]).reduce(_request(seed))
    seed["repository"].close()

    diagnostic = _seed(tmp_path / "diagnostic", diagnostic=True)
    with pytest.raises(IntegrityFailure, match="diagnostic"):
        RepositoryCanaryOutcomeReducer(diagnostic["repository"]).reduce(
            _request(diagnostic)
        )
    diagnostic["repository"].close()


def test_exact_replay_and_changed_idempotent_request_conflicts(tmp_path):
    seed = _seed(tmp_path)
    reducer = RepositoryCanaryOutcomeReducer(seed["repository"])
    original = _request(seed)
    first = reducer.reduce(original)
    replay = reducer.reduce(original)
    assert replay.replayed is True and replay.receipt == first.receipt

    changed = _request(seed, conclusion_record_id="conclusion:changed")
    with pytest.raises(IdempotencyConflict):
        reducer.reduce(changed)
    seed["repository"].close()
