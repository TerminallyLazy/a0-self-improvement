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
    CANARY_REGISTRY,
    POST_PROMOTION_MONITOR_SCHEMA_ID,
    BucketCalibration,
    Rational,
    activation_policy,
    canary_plan,
    monitor_plan,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_command_adapter import ExactRecord, SlotBinding
from usr.plugins.dspy_rlm.helpers.v3.calibration_authority import (
    CALIBRATION_AUTHORITY_REGISTRY,
    CalibrationApprovalRequest,
    ExactRecord as CalibrationExactRecord,
    approve_policy_calibration,
)
from usr.plugins.dspy_rlm.helpers.v3.post_activation_repository import (
    POST_ACTIVATION_REPOSITORY_REGISTRY,
    PostActivationAuthority,
    PostActivationOperation,
    RepositoryPostActivationCoordinator,
    build_certified_post_activation_outcome,
    build_post_activation_eligibility,
    digest_post_activation_request,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
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


NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
CONTEXT = "context:post-activation"
KEY_EPOCH = "post-activation-test-v1"
EXACT_SCHEMA = "test.post-activation-exact.v1"
AUTHORITY = PostActivationAuthority(
    "grant:post-activation", "issuer:operator", "subject:operator"
)

TEST_REGISTRY = merge_schema_registries(
    CALIBRATION_AUTHORITY_REGISTRY,
    POST_ACTIVATION_REPOSITORY_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                EXACT_SCHEMA,
                "post_activation_test_exact",
                strict_object(
                    {
                        "fact_type": strict_literal("post_activation_test_exact"),
                        "links": validate_links,
                    }
                ),
            ),
        )
    ),
)


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _exact(record_id: str):
    return build_typed_record(
        record_id=record_id,
        context_ref=CONTEXT,
        record_kind="post_activation_test_exact",
        schema_id=EXACT_SCHEMA,
        payload={"fact_type": "post_activation_test_exact", "links": []},
        key_epoch=KEY_EPOCH,
        registry=TEST_REGISTRY,
    )


def _calibration_grant(binding):
    return VerifiedGrant(
        grant_id="grant:calibration",
        authority_class=binding.authority_class,
        issuer_id=binding.issuer_ref,
        key_epoch=1,
        subject_ref=binding.subject_ref,
        context_ref=binding.context_ref,
        action=binding.action,
        purpose=binding.purpose,
        target_ref=binding.target_ref,
        target_revision=binding.target_revision,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        idempotency_key_digest=binding.idempotency_key_digest,
        session_nonce=binding.session_nonce,
    )


def _seed(tmp_path):
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile:active",
        context_ref=CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch=KEY_EPOCH,
    )
    policy = activation_policy(
        record_id="policy:1",
        context_ref=CONTEXT,
        policy_revision=1,
        activation_mode="canary_required",
        key_epoch=KEY_EPOCH,
    )
    trial_plan = canary_plan(
        record_id="canary-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=4,
        expiry_seconds=300,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=_digest("assignment"),
        hard_veto_failure_limit=0,
        buckets=(BucketCalibration("ordinary", 2, Rational(0, 1), Rational(0, 1)),),
        key_epoch=KEY_EPOCH,
    )
    monitoring = monitor_plan(
        record_id="monitor-plan:1",
        context_ref=CONTEXT,
        horizon_exposures=8,
        look_interval_exposures=2,
        ordinary_regression_boundary=Rational(0, 1),
        hard_veto_failure_limit=0,
        key_epoch=KEY_EPOCH,
    )
    candidate = _exact("candidate:1")
    canary_conclusion = _exact("canary-conclusion:1")
    producer = _exact("producer:certified")
    reducer = _exact("reducer-profile:1")
    measurements = _exact("measurements:1")
    repository = V3Repository.create(
        tmp_path / "post-activation.sqlite3", registry=TEST_REGISTRY
    )
    with repository.transaction() as transaction:
        for record in (
            guidance,
            prompt,
            profile,
            policy,
            trial_plan,
            monitoring,
            candidate,
            canary_conclusion,
            producer,
            reducer,
            measurements,
        ):
            transaction.insert_record(record)
        transaction.initialize_activation_scope(
            context_ref=CONTEXT,
            profile_id=profile.record_id,
            profile_digest=profile.content_digest,
        )
        transaction.compare_and_swap_activation_scope(
            context_ref=CONTEXT,
            expected_revision=0,
            profile_id=profile.record_id,
            profile_digest=profile.content_digest,
            mode="normal",
        )
    calibration = approve_policy_calibration(
        repository,
        request=CalibrationApprovalRequest(
            calibration_id="calibration:1",
            receipt_id="calibration-receipt:1",
            context_ref=CONTEXT,
            expected_policy_revision=1,
            environment_ref="environment:test",
            policy=CalibrationExactRecord.of(policy),
            canary_plan=CalibrationExactRecord.of(trial_plan),
            monitor_plan=CalibrationExactRecord.of(monitoring),
            activation_authorities=("manual",),
            soft_rollback_authorized=True,
            issuer_ref="issuer:calibration",
            subject_ref="subject:calibration",
            idempotency_key_digest=_digest("calibration"),
            session_nonce="session:calibration",
            reason_code="calibration_approved",
            key_epoch=KEY_EPOCH,
        ),
        revalidate_grant=_calibration_grant,
    ).calibration
    links = [
        ("candidate", candidate),
        ("incumbent_profile", profile),
        ("canary_conclusion", canary_conclusion),
        ("activation_policy", policy),
        ("policy_calibration", calibration),
        ("monitor_plan", monitoring),
    ]
    monitor = build_typed_record(
        record_id="monitor:1",
        context_ref=CONTEXT,
        record_kind="post_promotion_monitor",
        schema_id=POST_PROMOTION_MONITOR_SCHEMA_ID,
        payload={
            "fact_type": "post_promotion_monitor",
            "candidate_id": candidate.record_id,
            "candidate_digest": candidate.content_digest,
            "incumbent_profile_id": profile.record_id,
            "incumbent_profile_digest": profile.content_digest,
            "canary_conclusion_id": canary_conclusion.record_id,
            "canary_conclusion_digest": canary_conclusion.content_digest,
            "policy_id": policy.record_id,
            "policy_digest": policy.content_digest,
            "calibration_id": calibration.record_id,
            "calibration_digest": calibration.content_digest,
            "monitor_plan_id": monitoring.record_id,
            "monitor_plan_digest": monitoring.content_digest,
            "observed_scope_revision": 0,
            "resulting_scope_revision": 1,
            "links": [
                {
                    "role": role,
                    "ordinal": 0,
                    "target_id": record.record_id,
                    "target_digest": record.content_digest,
                }
                for role, record in links
            ],
        },
        key_epoch=KEY_EPOCH,
        registry=CANARY_REGISTRY,
    )
    with repository.transaction() as transaction:
        transaction.insert_record(monitor)
        monitor_slot = transaction.claim_empty_operation_slot(
            context_ref=CONTEXT,
            operation_kind="monitor",
            expected_revision=0,
            expected_scope_revision=1,
            operation_id=monitor.record_id,
            operation_digest=monitor.content_digest,
        )
    return {
        "repository": repository,
        "profile": profile,
        "policy": policy,
        "calibration": calibration,
        "monitor": monitor,
        "monitor_slot": monitor_slot,
        "producer": producer,
        "reducer": reducer,
        "measurements": measurements,
    }


def _operation(seed, action, decision, subject, monitor_slot, requalification_slot, key):
    repository = seed["repository"]
    outcome = build_certified_post_activation_outcome(
        record_id=f"outcome:{key}",
        context_ref=CONTEXT,
        subject=ExactRecord.of(subject),
        producer=ExactRecord.of(seed["producer"]),
        reducer_profile=ExactRecord.of(seed["reducer"]),
        measurement_bundle=ExactRecord.of(seed["measurements"]),
        decision=decision,
        key_epoch=KEY_EPOCH,
    )
    eligibility = build_post_activation_eligibility(
        record_id=f"eligibility:{key}",
        context_ref=CONTEXT,
        action=action,
        decision=decision,
        scope_revision=1,
        active_profile=ExactRecord.of(seed["profile"]),
        subject=ExactRecord.of(subject),
        certified_outcome=ExactRecord.of(outcome),
        policy=ExactRecord.of(seed["policy"]),
        calibration=ExactRecord.of(seed["calibration"]),
        key_epoch=KEY_EPOCH,
    )
    with repository.transaction() as transaction:
        transaction.insert_record(outcome)
        transaction.insert_record(eligibility)
    operation = PostActivationOperation(
        action=action,
        context_ref=CONTEXT,
        expected_scope_revision=1,
        monitor_slot=monitor_slot,
        requalification_slot=requalification_slot,
        subject=ExactRecord.of(subject),
        certified_outcome=ExactRecord.of(outcome),
        eligibility=ExactRecord.of(eligibility),
        policy=ExactRecord.of(seed["policy"]),
        calibration=ExactRecord.of(seed["calibration"]),
        authority=AUTHORITY,
        conclusion_record_id=f"conclusion:{key}",
        requalification_window_id=(f"requalification:{key}" if action == "requalification_start" else None),
        idempotency_key_digest=_digest(key),
        request_digest="0" * 64,
        key_epoch=KEY_EPOCH,
    )
    return replace(operation, request_digest=digest_post_activation_request(operation))


def _commit(seed, operation):
    return RepositoryPostActivationCoordinator(
        seed["repository"], key_epoch=KEY_EPOCH
    ).commit(operation, revalidate_authority=lambda _tx, _op: AUTHORITY)


def test_monitor_retain_clears_exact_slot_and_replays_after_restart(tmp_path):
    seed = _seed(tmp_path)
    operation = _operation(
        seed,
        "monitor_conclude",
        "retain",
        seed["monitor"],
        SlotBinding(1, ExactRecord.of(seed["monitor"])),
        SlotBinding(0, None),
        "retain",
    )
    result = _commit(seed, operation)
    assert result.receipt.payload["decision"] == "retain"
    assert result.monitor_slot.operation_id is None
    assert result.requalification_slot is None
    path = seed["repository"].path
    seed["repository"].close()
    with V3Repository.open(path, registry=TEST_REGISTRY) as reopened:
        seed["repository"] = reopened
        replay = _commit(seed, operation)
        assert replay.replayed is True
        assert replay.conclusion == result.conclusion


def test_requalification_start_and_conclusion_are_exact_slot_cas(tmp_path):
    seed = _seed(tmp_path)
    start = _operation(
        seed,
        "requalification_start",
        "requalify",
        seed["monitor"],
        SlotBinding(1, ExactRecord.of(seed["monitor"])),
        SlotBinding(0, None),
        "requalify",
    )
    started = _commit(seed, start)
    assert started.monitor_slot.operation_id is None
    assert started.requalification_slot.operation_id == started.requalification_window.record_id

    conclude = _operation(
        seed,
        "requalification_conclude",
        "retain",
        started.requalification_window,
        SlotBinding(2, None),
        SlotBinding(
            1,
            ExactRecord.of(started.requalification_window),
        ),
        "requalification-retain",
    )
    concluded = _commit(seed, conclude)
    assert concluded.requalification_slot.operation_id is None
    assert concluded.receipt.payload["decision"] == "retain"
    assert seed["repository"].get_activation_scope(CONTEXT).scope_revision == 1
    seed["repository"].close()


def test_rollback_required_emits_request_without_profile_mutation_and_conflicts_changed_request(tmp_path):
    seed = _seed(tmp_path)
    operation = _operation(
        seed,
        "monitor_conclude",
        "rollback_required",
        seed["monitor"],
        SlotBinding(1, ExactRecord.of(seed["monitor"])),
        SlotBinding(0, None),
        "rollback",
    )
    result = _commit(seed, operation)
    scope = seed["repository"].get_activation_scope(CONTEXT)
    assert result.rollback_request.payload["authority_ceiling"] == "request_only"
    assert result.rollback_request.payload["profile_mutation"] == "none"
    assert scope.scope_revision == 1
    assert scope.current_profile_id == seed["profile"].record_id
    changed = replace(operation, conclusion_record_id="conclusion:changed", request_digest="0" * 64)
    changed = replace(changed, request_digest=digest_post_activation_request(changed))
    with pytest.raises(IdempotencyConflict):
        _commit(seed, changed)
    seed["repository"].close()
