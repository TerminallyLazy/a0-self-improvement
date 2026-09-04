from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.activation_transition import (
    ACTIVATION_TRANSITION_REGISTRY,
    ActivationAuthorityFacts,
    ActivationRequest,
    ActivationTransitionDenied,
    ExactRecord,
    RollbackRequest,
    SafetyBypassRequest,
    SlotExpectation,
    TransitionCommand,
    activate_candidate,
    apply_safety_bypass,
    rollback_to_predecessor,
)
from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    POST_PROMOTION_MONITOR_SCHEMA_ID,
    BucketCalibration,
    BucketOutcome,
    CanaryConclusionRequest,
    CanaryCoordinator,
    CanaryStartRequest,
    Rational as CanaryRational,
    RecordIdentity,
    activation_policy as canary_policy,
    canary_plan,
    monitor_plan,
    policy_calibration,
)
from usr.plugins.dspy_rlm.helpers.v3.candidate_publication import (
    BoundedUsage,
    CandidatePolicy,
    ExactIdentity,
    PublicationAuthorities,
    STAGED_RESULT_SCHEMA_ID,
    plan_candidate_publication,
)
from usr.plugins.dspy_rlm.helpers.v3.evidence import (
    ActivationPolicyInput,
    BucketEvidence,
    BucketRule,
    FamilyEvidence,
    FamilyRequirement,
    Rational,
    ReductionContext,
    build_activation_policy,
    build_evaluation_envelope,
    build_evidence_bundle,
    reduce_evidence,
)
from usr.plugins.dspy_rlm.helpers.v3.fixtures import (
    FIXTURE_MANIFEST_SCHEMA_ID,
    assessment_profile,
    execution_profile,
)
from usr.plugins.dspy_rlm.helpers.v3.model_routes import (
    DEPENDENCY_PROBES,
    BoundIdentity,
    build_dependency_capability_certificate,
    build_worker_dependency_profile,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import RevisionConflict, V3Repository
from usr.plugins.dspy_rlm.helpers.v3.schemas import (
    RecordSchema,
    SchemaRegistry,
    build_typed_record,
    canonical_json,
    merge_schema_registries,
    strict_literal,
    strict_object,
    validate_links,
)


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
NOW_EPOCH = int(NOW.timestamp())
CONTEXT = "context.activation"
KEY = "transition-test"
TEST_FACT_SCHEMA_ID = "a0.test-activation-fact.v1"
TEST_FACT_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            TEST_FACT_SCHEMA_ID,
            "test_activation_fact",
            strict_object(
                {"record_type": strict_literal("test_activation_fact"), "links": validate_links}
            ),
        ),
    )
)
TEST_REGISTRY = merge_schema_registries(
    ACTIVATION_TRANSITION_REGISTRY, TEST_FACT_REGISTRY
)


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _fact(label: str):
    return build_typed_record(
        record_id=f"fact.{label}",
        context_ref=CONTEXT,
        record_kind="test_activation_fact",
        schema_id=TEST_FACT_SCHEMA_ID,
        payload={"record_type": "test_activation_fact", "links": []},
        key_epoch=KEY,
        registry=TEST_REGISTRY,
    )


def _exact(record) -> ExactIdentity:
    return ExactIdentity(record.record_id, record.content_digest)


def _bounded(value: int) -> BoundedUsage:
    return BoundedUsage(
        calls=value,
        tokens=value,
        cost_microunits=value,
        wall_time_ms=value,
        cases=value,
        variants=value,
        outputs=value,
        retries=value,
    )


def _staged_candidate() -> bytes:
    return canonical_json(
        {
            "schema": STAGED_RESULT_SCHEMA_ID,
            "attempt_conclusion": "succeeded",
            "publication_result": "candidate_published",
            "reason_codes": ["completed"],
            "actual_usage": {
                "calls": 1,
                "tokens": 1,
                "cost_microunits": 1,
                "wall_time_ms": 1,
                "cases": 1,
                "variants": 1,
                "outputs": 1,
                "retries": 0,
            },
            "cleanup_verified": True,
            "fence_retained": True,
            "artifact": {
                "artifact_type": "structured_guidance",
                "rules": [{"rule_id": "verify_tool_contract", "parameters": {}}],
            },
        }
    )


@dataclass
class Seeded:
    repository: V3Repository
    incumbent: object
    successor: object
    candidate: object
    disposition: object
    conclusion: object
    policy: object
    calibration: object
    monitor: object
    eligibility: object
    dependency: object
    capability: object
    fixture: object
    trial: object
    command: TransitionCommand
    request: ActivationRequest


def _seed(tmp_path, *, diagnostic: bool = False, automatic: bool = False) -> Seeded:
    repository = V3Repository.create(tmp_path / "activation.sqlite3", registry=TEST_REGISTRY)
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    incumbent = activation_profile(
        record_id="profile.incumbent",
        context_ref=CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch=KEY,
    )
    facts = {name: _fact(name) for name in (
        "engine", "publication-authority", "budget-profile", "budget-ledger",
        "input", "catalog", "renderer", "benefit", "lineage", "package-source",
        "framework", "runtime", "predict", "rlm", "metering", "canary-grant",
    )}
    dependency = build_worker_dependency_profile(
        record_id="dependency.profile",
        context_ref=CONTEXT,
        key_epoch=KEY,
        lock_digest=_digest("lock"),
        package_hash_manifest_digest=_digest("packages"),
        trusted_package_sources=(BoundIdentity(facts["package-source"].record_id, facts["package-source"].content_digest),),
        python_version="3.12.4",
        python_implementation="CPython",
        python_abi="cp312",
        os_name="linux",
        architecture="x86_64",
        agent_zero_build_digest=_digest("agent-zero"),
        framework_bridge=BoundIdentity(facts["framework"].record_id, facts["framework"].content_digest),
        deno_version="2.4.5",
        predict_adapter=BoundIdentity(facts["predict"].record_id, facts["predict"].content_digest),
        rlm_adapter=BoundIdentity(facts["rlm"].record_id, facts["rlm"].content_digest),
        metering_adapter=BoundIdentity(facts["metering"].record_id, facts["metering"].content_digest),
    )
    capability = build_dependency_capability_certificate(
        record_id="dependency.capability",
        context_ref=CONTEXT,
        key_epoch=KEY,
        dependency_profile=BoundIdentity(dependency.record_id, dependency.content_digest),
        observed_lock_digest=dependency.payload["lock_digest"],
        runtime=BoundIdentity(facts["runtime"].record_id, facts["runtime"].content_digest),
        route_capabilities={
            "typed_predict": BoundIdentity(facts["predict"].record_id, facts["predict"].content_digest),
            "recursive_rlm": BoundIdentity(facts["rlm"].record_id, facts["rlm"].content_digest),
        },
        probe_states={probe: "ready" for probe in DEPENDENCY_PROBES},
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=15),
    )
    execution = execution_profile(
        runtime_digest=_digest("runtime-profile"),
        model_configuration_digest=_digest("model-config"),
        replay_adapter_digest=_digest("replay"),
        behavior_configuration_digest=_digest("behavior"),
    )
    assessment = assessment_profile(
        validator_profile_digest=_digest("validator"),
        activation_policy_digest=_digest("evidence-policy-placeholder"),
        threshold_profile_digest=_digest("threshold"),
        freshness_policy_digest=_digest("freshness"),
        replay_seed=1,
        required_buckets=("decision",),
    )
    fixture = build_typed_record(
        record_id="fixture.manifest",
        context_ref="fixture-authority",
        record_kind="fixture_manifest",
        schema_id=FIXTURE_MANIFEST_SCHEMA_ID,
        payload={
            "record_type": "fixture_manifest",
            "selection_policy_ref": "selection.test",
            "execution_profile_id": execution.record_id,
            "execution_profile_digest": execution.content_digest,
            "assessment_profile_id": assessment.record_id,
            "assessment_profile_digest": assessment.content_digest,
            "entries": [{
                "ordinal": 0,
                "draft_id": "draft.1",
                "draft_digest": _digest("draft"),
                "admission_id": "admission.1",
                "admission_digest": _digest("admission"),
                "family_id": "family.1",
                "family_digest": _digest("family"),
                "partition": "certification_holdout",
            }],
            "links": [],
        },
        key_epoch=KEY,
        registry=TEST_REGISTRY,
    )

    with repository.transaction() as transaction:
        transaction.insert_record(guidance)
        transaction.insert_record(prompt)
        transaction.insert_record(incumbent)
        for fact in facts.values():
            transaction.insert_record(fact)
        transaction.insert_record(dependency)
        transaction.insert_record(capability)
        transaction.insert_record(execution)
        transaction.insert_record(assessment)
        transaction.insert_record(fixture)
        transaction.initialize_activation_scope(
            context_ref=CONTEXT,
            profile_id=incumbent.record_id,
            profile_digest=incumbent.content_digest,
        )

    publication = plan_candidate_publication(
        _staged_candidate(),
        authorities=PublicationAuthorities(
            context_ref=CONTEXT,
            work_item=_exact(facts["input"]),
            work_attempt=_exact(facts["input"]),
            fence_token=1,
            work_event_sequence=0,
            engine_profile=_exact(facts["engine"]),
            engine_semantic_id="a0.generate.guidance.deterministic_rules.v1",
            authority_ceiling="candidate_publication",
            incumbent_profile=incumbent,
            scope_ref=CONTEXT,
            scope_revision=0,
            worker_dependency_profile=ExactIdentity(dependency.record_id, dependency.content_digest),
            capability_certificate=ExactIdentity(capability.record_id, capability.content_digest),
            publication_authority=_exact(facts["publication-authority"]),
            model_use_grant=None,
            budget_profile=_exact(facts["budget-profile"]),
            budget_ledger=_exact(facts["budget-ledger"]),
            budget_limits=_bounded(10),
            fixture_authorities=(ExactIdentity(fixture.record_id, fixture.content_digest),),
            admitted_inputs=(_exact(facts["input"]),),
            guidance_rule_catalog=_exact(facts["catalog"]),
            renderer_contract=_exact(facts["renderer"]),
            key_epoch=KEY,
        ),
        candidate_policy=CandidatePolicy(
            benefit_kind="outcome",
            benefit_bucket="decision",
            benefit_claim=_exact(facts["benefit"]),
            risk_tier="standard",
            lineage=_exact(facts["lineage"]),
        ),
    )
    with repository.transaction() as transaction:
        for record in publication.records:
            transaction.insert_record(record)
    candidate = next(item for item in publication.records if item.record_kind == "improvement_candidate")
    successor = next(
        item for item in publication.records
        if item.record_kind == "activation_profile" and item.record_id != incumbent.record_id
    )

    evidence_policy = build_activation_policy(
        ActivationPolicyInput(
            policy_ref="evidence.policy",
            revision=1,
            calibration_state="approved",
            calibration_artifact_ref="evidence.calibration",
            calibration_artifact_digest=_digest("evidence-calibration"),
            maximum_evidence_age_seconds=300,
            required_families=("family.1",),
            family_requirements=(FamilyRequirement("family.1", 1),),
            required_buckets=("decision",),
            bucket_rules=(BucketRule("decision", 1, Rational(1, 1), Rational(0, 1), Rational(0, 1)),),
            candidate_hard_failure_codes=("safety_veto",),
        ),
        context_ref=CONTEXT,
        key_epoch=KEY,
    )
    # Assessment profiles are immutable; use a second exact profile bound to the policy.
    assessment_bound = assessment_profile(
        validator_profile_digest=_digest("validator"),
        activation_policy_digest=evidence_policy.content_digest,
        threshold_profile_digest=_digest("threshold"),
        freshness_policy_digest=_digest("freshness"),
        replay_seed=1,
        required_buckets=("decision",),
    )
    envelope = build_evaluation_envelope(
        context_ref=CONTEXT,
        frozen_at_epoch_seconds=NOW_EPOCH - 20,
        execution_profile=execution,
        assessment_profile=assessment_bound,
        fixture_manifest_id=fixture.record_id,
        fixture_manifest_digest=fixture.content_digest,
        activation_policy=evidence_policy,
        capability_certificate_id=capability.record_id,
        capability_certificate_digest=capability.content_digest,
        key_epoch=KEY,
    )
    bundle = build_evidence_bundle(
        context_ref=CONTEXT,
        candidate_id=candidate.record_id,
        candidate_digest=candidate.content_digest,
        incumbent_profile_id=incumbent.record_id,
        incumbent_profile_digest=incumbent.content_digest,
        activation_scope_ref=CONTEXT,
        activation_scope_revision=0,
        evaluation_envelope=envelope,
        evidence_observed_at_epoch_seconds=NOW_EPOCH - 10,
        global_unavailability_codes=(),
        global_candidate_hard_failure_codes=(),
        family_summaries=(FamilyEvidence("family.1", 1, 1, (), ()),),
        bucket_summaries=(BucketEvidence("family.1", "decision", 1, 1, 0, (), ()),),
        key_epoch=KEY,
    )
    disposition = reduce_evidence(
        bundle,
        envelope,
        evidence_policy,
        context=ReductionContext(
            observed_at_epoch_seconds=NOW_EPOCH,
            current_scope_revision=0,
            current_incumbent_profile_id=incumbent.record_id,
            current_incumbent_profile_digest=incumbent.content_digest,
        ),
        key_epoch=KEY,
    ).record
    with repository.transaction() as transaction:
        transaction.insert_record(evidence_policy)
        transaction.insert_record(assessment_bound)
        transaction.insert_record(envelope)
        transaction.insert_record(bundle)
        transaction.insert_record(disposition)

    policy = canary_policy(
        record_id="canary.policy",
        context_ref=CONTEXT,
        policy_revision=1,
        activation_mode="auto_after_canary" if automatic else "manual_only",
        key_epoch=KEY,
    )
    trial_plan = canary_plan(
        record_id="canary.plan",
        context_ref=CONTEXT,
        horizon_exposures=1,
        expiry_seconds=60,
        candidate_allocation=CanaryRational(1, 2),
        assignment_key_commitment=_digest("assignment"),
        hard_veto_failure_limit=0,
        buckets=(BucketCalibration("decision", 1, CanaryRational(0, 1), CanaryRational(0, 1)),),
        key_epoch=KEY,
    )
    monitoring = monitor_plan(
        record_id="monitor.plan",
        context_ref=CONTEXT,
        horizon_exposures=2,
        look_interval_exposures=1,
        ordinary_regression_boundary=CanaryRational(-1, 10),
        hard_veto_failure_limit=0,
        key_epoch=KEY,
    )
    calibration = policy_calibration(
        record_id="policy.calibration",
        context_ref=CONTEXT,
        status="approved",
        environment_ref="env.test",
        policy=policy,
        canary_plan_record=trial_plan,
        monitor_plan_record=monitoring,
        activation_authorities=("automatic", "manual") if automatic else ("manual",),
        soft_rollback_authorized=True,
        key_epoch=KEY,
    )
    coordinator = CanaryCoordinator(key_epoch=KEY)
    kind = "diagnostic" if diagnostic else "authoritative"
    trial = coordinator.plan_start(
        CanaryStartRequest(
            record_id=f"trial.{kind}",
            context_ref=CONTEXT,
            canary_kind=kind,
            disposition="review_only" if diagnostic else "promotion_ready",
            disposition_ref=RecordIdentity(disposition.record_id, disposition.content_digest),
            candidate=RecordIdentity(candidate.record_id, candidate.content_digest),
            incumbent_profile=RecordIdentity(incumbent.record_id, incumbent.content_digest),
            expected_scope_revision=0,
            observed_scope_revision=0,
            environment_ref="env.test",
            policy=policy,
            calibration=None if diagnostic else calibration,
            plan=trial_plan,
            authority_grant=RecordIdentity(facts["canary-grant"].record_id, facts["canary-grant"].content_digest),
            authority_purpose="diagnostic_canary" if diagnostic else "authoritative_canary",
            occupied_canary_ref=None,
        )
    )
    conclusion = coordinator.plan_conclusion(
        CanaryConclusionRequest(
            record_id=f"conclusion.{kind}",
            trial=trial,
            eligible_exposure_count=1,
            bucket_outcomes=(BucketOutcome("decision", 1, CanaryRational(0, 1), False),),
            candidate_hard_failure_count=0,
            shared_failure=False,
            identity_drift=False,
            cancelled=False,
            boundary_uncertain=False,
            operator_stopped=False,
        ),
        frozen_plan=trial_plan,
    )
    eligibility = None
    if not diagnostic:
        eligibility = coordinator.activation_eligibility(
            candidate=RecordIdentity(candidate.record_id, candidate.content_digest),
            conclusion=conclusion,
            policy=policy,
            calibration=calibration,
            environment_ref="env.test",
            expected_scope_revision=0,
            observed_scope_revision=0,
            requested_authority="automatic" if automatic else "manual",
        )
    else:
        # Deliberately construct the claimed identity: the coordinator must still reject
        # the diagnostic conclusion itself at the durable boundary.
        from usr.plugins.dspy_rlm.helpers.v3.canary import ActivationEligibility
        eligibility = ActivationEligibility(
            RecordIdentity(candidate.record_id, candidate.content_digest),
            RecordIdentity(conclusion.record_id, conclusion.content_digest),
            RecordIdentity(policy.record_id, policy.content_digest),
            RecordIdentity(calibration.record_id, calibration.content_digest),
            "env.test",
            0,
            1,
            "manual",
        )
    if diagnostic:
        monitor_links = [
            {"role": role, "ordinal": 0, "target_id": record.record_id, "target_digest": record.content_digest}
            for role, record in (
                ("candidate", candidate),
                ("incumbent_profile", incumbent),
                ("canary_conclusion", conclusion),
                ("activation_policy", policy),
                ("policy_calibration", calibration),
                ("monitor_plan", monitoring),
            )
        ]
        monitor = build_typed_record(
            record_id="monitor.1",
            context_ref=CONTEXT,
            record_kind="post_promotion_monitor",
            schema_id=POST_PROMOTION_MONITOR_SCHEMA_ID,
            payload={
                "fact_type": "post_promotion_monitor",
                "candidate_id": candidate.record_id,
                "candidate_digest": candidate.content_digest,
                "incumbent_profile_id": incumbent.record_id,
                "incumbent_profile_digest": incumbent.content_digest,
                "canary_conclusion_id": conclusion.record_id,
                "canary_conclusion_digest": conclusion.content_digest,
                "policy_id": policy.record_id,
                "policy_digest": policy.content_digest,
                "calibration_id": calibration.record_id,
                "calibration_digest": calibration.content_digest,
                "monitor_plan_id": monitoring.record_id,
                "monitor_plan_digest": monitoring.content_digest,
                "observed_scope_revision": 0,
                "resulting_scope_revision": 1,
                "links": monitor_links,
            },
            key_epoch=KEY,
            registry=TEST_REGISTRY,
        )
    else:
        monitor = coordinator.plan_monitor_start(
            record_id="monitor.1",
            context_ref=CONTEXT,
            eligibility=eligibility,
            incumbent_profile=RecordIdentity(incumbent.record_id, incumbent.content_digest),
            conclusion=conclusion,
            policy=policy,
            calibration=calibration,
            monitor_plan_record=monitoring,
        )
    with repository.transaction() as transaction:
        for record in (policy, trial_plan, monitoring, calibration, trial, conclusion):
            transaction.insert_record(record)
        claimed = transaction.claim_empty_operation_slot(
            context_ref=CONTEXT,
            operation_kind="canary",
            expected_revision=0,
            expected_scope_revision=0,
            operation_id=trial.record_id,
            operation_digest=trial.content_digest,
        )
    idem = _digest("activate-idempotency")
    command = TransitionCommand(
        issuer_ref="issuer.local",
        subject_ref="operator.local",
        context_ref=CONTEXT,
        target_ref=CONTEXT,
        expected_scope_revision=0,
        idempotency_key_digest=idem,
        authority_grant_id="grant.activate",
        now=NOW,
    )
    request = ActivationRequest(
        command=command,
        candidate=ExactRecord.of(candidate),
        disposition=ExactRecord.of(disposition),
        canary_conclusion=ExactRecord.of(conclusion),
        policy=ExactRecord.of(policy),
        calibration=ExactRecord.of(calibration),
        successor_profile=ExactRecord.of(successor),
        monitor=monitor,
        eligibility=eligibility,
        authorities=ActivationAuthorityFacts(
            ExactRecord.of(dependency),
            ExactRecord.of(capability),
            (ExactRecord.of(fixture),),
        ),
        canary_slot=SlotExpectation("canary", claimed.operation_revision, ExactRecord.of(trial)),
        monitor_slot=SlotExpectation("monitor", 0, None),
        requalification_slot=SlotExpectation("requalification", 0, None),
    )
    return Seeded(
        repository, incumbent, successor, candidate, disposition, conclusion, policy,
        calibration, monitor, eligibility, dependency, capability, fixture, trial,
        command, request,
    )


def _grant(command: TransitionCommand, action: str, *, automatic: bool = False):
    verified = VerifiedGrant(
        grant_id=command.authority_grant_id,
        authority_class=(
            "automatic_transition_grant" if automatic else "operator_authority_grant"
        ),
        issuer_id=command.issuer_ref,
        key_epoch=1,
        subject_ref=command.subject_ref,
        context_ref=command.context_ref,
        action=action,
        purpose="automatic_promotion" if automatic else "operator_mutation",
        target_ref=command.target_ref,
        target_revision=command.expected_scope_revision,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
        idempotency_key_digest=command.idempotency_key_digest,
        session_nonce="session.local",
    )
    return lambda _transaction: verified


def test_automatic_activation_requires_exact_automatic_transition_authority(tmp_path) -> None:
    seeded = _seed(tmp_path, automatic=True)

    with pytest.raises(ActivationTransitionDenied, match="authority_grant_mismatch"):
        activate_candidate(
            seeded.repository,
            request=seeded.request,
            revalidate_grant=_grant(seeded.command, "activate"),
        )

    result = activate_candidate(
        seeded.repository,
        request=seeded.request,
        revalidate_grant=_grant(seeded.command, "activate", automatic=True),
    )

    assert result.scope.scope_revision == 1
    assert result.receipt.payload["authority_class"] == "automatic_transition_grant"
    assert result.receipt.payload["authority_purpose"] == "automatic_promotion"


def test_activation_commits_exact_scope_slots_receipt_and_lost_ack_replay(tmp_path) -> None:
    seeded = _seed(tmp_path)
    result = activate_candidate(
        seeded.repository,
        request=seeded.request,
        revalidate_grant=_grant(seeded.command, "activate"),
    )
    replay = activate_candidate(
        seeded.repository,
        request=replace(
            seeded.request,
            command=replace(seeded.command, now=NOW + timedelta(minutes=1)),
        ),
        revalidate_grant=_grant(
            replace(seeded.command, now=NOW + timedelta(minutes=1)), "activate"
        ),
    )

    assert result.scope.scope_revision == 1
    assert result.scope.current_profile_id == seeded.successor.record_id
    assert result.slots[0].operation_id is None
    assert result.slots[1].operation_id == seeded.monitor.record_id
    assert result.receipt.payload["reason_codes"] == ["candidate_activated"]
    assert replay.replayed is True
    assert replay.receipt == result.receipt


def test_stale_scope_or_slot_revision_fails_before_any_transition(tmp_path) -> None:
    seeded = _seed(tmp_path)
    stale_slot = replace(
        seeded.request,
        canary_slot=replace(seeded.request.canary_slot, revision=0),
    )
    with pytest.raises(RevisionConflict):
        activate_candidate(
            seeded.repository,
            request=stale_slot,
            revalidate_grant=_grant(seeded.command, "activate"),
        )
    assert seeded.repository.get_activation_scope(CONTEXT).scope_revision == 0
    assert seeded.repository.get_operation_slot(CONTEXT, "canary").operation_id == seeded.trial.record_id


def test_diagnostic_canary_can_never_authorize_activation(tmp_path) -> None:
    seeded = _seed(tmp_path, diagnostic=True)
    with pytest.raises(ActivationTransitionDenied, match="passed_authoritative_canary_required"):
        activate_candidate(
            seeded.repository,
            request=seeded.request,
            revalidate_grant=_grant(seeded.command, "activate"),
        )
    assert seeded.repository.get_activation_scope(CONTEXT).scope_revision == 0


def test_rollback_restores_only_recorded_predecessor_and_stops_exact_monitor(tmp_path) -> None:
    seeded = _seed(tmp_path)
    activated = activate_candidate(
        seeded.repository,
        request=seeded.request,
        revalidate_grant=_grant(seeded.command, "activate"),
    )
    command = replace(
        seeded.command,
        expected_scope_revision=1,
        idempotency_key_digest=_digest("rollback-idempotency"),
        authority_grant_id="grant.rollback",
    )
    request = RollbackRequest(
        command,
        ExactRecord.of(activated.receipt),
        ExactRecord.of(seeded.incumbent),
        (
            SlotExpectation("canary", 2, None),
            SlotExpectation("monitor", 1, ExactRecord.of(seeded.monitor)),
            SlotExpectation("requalification", 0, None),
        ),
    )
    rolled_back = rollback_to_predecessor(
        seeded.repository,
        request=request,
        revalidate_grant=_grant(command, "rollback"),
    )

    assert rolled_back.scope.current_profile_id == seeded.incumbent.record_id
    assert rolled_back.scope.scope_revision == 2
    assert rolled_back.slots[1].operation_id is None
    assert rolled_back.receipt.payload["ancestry_receipt"]["record_id"] == activated.receipt.record_id


def test_safety_bypass_requires_all_null_profile_and_stops_slots(tmp_path) -> None:
    seeded = _seed(tmp_path)
    command = replace(
        seeded.command,
        idempotency_key_digest=_digest("safety-idempotency"),
        authority_grant_id="grant.safety",
    )
    bad = SafetyBypassRequest(
        command,
        ExactRecord.of(seeded.successor),
        (
            seeded.request.canary_slot,
            seeded.request.monitor_slot,
            seeded.request.requalification_slot,
        ),
    )
    with pytest.raises(ActivationTransitionDenied, match="all_null_activation_profile_required"):
        apply_safety_bypass(
            seeded.repository,
            request=bad,
            revalidate_grant=_grant(command, "safety_bypass"),
        )
    result = apply_safety_bypass(
        seeded.repository,
        request=replace(bad, null_profile=ExactRecord.of(seeded.incumbent)),
        revalidate_grant=_grant(command, "safety_bypass"),
    )

    assert result.scope.mode == "safety_bypass"
    assert result.scope.scope_revision == 1
    assert result.slots[0].operation_id is None
    assert result.receipt.payload["reason_codes"] == ["safety_bypass_applied"]
