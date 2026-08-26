from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.candidate_publication import (
    BoundedUsage,
    CANDIDATE_PUBLICATION_REGISTRY,
    CandidatePolicy,
    CandidatePublicationError,
    ExactIdentity,
    PublicationAuthorities,
    STAGED_RESULT_SCHEMA_ID,
    classify_attempt_retry,
    plan_candidate_publication,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _identity(label: str) -> ExactIdentity:
    return ExactIdentity(label, _digest(label))


def _usage(value: int = 1) -> dict[str, int]:
    return {
        "calls": value,
        "tokens": value,
        "cost_microunits": value,
        "wall_time_ms": value,
        "cases": value,
        "variants": value,
        "outputs": value,
        "retries": value,
    }


def _authorities() -> PublicationAuthorities:
    incumbent = activation_profile(
        record_id="profile.incumbent",
        context_ref="context.alpha",
        guidance_artifact=null_guidance_artifact(),
        prompt_patch_artifact=null_prompt_patch_artifact(),
        key_epoch="test-v1",
    )
    return PublicationAuthorities(
        context_ref="context.alpha",
        work_item=_identity("work.item.1"),
        work_attempt=_identity("work.attempt.1"),
        fence_token=3,
        work_event_sequence=4,
        engine_profile=_identity("engine.profile.1"),
        engine_semantic_id="a0.generate.guidance.deterministic_rules.v1",
        authority_ceiling="candidate_publication",
        incumbent_profile=incumbent,
        scope_ref="context.alpha",
        scope_revision=7,
        worker_dependency_profile=_identity("dependency.profile.1"),
        capability_certificate=_identity("capability.1"),
        publication_authority=_identity("operator.grant.1"),
        model_use_grant=None,
        budget_profile=_identity("budget.profile.1"),
        budget_ledger=_identity("budget.ledger.1"),
        budget_limits=BoundedUsage(**_usage(10)),
        fixture_authorities=(),
        admitted_inputs=(_identity("analysis.input.1"),),
        guidance_rule_catalog=_identity("rule.catalog.1"),
        renderer_contract=_identity("renderer.contract.1"),
    )


def _policy() -> CandidatePolicy:
    return CandidatePolicy(
        benefit_kind="outcome",
        benefit_bucket="shell",
        benefit_claim=_identity("benefit.claim.1"),
        risk_tier="standard",
        lineage=_identity("lineage.1"),
    )


def _staged(publication: str) -> bytes:
    artifact = None
    conclusion = "no_candidate"
    reasons = ["no_candidate"]
    if publication != "none":
        artifact = {
            "artifact_type": "structured_guidance",
            "rules": [
                {"rule_id": "verify_tool_contract", "parameters": {}},
                {"rule_id": "retry_after_failure", "parameters": {"max_retries": 1}},
            ],
        }
        conclusion = "succeeded"
        reasons = ["completed"]
    return canonical_json(
        {
            "schema": STAGED_RESULT_SCHEMA_ID,
            "attempt_conclusion": conclusion,
            "publication_result": publication,
            "reason_codes": reasons,
            "actual_usage": _usage(),
            "cleanup_verified": True,
            "fence_retained": True,
            "artifact": artifact,
        }
    )


def test_none_publishes_only_content_free_terminal_records() -> None:
    result = plan_candidate_publication(
        _staged("none"), authorities=_authorities(), candidate_policy=_policy()
    )

    assert [record.record_kind for record in result.records] == [
        "attempt_conclusion",
        "optimization_run_receipt",
        "publication_result",
    ]
    assert result.records[-1].payload["result"] == "none"
    assert result.records[-1].payload["artifact_id"] is None
    assert result.records[-1].payload["candidate_id"] is None
    assert [event.event_type for event in result.events] == ["publication_finalized"]
    for record in result.records:
        record.verify(CANDIDATE_PUBLICATION_REGISTRY)
    retry = classify_attempt_retry(
        conclusion="unavailable",
        reason_code="provider_unavailable",
        transient_reason_codes=("provider_unavailable",),
        attempts_remaining=True,
        cancellation_requested=False,
        authorities_current=True,
        cleanup_verified=True,
        budget_available=True,
    )
    assert retry.retry_eligible is True
    assert retry.terminal_work_state == "completed"
    assert classify_attempt_retry(
        conclusion="stopped",
        reason_code="cleanup_uncertain",
        transient_reason_codes=("provider_unavailable",),
        attempts_remaining=True,
        cancellation_requested=False,
        authorities_current=True,
        cleanup_verified=False,
        budget_available=True,
    ).publication_forced_none is True


def test_locked_artifact_is_one_strict_allowlisted_artifact_without_candidate() -> None:
    result = plan_candidate_publication(
        _staged("artifact_locked"), authorities=_authorities(), candidate_policy=_policy()
    )
    kinds = [record.record_kind for record in result.records]

    assert kinds.count("guidance_artifact") == 1
    assert kinds.count("artifact_generation_receipt") == 1
    assert "improvement_candidate" not in kinds
    artifact = next(record for record in result.records if record.record_kind == "guidance_artifact")
    assert set(artifact.payload) == {
        "record_type",
        "artifact_type",
        "artifact_slot",
        "payload_schema",
        "guidance_rule_catalog_id",
        "guidance_rule_catalog_digest",
        "renderer_contract_id",
        "renderer_contract_digest",
        "rules",
        "links",
    }
    assert [event.event_type for event in result.events] == [
        "publication_finalized",
        "artifact_locked",
    ]


def test_published_candidate_binds_exact_lineage_profile_scope_claim_risk_and_engine() -> None:
    authorities = _authorities()
    policy = _policy()
    result = plan_candidate_publication(
        _staged("candidate_published"),
        authorities=authorities,
        candidate_policy=policy,
    )
    kinds = [record.record_kind for record in result.records]

    assert kinds.count("guidance_artifact") == 1
    assert kinds.count("improvement_candidate") == 1
    assert kinds.count("activation_profile") == 1
    candidate = next(record for record in result.records if record.record_kind == "improvement_candidate")
    assert candidate.payload["incumbent_profile_id"] == authorities.incumbent_profile.record_id
    assert candidate.payload["observed_scope_revision"] == 7
    assert candidate.payload["lineage_id"] == policy.lineage.ref
    assert candidate.payload["benefit_claim"] == {
        "kind": "outcome",
        "bucket": "shell",
        "claim_ref": policy.benefit_claim.ref,
        "claim_digest": policy.benefit_claim.digest,
    }
    assert candidate.payload["risk_tier"] == "standard"
    assert candidate.payload["engine_semantic_id"] == authorities.engine_semantic_id
    assert not ({"activation_disposition", "evidence", "activation"} & set(candidate.payload))
    for record in result.records:
        record.verify(CANDIDATE_PUBLICATION_REGISTRY)


def test_malformed_unknown_nonfinite_noncanonical_or_fabricated_worker_data_yields_no_write_set() -> None:
    payloads = (
        b'{"schema":"a0.candidate-publication-staged-result.v1"}',
        canonical_json(
            {
                "schema": STAGED_RESULT_SCHEMA_ID,
                "attempt_conclusion": "no_candidate",
                "publication_result": "none",
                "reason_codes": ["no_candidate"],
                "actual_usage": _usage(),
                "cleanup_verified": True,
                "fence_retained": True,
                "artifact": None,
                "engine_profile_ref": "fabricated",
            }
        ),
        b'{"actual_usage":{"calls":NaN}}',
        _staged("none") + b"\n",
    )
    for payload in payloads:
        with pytest.raises(CandidatePublicationError):
            plan_candidate_publication(
                payload, authorities=_authorities(), candidate_policy=_policy()
            )


def test_candidate_authority_or_budget_drift_raises_before_any_discoverable_output() -> None:
    cases = (
        (
            replace(
                _authorities(),
                authority_ceiling="artifact_only",
            ),
            _staged("candidate_published"),
        ),
        (
            replace(
                _authorities(),
                budget_limits=BoundedUsage(**_usage(0)),
            ),
            _staged("artifact_locked"),
        ),
    )
    for authorities, staged in cases:
        with pytest.raises(CandidatePublicationError):
            plan_candidate_publication(
                staged, authorities=authorities, candidate_policy=_policy()
            )
    with pytest.raises(CandidatePublicationError, match="Model Use Grant"):
        replace(
            _authorities(),
            engine_semantic_id="a0.generate.guidance.outcome_gepa.v1",
        )
