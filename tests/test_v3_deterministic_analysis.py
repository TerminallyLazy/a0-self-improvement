from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from usr.plugins.dspy_rlm.helpers.v3.deterministic_analysis import (
    DETERMINISTIC_ANALYSIS_REGISTRY,
    DETERMINISTIC_ENGINE_ID,
    GUIDANCE_RENDERER_CONTRACT_ID,
    MAX_SELECTED_GUIDANCE_RULES,
    PROTECTED_CONSTRAINTS,
    DeterministicAnalysisError,
    ExactIdentity,
    build_completed_deterministic_attempt,
    build_deterministic_analysis_profile,
    build_initial_guidance_rule_catalog,
    build_observation_fact,
    build_safe_analysis_view,
    project_guidance_rules,
)


def _identity(label: str) -> ExactIdentity:
    return ExactIdentity(label, sha256(label.encode()).hexdigest())


def _profile(*, maximum_view_rows: int = 10, maximum_view_bytes: int = 100_000):
    return build_deterministic_analysis_profile(
        context_ref="context.alpha",
        key_epoch="test-v1",
        analytical_question=_identity("question.tool-outcomes"),
        worker_dependency_profile=_identity("dependency.framework-3.12"),
        maximum_view_rows=maximum_view_rows,
        maximum_view_bytes=maximum_view_bytes,
    )


def _fact(
    evidence_label: str,
    *,
    bucket: str,
    outcome: str,
    occurrences: int,
    source: str = "source.outcomes-v1",
):
    return build_observation_fact(
        context_ref="context.alpha",
        key_epoch="test-v1",
        bucket_ref=bucket,
        outcome_code=outcome,
        occurrences=occurrences,
        source_profile=_identity(source),
        window=_identity("window.2026-w34"),
        evidence=_identity(evidence_label),
        contains_raw_content=False,
        contains_quarantine_content=False,
        contains_certification_holdout=False,
    )


def test_safe_view_is_content_free_exact_bounded_and_order_independent() -> None:
    profile = _profile()
    facts = (
        _fact("evidence.2", bucket="shell", outcome="tool_failed", occurrences=2),
        _fact("evidence.1", bucket="shell", outcome="tool_failed", occurrences=3),
        _fact(
            "evidence.3",
            bucket="decision_making",
            outcome="reversible_selected",
            occurrences=4,
            source="source.decisions-v1",
        ),
    )

    forward = build_safe_analysis_view(
        context_ref="context.alpha",
        key_epoch="test-v1",
        analysis_profile=profile,
        window=_identity("window.2026-w34"),
        observation_facts=facts,
    )
    reverse = build_safe_analysis_view(
        context_ref="context.alpha",
        key_epoch="test-v1",
        analysis_profile=profile,
        window=_identity("window.2026-w34"),
        observation_facts=tuple(reversed(facts)),
    )

    assert forward.canonical_bytes == reverse.canonical_bytes
    assert forward.payload["rows"] == [
        {
            "bucket_ref": "decision_making",
            "outcome_code": "reversible_selected",
            "occurrences": 4,
        },
        {"bucket_ref": "shell", "outcome_code": "tool_failed", "occurrences": 5},
    ]
    assert forward.payload["source_profiles"] == [
        {"ref": item.ref, "digest": item.digest}
        for item in (_identity("source.decisions-v1"), _identity("source.outcomes-v1"))
    ]
    assert not forward.payload["contains_raw_content"]
    forward.verify(DETERMINISTIC_ANALYSIS_REGISTRY)


def test_safe_view_denies_unsafe_classifications_and_explicit_limits() -> None:
    kwargs = {
        "context_ref": "context.alpha",
        "key_epoch": "test-v1",
        "bucket_ref": "shell",
        "outcome_code": "failed",
        "occurrences": 1,
        "source_profile": _identity("source.1"),
        "window": _identity("window.1"),
        "evidence": _identity("evidence.1"),
        "contains_raw_content": False,
        "contains_quarantine_content": False,
        "contains_certification_holdout": False,
    }
    for flag in (
        "contains_raw_content",
        "contains_quarantine_content",
        "contains_certification_holdout",
    ):
        with pytest.raises(DeterministicAnalysisError, match="unsafe content"):
            build_observation_fact(**{**kwargs, flag: True})

    fact = build_observation_fact(**kwargs)
    with pytest.raises(DeterministicAnalysisError, match="row ceiling"):
        build_safe_analysis_view(
            context_ref="context.alpha",
            key_epoch="test-v1",
            analysis_profile=_profile(maximum_view_rows=1),
            window=_identity("window.1"),
            observation_facts=(fact, replace(fact, record_id="observation.second")),
        )
    with pytest.raises(DeterministicAnalysisError, match="byte ceiling"):
        build_safe_analysis_view(
            context_ref="context.alpha",
            key_epoch="test-v1",
            analysis_profile=_profile(maximum_view_bytes=20),
            window=_identity("window.1"),
            observation_facts=(fact,),
        )


def test_deterministic_profile_and_attempt_bind_zero_model_usage_work_and_budget() -> None:
    profile = _profile()
    view = build_safe_analysis_view(
        context_ref="context.alpha",
        key_epoch="test-v1",
        analysis_profile=profile,
        window=_identity("window.2026-w34"),
        observation_facts=(
            _fact("evidence.1", bucket="shell", outcome="tool_failed", occurrences=1),
        ),
    )
    attempt = build_completed_deterministic_attempt(
        context_ref="context.alpha",
        key_epoch="test-v1",
        analysis_profile=profile,
        safe_analysis_view=view,
        work_item=_identity("work.analysis.1"),
        budget_reservation=_identity("budget.reservation.zero-model.1"),
        budget_reconciliation=_identity("budget.reconciliation.zero-model.1"),
    )

    assert profile.payload["semantic_engine_id"] == DETERMINISTIC_ENGINE_ID
    assert profile.payload["model_authority"] == "none"
    assert set(profile.payload["external_model_usage_ceiling"].values()) == {0}
    assert attempt.payload["requested_route"] == attempt.payload["selected_route"] == "deterministic"
    assert set(attempt.payload["actual_external_model_usage"].values()) == {0}
    assert attempt.payload["work_item_ref"] == "work.analysis.1"
    assert attempt.payload["budget_reservation_ref"] == "budget.reservation.zero-model.1"
    assert attempt.payload["model_ref"] is None
    attempt.verify(DETERMINISTIC_ANALYSIS_REGISTRY)


def test_initial_catalog_freezes_conservative_mapping_renderer_and_structure() -> None:
    catalog = build_initial_guidance_rule_catalog(key_epoch="system-v1")
    payload = catalog.payload
    mapping = {
        item["rule_id"]: item["allowed_benefit_buckets"] for item in payload["rules"]
    }

    assert payload["maximum_selected_rules"] == MAX_SELECTED_GUIDANCE_RULES == 4
    assert payload["renderer_contract_id"] == GUIDANCE_RENDERER_CONTRACT_ID
    assert mapping == {
        "verify_tool_contract": ["shell", "tool_retrieval"],
        "check_tool_result": ["shell", "tool_retrieval"],
        "retry_after_failure": ["shell", "tool_retrieval"],
        "prefer_reversible_action": ["decision_making", "shell"],
        "bound_tool_scope": ["shell", "tool_retrieval"],
    }
    retry = next(item for item in payload["rules"] if item["rule_id"] == "retry_after_failure")
    assert retry["parameter_schema"] == [
        {
            "name": "max_retries",
            "type": "integer",
            "required": True,
            "minimum": 0,
            "maximum": 2,
        }
    ]
    assert all("reasoning" not in buckets for buckets in mapping.values())
    catalog.verify(DETERMINISTIC_ANALYSIS_REGISTRY)


def test_rule_projection_requires_exact_params_constraints_and_coverage_union() -> None:
    catalog = build_initial_guidance_rule_catalog(key_epoch="system-v1")
    projection = project_guidance_rules(
        catalog=catalog,
        selected_rules=(
            {"rule_id": "retry_after_failure", "parameters": {"max_retries": 1}},
            {"rule_id": "prefer_reversible_action", "parameters": {}},
        ),
        benefit_bucket="shell",
        slot_required_buckets=("reasoning",),
        risk_required_buckets=("decision_making",),
        policy_required_buckets=("tool_retrieval",),
        preserved_protected_constraints=PROTECTED_CONSTRAINTS,
    )
    assert projection.required_evaluation_buckets == (
        "decision_making",
        "reasoning",
        "shell",
        "tool_retrieval",
    )
    assert projection.renderer_contract.ref == GUIDANCE_RENDERER_CONTRACT_ID

    invalid_cases = (
        ({"rule_id": "retry_after_failure", "parameters": {"max_retries": "1"}}, "shell", PROTECTED_CONSTRAINTS),
        ({"rule_id": "verify_tool_contract", "parameters": {}}, "reasoning", PROTECTED_CONSTRAINTS),
        ({"rule_id": "verify_tool_contract", "parameters": {}}, "shell", PROTECTED_CONSTRAINTS[:-1]),
    )
    for rule, benefit, constraints in invalid_cases:
        with pytest.raises(DeterministicAnalysisError):
            project_guidance_rules(
                catalog=catalog,
                selected_rules=(rule,),
                benefit_bucket=benefit,
                slot_required_buckets=(),
                risk_required_buckets=(),
                policy_required_buckets=(),
                preserved_protected_constraints=constraints,
            )
