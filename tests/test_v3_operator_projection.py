from __future__ import annotations

from dataclasses import replace

import pytest

from usr.plugins.dspy_rlm.helpers.v3.operator_projection import (
    ActionSummary,
    Axis,
    BudgetSummary,
    BucketSummary,
    CanarySummary,
    CandidateSummary,
    CandidatesSnapshot,
    CapabilitySummary,
    EvidenceFixturesSnapshot,
    FixtureFamilySummary,
    GrantSummary,
    OperatorProjectionError,
    OverviewSnapshot,
    PolicyCapabilitiesSnapshot,
    PrivacyMigrationSnapshot,
    PrivacyOperationSummary,
    ReceiptSummary,
    ReceiptsAuditSnapshot,
    SlotSummary,
    project_candidates,
    project_evidence_fixtures,
    project_overview,
    project_policy_capabilities,
    project_privacy_migration,
    project_receipts_audit,
)


_CONTEXT = "context:ui"
_NOW = "2026-08-26T12:00:00Z"


def _axis(state: str = "ready", *reasons: str) -> Axis:
    return Axis(state, _NOW, "current", reasons)


def _not_observed(state: str, reason: str) -> Axis:
    return Axis(state, None, "not_observed", (reason,))


def _bucket(bucket_id: str = "ordinary") -> BucketSummary:
    return BucketSummary(bucket_id, _axis("completed"), 4, 4, "passed")


def _candidate() -> CandidateSummary:
    return CandidateSummary(
        axis=_axis("review_only", "diagnostic_only"),
        candidate_ref="candidate:7",
        artifact_ref="artifact:7",
        change_kind="structured_guidance",
        target_slot="structured_guidance",
        engine_semantic_id="a0.engine.deterministic-analysis.v1",
        authority_ceiling="factual_typed_reduction",
        benefit_claim="ordinary_task_quality",
        benefit_state="declared",
        risk_tier="moderate",
        incumbent_profile_ref="profile:4",
        successor_profile_ref="profile:5",
        observed_scope_revision=9,
        lineage=_axis("current"),
        disposition_axis=_axis("review_only", "policy_uncalibrated"),
        disposition="review_only",
        monitor=_not_observed("not_observed", "monitor_not_started"),
        monitor_receipt_refs=(),
        changed_component_count=1,
        protected_constraint_state="satisfied",
        rule_catalog_ids=("guidance.rule.v1",),
        evidence_buckets=(_bucket(),),
        canary=CanarySummary(
            axis=_axis("passed", "diagnostic_result_only"),
            canary_kind="diagnostic",
            authority_ceiling="no_promotion_authority",
            conclusion_ref="conclusion:3",
            activation_authoritative=False,
        ),
        diagnostic_labels=("diagnostic", "non_authoritative"),
        diagnostic_reason_codes=("no_promotion_authority",),
        allowed_actions=(
            ActionSummary(
                "activate", "blocked", ("diagnostic_canary_no_activation_authority",)
            ),
        ),
    )


class _Reader:
    def __init__(self) -> None:
        self.overview = OverviewSnapshot(
            ordinary_runtime=_axis("active"),
            improvement=_not_observed("unavailable", "safe_store_unavailable"),
            migration_cutover=_not_observed(
                "not_observed", "migration_authority_not_probed"
            ),
            activation=_not_observed("missing", "activation_scope_missing"),
            activation_profile_ref=None,
            scope_revision=None,
            safety_bypass_state="inactive",
            rollback_eligibility="unavailable",
            slots=(
                SlotSummary("structured_guidance", "missing", None),
                SlotSummary("prompt_patch", "missing", None),
            ),
            capabilities_axis=_not_observed("not_probed", "capabilities_not_probed"),
            capabilities=(
                CapabilitySummary(
                    "replay", "a0.replay.v1", "not_probed", ("not_probed",)
                ),
            ),
            attention_actions=(
                ActionSummary("inspect_local_state", "pending", ("operator_attention",)),
            ),
        )
        self.candidates = CandidatesSnapshot(
            axis=_axis("active"),
            candidates=(_candidate(),),
            disposition_counts=(("promotion_ready", 0), ("review_only", 1), ("rejected", 0)),
            attention_count=1,
        )
        self.evidence_fixtures = EvidenceFixturesSnapshot(
            evidence=_axis("completed"),
            evidence_buckets=(_bucket(),),
            fixtures=_axis("ready"),
            families=(
                FixtureFamilySummary(
                    "family:2", _axis("eligible"), "eligible", 5, 3, 2, "active"
                ),
            ),
            draft_count=1,
            review_pending_count=1,
            admitted_count=10,
            withdrawn_count=0,
        )
        self.privacy_migration = PrivacyMigrationSnapshot(
            privacy=_axis("ready"),
            migration=_axis("active"),
            migration_ref="migration:2",
            migration_phase="projection_verified",
            checkpoint_count=6,
            disposition_counts=(("supported", 4), ("quarantined", 1)),
            key_custody_state="ready",
            cutover_readiness="pending",
            recovery_state="ready",
            operations=(
                PrivacyOperationSummary(
                    "privacy-op:4",
                    "quarantine_export",
                    _axis("pending"),
                    "challenge:8",
                    ("receipt:11",),
                    "run_local_export_command",
                ),
            ),
        )
        self.policy_capabilities = PolicyCapabilitiesSnapshot(
            policy=_axis("active"),
            policy_ref="policy:3",
            calibration_state="approved",
            activation_mode="manual_only",
            automatic_authority_state="not_authorized",
            capabilities=_axis("ready"),
            capability_items=(
                CapabilitySummary("analysis", "a0.analysis.v1", "ready"),
            ),
            dependency_profile_ref="dependency-profile:5",
            dependency_state="ready",
            grants=_axis("active"),
            grant_items=(
                GrantSummary(
                    "grant:4", "model_use", "active", "model_analysis", "active"
                ),
            ),
            budgets=_axis("active"),
            budget_items=(BudgetSummary("model_tokens", "active", 100, 20, 40),),
            local_step_up_instruction_code="use_local_authority_cli",
        )
        self.receipts_audit = ReceiptsAuditSnapshot(
            receipts=_axis("active"),
            items=(
                ReceiptSummary(
                    4,
                    "receipt:4",
                    "canary",
                    "canary_conclude",
                    "completed",
                    _NOW,
                    ("receipt:3",),
                ),
                ReceiptSummary(
                    5,
                    "receipt:5",
                    "activation",
                    "activate",
                    "completed",
                    "2026-08-26T12:01:00Z",
                    ("receipt:4",),
                ),
            ),
            category_counts=(("canary", 1), ("activation", 1)),
        )

    def read_overview(self, context_ref: str) -> OverviewSnapshot:
        assert context_ref == _CONTEXT
        return self.overview

    def read_candidates(self, context_ref: str) -> CandidatesSnapshot:
        assert context_ref == _CONTEXT
        return self.candidates

    def read_evidence_fixtures(self, context_ref: str) -> EvidenceFixturesSnapshot:
        assert context_ref == _CONTEXT
        return self.evidence_fixtures

    def read_privacy_migration(self, context_ref: str) -> PrivacyMigrationSnapshot:
        assert context_ref == _CONTEXT
        return self.privacy_migration

    def read_policy_capabilities(self, context_ref: str) -> PolicyCapabilitiesSnapshot:
        assert context_ref == _CONTEXT
        return self.policy_capabilities

    def read_receipts_audit(self, context_ref: str) -> ReceiptsAuditSnapshot:
        assert context_ref == _CONTEXT
        return self.receipts_audit


def test_overview_keeps_continuity_and_unavailable_axes_explicit() -> None:
    view = project_overview(_Reader(), _CONTEXT)

    assert view["ordinary_runtime"]["state"] == "active"
    assert view["improvement"] == {
        "state": "unavailable",
        "observed_at": None,
        "freshness": "not_observed",
        "reason_codes": ["safe_store_unavailable"],
    }
    assert view["activation"]["slots"][0]["occupant_ref"] is None
    assert view["capabilities"]["state"] == "not_probed"


def test_diagnostic_canary_is_visibly_and_permanently_non_authoritative() -> None:
    view = project_candidates(_Reader(), _CONTEXT)
    item = view["items"][0]

    assert item["canary"]["canary_kind"] == "diagnostic"
    assert item["canary"]["authority_ceiling"] == "no_promotion_authority"
    assert item["canary"]["activation_authoritative"] is False
    assert item["diagnostic"]["authority_ceiling"] == "no_promotion_authority"
    assert item["allowed_actions"][0]["state"] == "blocked"
    assert item["allowed_actions"][0]["reason_codes"] == [
        "diagnostic_canary_no_activation_authority"
    ]


def test_evidence_privacy_and_policy_views_expose_only_bounded_summaries() -> None:
    reader = _Reader()
    evidence = project_evidence_fixtures(reader, _CONTEXT)
    privacy = project_privacy_migration(reader, _CONTEXT)
    policy = project_policy_capabilities(reader, _CONTEXT)

    assert evidence["fixtures"]["families"][0]["partition_counts"] == {
        "training": 5,
        "tuning": 3,
        "certification_holdout": 2,
    }
    assert privacy["migration"]["phase"] == "projection_verified"
    assert privacy["operations"][0]["execution_surface"] == "local_cli_only"
    assert policy["policy"]["calibration_state"] == "approved"
    assert policy["budgets"]["items"][0]["limit_units"] == 100


def test_receipts_are_content_free_reverse_chronological_links() -> None:
    view = project_receipts_audit(_Reader(), _CONTEXT)

    assert [item["sequence"] for item in view["items"]] == [5, 4]
    assert view["items"][0]["related_receipt_refs"] == ["receipt:4"]
    assert view["category_counts"] == {"canary": 1, "activation": 1}


def test_all_six_views_pass_forbidden_field_scan_and_reject_unsafe_refs() -> None:
    reader = _Reader()
    views = (
        project_overview(reader, _CONTEXT),
        project_candidates(reader, _CONTEXT),
        project_evidence_fixtures(reader, _CONTEXT),
        project_privacy_migration(reader, _CONTEXT),
        project_policy_capabilities(reader, _CONTEXT),
        project_receipts_audit(reader, _CONTEXT),
    )
    forbidden = {
        "raw_prompt",
        "prompt_replacement",
        "tool_arguments",
        "tool_results",
        "fixture_content",
        "actor_id",
        "subject_id",
        "reviewer_id",
        "provider_id",
        "filesystem_path",
        "exception_text",
        "canonical_bytes",
        "holdout_content",
        "quarantine_id",
        "key_handle",
    }

    def scan(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden.isdisjoint(value)
            for nested in value.values():
                scan(nested)
        elif isinstance(value, list):
            for nested in value:
                scan(nested)

    for view in views:
        scan(view)

    reader.candidates = replace(
        reader.candidates,
        candidates=(replace(_candidate(), artifact_ref="/private/artifact.json"),),
    )
    with pytest.raises(OperatorProjectionError, match="safe identifier"):
        project_candidates(reader, _CONTEXT)
