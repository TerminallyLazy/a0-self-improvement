from __future__ import annotations

from usr.plugins.dspy_rlm.api import autopilot_status
from usr.plugins.dspy_rlm.helpers import optimizer, paths
from usr.plugins.dspy_rlm.helpers.guidance import GuidanceArtifact, render_guidance_artifact
from usr.plugins.dspy_rlm.helpers.state import StateStore
from usr.plugins.dspy_rlm.helpers.store import Store
from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.autopilot_publication import (
    AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID,
    sync_legacy_candidates,
)
from usr.plugins.dspy_rlm.helpers.v3.candidate_publication import (
    IMPROVEMENT_CANDIDATE_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.operator_projection import (
    project_candidates,
    project_receipts_audit,
)
from usr.plugins.dspy_rlm.helpers.v3.operator_repository import (
    OperatorRepositoryAdapter,
    SafeStoreOperatorReader,
)
from usr.plugins.dspy_rlm.helpers.v3.registry import V3_REGISTRY
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Reader, V3Repository


def _seed_scope(path, context_ref: str) -> None:
    null_guidance = null_guidance_artifact()
    null_prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile.autopilot.incumbent",
        context_ref=context_ref,
        guidance_artifact=null_guidance,
        prompt_patch_artifact=null_prompt,
        key_epoch="test-autopilot-v1",
    )
    with V3Repository.create(path, registry=V3_REGISTRY) as repository:
        with repository.transaction() as transaction:
            transaction.insert_record(null_guidance)
            transaction.insert_record(null_prompt)
            transaction.insert_record(profile)
            transaction.initialize_activation_scope(
                context_ref=context_ref,
                profile_id=profile.record_id,
                profile_digest=profile.content_digest,
            )


def test_autopilot_candidate_reaches_review_only_candidate_and_receipt_projections(
    tmp_path,
) -> None:
    context_ref = "context-autopilot"
    legacy_path = tmp_path / "legacy.sqlite"
    safe_path = tmp_path / "safe.sqlite"
    manifest_path = tmp_path / "store-authority-manifest.json"
    legacy = Store(legacy_path)
    legacy.append_candidate(
        "legacy-candidate-1",
        context_ref,
        "reasoning",
        {
            "candidate_id": "legacy-candidate-1",
            "run_id": "legacy-run-1",
            "guidance_version": "guidance-1",
            "validation": {"passed": True},
        },
        run_id="legacy-run-1",
        guidance_version="guidance-1",
    )
    _seed_scope(safe_path, context_ref)

    first = sync_legacy_candidates(
        context_ref=context_ref,
        legacy_store=legacy,
        pre_cutover_path=safe_path,
        manifest_path=manifest_path,
    )
    second = sync_legacy_candidates(
        context_ref=context_ref,
        legacy_store=legacy,
        pre_cutover_path=safe_path,
        manifest_path=manifest_path,
    )

    assert first.discovered_count == 1
    assert first.published_count == 1
    assert second.discovered_count == 0
    assert second.published_count == 0
    with V3Reader.open(safe_path, registry=V3_REGISTRY) as reader:
        facts = SafeStoreOperatorReader(reader)
        adapter = OperatorRepositoryAdapter(facts)
        candidates = project_candidates(adapter, context_ref)
        receipts = project_receipts_audit(adapter, context_ref)
        stored_candidate = next(
            item
            for item in facts.list_records(context_ref)
            if item.record.record_kind == "improvement_candidate"
        ).record

    assert candidates["axis"]["state"] == "active"
    assert candidates["disposition_counts"]["review_only"] == 1
    assert len(candidates["items"]) == 1
    candidate = candidates["items"][0]
    assert candidate["disposition"]["value"] == "review_only"
    assert candidate["authority_ceiling"] == "no_promotion_authority"
    assert candidate["allowed_actions"] == [
        {
            "action": "activate",
            "state": "blocked",
            "reason_codes": ["autopilot_review_only"],
        }
    ]
    assert stored_candidate.schema_id == AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID
    assert stored_candidate.schema_id != IMPROVEMENT_CANDIDATE_SCHEMA_ID
    assert receipts["receipts"]["state"] == "active"
    assert receipts["category_counts"]["candidate"] == 1
    assert receipts["items"][0]["action"] == "candidate_staged_for_review"


def test_backfill_pages_once_and_reuses_durable_high_water_mark(tmp_path) -> None:
    context_ref = "context-paged-backfill"
    legacy = Store(tmp_path / "legacy.sqlite")
    safe_path = tmp_path / "safe.sqlite"
    manifest_path = tmp_path / "store-authority-manifest.json"
    for index in range(129):
        legacy.append_candidate(
            f"candidate-{index:03d}",
            context_ref,
            "reasoning",
            {"index": index},
        )
    _seed_scope(safe_path, context_ref)

    first = sync_legacy_candidates(
        context_ref=context_ref,
        legacy_store=legacy,
        pre_cutover_path=safe_path,
        manifest_path=manifest_path,
    )
    second = sync_legacy_candidates(
        context_ref=context_ref,
        legacy_store=legacy,
        pre_cutover_path=safe_path,
        manifest_path=manifest_path,
    )

    assert first.discovered_count == 129
    assert first.published_count == 129
    assert second.discovered_count == 0
    with V3Reader.open(safe_path, registry=V3_REGISTRY) as reader:
        projection = project_candidates(
            OperatorRepositoryAdapter(SafeStoreOperatorReader(reader)),
            context_ref,
        )
    assert len(projection["items"]) == 129


def test_failed_legacy_validation_projects_a_rejected_review_candidate(tmp_path) -> None:
    context_ref = "context-rejected"
    legacy = Store(tmp_path / "legacy.sqlite")
    safe_path = tmp_path / "safe.sqlite"
    manifest_path = tmp_path / "store-authority-manifest.json"
    legacy.append_candidate(
        "candidate-rejected",
        context_ref,
        "reasoning",
        {"validation": {"passed": False}},
    )
    _seed_scope(safe_path, context_ref)

    sync_legacy_candidates(
        context_ref=context_ref,
        legacy_store=legacy,
        pre_cutover_path=safe_path,
        manifest_path=manifest_path,
    )

    with V3Reader.open(safe_path, registry=V3_REGISTRY) as reader:
        projection = project_candidates(
            OperatorRepositoryAdapter(SafeStoreOperatorReader(reader)),
            context_ref,
        )
    assert projection["disposition_counts"]["rejected"] == 1
    candidate = projection["items"][0]
    assert candidate["disposition"]["value"] == "rejected"
    assert candidate["disposition"]["reason_codes"] == ["autopilot_rejected"]
    assert candidate["allowed_actions"][0]["reason_codes"] == [
        "autopilot_rejected"
    ]


def test_project_status_separates_selected_chat_from_project_totals(
    tmp_path, monkeypatch,
) -> None:
    selected = "context-selected"
    other = "context-other"
    legacy_path = tmp_path / "legacy.sqlite"
    safe_path = tmp_path / "safe.sqlite"
    manifest_path = tmp_path / "store-authority-manifest.json"
    legacy = Store(legacy_path)
    null_guidance = null_guidance_artifact()
    null_prompt = null_prompt_patch_artifact()
    with V3Repository.create(safe_path, registry=V3_REGISTRY) as repository:
        with repository.transaction() as transaction:
            transaction.insert_record(null_guidance)
            transaction.insert_record(null_prompt)
            for context_ref in (selected, other):
                profile = activation_profile(
                    record_id=f"profile.{context_ref}",
                    context_ref=context_ref,
                    guidance_artifact=null_guidance,
                    prompt_patch_artifact=null_prompt,
                    key_epoch="test-autopilot-v1",
                )
                transaction.insert_record(profile)
                transaction.initialize_activation_scope(
                    context_ref=context_ref,
                    profile_id=profile.record_id,
                    profile_digest=profile.content_digest,
                )
    for index in range(1):
        legacy.append_candidate(
            f"selected-{index}", selected, "reasoning", {"index": index}
        )
    for index in range(3):
        legacy.append_candidate(
            f"other-{index}", other, "reasoning", {"index": index}
        )
    for context_ref in (selected, other):
        sync_legacy_candidates(
            context_ref=context_ref,
            legacy_store=legacy,
            pre_cutover_path=safe_path,
            manifest_path=manifest_path,
        )
    monkeypatch.setattr(autopilot_status.paths, "SAFE_STORE_FILE", safe_path)
    monkeypatch.setattr(
        autopilot_status.paths,
        "STORE_AUTHORITY_MANIFEST_FILE",
        manifest_path,
    )

    result = autopilot_status._v3_runtime(
        (selected, other), selected_context_ref=selected
    )

    assert result["candidate_count"] == 1
    assert result["receipt_count"] == 1
    assert result["project_counts"]["candidates"] == 4
    assert result["project_counts"]["receipts"] == 4


def test_optimizer_persistence_immediately_publishes_review_candidate(
    tmp_path, monkeypatch,
) -> None:
    context_ref = "context-optimizer"
    safe_path = tmp_path / "safe.sqlite"
    manifest_path = tmp_path / "store-authority-manifest.json"
    legacy_state = StateStore(tmp_path, db_path=tmp_path / "legacy.sqlite")
    _seed_scope(safe_path, context_ref)
    monkeypatch.setattr(optimizer.state_module, "_store_for_root", lambda: legacy_state)
    monkeypatch.setattr(paths, "SAFE_STORE_FILE", safe_path)
    monkeypatch.setattr(paths, "STORE_AUTHORITY_MANIFEST_FILE", manifest_path)
    source_hash = "sha256:" + "1" * 64
    artifact = GuidanceArtifact.create(
        artifact_id="guidance-optimizer-1",
        context_id=context_ref,
        objective_bucket="reasoning",
        rules=[{"type": "verify_tool_contract"}],
        source_manifest_hashes=[source_hash],
        source_finding_hashes=[source_hash],
        issued_at="2026-09-03T00:00:00Z",
        expires_at="2026-09-04T00:00:00Z",
        engine_kind="gepa",
        engine_version="gepa-1",
    )

    result = optimizer._persist_candidate_artifacts(
        context_ref,
        "reasoning",
        "objective-signature-1",
        [],
        artifact,
        render_guidance_artifact(artifact),
        {},
        {"passed": True},
        {},
        {"decision": "review_only"},
        None,
        {},
        "2026-09-03T00:00:00Z",
    )

    assert result["v3_publication_state"] == "review_only"
    assert result["v3_published_count"] == 1
    with V3Reader.open(safe_path, registry=V3_REGISTRY) as reader:
        candidates = project_candidates(
            OperatorRepositoryAdapter(SafeStoreOperatorReader(reader)),
            context_ref,
        )
    assert len(candidates["items"]) == 1
    assert candidates["items"][0]["disposition"]["value"] == "review_only"


def test_reconciliation_preserves_old_lineage_after_scope_revision_changes(
    tmp_path,
) -> None:
    context_ref = "context-revision"
    legacy = Store(tmp_path / "legacy.sqlite")
    safe_path = tmp_path / "safe.sqlite"
    manifest_path = tmp_path / "store-authority-manifest.json"
    legacy.append_candidate("candidate-1", context_ref, "reasoning", {"index": 1})
    _seed_scope(safe_path, context_ref)
    sync_legacy_candidates(
        context_ref=context_ref,
        legacy_store=legacy,
        pre_cutover_path=safe_path,
        manifest_path=manifest_path,
    )
    null_guidance = null_guidance_artifact()
    null_prompt = null_prompt_patch_artifact()
    successor = activation_profile(
        record_id="profile.autopilot.successor",
        context_ref=context_ref,
        guidance_artifact=null_guidance,
        prompt_patch_artifact=null_prompt,
        key_epoch="test-autopilot-v1",
    )
    with V3Repository.open(safe_path, registry=V3_REGISTRY) as repository:
        with repository.transaction() as transaction:
            transaction.insert_record(successor)
            transaction.compare_and_swap_activation_scope(
                context_ref=context_ref,
                expected_revision=0,
                profile_id=successor.record_id,
                profile_digest=successor.content_digest,
                mode="normal",
            )
    legacy.append_candidate("candidate-2", context_ref, "reasoning", {"index": 2})

    result = sync_legacy_candidates(
        context_ref=context_ref,
        legacy_store=legacy,
        pre_cutover_path=safe_path,
        manifest_path=manifest_path,
    )

    assert result.published_count == 1
    assert result.already_published_count == 0
    with V3Reader.open(safe_path, registry=V3_REGISTRY) as reader:
        projection = project_candidates(
            OperatorRepositoryAdapter(SafeStoreOperatorReader(reader)),
            context_ref,
        )
    assert sorted(item["lineage"]["state"] for item in projection["items"]) == [
        "current",
        "stale",
    ]
