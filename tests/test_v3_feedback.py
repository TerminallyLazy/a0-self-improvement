from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.feedback import (
    FEEDBACK_ASSESSMENT_SCHEMA_ID,
    ExactFeedbackRecord,
    FeedbackDenied,
    FeedbackRequest,
    record_feedback,
    reduce_feedback,
)
from usr.plugins.dspy_rlm.helpers.v3.registry import V3_REGISTRY
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
    V3Reader,
    V3Repository,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    build_typed_record,
    merge_schema_registries,
    strict_literal,
    strict_object,
    validate_links,
)


CONTEXT = "context:feedback"
NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
OUTCOME_SCHEMA_ID = "test.outcome-evidence.v1"


def _outcome_payload(value, path):
    payload = strict_object(
        {"record_type": strict_literal("outcome_evidence"), "links": validate_links}
    )(value, path)
    if payload["links"]:
        raise SchemaValidationError(f"{path}.links must be empty")
    return payload


TEST_REGISTRY = merge_schema_registries(
    V3_REGISTRY,
    SchemaRegistry((RecordSchema(OUTCOME_SCHEMA_ID, "outcome_evidence", _outcome_payload),)),
)


def _idempotency(index: int) -> str:
    return f"{index:064x}"


def _seed(path: Path, *, context_ref: str = CONTEXT):
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id=f"profile:{context_ref.split(':')[-1]}",
        context_ref=context_ref,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="test-v1",
    )
    outcome = build_typed_record(
        record_id=f"outcome:{context_ref.split(':')[-1]}",
        context_ref=context_ref,
        record_kind="outcome_evidence",
        schema_id=OUTCOME_SCHEMA_ID,
        payload={"record_type": "outcome_evidence", "links": []},
        key_epoch="test-v1",
        registry=TEST_REGISTRY,
    )
    repository = V3Repository.create(path, registry=TEST_REGISTRY)
    with repository.transaction() as transaction:
        for record in (guidance, prompt, profile, outcome):
            transaction.insert_record(record)
    return repository, outcome, profile


def _request(
    outcome,
    profile,
    *,
    index: int,
    kind: str = "helpfulness",
    state: str = "pass",
    reasons: tuple[str, ...] = ("helpful",),
    operation: str = "assess",
    prior=None,
    context_ref: str = CONTEXT,
) -> FeedbackRequest:
    return FeedbackRequest(
        issuer_ref="issuer:local",
        subject_ref="operator:local",
        context_ref=context_ref,
        outcome_evidence=ExactFeedbackRecord.of(outcome),
        activation_profile=ExactFeedbackRecord.of(profile),
        assessment_kind=kind,
        state=state,
        reason_codes=reasons,
        operation=operation,
        prior_assessment=(None if prior is None else ExactFeedbackRecord.of(prior)),
        authority_grant_id=f"grant:{index}",
        idempotency_key_digest=_idempotency(index),
        now=NOW + timedelta(minutes=index),
    )


def _grant(request: FeedbackRequest) -> VerifiedGrant:
    return VerifiedGrant(
        grant_id=request.authority_grant_id,
        authority_class="operator_authority_grant",
        issuer_id=request.issuer_ref,
        key_epoch=1,
        subject_ref=request.subject_ref,
        context_ref=request.context_ref,
        action="feedback_submit",
        purpose="operator_mutation",
        target_ref=request.outcome_evidence.record_id,
        target_revision=0,
        issued_at=request.now - timedelta(minutes=1),
        expires_at=request.now + timedelta(hours=1),
        idempotency_key_digest=request.idempotency_key_digest,
        session_nonce=f"session:{request.authority_grant_id}",
    )


def _submit(repository, request):
    grant = _grant(request)
    return record_feedback(repository, request, revalidate_grant=lambda _tx: grant)


def test_feedback_is_exact_append_only_and_same_request_replays(tmp_path: Path) -> None:
    repository, outcome, profile = _seed(tmp_path / "feedback.sqlite3")
    request = _request(outcome, profile, index=1)
    first = _submit(repository, request)
    replay = _submit(repository, replace(request, now=request.now + timedelta(minutes=5)))

    assert replay.replayed is True
    assert replay.assessment == first.assessment
    assert replay.receipt == first.receipt
    assert first.assessment.payload["outcome_evidence"] == {
        "record_id": outcome.record_id,
        "digest": outcome.content_digest,
    }
    assert "comment" not in first.assessment.payload
    reduced = reduce_feedback(
        (first.assessment,),
        outcome_evidence=ExactFeedbackRecord.of(outcome),
        activation_profile=ExactFeedbackRecord.of(profile),
    )
    assert reduced.active_counts == (("helpfulness", "pass", 1),)
    assert reduced.authority_ceiling == "annotation_only"
    assert reduced.deterministic_outcome_unchanged is True
    assert reduced.deterministic_rejection_override is False
    repository.close()


def test_correction_and_withdrawal_append_exact_prior_lineage(tmp_path: Path) -> None:
    repository, outcome, profile = _seed(tmp_path / "lineage.sqlite3")
    initial = _submit(
        repository,
        _request(
            outcome,
            profile,
            index=1,
            kind="safety",
            state="fail",
            reasons=("unsafe",),
        ),
    )
    correction = _submit(
        repository,
        _request(
            outcome,
            profile,
            index=2,
            kind="safety",
            state="pass",
            reasons=("safe",),
            operation="correct",
            prior=initial.assessment,
        ),
    )
    withdrawal = _submit(
        repository,
        _request(
            outcome,
            profile,
            index=3,
            kind="safety",
            state="unavailable",
            reasons=("withdrawn",),
            operation="withdraw",
            prior=correction.assessment,
        ),
    )

    assert correction.assessment.payload["prior_assessment"]["record_id"] == initial.assessment.record_id
    assert withdrawal.event.event_type == "feedback_withdrawn"
    reduced = reduce_feedback(
        (initial.assessment, correction.assessment, withdrawal.assessment),
        outcome_evidence=ExactFeedbackRecord.of(outcome),
        activation_profile=ExactFeedbackRecord.of(profile),
    )
    assert reduced.active_counts == (("safety", "unavailable", 1),)
    assert reduced.conflict_kinds == ()
    repository.close()


def test_conflict_cross_context_and_missing_target_leave_no_partial_rows(tmp_path: Path) -> None:
    path = tmp_path / "fail-closed.sqlite3"
    repository, outcome, profile = _seed(path)
    original_request = _request(outcome, profile, index=1)
    _submit(repository, original_request)

    conflicting = replace(
        original_request, state="fail", reason_codes=("not_helpful",)
    )
    with pytest.raises(IdempotencyConflict):
        _submit(repository, conflicting)
    with pytest.raises(FeedbackDenied, match="outcome_evidence_context_mismatch"):
        _submit(
            repository,
            _request(outcome, profile, index=2, context_ref="context:other"),
        )
    missing = replace(
        _request(outcome, profile, index=3),
        outcome_evidence=ExactFeedbackRecord("outcome:missing", "f" * 64),
    )
    with pytest.raises(FeedbackDenied, match="exact_target_missing"):
        _submit(repository, missing)
    repository.close()

    with V3Reader.open(path, registry=TEST_REGISTRY) as reader:
        assert reader.count_records_for_context(CONTEXT) == 4
        assert reader.count_operator_commands_for_context(CONTEXT) == 1
        assert reader.count_records_for_context("context:other") == 0


def test_closed_schema_and_pure_reducer_report_conflict_without_override(tmp_path: Path) -> None:
    repository, outcome, profile = _seed(tmp_path / "conflict.sqlite3")
    initial = _submit(repository, _request(outcome, profile, index=1))
    passing = _submit(
        repository,
        _request(
            outcome,
            profile,
            index=2,
            operation="correct",
            prior=initial.assessment,
        ),
    )
    failing = _submit(
        repository,
        _request(
            outcome,
            profile,
            index=3,
            state="fail",
            reasons=("not_helpful",),
            operation="correct",
            prior=initial.assessment,
        ),
    )
    reduced = reduce_feedback(
        (initial.assessment, passing.assessment, failing.assessment),
        outcome_evidence=ExactFeedbackRecord.of(outcome),
        activation_profile=ExactFeedbackRecord.of(profile),
    )
    assert reduced.active_counts == (
        ("helpfulness", "fail", 1),
        ("helpfulness", "pass", 1),
    )
    assert reduced.conflict_kinds == ("helpfulness",)
    assert reduced.deterministic_rejection_override is False

    unsafe_payload = dict(initial.assessment.payload)
    unsafe_payload["comment"] = "free text must not enter the store"
    with pytest.raises(SchemaValidationError):
        build_typed_record(
            record_id="feedback:unsafe",
            context_ref=CONTEXT,
            record_kind="feedback_assessment",
            schema_id=FEEDBACK_ASSESSMENT_SCHEMA_ID,
            payload=unsafe_payload,
            key_epoch="test-v1",
            registry=TEST_REGISTRY,
        )
    repository.close()
