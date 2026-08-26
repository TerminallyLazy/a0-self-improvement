from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from usr.plugins.dspy_rlm.extensions.python.message_loop_end import (
    _90_dspy_rlm_optimize as loop_hook_module,
)
from usr.plugins.dspy_rlm.extensions.python.system_prompt import (
    _30_dspy_rlm_guidance as prompt_hook_module,
)
from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    CanaryCoordinator,
    CanaryStartRequest,
    Rational,
    RecordIdentity,
    activation_policy,
    canary_plan,
)
from usr.plugins.dspy_rlm.helpers.v3.canary_runtime import (
    CANARY_ASSIGNMENT_KEY_ENV,
    CANARY_RUNTIME_REGISTRY,
    CANARY_SELECTION_LOOP_KEY,
    exposure_identity,
    select_canary_runtime,
)
from usr.plugins.dspy_rlm.helpers.v3.candidate_publication import (
    CANDIDATE_PUBLICATION_REGISTRY,
    IMPROVEMENT_CANDIDATE_SCHEMA_ID,
    STRUCTURED_GUIDANCE_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.deterministic_analysis import (
    GUIDANCE_RENDERER_CONTRACT_DIGEST,
    GUIDANCE_RENDERER_CONTRACT_ID,
    build_initial_guidance_rule_catalog,
)
from usr.plugins.dspy_rlm.helpers.v3.migration import (
    COMPATIBILITY_GUIDANCE_SCHEMA_ID,
    MIGRATION_REGISTRY,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Reader, V3Repository
from usr.plugins.dspy_rlm.helpers.v3.runtime_composer import compose_runtime
from usr.plugins.dspy_rlm.helpers.v3.schemas import (
    build_typed_record,
    merge_schema_registries,
)


CONTEXT = "context-canary-01"
SECRET = b"explicit-local-assignment-key"
TEST_REGISTRY = merge_schema_registries(CANARY_RUNTIME_REGISTRY, MIGRATION_REGISTRY)


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _link(role: str, target: object) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": 0,
        "target_id": target.record_id,
        "target_digest": target.content_digest,
    }


def _compatibility_guidance():
    return build_typed_record(
        record_id="guidance-canary-successor",
        context_ref=CONTEXT,
        record_kind="guidance_artifact",
        schema_id=COMPATIBILITY_GUIDANCE_SCHEMA_ID,
        payload={
            "artifact_type": "compatibility_guidance_set",
            "legacy_schema": "guidance.v1",
            "selector_id": "a0.guidance-v1.last-objective-bucket-or-reasoning.v1",
            "renderer_id": "a0.guidance-v1.system-prompt-renderer.v1",
            "promotable": False,
            "members": [
                {
                    "objective_bucket": "reasoning",
                    "rules": [
                        {"rule_type": "verify_tool_contract", "max_retries": None}
                    ],
                    "engine_profile_id": "a0.generate.guidance.deterministic_rules.v1",
                    "engine_version": "canary-test",
                    "issued_at": "2026-08-20T00:00:00Z",
                    "expires_at": "2026-09-20T00:00:00Z",
                }
            ],
            "links": [],
        },
        key_epoch="test-v1",
        registry=MIGRATION_REGISTRY,
    )


def _candidate(incumbent: object, successor: object, artifact: object, anchor: object):
    payload = {
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
            "claim_ref": "claim-canary-01",
            "claim_digest": _digest("claim-canary-01"),
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
    }
    return build_typed_record(
        record_id="candidate-canary-01",
        context_ref=CONTEXT,
        record_kind="improvement_candidate",
        schema_id=IMPROVEMENT_CANDIDATE_SCHEMA_ID,
        payload=payload,
        key_epoch="test-v1",
        registry=CANDIDATE_PUBLICATION_REGISTRY,
    )


def _seed(path: Path) -> None:
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    incumbent = activation_profile(
        record_id="profile-canary-incumbent",
        context_ref=CONTEXT,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="test-v1",
    )
    successor_guidance = _compatibility_guidance()
    successor = activation_profile(
        record_id="profile-canary-successor",
        context_ref=CONTEXT,
        guidance_artifact=successor_guidance,
        prompt_patch_artifact=prompt,
        key_epoch="test-v1",
    )
    candidate = _candidate(incumbent, successor, successor_guidance, prompt)
    policy = activation_policy(
        record_id="policy-canary-01",
        context_ref=CONTEXT,
        policy_revision=1,
        activation_mode="canary_required",
        key_epoch="test-v1",
    )
    plan = canary_plan(
        record_id="plan-canary-01",
        context_ref=CONTEXT,
        horizon_exposures=4,
        expiry_seconds=86_400,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=sha256(
            b"a0-canary-assignment-key\0" + SECRET
        ).hexdigest(),
        hard_veto_failure_limit=0,
        buckets=(
            BucketCalibration("shell", 2, Rational(0, 1), Rational(0, 1)),
        ),
        key_epoch="test-v1",
    )
    trial = CanaryCoordinator(key_epoch="test-v1").plan_start(
        CanaryStartRequest(
            record_id="trial-canary-01",
            context_ref=CONTEXT,
            canary_kind="diagnostic",
            disposition="review_only",
            disposition_ref=RecordIdentity.of(prompt),
            candidate=RecordIdentity.of(candidate),
            incumbent_profile=RecordIdentity.of(incumbent),
            expected_scope_revision=0,
            observed_scope_revision=0,
            environment_ref="environment-test",
            policy=policy,
            calibration=None,
            plan=plan,
            authority_grant=RecordIdentity.of(prompt),
            authority_purpose="diagnostic_canary",
            occupied_canary_ref=None,
        )
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with V3Repository.create(path, registry=TEST_REGISTRY) as repository:
        with repository.transaction() as transaction:
            for record in (
                guidance,
                prompt,
                incumbent,
                successor_guidance,
                successor,
                candidate,
                policy,
                plan,
                trial,
            ):
                transaction.insert_record(record)
            transaction.initialize_activation_scope(
                context_ref=CONTEXT,
                profile_id=incumbent.record_id,
                profile_digest=incumbent.content_digest,
            )
            transaction.claim_empty_operation_slot(
                context_ref=CONTEXT,
                operation_kind="canary",
                expected_revision=0,
                expected_scope_revision=0,
                operation_id=trial.record_id,
                operation_digest=trial.content_digest,
            )


def _candidate_message_ref(store: Path) -> str:
    with V3Reader.open(store, registry=TEST_REGISTRY) as reader:
        for index in range(128):
            message_ref = f"message-canary-{index}"
            selection = select_canary_runtime(
                reader,
                identity=exposure_identity(
                    context_ref=CONTEXT,
                    message_ref=message_ref,
                    loop_iteration=0,
                ),
                assignment_secret=SECRET,
                now=datetime.now(timezone.utc),
            )
            if selection is not None and selection.arm == "candidate":
                return message_ref
    raise AssertionError("test input did not produce a candidate assignment")


def _reader_opener(store: Path):
    return lambda **_kwargs: V3Reader.open(store, registry=TEST_REGISTRY)


def _repository_opener(store: Path):
    return lambda **_kwargs: V3Repository.open(store, registry=TEST_REGISTRY)


def _context() -> Any:
    return SimpleNamespace(
        id=CONTEXT,
        get_data=lambda key, recursive=False: False,
    )


def test_selection_is_pure_key_bound_and_expiry_bound(tmp_path: Path) -> None:
    store = tmp_path / "safe.sqlite3"
    _seed(store)
    identity = exposure_identity(
        context_ref=CONTEXT,
        message_ref=_candidate_message_ref(store),
        loop_iteration=0,
    )
    before = store.read_bytes()
    with V3Reader.open(store, registry=TEST_REGISTRY) as reader:
        selection = select_canary_runtime(
            reader,
            identity=identity,
            assignment_secret=SECRET,
            now=datetime.now(timezone.utc),
        )
        assert selection is not None and selection.arm == "candidate"
        assert selection.selected_profile_id == "profile-canary-successor"
        assert select_canary_runtime(
            reader,
            identity=identity,
            assignment_secret=None,
            now=datetime.now(timezone.utc),
        ) is None
        assert select_canary_runtime(
            reader,
            identity=identity,
            assignment_secret=b"wrong-key",
            now=datetime.now(timezone.utc),
        ) is None
        assert select_canary_runtime(
            reader,
            identity=identity,
            assignment_secret=SECRET,
            now=datetime.now(timezone.utc) + timedelta(days=2),
        ) is None
    assert store.read_bytes() == before
    assert SECRET.decode() not in repr(selection)


@pytest.mark.asyncio
async def test_prompt_selection_is_zero_write_then_outcome_commits_exact_exposure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = tmp_path / "safe.sqlite3"
    _seed(store)
    message_ref = _candidate_message_ref(store)
    monkeypatch.setenv(CANARY_ASSIGNMENT_KEY_ENV, SECRET.decode())
    monkeypatch.setattr(
        prompt_hook_module.config_module,
        "load_config",
        lambda _agent: {"enabled": True},
    )
    monkeypatch.setattr(prompt_hook_module, "open_runtime_reader", _reader_opener(store))
    monkeypatch.setattr(loop_hook_module, "open_runtime_repository", _repository_opener(store))
    loop_data = SimpleNamespace(
        iteration=0,
        user_message=SimpleNamespace(id=message_ref),
        params_temporary={"log_item_generating": SimpleNamespace(id="model-log-canary-01")},
    )
    agent = SimpleNamespace(context=_context(), loop_data=loop_data)
    prompt = ["core"]

    await prompt_hook_module.DspyRlmGuidance(agent=agent).execute(
        system_prompt=prompt,
        loop_data=loop_data,
    )

    assert prompt[0] == "core"
    assert "verify its documented input contract" in prompt[1]
    assert CANARY_SELECTION_LOOP_KEY in loop_data.params_temporary
    with V3Reader.open(store, registry=TEST_REGISTRY) as reader:
        kinds = [
            item.record.record_kind
            for item in reader.list_records_for_context(CONTEXT, maximum=32)
        ]
        assert "canary_exposure_receipt" not in kinds
        assert "canary_runtime_observation" not in kinds

    for _ in range(2):
        await loop_hook_module.DspyRlmOptimizationScheduler(agent=agent).execute(
            loop_data=loop_data,
            raw_prompt="RAW_PROMPT_CANARY_SECRET",
            provider_id="RAW_PROVIDER_CANARY_SECRET",
        )

    with V3Reader.open(store, registry=TEST_REGISTRY) as reader:
        records = reader.list_records_for_context(CONTEXT, maximum=32)
        runtime = [item.record for item in records if item.record.record_kind == "runtime_observation_fact"]
        receipts = [item.record for item in records if item.record.record_kind == "canary_exposure_receipt"]
        observations = [item.record for item in records if item.record.record_kind == "canary_runtime_observation"]
        assert len(runtime) == len(receipts) == len(observations) == 1
        assert observations[0].payload["arm"] == "candidate"
        assert observations[0].payload["selected_profile_id"] == "profile-canary-successor"
        assert observations[0].payload["outcome_authority"] == "exposure_only"
        assert observations[0].payload["promotion_authority"] == "none"
    durable = store.read_bytes()
    assert SECRET not in durable
    assert b"RAW_PROMPT_CANARY_SECRET" not in durable
    assert b"RAW_PROVIDER_CANARY_SECRET" not in durable


@pytest.mark.asyncio
async def test_missing_assignment_key_stays_incumbent_without_exposure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = tmp_path / "safe.sqlite3"
    _seed(store)
    monkeypatch.delenv(CANARY_ASSIGNMENT_KEY_ENV, raising=False)
    monkeypatch.setattr(
        prompt_hook_module.config_module,
        "load_config",
        lambda _agent: {"enabled": True},
    )
    monkeypatch.setattr(prompt_hook_module, "open_runtime_reader", _reader_opener(store))
    monkeypatch.setattr(loop_hook_module, "open_runtime_repository", _repository_opener(store))
    loop_data = SimpleNamespace(
        iteration=0,
        user_message=SimpleNamespace(id="message-no-key"),
        params_temporary={"log_item_generating": SimpleNamespace(id="model-log-no-key")},
    )
    agent = SimpleNamespace(context=_context(), loop_data=loop_data)
    prompt = ["core"]

    await prompt_hook_module.DspyRlmGuidance(agent=agent).execute(
        system_prompt=prompt, loop_data=loop_data
    )
    await loop_hook_module.DspyRlmOptimizationScheduler(agent=agent).execute(
        loop_data=loop_data
    )

    assert prompt == ["core"]
    assert CANARY_SELECTION_LOOP_KEY not in loop_data.params_temporary
    with V3Reader.open(store, registry=TEST_REGISTRY) as reader:
        kinds = [
            item.record.record_kind
            for item in reader.list_records_for_context(CONTEXT, maximum=32)
        ]
        assert kinds.count("runtime_observation_fact") == 1
        assert "canary_exposure_receipt" not in kinds
        assert "canary_runtime_observation" not in kinds


def test_structured_guidance_uses_only_the_exact_fixed_renderer_contract() -> None:
    catalog = build_initial_guidance_rule_catalog(key_epoch="test-v1")
    prompt_patch = null_prompt_patch_artifact()
    artifact = build_typed_record(
        record_id="guidance-structured-01",
        context_ref=CONTEXT,
        record_kind="guidance_artifact",
        schema_id=STRUCTURED_GUIDANCE_SCHEMA_ID,
        payload={
            "record_type": "improvement_artifact",
            "artifact_type": "structured_guidance",
            "artifact_slot": "structured_guidance",
            "payload_schema": STRUCTURED_GUIDANCE_SCHEMA_ID,
            "guidance_rule_catalog_id": catalog.record_id,
            "guidance_rule_catalog_digest": catalog.content_digest,
            "renderer_contract_id": GUIDANCE_RENDERER_CONTRACT_ID,
            "renderer_contract_digest": GUIDANCE_RENDERER_CONTRACT_DIGEST,
            "rules": [
                {"rule_id": "retry_after_failure", "parameters": {"max_retries": 1}}
            ],
            "links": [
                _link("guidance_rule_catalog", catalog),
                {
                    "role": "renderer_contract",
                    "ordinal": 0,
                    "target_id": GUIDANCE_RENDERER_CONTRACT_ID,
                    "target_digest": GUIDANCE_RENDERER_CONTRACT_DIGEST,
                },
            ],
        },
        key_epoch="test-v1",
        registry=CANDIDATE_PUBLICATION_REGISTRY,
    )
    profile = activation_profile(
        record_id="profile-structured-01",
        context_ref=CONTEXT,
        guidance_artifact=artifact,
        prompt_patch_artifact=prompt_patch,
        key_epoch="test-v1",
    )

    class Reader:
        records = {
            item.record_id: item for item in (catalog, prompt_patch, artifact, profile)
        }

        def get_activation_scope(self, context_ref: str):
            return SimpleNamespace(
                context_ref=context_ref,
                current_profile_id=profile.record_id,
                current_profile_digest=profile.content_digest,
                scope_revision=0,
            )

        def get_record(self, record_id: str):
            return self.records.get(record_id)

    result = compose_runtime(Reader(), context_ref=CONTEXT, system_prompt=["core"])

    assert result.applied
    assert result.reason_codes[0] == "structured_guidance_applied"
    assert "at most 1 corrected retry" in result.segments[-1]
