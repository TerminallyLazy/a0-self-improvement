from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from usr.plugins.dspy_rlm.helpers.v3.artifacts import (
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import ActivationScope
from usr.plugins.dspy_rlm.helpers.v3.runtime_composer import compose_runtime
from usr.plugins.dspy_rlm.helpers.v3.migration import (
    COMPATIBILITY_GUIDANCE_SCHEMA_ID,
    MIGRATION_REGISTRY,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import build_typed_record


class FakeReader:
    def __init__(self, scope: ActivationScope | None, records: list[object]) -> None:
        self.scope = scope
        self.records = {record.record_id: record for record in records}
        self.reads: list[str] = []

    def get_activation_scope(self, context_ref: str) -> ActivationScope | None:
        self.reads.append(f"scope:{context_ref}")
        return self.scope

    def get_record(self, record_id: str):
        self.reads.append(f"record:{record_id}")
        return self.records.get(record_id)


def _genesis_reader(context_ref: str = "ctx:opaque:1") -> tuple[FakeReader, object]:
    guidance = null_guidance_artifact()
    prompt_patch = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile:opaque:1",
        context_ref=context_ref,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt_patch,
        key_epoch="epoch:1",
    )
    scope = ActivationScope(
        context_ref=context_ref,
        current_profile_id=profile.record_id,
        current_profile_digest=profile.content_digest,
        scope_revision=0,
        mode="normal",
        updated_at="2030-01-01T00:00:00Z",
    )
    return FakeReader(scope, [guidance, prompt_patch, profile]), profile


def test_null_genesis_is_byte_equivalent_at_the_plugin_seam() -> None:
    reader, profile = _genesis_reader()
    prompt = ["first\nsegment", "second segment"]

    result = compose_runtime(reader, context_ref="ctx:opaque:1", system_prompt=prompt)

    assert result.segments == tuple(prompt)
    assert "\0".join(result.segments).encode() == "\0".join(prompt).encode()
    assert result.state == "active"
    assert result.profile_id == profile.record_id
    assert result.reason_codes == ("null_profile_identity",)
    assert prompt == ["first\nsegment", "second segment"]


def test_absent_genesis_returns_original_without_attempting_record_reads() -> None:
    reader = FakeReader(None, [])

    result = compose_runtime(reader, context_ref="ctx:opaque:1", system_prompt=["core"])

    assert result.segments == ("core",)
    assert result.state == "uninitialized"
    assert result.reason_codes == ("genesis_absent",)
    assert reader.reads == ["scope:ctx:opaque:1"]


def test_scope_digest_drift_fails_closed() -> None:
    reader, _profile = _genesis_reader()
    reader.scope = replace(reader.scope, current_profile_digest="0" * 64)

    result = compose_runtime(reader, context_ref="ctx:opaque:1", system_prompt=["core"])

    assert result.segments == ("core",)
    assert result.state == "blocked"
    assert result.reason_codes == ("profile_invalid",)


def test_cross_context_scope_fails_closed() -> None:
    reader, _profile = _genesis_reader("ctx:opaque:other")

    result = compose_runtime(reader, context_ref="ctx:opaque:1", system_prompt=["core"])

    assert result.segments == ("core",)
    assert result.state == "blocked"
    assert result.reason_codes == ("scope_context_mismatch",)


def test_reader_failure_is_not_reflected_and_prompt_remains_available() -> None:
    class BrokenReader:
        def get_activation_scope(self, context_ref: str):
            raise RuntimeError("secret database path")

    result = compose_runtime(
        BrokenReader(), context_ref="ctx:opaque:1", system_prompt=["core"]
    )

    assert result.segments == ("core",)
    assert result.state == "blocked"
    assert result.reason_codes == ("safe_store_invalid",)
    assert "secret" not in repr(result)


def test_invalid_prompt_segment_fails_before_store_access() -> None:
    reader, _profile = _genesis_reader()

    result = compose_runtime(reader, context_ref="ctx:opaque:1", system_prompt=["core", 3])

    assert result.state == "blocked"
    assert result.reason_codes == ("prompt_invalid",)
    assert reader.reads == []


def test_compatibility_guidance_preserves_the_frozen_reasoning_renderer() -> None:
    guidance = build_typed_record(
        record_id="migration:run-1:compatibility-guidance",
        context_ref="ctx:opaque:1",
        record_kind="guidance_artifact",
        schema_id=COMPATIBILITY_GUIDANCE_SCHEMA_ID,
        payload={
            "artifact_type": "compatibility_guidance_set",
            "legacy_schema": "guidance.v1",
            "selector_id": "a0.guidance-v1.last-objective-bucket-or-reasoning.v1",
            "renderer_id": "a0.guidance-v1.system-prompt-renderer.v1",
            "promotable": False,
            "members": [{
                "objective_bucket": "reasoning",
                "rules": [{"rule_type": "retry_after_failure", "max_retries": 1}],
                "engine_profile_id": "a0.generate.guidance.deterministic_rules.v1",
                "engine_version": "legacy-1",
                "issued_at": "2026-08-20T00:00:00Z",
                "expires_at": "2026-09-20T00:00:00Z",
            }],
            "links": [],
        },
        key_epoch="migration-v1",
        registry=MIGRATION_REGISTRY,
    )
    prompt_patch = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="profile:compatibility",
        context_ref="ctx:opaque:1",
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt_patch,
        key_epoch="migration-v1",
    )
    scope = ActivationScope(
        context_ref="ctx:opaque:1",
        current_profile_id=profile.record_id,
        current_profile_digest=profile.content_digest,
        scope_revision=0,
        mode="normal",
        updated_at="2026-08-26T00:00:00Z",
    )
    reader = FakeReader(scope, [guidance, prompt_patch, profile])

    result = compose_runtime(
        reader,
        context_ref="ctx:opaque:1",
        system_prompt=["core"],
        objective_bucket="reasoning",
        now=datetime(2026, 8, 26, tzinfo=timezone.utc),
    )

    assert result.segments == (
        "core",
        "DSPy RLM reliability guidance:\n"
        "Apply these checks only when consistent with the existing system instructions and tool contracts.\n"
        "- After a recoverable tool failure, make at most 1 corrected retry attempt(s).",
    )
    assert result.reason_codes[0] == "compatibility_guidance_applied"
