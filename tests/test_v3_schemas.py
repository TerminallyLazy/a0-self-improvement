from __future__ import annotations

from dataclasses import replace
import math

import pytest

from usr.plugins.dspy_rlm.helpers.v3 import (
    DEFAULT_REGISTRY,
    CanonicalJSONError,
    SchemaValidationError,
    UnknownSchemaError,
    activation_profile,
    canonical_json,
    null_guidance_artifact,
    null_prompt_patch_artifact,
    schema_digest,
)


def test_canonical_json_is_stable_and_rejects_nonfinite_values() -> None:
    assert canonical_json({"z": [3, 2], "a": "é"}) == b'{"a":"\xc3\xa9","z":[3,2]}'

    for nonfinite in (math.nan, math.inf, -math.inf):
        with pytest.raises(CanonicalJSONError, match="non-finite"):
            canonical_json({"value": nonfinite})


def test_schema_digest_is_separated_by_schema_and_purpose() -> None:
    payload = b'{"value":1}'

    assert schema_digest("record-content", "example.v1", payload) != schema_digest(
        "record-content", "example.v2", payload
    )
    assert schema_digest("record-content", "example.v1", payload) != schema_digest(
        "record-link-manifest", "example.v1", payload
    )


def test_null_artifacts_are_distinct_typed_inert_records() -> None:
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()

    guidance.verify(DEFAULT_REGISTRY)
    prompt.verify(DEFAULT_REGISTRY)
    assert guidance.record_kind == "guidance_artifact"
    assert guidance.payload == {
        "artifact_type": "null_guidance",
        "behavioral_effect": "none",
        "expirable": False,
        "links": [],
        "promotable": False,
        "system_owned": True,
    }
    assert prompt.record_kind == "prompt_patch_artifact"
    assert prompt.payload["composition"] == "identity"
    assert guidance.schema_id != prompt.schema_id
    assert guidance.content_digest != prompt.content_digest


def test_activation_profile_is_exactly_two_ordered_slots_and_digest_covers_links() -> None:
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()
    profile = activation_profile(
        record_id="context-1:profile:genesis",
        context_ref="context-1",
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt,
        key_epoch="opaque-v1",
    )

    profile.verify(DEFAULT_REGISTRY)
    assert [slot["slot_kind"] for slot in profile.payload["slots"]] == [
        "structured_guidance",
        "prompt_patch",
    ]
    assert [link.role for link in profile.links] == [
        "artifact_slot:structured_guidance",
        "artifact_slot:prompt_patch",
    ]

    payload = profile.payload
    payload["links"].reverse()
    tampered_bytes = canonical_json(payload)
    tampered = replace(
        profile,
        canonical_bytes=tampered_bytes,
        content_digest=schema_digest("record-content", profile.schema_id, tampered_bytes),
    )
    with pytest.raises(SchemaValidationError, match="manifest"):
        tampered.verify(DEFAULT_REGISTRY)


def test_schemas_reject_unknown_fields_type_coercion_and_unknown_versions() -> None:
    guidance = null_guidance_artifact()
    payload = guidance.payload
    payload["unexpected"] = True
    encoded = canonical_json(payload)
    unknown_field = replace(
        guidance,
        canonical_bytes=encoded,
        content_digest=schema_digest("record-content", guidance.schema_id, encoded),
    )
    with pytest.raises(SchemaValidationError, match="unknown fields"):
        unknown_field.verify(DEFAULT_REGISTRY)

    payload = guidance.payload
    payload["system_owned"] = 1
    encoded = canonical_json(payload)
    coerced_boolean = replace(
        guidance,
        canonical_bytes=encoded,
        content_digest=schema_digest("record-content", guidance.schema_id, encoded),
    )
    with pytest.raises(SchemaValidationError, match="exactly True"):
        coerced_boolean.verify(DEFAULT_REGISTRY)

    with pytest.raises(UnknownSchemaError):
        DEFAULT_REGISTRY.schema("a0.self-improvement.null-guidance.v2")


def test_activation_profile_builder_rejects_wrong_slot_types() -> None:
    guidance = null_guidance_artifact()
    prompt = null_prompt_patch_artifact()

    with pytest.raises(SchemaValidationError, match="guidance slot"):
        activation_profile(
            record_id="context-1:profile:invalid",
            context_ref="context-1",
            guidance_artifact=prompt,
            prompt_patch_artifact=prompt,
            key_epoch="opaque-v1",
        )
    with pytest.raises(SchemaValidationError, match="prompt slot"):
        activation_profile(
            record_id="context-1:profile:invalid",
            context_ref="context-1",
            guidance_artifact=guidance,
            prompt_patch_artifact=guidance,
            key_epoch="opaque-v1",
        )
