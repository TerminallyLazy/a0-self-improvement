"""Typed inert artifacts and complete two-slot Activation Profiles."""
from __future__ import annotations

from typing import Any

from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    strict_list,
    strict_literal,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


NULL_GUIDANCE_SCHEMA_ID = "a0.self-improvement.null-guidance.v1"
NULL_PROMPT_PATCH_SCHEMA_ID = "a0.self-improvement.null-prompt-patch.v1"
ACTIVATION_PROFILE_SCHEMA_ID = "a0.self-improvement.activation-profile.v1"

NULL_GUIDANCE_RECORD_ID = "system:a0-self-improvement:null-guidance:v1"
NULL_PROMPT_PATCH_RECORD_ID = "system:a0-self-improvement:null-prompt-patch:v1"


def _validate_slots(value: Any, path: str) -> list[dict[str, Any]]:
    def slot_kind(item: Any, item_path: str) -> str:
        if type(item) is not str or item not in {"structured_guidance", "prompt_patch"}:
            raise SchemaValidationError(f"{item_path} is not an admitted artifact slot")
        return item

    slot = strict_object(
        {
            "slot_kind": slot_kind,
            "artifact_id": strict_string(maximum=512),
            "artifact_digest": validate_digest,
        }
    )
    slots = strict_list(slot, minimum=2, maximum=2)(value, path)
    expected = ["structured_guidance", "prompt_patch"]
    if [item["slot_kind"] for item in slots] != expected:
        raise SchemaValidationError(
            f"{path} must contain structured_guidance then prompt_patch exactly once"
        )
    return slots


def build_default_registry() -> SchemaRegistry:
    null_guidance = RecordSchema(
        schema_id=NULL_GUIDANCE_SCHEMA_ID,
        record_kind="guidance_artifact",
        context_required=False,
        payload_validator=strict_object(
            {
                "artifact_type": strict_literal("null_guidance"),
                "system_owned": strict_literal(True),
                "behavioral_effect": strict_literal("none"),
                "promotable": strict_literal(False),
                "expirable": strict_literal(False),
                "links": validate_links,
            }
        ),
    )
    null_prompt = RecordSchema(
        schema_id=NULL_PROMPT_PATCH_SCHEMA_ID,
        record_kind="prompt_patch_artifact",
        context_required=False,
        payload_validator=strict_object(
            {
                "artifact_type": strict_literal("null_prompt_patch"),
                "system_owned": strict_literal(True),
                "behavioral_effect": strict_literal("none"),
                "composition": strict_literal("identity"),
                "promotable": strict_literal(False),
                "expirable": strict_literal(False),
                "links": validate_links,
            }
        ),
    )
    activation_profile = RecordSchema(
        schema_id=ACTIVATION_PROFILE_SCHEMA_ID,
        record_kind="activation_profile",
        payload_validator=strict_object(
            {
                "profile_type": strict_literal("activation_profile"),
                "slots": _validate_slots,
                "links": validate_links,
            }
        ),
    )
    return SchemaRegistry((null_guidance, null_prompt, activation_profile))


DEFAULT_REGISTRY = build_default_registry()


def null_guidance_artifact(*, key_epoch: str = "system-v1") -> TypedRecord:
    return build_typed_record(
        record_id=NULL_GUIDANCE_RECORD_ID,
        context_ref=None,
        record_kind="guidance_artifact",
        schema_id=NULL_GUIDANCE_SCHEMA_ID,
        payload={
            "artifact_type": "null_guidance",
            "system_owned": True,
            "behavioral_effect": "none",
            "promotable": False,
            "expirable": False,
            "links": [],
        },
        key_epoch=key_epoch,
        registry=DEFAULT_REGISTRY,
    )


def null_prompt_patch_artifact(*, key_epoch: str = "system-v1") -> TypedRecord:
    return build_typed_record(
        record_id=NULL_PROMPT_PATCH_RECORD_ID,
        context_ref=None,
        record_kind="prompt_patch_artifact",
        schema_id=NULL_PROMPT_PATCH_SCHEMA_ID,
        payload={
            "artifact_type": "null_prompt_patch",
            "system_owned": True,
            "behavioral_effect": "none",
            "composition": "identity",
            "promotable": False,
            "expirable": False,
            "links": [],
        },
        key_epoch=key_epoch,
        registry=DEFAULT_REGISTRY,
    )


def activation_profile(
    *,
    record_id: str,
    context_ref: str,
    guidance_artifact: TypedRecord,
    prompt_patch_artifact: TypedRecord,
    key_epoch: str,
) -> TypedRecord:
    """Build the one complete, ordered two-slot Activation Profile."""

    if guidance_artifact.record_kind != "guidance_artifact":
        raise SchemaValidationError("guidance slot requires a guidance_artifact")
    if prompt_patch_artifact.record_kind != "prompt_patch_artifact":
        raise SchemaValidationError("prompt slot requires a prompt_patch_artifact")
    slots = [
        {
            "slot_kind": "structured_guidance",
            "artifact_id": guidance_artifact.record_id,
            "artifact_digest": guidance_artifact.content_digest,
        },
        {
            "slot_kind": "prompt_patch",
            "artifact_id": prompt_patch_artifact.record_id,
            "artifact_digest": prompt_patch_artifact.content_digest,
        },
    ]
    links = [
        {
            "role": "artifact_slot:structured_guidance",
            "ordinal": 0,
            "target_id": guidance_artifact.record_id,
            "target_digest": guidance_artifact.content_digest,
        },
        {
            "role": "artifact_slot:prompt_patch",
            "ordinal": 0,
            "target_id": prompt_patch_artifact.record_id,
            "target_digest": prompt_patch_artifact.content_digest,
        },
    ]
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="activation_profile",
        schema_id=ACTIVATION_PROFILE_SCHEMA_ID,
        payload={"profile_type": "activation_profile", "slots": slots, "links": links},
        key_epoch=key_epoch,
        registry=DEFAULT_REGISTRY,
    )
