"""Pure, fail-closed composition of one exact v3 Activation Profile."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, Sequence

from .artifacts import (
    ACTIVATION_PROFILE_SCHEMA_ID,
    NULL_GUIDANCE_SCHEMA_ID,
    NULL_PROMPT_PATCH_SCHEMA_ID,
)
from .candidate_publication import (
    CANDIDATE_PUBLICATION_REGISTRY,
    STRUCTURED_GUIDANCE_SCHEMA_ID,
)
from .deterministic_analysis import (
    DETERMINISTIC_ANALYSIS_REGISTRY,
    GUIDANCE_RENDERER_CONTRACT_DIGEST,
    GUIDANCE_RENDERER_CONTRACT_ID,
    GUIDANCE_RULE_CATALOG_SCHEMA_ID,
)
from .repository import ActivationScope
from .schemas import TypedRecord


COMPATIBILITY_GUIDANCE_SCHEMA_ID = "a0.self-improvement.compatibility-guidance-set.v1"
LEGACY_DEFAULT_OBJECTIVE_BUCKET = "reasoning"
LEGACY_RENDERER_ID = "a0.guidance-v1.system-prompt-renderer.v1"
LEGACY_SELECTOR_ID = "a0.guidance-v1.last-objective-bucket-or-reasoning.v1"
LEGACY_MAX_RENDERED_CHARS = 1_800
_LEGACY_RULE_ORDER = (
    "verify_tool_contract",
    "check_tool_result",
    "retry_after_failure",
    "prefer_reversible_action",
    "bound_tool_scope",
)


class RuntimeRecordReader(Protocol):
    """The read-only authority surface consumed by prompt composition."""

    def get_activation_scope(self, context_ref: str) -> ActivationScope | None: ...

    def get_record(self, record_id: str) -> TypedRecord | None: ...


@dataclass(frozen=True, slots=True)
class CompositionResult:
    segments: tuple[str, ...]
    state: str
    profile_id: str | None
    scope_revision: int | None
    reason_codes: tuple[str, ...]

    @property
    def applied(self) -> bool:
        return self.state == "active"


@dataclass(frozen=True, slots=True)
class ProfileSelection:
    """Exact non-mutating profile selection already authorized by its caller."""

    profile_id: str
    profile_digest: str
    scope_revision: int


def _unchanged(
    original: tuple[str, ...],
    *,
    state: str,
    reason_code: str,
    profile_id: str | None = None,
    scope_revision: int | None = None,
) -> CompositionResult:
    return CompositionResult(
        segments=original,
        state=state,
        profile_id=profile_id,
        scope_revision=scope_revision,
        reason_codes=(reason_code,),
    )


def _legacy_timestamp(value: Any) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError("compatibility timestamp is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("compatibility timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _render_compatibility_member(member: dict[str, Any]) -> str:
    rules = member.get("rules")
    if type(rules) is not list or not 1 <= len(rules) <= 4:
        raise ValueError("compatibility rules exceed the frozen legacy boundary")
    names = [item.get("rule_type") for item in rules if type(item) is dict]
    if len(names) != len(rules) or len(set(names)) != len(names):
        raise ValueError("compatibility rules are malformed or repeated")
    try:
        positions = [_LEGACY_RULE_ORDER.index(name) for name in names]
    except ValueError as exc:
        raise ValueError("compatibility rule is unknown") from exc
    if positions != sorted(positions):
        raise ValueError("compatibility rule order differs from guidance.v1")

    lines = [
        "DSPy RLM reliability guidance:",
        "Apply these checks only when consistent with the existing system instructions and tool contracts.",
    ]
    for rule in rules:
        name = rule["rule_type"]
        retries = rule["max_retries"]
        if name == "verify_tool_contract" and retries is None:
            lines.append("- Before a tool call, verify its documented input contract and expected result.")
        elif name == "check_tool_result" and retries is None:
            lines.append("- Check a tool result for completion or a recoverable failure before taking the next step.")
        elif name == "retry_after_failure" and type(retries) is int and 0 <= retries <= 1_000:
            lines.append(
                f"- After a recoverable tool failure, make at most {retries} corrected retry attempt(s)."
            )
        elif name == "prefer_reversible_action" and retries is None:
            lines.append("- Prefer a reversible action when the available evidence does not establish a safe irreversible action.")
        elif name == "bound_tool_scope" and retries is None:
            lines.append("- Keep each tool action within the smallest scope needed for the current task.")
        else:
            raise ValueError("compatibility rule parameters differ from guidance.v1")
    rendered = "\n".join(lines)
    if len(rendered) > LEGACY_MAX_RENDERED_CHARS:
        raise ValueError("compatibility rendering exceeds the frozen bound")
    return rendered


def _render_structured_guidance(
    reader: RuntimeRecordReader, artifact: TypedRecord
) -> str:
    artifact.verify(CANDIDATE_PUBLICATION_REGISTRY)
    payload = artifact.payload
    if (
        artifact.record_kind != "guidance_artifact"
        or artifact.schema_id != STRUCTURED_GUIDANCE_SCHEMA_ID
        or payload["renderer_contract_id"] != GUIDANCE_RENDERER_CONTRACT_ID
        or payload["renderer_contract_digest"] != GUIDANCE_RENDERER_CONTRACT_DIGEST
    ):
        raise ValueError("structured guidance renderer contract is invalid")
    catalog = reader.get_record(payload["guidance_rule_catalog_id"])
    if (
        catalog is None
        or catalog.content_digest != payload["guidance_rule_catalog_digest"]
        or catalog.context_ref is not None
        or catalog.record_kind != "guidance_rule_catalog"
        or catalog.schema_id != GUIDANCE_RULE_CATALOG_SCHEMA_ID
    ):
        raise ValueError("structured guidance catalog is unavailable")
    catalog.verify(DETERMINISTIC_ANALYSIS_REGISTRY)

    lines = [
        "DSPy RLM reliability guidance:",
        "Apply these checks only when consistent with the existing system instructions and tool contracts.",
    ]
    for rule in payload["rules"]:
        name = rule["rule_id"]
        parameters = rule["parameters"]
        if name == "verify_tool_contract" and parameters == {}:
            lines.append(
                "- Before a tool call, verify its documented input contract and expected result."
            )
        elif name == "check_tool_result" and parameters == {}:
            lines.append(
                "- Check a tool result for completion or a recoverable failure before taking the next step."
            )
        elif name == "retry_after_failure" and set(parameters) == {"max_retries"}:
            lines.append(
                "- After a recoverable tool failure, make at most "
                f"{parameters['max_retries']} corrected retry attempt(s)."
            )
        elif name == "prefer_reversible_action" and parameters == {}:
            lines.append(
                "- Prefer a reversible action when the available evidence does not establish a safe irreversible action."
            )
        elif name == "bound_tool_scope" and parameters == {}:
            lines.append(
                "- Keep each tool action within the smallest scope needed for the current task."
            )
        else:
            raise ValueError("structured guidance contains an unknown renderer input")
    return "\n".join(lines)


def compose_runtime(
    reader: RuntimeRecordReader,
    *,
    context_ref: str,
    system_prompt: Sequence[str],
    objective_bucket: str = LEGACY_DEFAULT_OBJECTIVE_BUCKET,
    now: datetime | None = None,
    profile_selection: ProfileSelection | None = None,
) -> CompositionResult:
    """Compose without creating, repairing, caching, or mutating authority.

    The only non-Null migration occupant is the frozen Compatibility Guidance
    Set. Its default objective bucket and renderer are the exact guidance.v1
    selector/renderer behavior, not configurable vNext policy.
    """

    original = tuple(system_prompt)
    if type(context_ref) is not str or not context_ref:
        return _unchanged(original, state="blocked", reason_code="context_invalid")
    if any(type(segment) is not str for segment in original):
        return _unchanged(original, state="blocked", reason_code="prompt_invalid")
    if type(objective_bucket) is not str or not objective_bucket:
        return _unchanged(original, state="blocked", reason_code="objective_bucket_invalid")
    if profile_selection is not None and type(profile_selection) is not ProfileSelection:
        return _unchanged(original, state="blocked", reason_code="profile_selection_invalid")

    try:
        scope = reader.get_activation_scope(context_ref)
        if scope is None:
            return _unchanged(original, state="uninitialized", reason_code="genesis_absent")
        if scope.context_ref != context_ref:
            return _unchanged(original, state="blocked", reason_code="scope_context_mismatch")

        selected_profile_id = scope.current_profile_id
        selected_profile_digest = scope.current_profile_digest
        if profile_selection is not None:
            if profile_selection.scope_revision != scope.scope_revision:
                return _unchanged(
                    original,
                    state="blocked",
                    reason_code="profile_selection_scope_mismatch",
                    profile_id=profile_selection.profile_id,
                    scope_revision=scope.scope_revision,
                )
            selected_profile_id = profile_selection.profile_id
            selected_profile_digest = profile_selection.profile_digest
        profile = reader.get_record(selected_profile_id)
        if profile is None:
            return _unchanged(
                original,
                state="blocked",
                reason_code="profile_missing",
                profile_id=selected_profile_id,
                scope_revision=scope.scope_revision,
            )
        if (
            profile.context_ref != context_ref
            or profile.schema_id != ACTIVATION_PROFILE_SCHEMA_ID
            or profile.record_kind != "activation_profile"
            or profile.content_digest != selected_profile_digest
        ):
            return _unchanged(
                original,
                state="blocked",
                reason_code="profile_invalid",
                profile_id=scope.current_profile_id,
                scope_revision=scope.scope_revision,
            )

        payload = profile.payload
        slots = payload["slots"]
        links = payload["links"]
        if len(slots) != 2 or len(links) != 2:
            raise ValueError("activation profile is not complete")
        expected_slots = ("structured_guidance", "prompt_patch")
        if tuple(slot["slot_kind"] for slot in slots) != expected_slots:
            raise ValueError("activation profile slot order is invalid")

        artifacts: list[TypedRecord] = []
        for slot, link in zip(slots, links, strict=True):
            artifact = reader.get_record(slot["artifact_id"])
            if artifact is None:
                raise ValueError("activation artifact is missing")
            if (
                artifact.record_id != link["target_id"]
                or artifact.content_digest != slot["artifact_digest"]
                or artifact.content_digest != link["target_digest"]
            ):
                raise ValueError("activation artifact identity or digest mismatch")
            artifacts.append(artifact)

        guidance_artifact, prompt_patch_artifact = artifacts
        if (
            prompt_patch_artifact.schema_id != NULL_PROMPT_PATCH_SCHEMA_ID
            or prompt_patch_artifact.payload.get("composition") != "identity"
        ):
            return _unchanged(
                original,
                state="blocked",
                reason_code="artifact_unsupported",
                profile_id=profile.record_id,
                scope_revision=scope.scope_revision,
            )
        if (
            guidance_artifact.schema_id == NULL_GUIDANCE_SCHEMA_ID
            and guidance_artifact.payload.get("behavioral_effect") == "none"
        ):
            return CompositionResult(
                segments=original,
                state="active",
                profile_id=profile.record_id,
                scope_revision=scope.scope_revision,
                reason_codes=("null_profile_identity",),
            )
        if guidance_artifact.schema_id == STRUCTURED_GUIDANCE_SCHEMA_ID:
            rendered = _render_structured_guidance(reader, guidance_artifact)
            return CompositionResult(
                segments=(*original, rendered),
                state="active",
                profile_id=profile.record_id,
                scope_revision=scope.scope_revision,
                reason_codes=(
                    "structured_guidance_applied",
                    GUIDANCE_RENDERER_CONTRACT_ID,
                ),
            )
        if guidance_artifact.schema_id != COMPATIBILITY_GUIDANCE_SCHEMA_ID:
            return _unchanged(
                original,
                state="blocked",
                reason_code="artifact_unsupported",
                profile_id=profile.record_id,
                scope_revision=scope.scope_revision,
            )

        payload = guidance_artifact.payload
        if (
            payload.get("artifact_type") != "compatibility_guidance_set"
            or payload.get("renderer_id") != LEGACY_RENDERER_ID
            or payload.get("selector_id") != LEGACY_SELECTOR_ID
        ):
            raise ValueError("compatibility artifact type is invalid")
        members = payload.get("members")
        if type(members) is not list:
            raise ValueError("compatibility members are invalid")
        selected = [item for item in members if item.get("objective_bucket") == objective_bucket]
        if len(selected) > 1:
            raise ValueError("compatibility objective bucket is ambiguous")
        if not selected:
            return CompositionResult(
                segments=original,
                state="active",
                profile_id=profile.record_id,
                scope_revision=scope.scope_revision,
                reason_codes=("compatibility_bucket_absent",),
            )
        if now is None:
            return _unchanged(
                original,
                state="blocked",
                reason_code="reference_time_unavailable",
                profile_id=profile.record_id,
                scope_revision=scope.scope_revision,
            )
        reference = now
        if reference.tzinfo is None:
            raise ValueError("compatibility reference time has no timezone")
        member = selected[0]
        if not (_legacy_timestamp(member["issued_at"]) <= reference.astimezone(timezone.utc) < _legacy_timestamp(member["expires_at"])):
            return CompositionResult(
                segments=original,
                state="active",
                profile_id=profile.record_id,
                scope_revision=scope.scope_revision,
                reason_codes=("compatibility_bucket_inactive",),
            )
        rendered = _render_compatibility_member(member)
        return CompositionResult(
            segments=(*original, rendered),
            state="active",
            profile_id=profile.record_id,
            scope_revision=scope.scope_revision,
            reason_codes=("compatibility_guidance_applied", LEGACY_RENDERER_ID),
        )
    except Exception:
        return _unchanged(original, state="blocked", reason_code="safe_store_invalid")
