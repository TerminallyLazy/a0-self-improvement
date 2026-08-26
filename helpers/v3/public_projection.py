"""Content-free public status projections for the v3 authority store.

This module deliberately accepts an already-open read-only repository.  It has
no filesystem, framework, clock, cache, migration, repair, or worker imports,
so projecting status cannot become an accidental initialization path.
"""
from __future__ import annotations

import re
from typing import Any, Protocol

from .repository import ActivationScope
from .schemas import TypedRecord


PUBLIC_STATUS_SCHEMA = "a0.public-status.v1"

_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)


class PublicProjectionError(RuntimeError):
    """Raised when authoritative state cannot be safely projected."""


class PublicStatusReader(Protocol):
    def get_activation_scope(self, context_ref: str) -> ActivationScope | None: ...

    def get_record(self, record_id: str) -> TypedRecord | None: ...


def _safe_reference(value: object) -> str:
    if type(value) is not str or _SAFE_REFERENCE.fullmatch(value) is None:
        raise PublicProjectionError("unsafe opaque reference")
    return value


def _safe_context_reference(value: object) -> str:
    """Return a bounded public context handle without reflecting unsafe text."""

    if type(value) is str and _SAFE_REFERENCE.fullmatch(value) is not None:
        return value
    return "redacted"


def _safe_observed_at(value: object) -> str:
    if type(value) is not str or _SAFE_TIMESTAMP.fullmatch(value) is None:
        raise PublicProjectionError("unsafe observation timestamp")
    return value


def _axis(
    state: str,
    *,
    observed_at: str | None = None,
    freshness: str = "not_observed",
    reason_codes: tuple[str, ...] = (),
    **summary: Any,
) -> dict[str, Any]:
    return {
        "state": state,
        "observed_at": observed_at,
        "freshness": freshness,
        "reason_codes": list(reason_codes),
        **summary,
    }


def _inert_axes() -> dict[str, dict[str, Any]]:
    """Return explicit Slice 1 axes without probing unavailable authorities."""

    return {
        "policy": _axis(
            "unavailable", reason_codes=("policy_authority_not_available",)
        ),
        "capabilities": _axis(
            "not_probed", reason_codes=("capabilities_not_probed",)
        ),
        "candidates": _axis("none", reason_codes=("no_candidates",)),
        "canary": _axis("inactive", reason_codes=("no_active_canary",)),
        "monitor": _axis("inactive", reason_codes=("no_active_monitor",)),
        "evidence": _axis(
            "unavailable", reason_codes=("evidence_authority_not_available",)
        ),
        "fixtures": _axis(
            "unavailable", reason_codes=("fixture_authority_not_available",)
        ),
        "migration": _axis(
            "not_observed", reason_codes=("migration_authority_not_probed",)
        ),
        "recent_receipts": _axis("none", reason_codes=("no_recent_receipts",)),
    }


def _base_status(
    *,
    context_ref: str,
    plugin_state: str,
    activation_scope: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": PUBLIC_STATUS_SCHEMA,
        "plugin": "dspy_rlm",
        "context_ref": _safe_context_reference(context_ref),
        "plugin_state": plugin_state,
        "ordinary_runtime_state": "unaffected",
        "activation_scope": activation_scope,
        **_inert_axes(),
    }


def unavailable_public_status(
    *, context_ref: str, enabled: bool, blocked: bool = False
) -> dict[str, Any]:
    """Project a missing or unreadable store without touching the filesystem."""

    if blocked:
        return _base_status(
            context_ref=context_ref,
            plugin_state="blocked" if enabled else "disabled",
            activation_scope=_axis(
                "blocked", reason_codes=("safe_store_unreadable",)
            ),
        )
    return _base_status(
        context_ref=context_ref,
        plugin_state="uninitialized" if enabled else "disabled",
        activation_scope=_axis(
            "uninitialized", reason_codes=("safe_store_missing",)
        ),
    )


def _activation_projection(
    reader: PublicStatusReader, scope: ActivationScope
) -> dict[str, Any]:
    profile_ref = _safe_reference(scope.current_profile_id)
    observed_at = _safe_observed_at(scope.updated_at)
    if type(scope.scope_revision) is not int or scope.scope_revision < 0:
        raise PublicProjectionError("invalid activation revision")
    if scope.mode not in {"normal", "safety_bypass"}:
        raise PublicProjectionError("invalid activation mode")

    profile = reader.get_record(profile_ref)
    if profile is None or profile.record_kind != "activation_profile":
        raise PublicProjectionError("activation profile is unavailable")
    payload = profile.payload
    raw_slots = payload.get("slots")
    if type(raw_slots) is not list or len(raw_slots) != 2:
        raise PublicProjectionError("activation profile slots are incomplete")

    expected_kinds = ("structured_guidance", "prompt_patch")
    expected_records = ("guidance_artifact", "prompt_patch_artifact")
    slots: list[dict[str, str]] = []
    for index, (slot_kind, record_kind) in enumerate(
        zip(expected_kinds, expected_records, strict=True)
    ):
        slot = raw_slots[index]
        if type(slot) is not dict or slot.get("slot_kind") != slot_kind:
            raise PublicProjectionError("activation profile slot kind is invalid")
        artifact_ref = _safe_reference(slot.get("artifact_id"))
        artifact = reader.get_record(artifact_ref)
        if artifact is None or artifact.record_kind != record_kind:
            raise PublicProjectionError("activation artifact is unavailable")
        if slot.get("artifact_digest") != artifact.content_digest:
            raise PublicProjectionError("activation artifact identity is invalid")
        slots.append(
            {
                "slot_kind": slot_kind,
                "artifact_ref": artifact_ref,
                "state": "active",
            }
        )

    return _axis(
        "safety_bypass" if scope.mode == "safety_bypass" else "active",
        observed_at=observed_at,
        freshness="current",
        profile_ref=profile_ref,
        scope_revision=scope.scope_revision,
        mode=scope.mode,
        rollback_eligibility="not_evaluated",
        slots=slots,
    )


def project_public_status(
    *, context_ref: str, enabled: bool, reader: PublicStatusReader
) -> dict[str, Any]:
    """Build the strict public projection from a side-effect-free reader."""

    scope = reader.get_activation_scope(context_ref)
    if scope is None:
        return _base_status(
            context_ref=context_ref,
            plugin_state="uninitialized" if enabled else "disabled",
            activation_scope=_axis(
                "uninitialized", reason_codes=("activation_scope_missing",)
            ),
        )
    return _base_status(
        context_ref=context_ref,
        plugin_state="ready" if enabled else "disabled",
        activation_scope=_activation_projection(reader, scope),
    )
