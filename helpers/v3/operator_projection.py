"""Pure, content-free projections for the six v3 operator views.

The reader protocol deliberately returns immutable snapshot facts.  A repository
adapter owns joins and authority interpretation; this module only validates and
serializes those facts.  It performs no I/O, clock reads, fallback, repair, or
worker activity.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol


OVERVIEW_SCHEMA = "a0.operator-overview.v1"
CANDIDATES_SCHEMA = "a0.operator-candidates.v1"
EVIDENCE_FIXTURES_SCHEMA = "a0.operator-evidence-fixtures.v1"
PRIVACY_MIGRATION_SCHEMA = "a0.operator-privacy-migration.v1"
POLICY_CAPABILITIES_SCHEMA = "a0.operator-policy-capabilities.v1"
RECEIPTS_AUDIT_SCHEMA = "a0.operator-receipts-audit.v1"

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)

_AXIS_STATES = frozenset(
    {
        "active",
        "blocked",
        "cancelled",
        "completed",
        "corrupt",
        "current",
        "degraded",
        "disabled",
        "eligible",
        "expired",
        "failed",
        "inactive",
        "ineligible",
        "inconclusive",
        "leased",
        "missing",
        "not_observed",
        "not_probed",
        "pending",
        "passed",
        "promotion_ready",
        "queued",
        "ready",
        "rejected",
        "review_only",
        "revoked",
        "stale",
        "stopped",
        "unavailable",
        "unsupported",
        "withdrawn",
    }
)
_FRESHNESS_STATES = frozenset(
    {"current", "stale", "not_observed", "unavailable", "unknown"}
)
_CAPABILITY_STATES = frozenset(
    {"not_probed", "ready", "degraded", "blocked", "unavailable", "unsupported"}
)
_DISPOSITIONS = frozenset({"promotion_ready", "review_only", "rejected", "none"})
_CANARY_KINDS = frozenset({"authoritative", "diagnostic", "none"})
_AUTHORITY_CEILINGS = frozenset(
    {
        "activation_authority",
        "no_promotion_authority",
        "candidate_publication",
        "artifact_only",
        "factual_typed_reduction",
        "search_only",
        "none",
    }
)
_GRANT_AUTHORITY_CEILINGS = frozenset(
    {
        "operator_mutation",
        "fixture_authoring",
        "fixture_review",
        "fixture_replay",
        "model_analysis",
        "candidate_search",
        "policy_calibration",
        "diagnostic_canary",
        "migration",
        "quarantine_export",
        "quarantine_deletion",
        "quarantine_release",
        "none",
    }
)
_CHANGE_KINDS = frozenset({"structured_guidance", "prompt_patch"})
_TARGET_SLOTS = frozenset({"structured_guidance", "prompt_patch"})
_RISK_TIERS = frozenset({"low", "moderate", "high", "critical", "not_assessed"})
_BENEFIT_STATES = frozenset(
    {"declared", "supported", "unsupported", "unavailable", "not_assessed"}
)
_CALIBRATION_STATES = frozenset(
    {"approved", "uncalibrated", "withdrawn", "expired", "unavailable"}
)
_ACTIVATION_MODES = frozenset({"manual_only", "auto_after_canary", "unavailable"})
_AUTOMATIC_AUTHORITY_STATES = frozenset(
    {"authorized", "not_authorized", "unavailable"}
)
_SLOT_KINDS = frozenset(
    {"structured_guidance", "prompt_patch", "canary", "monitor", "requalification"}
)
_MIGRATION_PHASES = frozenset(
    {
        "preflight",
        "workers_stopped",
        "snapshot_verified",
        "staging_created",
        "projecting",
        "projection_verified",
        "awaiting_cutover",
        "cutover_committed",
        "completed",
        "not_started",
        "unavailable",
    }
)
_RECEIPT_CATEGORIES = frozenset(
    {"mutation", "activation", "canary", "fixture", "migration", "privacy", "withdrawal"}
)


class OperatorProjectionError(ValueError):
    """Raised when a snapshot cannot be exposed through the public contract."""


def _token(value: object, field: str) -> str:
    if type(value) is not str or _SAFE_TOKEN.fullmatch(value) is None:
        raise OperatorProjectionError(f"{field} is not a safe identifier")
    return value


def _enum(value: object, allowed: frozenset[str], field: str) -> str:
    if type(value) is not str or value not in allowed:
        raise OperatorProjectionError(f"{field} is not allowlisted")
    return value


def _optional_ref(value: str | None, field: str) -> str | None:
    return None if value is None else _token(value, field)


def _timestamp(value: object, field: str) -> str:
    if type(value) is not str or _SAFE_TIMESTAMP.fullmatch(value) is None:
        raise OperatorProjectionError(f"{field} is not a safe timestamp")
    return value


def _count(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise OperatorProjectionError(f"{field} must be a non-negative integer")
    return value


def _boolean(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise OperatorProjectionError(f"{field} must be a boolean")
    return value


def _codes(values: tuple[str, ...], field: str) -> list[str]:
    if type(values) is not tuple or len(values) > 32:
        raise OperatorProjectionError(f"{field} must be a bounded tuple")
    result = [_token(value, field) for value in values]
    if len(set(result)) != len(result):
        raise OperatorProjectionError(f"{field} contains duplicates")
    return result


@dataclass(frozen=True)
class Axis:
    state: str
    observed_at: str | None
    freshness: str
    reason_codes: tuple[str, ...] = ()


def _axis(value: Axis, field: str) -> dict[str, object]:
    if type(value) is not Axis:
        raise OperatorProjectionError(f"{field} axis is required")
    state = _enum(value.state, _AXIS_STATES, f"{field}.state")
    freshness = _enum(value.freshness, _FRESHNESS_STATES, f"{field}.freshness")
    observed_at = (
        None
        if value.observed_at is None
        else _timestamp(value.observed_at, f"{field}.observed_at")
    )
    if observed_at is None and freshness not in {"not_observed", "unavailable", "unknown"}:
        raise OperatorProjectionError(f"{field} lacks an observation timestamp")
    return {
        "state": state,
        "observed_at": observed_at,
        "freshness": freshness,
        "reason_codes": _codes(value.reason_codes, f"{field}.reason_codes"),
    }


@dataclass(frozen=True)
class SlotSummary:
    slot_kind: str
    state: str
    occupant_ref: str | None


def _slot(value: SlotSummary, field: str) -> dict[str, object]:
    return {
        "slot_kind": _enum(value.slot_kind, _SLOT_KINDS, f"{field}.slot_kind"),
        "state": _enum(value.state, _AXIS_STATES, f"{field}.state"),
        "occupant_ref": _optional_ref(value.occupant_ref, f"{field}.occupant_ref"),
    }


@dataclass(frozen=True)
class CapabilitySummary:
    capability_id: str
    semantic_id: str
    state: str
    reason_codes: tuple[str, ...] = ()


def _capability(value: CapabilitySummary, field: str) -> dict[str, object]:
    return {
        "capability_id": _token(value.capability_id, f"{field}.capability_id"),
        "semantic_id": _token(value.semantic_id, f"{field}.semantic_id"),
        "state": _enum(value.state, _CAPABILITY_STATES, f"{field}.state"),
        "reason_codes": _codes(value.reason_codes, f"{field}.reason_codes"),
    }


@dataclass(frozen=True)
class ActionSummary:
    action: str
    state: str
    reason_codes: tuple[str, ...] = ()


def _action(value: ActionSummary, field: str) -> dict[str, object]:
    return {
        "action": _token(value.action, f"{field}.action"),
        "state": _enum(value.state, _AXIS_STATES, f"{field}.state"),
        "reason_codes": _codes(value.reason_codes, f"{field}.reason_codes"),
    }


@dataclass(frozen=True)
class OverviewSnapshot:
    ordinary_runtime: Axis
    improvement: Axis
    migration_cutover: Axis
    activation: Axis
    activation_profile_ref: str | None
    scope_revision: int | None
    safety_bypass_state: str
    rollback_eligibility: str
    slots: tuple[SlotSummary, ...]
    capabilities_axis: Axis
    capabilities: tuple[CapabilitySummary, ...]
    attention_actions: tuple[ActionSummary, ...]


@dataclass(frozen=True)
class BucketSummary:
    bucket_id: str
    axis: Axis
    required_count: int
    eligible_count: int
    outcome_state: str


def _bucket(value: BucketSummary, field: str) -> dict[str, object]:
    result = _axis(value.axis, field)
    result.update(
        {
            "bucket_id": _token(value.bucket_id, f"{field}.bucket_id"),
            "required_count": _count(value.required_count, f"{field}.required_count"),
            "eligible_count": _count(value.eligible_count, f"{field}.eligible_count"),
            "outcome_state": _token(value.outcome_state, f"{field}.outcome_state"),
        }
    )
    return result


@dataclass(frozen=True)
class CanarySummary:
    axis: Axis
    canary_kind: str
    authority_ceiling: str
    conclusion_ref: str | None
    activation_authoritative: bool


def _canary(value: CanarySummary, field: str) -> dict[str, object]:
    result = _axis(value.axis, field)
    kind = _enum(value.canary_kind, _CANARY_KINDS, f"{field}.canary_kind")
    ceiling = _enum(
        value.authority_ceiling, _AUTHORITY_CEILINGS, f"{field}.authority_ceiling"
    )
    authoritative = _boolean(
        value.activation_authoritative, f"{field}.activation_authoritative"
    )
    if kind == "diagnostic" and (ceiling != "no_promotion_authority" or authoritative):
        raise OperatorProjectionError("diagnostic canary cannot have activation authority")
    if kind == "authoritative" and ceiling != "activation_authority":
        raise OperatorProjectionError("authoritative canary lacks its declared ceiling")
    if kind == "none" and (
        ceiling != "none" or value.conclusion_ref is not None or authoritative
    ):
        raise OperatorProjectionError("inactive canary carries authority")
    if authoritative and (kind != "authoritative" or ceiling != "activation_authority"):
        raise OperatorProjectionError("activation authority is inconsistent")
    result.update(
        {
            "canary_kind": kind,
            "authority_ceiling": ceiling,
            "conclusion_ref": _optional_ref(
                value.conclusion_ref, f"{field}.conclusion_ref"
            ),
            "activation_authoritative": authoritative,
        }
    )
    return result


@dataclass(frozen=True)
class CandidateSummary:
    axis: Axis
    candidate_ref: str
    artifact_ref: str
    change_kind: str
    target_slot: str
    engine_semantic_id: str
    authority_ceiling: str
    benefit_claim: str
    benefit_state: str
    risk_tier: str
    incumbent_profile_ref: str
    successor_profile_ref: str | None
    observed_scope_revision: int
    lineage: Axis
    disposition_axis: Axis
    disposition: str
    monitor: Axis
    monitor_receipt_refs: tuple[str, ...]
    changed_component_count: int
    protected_constraint_state: str
    rule_catalog_ids: tuple[str, ...]
    evidence_buckets: tuple[BucketSummary, ...]
    canary: CanarySummary
    diagnostic_labels: tuple[str, ...]
    diagnostic_reason_codes: tuple[str, ...]
    allowed_actions: tuple[ActionSummary, ...]


@dataclass(frozen=True)
class CandidatesSnapshot:
    axis: Axis
    candidates: tuple[CandidateSummary, ...]
    disposition_counts: tuple[tuple[str, int], ...]
    attention_count: int


def _candidate(value: CandidateSummary, field: str) -> dict[str, object]:
    result = _axis(value.axis, field)
    result.update(
        {
            "candidate_ref": _token(value.candidate_ref, f"{field}.candidate_ref"),
            "artifact_ref": _token(value.artifact_ref, f"{field}.artifact_ref"),
            "change_kind": _enum(value.change_kind, _CHANGE_KINDS, f"{field}.change_kind"),
            "target_slot": _enum(value.target_slot, _TARGET_SLOTS, f"{field}.target_slot"),
            "engine_semantic_id": _token(
                value.engine_semantic_id, f"{field}.engine_semantic_id"
            ),
            "authority_ceiling": _enum(
                value.authority_ceiling,
                _AUTHORITY_CEILINGS,
                f"{field}.authority_ceiling",
            ),
            "benefit_claim": _token(value.benefit_claim, f"{field}.benefit_claim"),
            "benefit_state": _enum(
                value.benefit_state, _BENEFIT_STATES, f"{field}.benefit_state"
            ),
            "risk_tier": _enum(value.risk_tier, _RISK_TIERS, f"{field}.risk_tier"),
            "incumbent_profile_ref": _token(
                value.incumbent_profile_ref, f"{field}.incumbent_profile_ref"
            ),
            "successor_profile_ref": _optional_ref(
                value.successor_profile_ref, f"{field}.successor_profile_ref"
            ),
            "observed_scope_revision": _count(
                value.observed_scope_revision, f"{field}.observed_scope_revision"
            ),
            "lineage": _axis(value.lineage, f"{field}.lineage"),
            "disposition": {
                **_axis(value.disposition_axis, f"{field}.disposition"),
                "value": _enum(
                    value.disposition, _DISPOSITIONS, f"{field}.disposition.value"
                ),
            },
            "monitor": {
                **_axis(value.monitor, f"{field}.monitor"),
                "receipt_refs": [
                    _token(item, f"{field}.monitor.receipt_refs")
                    for item in value.monitor_receipt_refs
                ],
            },
            "changed_component_count": _count(
                value.changed_component_count, f"{field}.changed_component_count"
            ),
            "protected_constraint_state": _token(
                value.protected_constraint_state, f"{field}.protected_constraint_state"
            ),
            "rule_catalog_ids": [
                _token(item, f"{field}.rule_catalog_ids") for item in value.rule_catalog_ids
            ],
            "evidence_buckets": [
                _bucket(item, f"{field}.evidence_buckets[{index}]")
                for index, item in enumerate(value.evidence_buckets)
            ],
            "canary": _canary(value.canary, f"{field}.canary"),
            "diagnostic": {
                "authority_ceiling": "no_promotion_authority",
                "labels": [
                    _token(item, f"{field}.diagnostic_labels")
                    for item in value.diagnostic_labels
                ],
                "reason_codes": _codes(
                    value.diagnostic_reason_codes, f"{field}.diagnostic_reason_codes"
                ),
            },
            "allowed_actions": [
                _action(item, f"{field}.allowed_actions[{index}]")
                for index, item in enumerate(value.allowed_actions)
            ],
        }
    )
    return result


@dataclass(frozen=True)
class FixtureFamilySummary:
    family_ref: str
    axis: Axis
    eligibility_state: str
    training_count: int
    tuning_count: int
    certification_holdout_count: int
    grant_state: str


def _fixture_family(value: FixtureFamilySummary, field: str) -> dict[str, object]:
    result = _axis(value.axis, field)
    result.update(
        {
            "family_ref": _token(value.family_ref, f"{field}.family_ref"),
            "eligibility_state": _enum(
                value.eligibility_state, _AXIS_STATES, f"{field}.eligibility_state"
            ),
            "partition_counts": {
                "training": _count(value.training_count, f"{field}.training_count"),
                "tuning": _count(value.tuning_count, f"{field}.tuning_count"),
                "certification_holdout": _count(
                    value.certification_holdout_count,
                    f"{field}.certification_holdout_count",
                ),
            },
            "grant_state": _enum(value.grant_state, _AXIS_STATES, f"{field}.grant_state"),
        }
    )
    return result


@dataclass(frozen=True)
class EvidenceFixturesSnapshot:
    evidence: Axis
    evidence_buckets: tuple[BucketSummary, ...]
    fixtures: Axis
    families: tuple[FixtureFamilySummary, ...]
    draft_count: int
    review_pending_count: int
    admitted_count: int
    withdrawn_count: int


@dataclass(frozen=True)
class PrivacyOperationSummary:
    operation_ref: str
    operation_kind: str
    axis: Axis
    challenge_ref: str | None
    receipt_refs: tuple[str, ...]
    instruction_code: str


def _privacy_operation(value: PrivacyOperationSummary, field: str) -> dict[str, object]:
    result = _axis(value.axis, field)
    result.update(
        {
            "operation_ref": _token(value.operation_ref, f"{field}.operation_ref"),
            "operation_kind": _token(value.operation_kind, f"{field}.operation_kind"),
            "challenge_ref": _optional_ref(value.challenge_ref, f"{field}.challenge_ref"),
            "receipt_refs": [
                _token(item, f"{field}.receipt_refs") for item in value.receipt_refs
            ],
            "instruction_code": _token(
                value.instruction_code, f"{field}.instruction_code"
            ),
            "execution_surface": "local_cli_only",
        }
    )
    return result


@dataclass(frozen=True)
class PrivacyMigrationSnapshot:
    privacy: Axis
    migration: Axis
    migration_ref: str | None
    migration_phase: str
    checkpoint_count: int
    disposition_counts: tuple[tuple[str, int], ...]
    key_custody_state: str
    cutover_readiness: str
    recovery_state: str
    operations: tuple[PrivacyOperationSummary, ...]


@dataclass(frozen=True)
class GrantSummary:
    grant_ref: str
    grant_kind: str
    state: str
    authority_ceiling: str
    expiry_state: str


def _grant(value: GrantSummary, field: str) -> dict[str, object]:
    return {
        "grant_ref": _token(value.grant_ref, f"{field}.grant_ref"),
        "grant_kind": _token(value.grant_kind, f"{field}.grant_kind"),
        "state": _enum(value.state, _AXIS_STATES, f"{field}.state"),
        "authority_ceiling": _enum(
            value.authority_ceiling,
            _GRANT_AUTHORITY_CEILINGS,
            f"{field}.authority_ceiling",
        ),
        "expiry_state": _enum(value.expiry_state, _AXIS_STATES, f"{field}.expiry_state"),
    }


@dataclass(frozen=True)
class BudgetSummary:
    budget_id: str
    state: str
    limit_units: int
    reserved_units: int
    consumed_units: int


def _budget(value: BudgetSummary, field: str) -> dict[str, object]:
    return {
        "budget_id": _token(value.budget_id, f"{field}.budget_id"),
        "state": _enum(value.state, _AXIS_STATES, f"{field}.state"),
        "limit_units": _count(value.limit_units, f"{field}.limit_units"),
        "reserved_units": _count(value.reserved_units, f"{field}.reserved_units"),
        "consumed_units": _count(value.consumed_units, f"{field}.consumed_units"),
    }


@dataclass(frozen=True)
class PolicyCapabilitiesSnapshot:
    policy: Axis
    policy_ref: str | None
    calibration_state: str
    activation_mode: str
    automatic_authority_state: str
    capabilities: Axis
    capability_items: tuple[CapabilitySummary, ...]
    dependency_profile_ref: str | None
    dependency_state: str
    grants: Axis
    grant_items: tuple[GrantSummary, ...]
    budgets: Axis
    budget_items: tuple[BudgetSummary, ...]
    local_step_up_instruction_code: str


@dataclass(frozen=True)
class ReceiptSummary:
    sequence: int
    receipt_ref: str
    category: str
    action: str
    state: str
    observed_at: str
    related_receipt_refs: tuple[str, ...]


def _receipt(value: ReceiptSummary, field: str) -> dict[str, object]:
    return {
        "sequence": _count(value.sequence, f"{field}.sequence"),
        "receipt_ref": _token(value.receipt_ref, f"{field}.receipt_ref"),
        "category": _enum(value.category, _RECEIPT_CATEGORIES, f"{field}.category"),
        "action": _token(value.action, f"{field}.action"),
        "state": _enum(value.state, _AXIS_STATES, f"{field}.state"),
        "observed_at": _timestamp(value.observed_at, f"{field}.observed_at"),
        "related_receipt_refs": [
            _token(item, f"{field}.related_receipt_refs")
            for item in value.related_receipt_refs
        ],
    }


@dataclass(frozen=True)
class ReceiptsAuditSnapshot:
    receipts: Axis
    items: tuple[ReceiptSummary, ...]
    category_counts: tuple[tuple[str, int], ...]


class OperatorProjectionReader(Protocol):
    """Read-only adapter boundary for already-open authoritative stores."""

    def read_overview(self, context_ref: str) -> OverviewSnapshot: ...

    def read_candidates(self, context_ref: str) -> CandidatesSnapshot: ...

    def read_evidence_fixtures(self, context_ref: str) -> EvidenceFixturesSnapshot: ...

    def read_privacy_migration(self, context_ref: str) -> PrivacyMigrationSnapshot: ...

    def read_policy_capabilities(self, context_ref: str) -> PolicyCapabilitiesSnapshot: ...

    def read_receipts_audit(self, context_ref: str) -> ReceiptsAuditSnapshot: ...


def _base(schema: str, view: str, context_ref: str) -> dict[str, object]:
    return {
        "schema": schema,
        "view": view,
        "context_ref": _token(context_ref, "context_ref"),
    }


def _pairs(
    values: tuple[tuple[str, int], ...],
    *,
    field: str,
    allowed: frozenset[str] | None = None,
) -> dict[str, int]:
    if type(values) is not tuple:
        raise OperatorProjectionError(f"{field} must be a tuple")
    result: dict[str, int] = {}
    for key, value in values:
        safe_key = _token(key, field)
        if allowed is not None:
            _enum(safe_key, allowed, field)
        if safe_key in result:
            raise OperatorProjectionError(f"{field} contains duplicate keys")
        result[safe_key] = _count(value, field)
    return result


def project_overview(reader: OperatorProjectionReader, context_ref: str) -> dict[str, object]:
    snapshot = reader.read_overview(context_ref)
    result = _base(OVERVIEW_SCHEMA, "overview", context_ref)
    result.update(
        {
            "ordinary_runtime": _axis(snapshot.ordinary_runtime, "ordinary_runtime"),
            "improvement": _axis(snapshot.improvement, "improvement"),
            "migration_cutover": _axis(
                snapshot.migration_cutover, "migration_cutover"
            ),
            "activation": {
                **_axis(snapshot.activation, "activation"),
                "profile_ref": _optional_ref(
                    snapshot.activation_profile_ref, "activation.profile_ref"
                ),
                "scope_revision": (
                    None
                    if snapshot.scope_revision is None
                    else _count(snapshot.scope_revision, "activation.scope_revision")
                ),
                "safety_bypass_state": _enum(
                    snapshot.safety_bypass_state,
                    _AXIS_STATES,
                    "activation.safety_bypass_state",
                ),
                "rollback_eligibility": _enum(
                    snapshot.rollback_eligibility,
                    _AXIS_STATES,
                    "activation.rollback_eligibility",
                ),
                "slots": [
                    _slot(item, f"activation.slots[{index}]")
                    for index, item in enumerate(snapshot.slots)
                ],
            },
            "capabilities": {
                **_axis(snapshot.capabilities_axis, "capabilities"),
                "items": [
                    _capability(item, f"capabilities.items[{index}]")
                    for index, item in enumerate(snapshot.capabilities)
                ],
            },
            "attention_actions": [
                _action(item, f"attention_actions[{index}]")
                for index, item in enumerate(snapshot.attention_actions)
            ],
        }
    )
    return result


def project_candidates(reader: OperatorProjectionReader, context_ref: str) -> dict[str, object]:
    snapshot = reader.read_candidates(context_ref)
    result = _base(CANDIDATES_SCHEMA, "candidates", context_ref)
    result.update(
        {
            "axis": _axis(snapshot.axis, "candidates"),
            "disposition_counts": _pairs(
                snapshot.disposition_counts,
                field="disposition_counts",
                allowed=_DISPOSITIONS,
            ),
            "attention_count": _count(snapshot.attention_count, "attention_count"),
            "items": [
                _candidate(item, f"candidates[{index}]")
                for index, item in enumerate(snapshot.candidates)
            ],
        }
    )
    return result


def project_evidence_fixtures(
    reader: OperatorProjectionReader, context_ref: str
) -> dict[str, object]:
    snapshot = reader.read_evidence_fixtures(context_ref)
    result = _base(EVIDENCE_FIXTURES_SCHEMA, "evidence_fixtures", context_ref)
    result.update(
        {
            "evidence": {
                **_axis(snapshot.evidence, "evidence"),
                "buckets": [
                    _bucket(item, f"evidence.buckets[{index}]")
                    for index, item in enumerate(snapshot.evidence_buckets)
                ],
            },
            "fixtures": {
                **_axis(snapshot.fixtures, "fixtures"),
                "workflow_counts": {
                    "draft": _count(snapshot.draft_count, "fixtures.draft_count"),
                    "review_pending": _count(
                        snapshot.review_pending_count, "fixtures.review_pending_count"
                    ),
                    "admitted": _count(
                        snapshot.admitted_count, "fixtures.admitted_count"
                    ),
                    "withdrawn": _count(
                        snapshot.withdrawn_count, "fixtures.withdrawn_count"
                    ),
                },
                "families": [
                    _fixture_family(item, f"fixtures.families[{index}]")
                    for index, item in enumerate(snapshot.families)
                ],
            },
        }
    )
    return result


def project_privacy_migration(
    reader: OperatorProjectionReader, context_ref: str
) -> dict[str, object]:
    snapshot = reader.read_privacy_migration(context_ref)
    result = _base(PRIVACY_MIGRATION_SCHEMA, "privacy_migration", context_ref)
    result.update(
        {
            "privacy": _axis(snapshot.privacy, "privacy"),
            "migration": {
                **_axis(snapshot.migration, "migration"),
                "migration_ref": _optional_ref(
                    snapshot.migration_ref, "migration.migration_ref"
                ),
                "phase": _enum(snapshot.migration_phase, _MIGRATION_PHASES, "migration.phase"),
                "checkpoint_count": _count(
                    snapshot.checkpoint_count, "migration.checkpoint_count"
                ),
                "disposition_counts": _pairs(
                    snapshot.disposition_counts, field="migration.disposition_counts"
                ),
                "key_custody_state": _enum(
                    snapshot.key_custody_state, _AXIS_STATES, "migration.key_custody_state"
                ),
                "cutover_readiness": _enum(
                    snapshot.cutover_readiness, _AXIS_STATES, "migration.cutover_readiness"
                ),
                "recovery_state": _enum(
                    snapshot.recovery_state, _AXIS_STATES, "migration.recovery_state"
                ),
            },
            "operations": [
                _privacy_operation(item, f"operations[{index}]")
                for index, item in enumerate(snapshot.operations)
            ],
        }
    )
    return result


def project_policy_capabilities(
    reader: OperatorProjectionReader, context_ref: str
) -> dict[str, object]:
    snapshot = reader.read_policy_capabilities(context_ref)
    result = _base(POLICY_CAPABILITIES_SCHEMA, "policy_capabilities", context_ref)
    result.update(
        {
            "policy": {
                **_axis(snapshot.policy, "policy"),
                "policy_ref": _optional_ref(snapshot.policy_ref, "policy.policy_ref"),
                "calibration_state": _enum(
                    snapshot.calibration_state,
                    _CALIBRATION_STATES,
                    "policy.calibration_state",
                ),
                "activation_mode": _enum(
                    snapshot.activation_mode, _ACTIVATION_MODES, "policy.activation_mode"
                ),
                "automatic_authority_state": _enum(
                    snapshot.automatic_authority_state,
                    _AUTOMATIC_AUTHORITY_STATES,
                    "policy.automatic_authority_state",
                ),
            },
            "capabilities": {
                **_axis(snapshot.capabilities, "capabilities"),
                "items": [
                    _capability(item, f"capabilities.items[{index}]")
                    for index, item in enumerate(snapshot.capability_items)
                ],
                "dependency_profile_ref": _optional_ref(
                    snapshot.dependency_profile_ref,
                    "capabilities.dependency_profile_ref",
                ),
                "dependency_state": _enum(
                    snapshot.dependency_state,
                    _CAPABILITY_STATES,
                    "capabilities.dependency_state",
                ),
            },
            "grants": {
                **_axis(snapshot.grants, "grants"),
                "items": [
                    _grant(item, f"grants.items[{index}]")
                    for index, item in enumerate(snapshot.grant_items)
                ],
            },
            "budgets": {
                **_axis(snapshot.budgets, "budgets"),
                "items": [
                    _budget(item, f"budgets.items[{index}]")
                    for index, item in enumerate(snapshot.budget_items)
                ],
            },
            "local_step_up_instruction_code": _token(
                snapshot.local_step_up_instruction_code,
                "local_step_up_instruction_code",
            ),
        }
    )
    return result


def project_receipts_audit(
    reader: OperatorProjectionReader, context_ref: str
) -> dict[str, object]:
    snapshot = reader.read_receipts_audit(context_ref)
    result = _base(RECEIPTS_AUDIT_SCHEMA, "receipts_audit", context_ref)
    if len({item.sequence for item in snapshot.items}) != len(snapshot.items):
        raise OperatorProjectionError("receipt sequence is ambiguous")
    ordered = sorted(snapshot.items, key=lambda item: item.sequence, reverse=True)
    result.update(
        {
            "receipts": _axis(snapshot.receipts, "receipts"),
            "category_counts": _pairs(
                snapshot.category_counts,
                field="category_counts",
                allowed=_RECEIPT_CATEGORIES,
            ),
            "items": [
                _receipt(item, f"receipts.items[{index}]")
                for index, item in enumerate(ordered)
            ],
        }
    )
    return result
