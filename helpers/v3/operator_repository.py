"""Read-only repository facts adapter for the public operator projections.

This module deliberately does not know how to open a database.  Its caller owns
an already-open, read-only facts interface and supplies observation timestamps.
The adapter performs content-free joins over strict typed records and returns
only the dataclasses accepted by :mod:`operator_projection`.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Protocol

from .operator_projection import (
    ActionSummary,
    Axis,
    BucketSummary,
    CanarySummary,
    CandidateSummary,
    CandidatesSnapshot,
    CapabilitySummary,
    EvidenceFixturesSnapshot,
    FixtureFamilySummary,
    OverviewSnapshot,
    PolicyCapabilitiesSnapshot,
    PrivacyMigrationSnapshot,
    ReceiptSummary,
    ReceiptsAuditSnapshot,
    SlotSummary,
)
from .repository import (
    ActivationScope,
    DomainEvent,
    OperationSlot,
    OperatorCommand,
    V3Reader,
)
from .schemas import TypedRecord


_PUBLIC_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_RECEIPT_CATEGORIES = {
    "activation_receipt": "activation",
    "activation_transition_receipt": "activation",
    "operator_mutation_receipt": "mutation",
    "feedback_mutation_receipt": "mutation",
    "policy_calibration_mutation_receipt": "mutation",
    "fixture_command_mutation_receipt": "fixture",
    "canary_mutation_receipt": "canary",
    "replay_pair_receipt": "fixture",
    "closed_loop_step_receipt": "mutation",
    "closed_loop_runner_receipt": "mutation",
    "canary_exposure_receipt": "canary",
    "canary_conclusion": "canary",
    "canary_conclusion_receipt": "canary",
    "canary_outcome_reduction_receipt": "canary",
    "observation_bridge_receipt": "mutation",
    "post_activation_mutation_receipt": "mutation",
    "fixture_admission_receipt": "fixture",
    "fixture_eligibility_event": "withdrawal",
    "migration_receipt": "migration",
}


@dataclass(frozen=True, slots=True)
class ObservedRecord:
    record: TypedRecord
    observed_at: str


@dataclass(frozen=True, slots=True)
class ObservedDomainEvent:
    event: DomainEvent
    observed_at: str


@dataclass(frozen=True, slots=True)
class ObservedOperatorCommand:
    command: OperatorCommand
    observed_at: str


class OperatorFactsReader(Protocol):
    """Narrow enumeration contract implemented around an already-open reader.

    Implementations must return records that were already verified by the
    active schema registry.  They must not repair, migrate, or fall back to a
    legacy store while satisfying these calls.
    """

    def get_activation_scope(self, context_ref: str) -> ActivationScope | None: ...

    def get_operation_slot(
        self, context_ref: str, operation_kind: str
    ) -> OperationSlot | None: ...

    def get_record(self, record_id: str) -> TypedRecord | None: ...

    def list_records(self, context_ref: str) -> tuple[ObservedRecord, ...]: ...

    def list_domain_events(
        self, context_ref: str
    ) -> tuple[ObservedDomainEvent, ...]: ...

    def list_operator_commands(
        self, context_ref: str
    ) -> tuple[ObservedOperatorCommand, ...]: ...


class SafeStoreOperatorReader:
    """Concrete facts interface over one already-open immutable ``V3Reader``.

    Each enumeration first reads the exact current context count and supplies it
    as the repository query bound.  This avoids an unsupported product-level
    page-size default while retaining a fail-closed bounded query contract.
    """

    def __init__(self, reader: V3Reader) -> None:
        if not isinstance(reader, V3Reader):
            raise TypeError("reader must be an already-open V3Reader")
        if not reader.query_only:
            raise ValueError("reader must enforce SQLite query_only")
        self._reader = reader

    def get_activation_scope(self, context_ref: str) -> ActivationScope | None:
        return self._reader.get_activation_scope(context_ref)

    def get_operation_slot(
        self, context_ref: str, operation_kind: str
    ) -> OperationSlot | None:
        if operation_kind not in {"canary", "monitor", "requalification"}:
            raise ValueError("operation_kind is not admitted")
        return self._reader.get_operation_slot(context_ref, operation_kind)

    def get_record(self, record_id: str) -> TypedRecord | None:
        return self._reader.get_record(record_id)

    def list_records(self, context_ref: str) -> tuple[ObservedRecord, ...]:
        maximum = self._reader.count_records_for_context(context_ref)
        return tuple(
            ObservedRecord(item.record, item.created_at)
            for item in self._reader.list_records_for_context(
                context_ref, maximum=maximum
            )
        )

    def list_domain_events(
        self, context_ref: str
    ) -> tuple[ObservedDomainEvent, ...]:
        maximum = self._reader.count_domain_events_for_context(context_ref)
        return tuple(
            ObservedDomainEvent(item.event, item.created_at)
            for item in self._reader.list_domain_events_for_context(
                context_ref, maximum=maximum
            )
        )

    def list_operator_commands(
        self, context_ref: str
    ) -> tuple[ObservedOperatorCommand, ...]:
        maximum = self._reader.count_operator_commands_for_context(context_ref)
        return tuple(
            ObservedOperatorCommand(item.command, item.created_at)
            for item in self._reader.list_operator_commands_for_context(
                context_ref, maximum=maximum
            )
        )


def _axis(
    state: str,
    observed_at: str | None = None,
    *reasons: str,
    freshness: str | None = None,
) -> Axis:
    if freshness is None:
        freshness = "current" if observed_at is not None else "not_observed"
    return Axis(state, observed_at, freshness, tuple(reasons))


def _unavailable(reason: str) -> Axis:
    return _axis("unavailable", None, reason)


def _not_observed(reason: str) -> Axis:
    return _axis("not_observed", None, reason)


def _public_ref(value: object) -> str | None:
    return value if type(value) is str and _PUBLIC_REF.fullmatch(value) else None


def _safe_codes(values: object) -> tuple[str, ...]:
    if type(values) is not list:
        return ()
    result = tuple(
        value
        for value in values
        if type(value) is str and _PUBLIC_REF.fullmatch(value) is not None
    )
    return tuple(sorted(set(result)))


class OperatorRepositoryAdapter:
    """Content-free implementation of ``OperatorProjectionReader``.

    ``privacy_migration_snapshot`` is an explicit, already-authorized aggregate
    snapshot.  Privacy operation identities are intentionally removed here;
    operators perform those actions only through their separate local command
    surface.
    """

    def __init__(
        self,
        facts: OperatorFactsReader,
        *,
        privacy_migration_snapshot: PrivacyMigrationSnapshot | None = None,
    ) -> None:
        self._facts = facts
        self._privacy_migration = (
            None
            if privacy_migration_snapshot is None
            else replace(privacy_migration_snapshot, operations=())
        )

    def _records(self, context_ref: str) -> tuple[ObservedRecord, ...]:
        return self._facts.list_records(context_ref)

    def read_overview(self, context_ref: str) -> OverviewSnapshot:
        scope = self._facts.get_activation_scope(context_ref)
        privacy_migration = self._privacy_migration
        if scope is None:
            activation = _not_observed("activation_scope_missing")
            improvement = _unavailable("activation_authority_unavailable")
            profile_ref = None
            scope_revision = None
            safety_bypass = "unavailable"
            profile_slots = (
                SlotSummary("structured_guidance", "unavailable", None),
                SlotSummary("prompt_patch", "unavailable", None),
            )
        else:
            activation = _axis("active", scope.updated_at)
            improvement = _axis("active", scope.updated_at)
            profile_ref = _public_ref(scope.current_profile_id)
            scope_revision = scope.scope_revision
            safety_bypass = "active" if scope.mode == "safety_bypass" else "inactive"
            profile_slots = self._profile_slots(scope)

        operation_slots = tuple(
            self._operation_slot(context_ref, kind)
            for kind in ("canary", "monitor", "requalification")
        )
        migration_axis = (
            privacy_migration.migration
            if privacy_migration is not None
            else _not_observed("migration_authority_not_supplied")
        )
        attention = ()
        if scope is None:
            attention = (
                ActionSummary(
                    "inspect_local_authority", "pending", ("activation_scope_missing",)
                ),
            )
        return OverviewSnapshot(
            ordinary_runtime=_unavailable("ordinary_runtime_authority_not_supplied"),
            improvement=improvement,
            migration_cutover=migration_axis,
            activation=activation,
            activation_profile_ref=profile_ref,
            scope_revision=scope_revision,
            safety_bypass_state=safety_bypass,
            rollback_eligibility="unavailable",
            slots=profile_slots + operation_slots,
            capabilities_axis=_unavailable("capability_authority_not_observed"),
            capabilities=(),
            attention_actions=attention,
        )

    def _profile_slots(self, scope: ActivationScope) -> tuple[SlotSummary, ...]:
        profile = self._facts.get_record(scope.current_profile_id)
        if profile is None or profile.record_kind != "activation_profile":
            return (
                SlotSummary("structured_guidance", "unavailable", None),
                SlotSummary("prompt_patch", "unavailable", None),
            )
        payload = profile.payload
        slots = payload.get("slots")
        if type(slots) is not list or len(slots) != 2:
            return (
                SlotSummary("structured_guidance", "corrupt", None),
                SlotSummary("prompt_patch", "corrupt", None),
            )
        result: list[SlotSummary] = []
        for expected, item in zip(("structured_guidance", "prompt_patch"), slots):
            if type(item) is not dict or item.get("slot_kind") != expected:
                result.append(SlotSummary(expected, "corrupt", None))
                continue
            occupant = _public_ref(item.get("artifact_id"))
            result.append(
                SlotSummary(expected, "active" if occupant else "unavailable", occupant)
            )
        return tuple(result)

    def _operation_slot(self, context_ref: str, kind: str) -> SlotSummary:
        slot = self._facts.get_operation_slot(context_ref, kind)
        if slot is None:
            return SlotSummary(kind, "not_observed", None)
        occupant = _public_ref(slot.operation_id)
        return SlotSummary(kind, "active" if occupant else "inactive", occupant)

    def read_candidates(self, context_ref: str) -> CandidatesSnapshot:
        observed = self._records(context_ref)
        candidates = [item for item in observed if item.record.record_kind == "improvement_candidate"]
        summaries = tuple(self._candidate(item, observed) for item in candidates)
        counts = tuple(
            (state, sum(item.disposition == state for item in summaries))
            for state in ("promotion_ready", "review_only", "rejected")
        )
        if not summaries:
            return CandidatesSnapshot(_not_observed("candidates_not_observed"), (), counts, 0)
        return CandidatesSnapshot(
            _axis("active", max(item.observed_at for item in candidates)),
            summaries,
            counts,
            sum(item.disposition != "promotion_ready" for item in summaries),
        )

    def _candidate(
        self, item: ObservedRecord, observed: tuple[ObservedRecord, ...]
    ) -> CandidateSummary:
        record = item.record
        payload = record.payload
        candidate_ref = _public_ref(record.record_id) or "candidate:unavailable"
        artifact_ref = _public_ref(payload.get("artifact_id")) or "artifact:unavailable"
        dispositions = [
            fact
            for fact in observed
            if fact.record.record_kind == "activation_disposition"
            and fact.record.payload.get("candidate_id") == record.record_id
        ]
        disposition_fact = max(dispositions, key=lambda fact: fact.observed_at) if dispositions else None
        disposition = (
            disposition_fact.record.payload.get("disposition", "none")
            if disposition_fact is not None
            else "none"
        )
        if disposition not in {"promotion_ready", "review_only", "rejected"}:
            disposition = "none"
        disposition_axis = (
            _axis(disposition, disposition_fact.observed_at)
            if disposition_fact is not None
            else _not_observed("disposition_not_observed")
        )
        scope = self._facts.get_activation_scope(record.context_ref or "")
        lineage_current = bool(
            scope
            and payload.get("observed_scope_revision") == scope.scope_revision
            and payload.get("incumbent_profile_id") == scope.current_profile_id
        )
        lineage = (
            _axis("current", item.observed_at)
            if lineage_current
            else _axis("stale", item.observed_at, "activation_scope_changed")
        )
        conclusions = [
            fact
            for fact in observed
            if fact.record.record_kind == "canary_conclusion"
            and fact.record.payload.get("candidate_id") == record.record_id
        ]
        conclusion = max(conclusions, key=lambda fact: fact.observed_at) if conclusions else None
        canary = self._canary(conclusion)
        diagnostic = canary.canary_kind == "diagnostic"
        allowed = self._candidate_actions(disposition, lineage_current, canary)
        monitor_records = [
            fact
            for fact in observed
            if fact.record.record_kind == "post_promotion_monitor"
            and fact.record.payload.get("candidate_id") == record.record_id
        ]
        monitor = (
            _axis("active", max(fact.observed_at for fact in monitor_records))
            if monitor_records
            else _not_observed("monitor_not_observed")
        )
        claim = payload.get("benefit_claim")
        claim_ref = claim.get("bucket") if type(claim) is dict else None
        return CandidateSummary(
            axis=_axis(disposition if disposition != "none" else "pending", item.observed_at),
            candidate_ref=candidate_ref,
            artifact_ref=artifact_ref,
            change_kind="structured_guidance",
            target_slot="structured_guidance",
            engine_semantic_id=_public_ref(payload.get("engine_semantic_id")) or "unavailable",
            authority_ceiling="none",
            benefit_claim=_public_ref(claim_ref) or "not_assessed",
            benefit_state="declared" if claim_ref is not None else "not_assessed",
            # The source and public projection use different risk vocabularies.
            # No policy-backed translation is supplied to this adapter.
            risk_tier="not_assessed",
            incumbent_profile_ref=_public_ref(payload.get("incumbent_profile_id")) or "profile:unavailable",
            successor_profile_ref=_public_ref(payload.get("successor_profile_id")),
            observed_scope_revision=payload["observed_scope_revision"],
            lineage=lineage,
            disposition_axis=disposition_axis,
            disposition=disposition,
            monitor=monitor,
            monitor_receipt_refs=(),
            changed_component_count=1,
            protected_constraint_state="not_assessed",
            rule_catalog_ids=(),
            evidence_buckets=(),
            canary=canary,
            diagnostic_labels=("diagnostic", "non_authoritative") if diagnostic else (),
            diagnostic_reason_codes=("no_promotion_authority",) if diagnostic else (),
            allowed_actions=allowed,
        )

    @staticmethod
    def _canary(conclusion: ObservedRecord | None) -> CanarySummary:
        if conclusion is None:
            return CanarySummary(
                _not_observed("canary_not_observed"), "none", "none", None, False
            )
        payload = conclusion.record.payload
        kind = payload.get("canary_kind")
        ceiling = payload.get("authority_ceiling")
        authoritative = payload.get("activation_authoritative") is True
        if kind not in {"authoritative", "diagnostic"} or ceiling not in {
            "activation_authority",
            "no_promotion_authority",
        }:
            return CanarySummary(
                _unavailable("canary_authority_invalid"), "none", "none", None, False
            )
        state = payload.get("conclusion")
        if state not in {"passed", "failed", "inconclusive", "stopped"}:
            state = "unavailable"
        return CanarySummary(
            _axis(state, conclusion.observed_at, *_safe_codes(payload.get("reason_codes"))),
            kind,
            ceiling,
            _public_ref(conclusion.record.record_id),
            authoritative,
        )

    @staticmethod
    def _candidate_actions(
        disposition: str, lineage_current: bool, canary: CanarySummary
    ) -> tuple[ActionSummary, ...]:
        if not lineage_current:
            reasons = ("activation_scope_changed",)
            state = "blocked"
        elif canary.canary_kind == "diagnostic":
            reasons = ("diagnostic_canary_no_activation_authority",)
            state = "blocked"
        elif disposition == "promotion_ready" and canary.activation_authoritative:
            reasons = ()
            state = "eligible"
        else:
            reasons = ("activation_authority_not_observed",)
            state = "blocked"
        return (ActionSummary("activate", state, reasons),)

    def read_evidence_fixtures(self, context_ref: str) -> EvidenceFixturesSnapshot:
        observed = self._records(context_ref)
        evidence = [item for item in observed if item.record.record_kind == "evidence_bundle"]
        families = [item for item in observed if item.record.record_kind == "fixture_family"]
        drafts = sum(item.record.record_kind == "fixture_draft" for item in observed)
        reviews = sum(item.record.record_kind == "fixture_review" for item in observed)
        admitted = sum(item.record.record_kind == "fixture_admission_receipt" for item in observed)
        withdrawn = sum(
            item.record.record_kind == "fixture_eligibility_event"
            and item.record.payload.get("state") == "withdrawn"
            for item in observed
        )
        family_items: list[FixtureFamilySummary] = []
        for family in families:
            payload = family.record.payload
            partition = payload.get("partition")
            family_ref = _public_ref(payload.get("family_ref"))
            if family_ref is None or partition not in {
                "training",
                "tuning",
                "certification_holdout",
            }:
                continue
            counts = {"training": 0, "tuning": 0, "certification_holdout": 0}
            counts[partition] = 1
            family_items.append(
                FixtureFamilySummary(
                    family_ref,
                    _axis("not_observed", family.observed_at, "eligibility_not_joined"),
                    "not_observed",
                    counts["training"],
                    counts["tuning"],
                    counts["certification_holdout"],
                    "not_observed",
                )
            )
        latest_evidence = max((item.observed_at for item in evidence), default=None)
        latest_fixture = max((item.observed_at for item in families), default=None)
        return EvidenceFixturesSnapshot(
            _axis("ready", latest_evidence) if latest_evidence else _not_observed("evidence_not_observed"),
            (),
            _axis("ready", latest_fixture) if latest_fixture else _not_observed("fixtures_not_observed"),
            tuple(family_items),
            drafts,
            reviews,
            admitted,
            withdrawn,
        )

    def read_privacy_migration(self, context_ref: str) -> PrivacyMigrationSnapshot:
        if self._privacy_migration is not None:
            return self._privacy_migration
        return PrivacyMigrationSnapshot(
            privacy=_unavailable("privacy_authority_not_supplied"),
            migration=_not_observed("migration_authority_not_supplied"),
            migration_ref=None,
            migration_phase="unavailable",
            checkpoint_count=0,
            disposition_counts=(),
            key_custody_state="unavailable",
            cutover_readiness="unavailable",
            recovery_state="unavailable",
            operations=(),
        )

    def read_policy_capabilities(self, context_ref: str) -> PolicyCapabilitiesSnapshot:
        observed = self._records(context_ref)
        policies = [item for item in observed if item.record.record_kind == "activation_policy"]
        policy = policies[0] if len(policies) == 1 else None
        calibration_state = "unavailable"
        activation_mode = "unavailable"
        policy_ref = None
        policy_axis = _unavailable("policy_authority_ambiguous" if policies else "policy_not_observed")
        if policy is not None:
            payload = policy.record.payload
            policy_ref = _public_ref(policy.record.record_id)
            calibration_state = payload.get("calibration_state", "uncalibrated")
            if calibration_state not in {"approved", "uncalibrated", "withdrawn", "expired"}:
                calibration_state = "unavailable"
            activation_mode = payload.get("activation_mode", "unavailable")
            if activation_mode not in {"manual_only", "auto_after_canary"}:
                activation_mode = "unavailable"
            policy_axis = _axis("active", policy.observed_at)
        capability_records = [
            item
            for item in observed
            if item.record.record_kind
            in {
                "worker_dependency_capability_certificate",
                "provider_capability_certificate",
                "replay_capability_certificate",
            }
        ]
        capabilities = tuple(
            CapabilitySummary(
                f"capability:{index}",
                item.record.schema_id,
                item.record.payload.get("state", "unavailable")
                if item.record.payload.get("state") in {"ready", "unavailable"}
                else "unavailable",
            )
            for index, item in enumerate(capability_records)
        )
        capability_axis = (
            _axis("ready", max(item.observed_at for item in capability_records))
            if capability_records
            else _unavailable("capabilities_not_observed")
        )
        return PolicyCapabilitiesSnapshot(
            policy_axis,
            policy_ref,
            calibration_state,
            activation_mode,
            "not_authorized" if policy is not None else "unavailable",
            capability_axis,
            capabilities,
            None,
            "unavailable",
            _unavailable("grant_authority_not_observed"),
            (),
            _unavailable("budget_authority_not_observed"),
            (),
            "use_local_authority_cli",
        )

    def read_receipts_audit(self, context_ref: str) -> ReceiptsAuditSnapshot:
        observed = self._records(context_ref)
        by_id = {item.record.record_id: item.record for item in observed}
        events = self._facts.list_domain_events(context_ref)
        receipts: list[ReceiptSummary] = []
        for item in events:
            record = (
                None
                if item.event.payload_record_id is None
                else by_id.get(item.event.payload_record_id)
            )
            category = (
                None if record is None else _RECEIPT_CATEGORIES.get(record.record_kind)
            )
            if category is None:
                continue
            receipt_ref = _public_ref(record.record_id)
            action = _public_ref(item.event.event_type)
            if receipt_ref is None:
                continue
            if action is None:
                continue
            receipts.append(
                ReceiptSummary(
                    sequence=item.event.sequence,
                    receipt_ref=receipt_ref,
                    category=category,
                    action=action,
                    state="completed",
                    observed_at=item.observed_at,
                    related_receipt_refs=(),
                )
            )
        if len({item.sequence for item in receipts}) != len(receipts):
            return ReceiptsAuditSnapshot(
                _unavailable("global_receipt_sequence_ambiguous"), (), ()
            )
        counts = tuple(
            (category, sum(item.category == category for item in receipts))
            for category in sorted({item.category for item in receipts})
        )
        latest = max((item.observed_at for item in receipts), default=None)
        return ReceiptsAuditSnapshot(
            _axis("active", latest) if latest else _not_observed("receipts_not_observed"),
            tuple(receipts),
            counts,
        )


__all__ = [
    "ObservedDomainEvent",
    "ObservedOperatorCommand",
    "ObservedRecord",
    "OperatorFactsReader",
    "OperatorRepositoryAdapter",
    "SafeStoreOperatorReader",
]
