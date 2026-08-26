"""Fail-closed production seam between queued work and the durable closed loop.

The runner owns orchestration only.  Every stage service, lease time, worker
identity, claim condition, finalization revalidator, and failure classifier is
injected explicitly.  It never selects a provider or manufactures a retry,
cleanup, cancellation, or terminal-failure policy.

Successful completion is fenced through :class:`WorkCoordinator` in the same
transaction that inserts the runner receipt.  A stage/fence/cancellation
failure is recorded as an immutable observation, but the live Work Item is
left for the Work Coordinator's signed cancellation or two-phase recovery
protocol.  This prevents a runner from turning an unverified cleanup into a
retry or terminal state.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import re
from typing import Callable, Literal

from .closed_loop import ClosedLoopPlan, ExactTypedRecord, STAGES
from .closed_loop_repository import (
    RepositoryClosedLoopCoordinator,
    RepositoryClosedLoopServices,
)
from .repository import DomainEvent, IntegrityFailure, V3Repository, V3Transaction
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    strict_enum,
    strict_integer,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)
from .work_authority import (
    ClaimConditions,
    FinalizationConditions,
    LeaseIdentity,
    PublicationWriteSet,
    WorkCoordinator,
    WorkItem,
    WorkLease,
)


CLOSED_LOOP_RUNNER_RECEIPT_SCHEMA_ID = "a0.closed-loop-runner-receipt.v1"
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")
_WORK_STATES = (
    "queued",
    "leased",
    "cancel_requested",
    "recovery_required",
    "completed",
    "failed",
    "cancelled",
)
_TERMINAL_STATES = (
    "evidence_rejected",
    "review_only",
    "canary_failed",
    "canary_inconclusive",
    "canary_stopped",
    "retained",
    "rolled_back",
)
_EXACT = strict_object(
    {
        "record_id": strict_string(maximum=512),
        "digest": validate_digest,
        "schema_id": strict_string(maximum=512),
        "record_kind": strict_string(maximum=128),
        "context_ref": strict_string(maximum=512),
    }
)


class ClosedLoopRunnerError(RuntimeError):
    """The queued work cannot be run without weakening an authority boundary."""


def _receipt_payload(value: object, path: str) -> dict[str, object]:
    payload = strict_object(
        {
            "record_type": strict_literal("closed_loop_runner_receipt"),
            "runner_ref": strict_string(maximum=512),
            "execution_digest": validate_digest,
            "work_id": strict_string(maximum=512),
            "attempt_id": strict_string(maximum=512),
            "owner_id": strict_string(maximum=512),
            "fence_token": strict_integer(minimum=1),
            "lease_identity_digest": validate_digest,
            "status": strict_enum(("completed", "failed", "cancelled")),
            "reason_code": strict_string(maximum=128),
            "work_state": strict_enum(_WORK_STATES),
            "failure_stage": strict_nullable(strict_enum(STAGES)),
            "plan_run_ref": strict_string(maximum=512),
            "terminal_state": strict_nullable(strict_enum(_TERMINAL_STATES)),
            "initial_input": _EXACT,
            "closed_loop_terminal": strict_nullable(_EXACT),
            "links": validate_links,
        }
    )(value, path)
    links = [_link("initial_input", 0, payload["initial_input"])]
    terminal = payload["closed_loop_terminal"]
    if terminal is not None:
        links.append(_link("closed_loop_terminal", 0, terminal))
    if payload["links"] != links:
        raise SchemaValidationError(f"{path}.links do not bind the exact execution")
    if payload["status"] == "completed":
        if (
            payload["work_state"] != "completed"
            or payload["terminal_state"] is None
            or terminal is None
            or payload["failure_stage"] is not None
        ):
            raise SchemaValidationError(
                f"{path} completed receipt lacks its exact terminal"
            )
    elif payload["failure_stage"] is None and payload["work_state"] == "leased":
        raise SchemaValidationError(
            f"{path} live-lease failure must identify its stage"
        )
    return payload


CLOSED_LOOP_RUNNER_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            CLOSED_LOOP_RUNNER_RECEIPT_SCHEMA_ID,
            "closed_loop_runner_receipt",
            _receipt_payload,
        ),
    )
)


@dataclass(frozen=True, slots=True)
class LeaseRenewal:
    stage: str
    heartbeat_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise ClosedLoopRunnerError("lease renewal has an unknown stage")
        heartbeat = _utc(self.heartbeat_at, "heartbeat_at")
        expiry = _utc(self.expires_at, "expires_at")
        if expiry <= heartbeat:
            raise ClosedLoopRunnerError("lease renewal expiry must follow heartbeat")


@dataclass(frozen=True, slots=True)
class ClosedLoopRunRequest:
    runner_ref: str
    work_id: str
    attempt_id: str
    owner_id: str
    process_nonce: str
    process_start_identity: str
    runner_authority_ref: str
    claim_at: datetime
    claim_expires_at: datetime
    stage_renewals: tuple[LeaseRenewal, ...]
    finalization_renewal: LeaseRenewal

    def __post_init__(self) -> None:
        for name in (
            "runner_ref",
            "work_id",
            "attempt_id",
            "owner_id",
            "process_nonce",
            "process_start_identity",
            "runner_authority_ref",
        ):
            _ref(getattr(self, name), name)
        claimed = _utc(self.claim_at, "claim_at")
        claim_expiry = _utc(self.claim_expires_at, "claim_expires_at")
        if claim_expiry <= claimed:
            raise ClosedLoopRunnerError("claim expiry must follow claim time")
        if type(self.stage_renewals) is not tuple or tuple(
            renewal.stage for renewal in self.stage_renewals
        ) != STAGES:
            raise ClosedLoopRunnerError(
                "one explicit lease renewal is required for every closed-loop stage"
            )
        if self.finalization_renewal.stage != STAGES[-1]:
            raise ClosedLoopRunnerError(
                "finalization renewal must use the final stage identity"
            )
        previous_expiry = claim_expiry
        for renewal in (*self.stage_renewals, self.finalization_renewal):
            if _utc(renewal.expires_at, "expires_at") <= previous_expiry:
                raise ClosedLoopRunnerError(
                    "every lease renewal must advance the prior expiry"
                )
            previous_expiry = renewal.expires_at.astimezone(timezone.utc)


FinalizationRevalidator = Callable[
    [V3Transaction, WorkItem, LeaseIdentity], FinalizationConditions
]
FailureClassifier = Callable[[Exception], str]


@dataclass(frozen=True, slots=True)
class ClosedLoopRunnerResult:
    work: WorkItem
    receipt: TypedRecord
    closed_loop_terminal: TypedRecord | None
    replayed: bool


class RepositoryClosedLoopRunner:
    """Claim and drive one exact optimize Work Item under explicit authorities."""

    def __init__(self, repository: V3Repository) -> None:
        if not isinstance(repository, V3Repository):
            raise TypeError("closed-loop runner requires a V3Repository")
        self._repository = repository
        self._work = WorkCoordinator(repository)
        self._closed_loop = RepositoryClosedLoopCoordinator(repository)

    def run(
        self,
        request: ClosedLoopRunRequest,
        *,
        plan: ClosedLoopPlan,
        services: RepositoryClosedLoopServices,
        claim_conditions: ClaimConditions,
        finalization_revalidator: FinalizationRevalidator,
        failure_classifier: FailureClassifier,
    ) -> ClosedLoopRunnerResult:
        """Run or replay one attempt without ambient provider or timing defaults."""

        if type(request) is not ClosedLoopRunRequest:
            raise ClosedLoopRunnerError("one exact ClosedLoopRunRequest is required")
        if type(plan) is not ClosedLoopPlan:
            raise ClosedLoopRunnerError("one exact ClosedLoopPlan is required")
        if type(services) is not RepositoryClosedLoopServices:
            raise ClosedLoopRunnerError("all repository stage services must be injected")
        for stage in STAGES:
            services.for_stage(stage)
        if type(claim_conditions) is not ClaimConditions:
            raise ClosedLoopRunnerError("claim conditions must be explicit")
        if not callable(finalization_revalidator):
            raise ClosedLoopRunnerError("finalization revalidator must be injected")
        if not callable(failure_classifier):
            raise ClosedLoopRunnerError("failure classifier must be injected")

        item = self._work.get(request.work_id)
        if item is None:
            raise ClosedLoopRunnerError("work item does not exist")
        _require_work_plan(item, plan)
        execution_digest = _execution_digest(request, plan)
        receipt_id = _receipt_id(request)
        replay = self._repository.get_record(receipt_id)
        if replay is not None:
            return self._replayed_result(item, replay, execution_digest)
        if item.state == "completed":
            raise IntegrityFailure("completed work lost its runner receipt")
        if item.state in ("cancel_requested", "cancelled"):
            identity = self._identity_for_nonrunning_item(request, item)
            return self._stop(
                request,
                plan,
                identity,
                item,
                execution_digest,
                status="cancelled",
                reason_code="cancellation_requested",
                failure_stage=None,
                terminal=None,
            )
        if item.state in ("recovery_required", "failed"):
            identity = self._identity_for_nonrunning_item(request, item)
            return self._stop(
                request,
                plan,
                identity,
                item,
                execution_digest,
                status="failed",
                reason_code=item.state,
                failure_stage=None,
                terminal=None,
            )

        identity = self._claim_or_resume(request, item, claim_conditions)
        current_stage: str | None = STAGES[0]
        terminal: TypedRecord | None = None
        try:
            run_record = self._closed_loop.start(plan)
            sequence = _completed_sequence(self._repository, run_record.record_id)
            if sequence == len(STAGES):
                terminal = self._closed_loop.run(plan, services).terminal
                current_stage = None
            else:
                for sequence in range(sequence, len(STAGES)):
                    current_stage = STAGES[sequence]
                    self._heartbeat(identity, request.stage_renewals[sequence])
                    step = self._closed_loop.execute_stage(
                        plan, expected_sequence=sequence, services=services
                    )
                    if step.terminal is not None:
                        terminal = step.terminal
                        break
            if terminal is None:
                raise ClosedLoopRunnerError(
                    "closed loop exhausted its stage contract without a terminal"
                )
            self._heartbeat(identity, request.finalization_renewal)
            terminal_state = terminal.payload["terminal_state"]
            receipt = _build_receipt(
                request,
                plan,
                identity,
                execution_digest,
                status="completed",
                reason_code="closed_loop_terminal_committed",
                work_state="completed",
                failure_stage=None,
                terminal_state=terminal_state,
                terminal=terminal,
            )
            event = _receipt_event(request, identity, receipt)
            completed = self._work.finalize(
                identity=identity,
                now=request.finalization_renewal.heartbeat_at,
                authority_revalidator=finalization_revalidator,
                publication_planner=lambda: PublicationWriteSet((receipt,), (event,)),
            )
            return ClosedLoopRunnerResult(completed, receipt, terminal, False)
        except Exception as exc:
            item = self._work.get(request.work_id)
            if item is None:  # pragma: no cover - Work Items cannot be deleted
                raise IntegrityFailure("running work item disappeared") from exc
            cancelled = item.state in ("cancel_requested", "cancelled")
            reason = "cancellation_requested" if cancelled else failure_classifier(exc)
            _ref(reason, "failure reason code", maximum=128)
            return self._stop(
                request,
                plan,
                identity,
                item,
                execution_digest,
                status="cancelled" if cancelled else "failed",
                reason_code=reason,
                failure_stage=current_stage,
                terminal=terminal,
            )

    def _claim_or_resume(
        self,
        request: ClosedLoopRunRequest,
        item: WorkItem,
        conditions: ClaimConditions,
    ) -> LeaseIdentity:
        if item.state == "queued":
            lease = self._work.claim(
                work_id=request.work_id,
                attempt_id=request.attempt_id,
                owner_id=request.owner_id,
                process_nonce=request.process_nonce,
                process_start_identity=request.process_start_identity,
                now=request.claim_at,
                expires_at=request.claim_expires_at,
                conditions=conditions,
            )
        elif item.state == "leased":
            lease = self._current_lease(item.work_id)
        else:
            raise ClosedLoopRunnerError("work item is not claimable or resumable")
        expected = (
            request.work_id,
            request.attempt_id,
            request.owner_id,
            request.process_nonce,
            request.process_start_identity,
        )
        actual = (
            lease.work_id,
            lease.attempt_id,
            lease.owner_id,
            lease.process_nonce,
            lease.process_start_identity,
        )
        if actual != expected:
            raise ClosedLoopRunnerError("live lease belongs to another exact runner")
        return _lease_identity(lease)

    def _identity_for_nonrunning_item(
        self, request: ClosedLoopRunRequest, item: WorkItem
    ) -> LeaseIdentity:
        try:
            lease = self._current_lease(item.work_id)
        except ClosedLoopRunnerError:
            return LeaseIdentity(
                item.work_id,
                request.attempt_id,
                request.owner_id,
                max(item.fence_token, 1),
                request.process_nonce,
                request.process_start_identity,
            )
        return _lease_identity(lease)

    def _current_lease(self, work_id: str) -> WorkLease:
        lease = self._work.get_lease(work_id)
        if lease is None:
            raise ClosedLoopRunnerError("work item has no resumable lease")
        return lease

    def _heartbeat(self, identity: LeaseIdentity, renewal: LeaseRenewal) -> None:
        self._work.heartbeat(
            identity=identity,
            now=renewal.heartbeat_at,
            new_expires_at=renewal.expires_at,
        )

    def _stop(
        self,
        request: ClosedLoopRunRequest,
        plan: ClosedLoopPlan,
        identity: LeaseIdentity,
        item: WorkItem,
        execution_digest: str,
        *,
        status: Literal["failed", "cancelled"],
        reason_code: str,
        failure_stage: str | None,
        terminal: TypedRecord | None,
    ) -> ClosedLoopRunnerResult:
        terminal_state = None if terminal is None else terminal.payload["terminal_state"]
        receipt = _build_receipt(
            request,
            plan,
            identity,
            execution_digest,
            status=status,
            reason_code=reason_code,
            work_state=item.state,
            failure_stage=failure_stage,
            terminal_state=terminal_state,
            terminal=terminal,
        )
        event = _receipt_event(request, identity, receipt)
        with self._repository.transaction() as transaction:
            transaction.insert_record(receipt)
            transaction.append_event(event)
        return ClosedLoopRunnerResult(item, receipt, terminal, False)

    def _replayed_result(
        self, item: WorkItem, receipt: TypedRecord, execution_digest: str
    ) -> ClosedLoopRunnerResult:
        receipt.verify(CLOSED_LOOP_RUNNER_REGISTRY)
        if receipt.payload["execution_digest"] != execution_digest:
            raise ClosedLoopRunnerError("runner identity was reused with another request")
        exact = receipt.payload["closed_loop_terminal"]
        terminal = None
        if exact is not None:
            terminal = self._repository.get_record(exact["record_id"])
            if terminal is None or ExactTypedRecord.of(terminal).payload() != exact:
                raise IntegrityFailure("runner receipt lost its exact terminal")
        if receipt.payload["status"] == "completed" and item.state != "completed":
            raise IntegrityFailure("completed runner receipt differs from Work Item state")
        return ClosedLoopRunnerResult(item, receipt, terminal, True)


def _require_work_plan(item: WorkItem, plan: ClosedLoopPlan) -> None:
    if item.operation_kind != "candidate_search":
        raise ClosedLoopRunnerError("runner accepts only candidate_search work")
    if item.context_ref != plan.context_ref:
        raise ClosedLoopRunnerError("work and closed-loop context differ")
    exact = plan.admitted_input
    if item.input_record_id != exact.record_id or item.input_digest != exact.digest:
        raise ClosedLoopRunnerError("work input differs from the closed-loop input")


def _completed_sequence(repository: V3Repository, run_record_id: str) -> int:
    sequence = 0
    while sequence < len(STAGES):
        if repository.get_domain_event(run_record_id, sequence) is None:
            return sequence
        sequence += 1
    return sequence


def _build_receipt(
    request: ClosedLoopRunRequest,
    plan: ClosedLoopPlan,
    identity: LeaseIdentity,
    execution_digest: str,
    *,
    status: str,
    reason_code: str,
    work_state: str,
    failure_stage: str | None,
    terminal_state: str | None,
    terminal: TypedRecord | None,
) -> TypedRecord:
    initial = plan.admitted_input.payload()
    exact_terminal = None if terminal is None else ExactTypedRecord.of(terminal).payload()
    links = [_link("initial_input", 0, initial)]
    if exact_terminal is not None:
        links.append(_link("closed_loop_terminal", 0, exact_terminal))
    return build_typed_record(
        record_id=_receipt_id(request),
        context_ref=plan.context_ref,
        record_kind="closed_loop_runner_receipt",
        schema_id=CLOSED_LOOP_RUNNER_RECEIPT_SCHEMA_ID,
        payload={
            "record_type": "closed_loop_runner_receipt",
            "runner_ref": request.runner_ref,
            "execution_digest": execution_digest,
            "work_id": request.work_id,
            "attempt_id": identity.attempt_id,
            "owner_id": identity.owner_id,
            "fence_token": identity.fence_token,
            "lease_identity_digest": _lease_digest(identity),
            "status": status,
            "reason_code": reason_code,
            "work_state": work_state,
            "failure_stage": failure_stage,
            "plan_run_ref": plan.run_ref,
            "terminal_state": terminal_state,
            "initial_input": initial,
            "closed_loop_terminal": exact_terminal,
            "links": links,
        },
        key_epoch=plan.key_epoch,
        registry=CLOSED_LOOP_RUNNER_REGISTRY,
    )


def _receipt_event(
    request: ClosedLoopRunRequest, identity: LeaseIdentity, receipt: TypedRecord
) -> DomainEvent:
    return DomainEvent(
        event_id=f"closed-loop-runner-event:{_stable_digest(request.runner_ref, request.attempt_id)}",
        subject_id=receipt.record_id,
        subject_kind=receipt.record_kind,
        sequence=0,
        event_type=f"closed_loop_runner_{receipt.payload['status']}",
        payload_record_id=receipt.record_id,
        actor_authority_ref=request.runner_authority_ref,
        fence_token=identity.fence_token,
    )


def _execution_digest(request: ClosedLoopRunRequest, plan: ClosedLoopPlan) -> str:
    payload = {
        "runner_ref": request.runner_ref,
        "work_id": request.work_id,
        "attempt_id": request.attempt_id,
        "owner_id": request.owner_id,
        "process_nonce": request.process_nonce,
        "process_start_identity": request.process_start_identity,
        "runner_authority_ref": request.runner_authority_ref,
        "claim_at": _timestamp(request.claim_at),
        "claim_expires_at": _timestamp(request.claim_expires_at),
        "stage_renewals": [
            {
                "stage": item.stage,
                "heartbeat_at": _timestamp(item.heartbeat_at),
                "expires_at": _timestamp(item.expires_at),
            }
            for item in request.stage_renewals
        ],
        "finalization_renewal": {
            "stage": request.finalization_renewal.stage,
            "heartbeat_at": _timestamp(request.finalization_renewal.heartbeat_at),
            "expires_at": _timestamp(request.finalization_renewal.expires_at),
        },
        "plan": {
            "run_ref": plan.run_ref,
            "context_ref": plan.context_ref,
            "key_epoch": plan.key_epoch,
            "admitted_input": plan.admitted_input.payload(),
            "stage_authorities": [
                {
                    "stage": item.stage,
                    "authorities": [authority.payload() for authority in item.authorities],
                }
                for item in plan.stage_authorities
            ],
        },
    }
    return sha256(canonical_json(payload)).hexdigest()


def _lease_identity(lease: WorkLease) -> LeaseIdentity:
    return LeaseIdentity(
        lease.work_id,
        lease.attempt_id,
        lease.owner_id,
        lease.fence_token,
        lease.process_nonce,
        lease.process_start_identity,
    )


def _lease_digest(identity: LeaseIdentity) -> str:
    return sha256(
        canonical_json(
            {
                "work_id": identity.work_id,
                "attempt_id": identity.attempt_id,
                "owner_id": identity.owner_id,
                "fence_token": identity.fence_token,
                "process_nonce": identity.process_nonce,
                "process_start_identity": identity.process_start_identity,
            }
        )
    ).hexdigest()


def _receipt_id(request: ClosedLoopRunRequest) -> str:
    return f"closed-loop-runner:{_stable_digest(request.runner_ref, request.work_id, request.attempt_id)}"


def _stable_digest(*parts: str) -> str:
    return sha256("\0".join(parts).encode()).hexdigest()


def _link(role: str, ordinal: int, exact: object) -> dict[str, object]:
    if type(exact) is not dict:
        raise SchemaValidationError("exact link target must be an object")
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": exact["record_id"],
        "target_digest": exact["digest"],
    }


def _ref(value: object, name: str, *, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or len(value) > maximum
        or _SAFE_REF.fullmatch(value) is None
    ):
        raise ClosedLoopRunnerError(f"{name} must be a bounded opaque value")
    return value


def _utc(value: object, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise ClosedLoopRunnerError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value, "timestamp").strftime("%Y-%m-%dT%H:%M:%S.%fZ")


__all__ = [
    "CLOSED_LOOP_RUNNER_RECEIPT_SCHEMA_ID",
    "CLOSED_LOOP_RUNNER_REGISTRY",
    "ClosedLoopRunnerError",
    "LeaseRenewal",
    "ClosedLoopRunRequest",
    "ClosedLoopRunnerResult",
    "RepositoryClosedLoopRunner",
]
