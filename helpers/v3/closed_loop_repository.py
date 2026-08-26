"""Durable branch-aware repository authority for the v3 closed loop.

Each stage executes under the owning ``V3Transaction``.  A service returns one
fully materialized typed output; the coordinator then persists the invocation,
output, immutable step receipt, and event atomically.  No worker is given an
activation or rollback authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Mapping

from .artifacts import ACTIVATION_PROFILE_SCHEMA_ID
from .canary import (
    ACTIVATION_POLICY_SCHEMA_ID,
    POST_PROMOTION_MONITOR_SCHEMA_ID,
)
from .closed_loop import (
    MONITOR_CONCLUSION_SCHEMA_ID,
    STAGES,
    STAGE_CONTRACTS,
    ClosedLoopError,
    ClosedLoopPlan,
    ExactTypedRecord,
    StageInvocation,
)
from .repository import DomainEvent, IntegrityFailure, V3Repository, V3Transaction
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    strict_boolean,
    strict_enum,
    strict_integer,
    strict_list,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


CLOSED_LOOP_RUN_SCHEMA_ID = "a0.closed-loop-run.v1"
CLOSED_LOOP_INVOCATION_SCHEMA_ID = "a0.closed-loop-stage-invocation.v1"
CLOSED_LOOP_STEP_RECEIPT_SCHEMA_ID = "a0.closed-loop-step-receipt.v1"
CLOSED_LOOP_TERMINAL_SCHEMA_ID = "a0.closed-loop-terminal.v1"

_TERMINAL_STATES = (
    "evidence_rejected",
    "review_only",
    "canary_failed",
    "canary_inconclusive",
    "canary_stopped",
    "retained",
    "rolled_back",
)
_DECISIONS: Mapping[str, tuple[str, ...]] = {
    "observation": ("observation_recorded",),
    "safe_analysis_view": ("safe_view_built",),
    "analysis_attempt": ("deterministic_attempt_completed",),
    "candidate_publication": ("candidate_locked",),
    "certified_replay": ("certified_pair_completed",),
    "evidence_reduction": ("promotion_ready", "review_only", "rejected"),
    "canary_start": ("authoritative_canary_started",),
    "canary_conclusion": (
        "authoritative_canary_passed",
        "authoritative_canary_failed",
        "authoritative_canary_inconclusive",
        "authoritative_canary_stopped",
    ),
    "activation": ("candidate_activated_monitor_started",),
    "monitor_conclusion": ("retain", "rollback_required"),
    "rollback": ("predecessor_restored",),
}
_ALL_DECISIONS = tuple(
    decision for stage in STAGES for decision in _DECISIONS[stage]
)
_OWNERS = tuple(sorted({contract.owner for contract in STAGE_CONTRACTS.values()}))

_EXACT = strict_object(
    {
        "record_id": strict_string(maximum=512),
        "digest": validate_digest,
        "schema_id": strict_string(maximum=512),
        "record_kind": strict_string(maximum=128),
        "context_ref": strict_string(maximum=512),
    }
)
_AUTHORITY = strict_object(
    {"ref": strict_string(maximum=512), "digest": validate_digest}
)
_STAGE_AUTHORITY = strict_object(
    {
        "stage": strict_enum(STAGES),
        "authorities": strict_list(_AUTHORITY, maximum=128),
    }
)
_EXACT_REF = strict_object(
    {"record_id": strict_string(maximum=512), "digest": validate_digest}
)


def _run_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("closed_loop_run"),
            "run_ref": strict_string(maximum=512),
            "context_ref": strict_string(maximum=512),
            "initial_input": _EXACT,
            "stage_authorities": strict_list(
                _STAGE_AUTHORITY, minimum=len(STAGES), maximum=len(STAGES)
            ),
            "worker_activation_authority": strict_literal("none"),
            "links": validate_links,
        }
    )(value, path)
    if [item["stage"] for item in payload["stage_authorities"]] != list(STAGES):
        raise SchemaValidationError(f"{path}.stage_authorities must freeze every stage")
    links = [_link("initial_input", 0, payload["initial_input"])]
    for stage_index, authority_set in enumerate(payload["stage_authorities"]):
        links.extend(
            _link(
                f"stage_authority:{stage_index}", ordinal, authority
            )
            for ordinal, authority in enumerate(authority_set["authorities"])
        )
    if payload["links"] != links:
        raise SchemaValidationError(f"{path}.links do not freeze run authority")
    return payload


def _invocation_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("closed_loop_stage_invocation"),
            "run_ref": strict_string(maximum=512),
            "sequence": strict_integer(minimum=0, maximum=len(STAGES) - 1),
            "stage": strict_enum(STAGES),
            "owner": strict_enum(_OWNERS),
            "predecessor": _EXACT,
            "authorities": strict_list(_AUTHORITY, maximum=128),
            "worker_activation_authority": strict_literal("none"),
            "links": validate_links,
        }
    )(value, path)
    if payload["owner"] != STAGE_CONTRACTS[payload["stage"]].owner:
        raise SchemaValidationError(f"{path}.owner is not the stage authority")
    expected = [
        _link("predecessor", 0, payload["predecessor"]),
        *(
            _link("authority", ordinal, authority)
            for ordinal, authority in enumerate(payload["authorities"])
        ),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind invocation authority")
    return payload


def _step_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("closed_loop_step_receipt"),
            "run_ref": strict_string(maximum=512),
            "sequence": strict_integer(minimum=0, maximum=len(STAGES) - 1),
            "stage": strict_enum(STAGES),
            "owner": strict_enum(_OWNERS),
            "decision": strict_enum(_ALL_DECISIONS),
            "invocation": _EXACT_REF,
            "predecessor": _EXACT,
            "authorities": strict_list(_AUTHORITY, maximum=128),
            "output": _EXACT,
            "next_stage": strict_nullable(strict_enum(STAGES)),
            "terminal_state": strict_nullable(strict_enum(_TERMINAL_STATES)),
            "domain_mutation": strict_boolean(),
            "worker_activation_authority": strict_literal("none"),
            "links": validate_links,
        }
    )(value, path)
    stage = payload["stage"]
    next_stage, terminal = _transition(stage, payload["decision"])
    contract = STAGE_CONTRACTS[stage]
    if (
        payload["owner"] != contract.owner
        or payload["decision"] not in _DECISIONS[stage]
        or payload["output"]["schema_id"] != contract.output_schema_id
        or payload["output"]["record_kind"] != contract.output_record_kind
        or payload["next_stage"] != next_stage
        or payload["terminal_state"] != terminal
        or payload["domain_mutation"] != contract.committed
    ):
        raise SchemaValidationError(f"{path} violates the branch-aware stage contract")
    expected = [
        _link("invocation", 0, payload["invocation"]),
        _link("predecessor", 0, payload["predecessor"]),
        _link("output", 0, payload["output"]),
        *(
            _link("authority", ordinal, authority)
            for ordinal, authority in enumerate(payload["authorities"])
        ),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the complete step")
    return payload


def _terminal_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("closed_loop_terminal"),
            "run_ref": strict_string(maximum=512),
            "terminal_state": strict_enum(_TERMINAL_STATES),
            "completed_stages": strict_list(
                strict_enum(STAGES), minimum=1, maximum=len(STAGES)
            ),
            "initial_input": _EXACT,
            "final_output": _EXACT,
            "step_receipts": strict_list(
                _EXACT_REF, minimum=1, maximum=len(STAGES)
            ),
            "stage_outputs": strict_list(_EXACT, minimum=1, maximum=len(STAGES)),
            "worker_activation_observed": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    if payload["final_output"] != payload["stage_outputs"][-1]:
        raise SchemaValidationError(f"{path}.final_output is not the terminal stage output")
    expected = [
        *(
            _link("step_receipt", ordinal, receipt)
            for ordinal, receipt in enumerate(payload["step_receipts"])
        ),
        *(
            _link("stage_output", ordinal, output)
            for ordinal, output in enumerate(payload["stage_outputs"])
        ),
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the durable run result")
    return payload


def _monitor_conclusion_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "fact_type": strict_literal("post_promotion_monitor_conclusion"),
            "decision": strict_enum(("retain", "rollback_required")),
            "monitor": _EXACT,
            "active_profile": _EXACT,
            "policy": _EXACT,
            "links": validate_links,
        }
    )(value, path)
    expected_types = (
        (
            "monitor",
            POST_PROMOTION_MONITOR_SCHEMA_ID,
            "post_promotion_monitor",
        ),
        ("active_profile", ACTIVATION_PROFILE_SCHEMA_ID, "activation_profile"),
        ("policy", ACTIVATION_POLICY_SCHEMA_ID, "activation_policy"),
    )
    contexts: set[str] = set()
    for field, schema_id, record_kind in expected_types:
        exact = payload[field]
        contexts.add(exact["context_ref"])
        if exact["schema_id"] != schema_id or exact["record_kind"] != record_kind:
            raise SchemaValidationError(f"{path}.{field} has the wrong exact type")
    if len(contexts) != 1:
        raise SchemaValidationError(f"{path} mixes monitor contexts")
    expected_links = [
        _link("post_promotion_monitor", 0, payload["monitor"]),
        _link("active_profile", 0, payload["active_profile"]),
        _link("activation_policy", 0, payload["policy"]),
    ]
    if payload["links"] != expected_links:
        raise SchemaValidationError(f"{path}.links do not bind exact monitor inputs")
    return payload


CLOSED_LOOP_REPOSITORY_REGISTRY = SchemaRegistry(
    (
        RecordSchema(CLOSED_LOOP_RUN_SCHEMA_ID, "closed_loop_run", _run_payload),
        RecordSchema(
            CLOSED_LOOP_INVOCATION_SCHEMA_ID,
            "closed_loop_stage_invocation",
            _invocation_payload,
        ),
        RecordSchema(
            CLOSED_LOOP_STEP_RECEIPT_SCHEMA_ID,
            "closed_loop_step_receipt",
            _step_payload,
        ),
        RecordSchema(
            CLOSED_LOOP_TERMINAL_SCHEMA_ID,
            "closed_loop_terminal",
            _terminal_payload,
        ),
        RecordSchema(
            MONITOR_CONCLUSION_SCHEMA_ID,
            "post_promotion_monitor_conclusion",
            _monitor_conclusion_payload,
        ),
    )
)


def build_monitor_conclusion(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    decision: str,
    monitor: ExactTypedRecord,
    active_profile: ExactTypedRecord,
    policy: ExactTypedRecord,
) -> TypedRecord:
    """Materialize a decision over exact, already-authoritative monitor inputs."""

    exact_inputs = (monitor, active_profile, policy)
    if any(type(item) is not ExactTypedRecord for item in exact_inputs):
        raise ClosedLoopError("monitor conclusion requires exact typed inputs")
    if any(item.context_ref != context_ref for item in exact_inputs):
        raise ClosedLoopError("monitor conclusion inputs belong to another context")
    payload = {
        "fact_type": "post_promotion_monitor_conclusion",
        "decision": decision,
        "monitor": monitor.payload(),
        "active_profile": active_profile.payload(),
        "policy": policy.payload(),
        "links": [
            _link("post_promotion_monitor", 0, monitor.payload()),
            _link("active_profile", 0, active_profile.payload()),
            _link("activation_policy", 0, policy.payload()),
        ],
    }
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind="post_promotion_monitor_conclusion",
        schema_id=MONITOR_CONCLUSION_SCHEMA_ID,
        payload=payload,
        key_epoch=key_epoch,
        registry=CLOSED_LOOP_REPOSITORY_REGISTRY,
    )


@dataclass(frozen=True, slots=True)
class RepositoryStageResult:
    owner: str
    decision: str
    output: TypedRecord


RepositoryStageService = Callable[
    [V3Transaction, StageInvocation], RepositoryStageResult
]


@dataclass(frozen=True, slots=True)
class RepositoryClosedLoopServices:
    observation: RepositoryStageService
    safe_analysis_view: RepositoryStageService
    analysis_attempt: RepositoryStageService
    candidate_publication: RepositoryStageService
    certified_replay: RepositoryStageService
    evidence_reduction: RepositoryStageService
    canary_start: RepositoryStageService
    canary_conclusion: RepositoryStageService
    activation: RepositoryStageService
    monitor_conclusion: RepositoryStageService
    rollback: RepositoryStageService

    def for_stage(self, stage: str) -> RepositoryStageService:
        service = getattr(self, stage, None)
        if not callable(service):
            raise ClosedLoopError(f"{stage} has no explicit stage service")
        return service


@dataclass(frozen=True, slots=True)
class RepositoryStepResult:
    invocation: TypedRecord
    output: TypedRecord
    receipt: TypedRecord
    terminal: TypedRecord | None
    replayed: bool


@dataclass(frozen=True, slots=True)
class RepositoryClosedLoopResult:
    run: TypedRecord
    receipts: tuple[TypedRecord, ...]
    outputs: tuple[TypedRecord, ...]
    terminal: TypedRecord
    replayed: bool


@dataclass(frozen=True, slots=True)
class _DurableState:
    receipts: tuple[TypedRecord, ...]
    outputs: tuple[TypedRecord, ...]
    next_stage: str | None
    predecessor: ExactTypedRecord
    terminal_state: str | None


class RepositoryClosedLoopCoordinator:
    def __init__(self, repository: V3Repository) -> None:
        if not isinstance(repository, V3Repository):
            raise TypeError("closed-loop coordination requires a V3Repository")
        self._repository = repository

    def start(self, plan: ClosedLoopPlan) -> TypedRecord:
        _require_plan(plan)
        with self._repository.transaction() as transaction:
            _require_exact(transaction, plan.admitted_input)
            _require_authorities(transaction, plan, STAGES)
            record = _build_run(plan)
            existing = transaction.get_record(record.record_id)
            if existing is not None and existing != record:
                raise ClosedLoopError("run identity was reused with a different plan")
            transaction.insert_record(record)
            return record

    def execute_stage(
        self,
        plan: ClosedLoopPlan,
        *,
        expected_sequence: int,
        services: RepositoryClosedLoopServices,
    ) -> RepositoryStepResult:
        _require_plan(plan)
        if type(expected_sequence) is not int or not 0 <= expected_sequence < len(STAGES):
            raise ClosedLoopError("expected_sequence is outside the closed loop")
        self.start(plan)
        with self._repository.transaction() as transaction:
            state = _load_state(transaction, plan)
            if expected_sequence < len(state.receipts):
                receipt = state.receipts[expected_sequence]
                invocation = transaction.get_record(receipt.payload["invocation"]["record_id"])
                output = transaction.get_record(receipt.payload["output"]["record_id"])
                if invocation is None or output is None:
                    raise IntegrityFailure("durable closed-loop replay lost exact records")
                return RepositoryStepResult(
                    invocation,
                    output,
                    receipt,
                    _load_terminal(transaction, plan),
                    True,
                )
            if expected_sequence != len(state.receipts):
                raise ClosedLoopError("stage sequence skipped durable predecessors")
            if state.next_stage is None:
                raise ClosedLoopError("closed-loop run is already terminal")
            stage = state.next_stage
            authorities = _authorities(plan, stage)
            _require_exact(transaction, state.predecessor)
            _require_authorities(transaction, plan, (stage,))
            invocation = StageInvocation(
                plan.run_ref,
                plan.context_ref,
                expected_sequence,
                stage,
                state.predecessor,
                authorities,
            )
            invocation_record = _build_invocation(plan, invocation)
            transaction.insert_record(invocation_record)

            result = services.for_stage(stage)(transaction, invocation)
            _validate_stage_result(invocation, result)
            transaction.insert_record(result.output)
            receipt = _build_step_receipt(plan, invocation, invocation_record, result)
            transaction.insert_record(receipt)
            event = DomainEvent(
                event_id=_stable_id("closed-loop-event", plan.run_ref, expected_sequence),
                subject_id=_run_id(plan.run_ref),
                subject_kind="closed_loop_run",
                sequence=expected_sequence,
                event_type="closed_loop_step_completed",
                payload_record_id=receipt.record_id,
                actor_authority_ref=_owner_authority_ref(invocation),
            )
            if transaction.next_domain_event_sequence(event.subject_id) != expected_sequence:
                raise IntegrityFailure("closed-loop event sequence differs from stage sequence")
            transaction.append_event(event)

            _next, terminal_state = _transition(stage, result.decision)
            terminal = None
            if terminal_state is not None:
                terminal = _build_terminal(
                    plan,
                    (*state.receipts, receipt),
                    (*state.outputs, result.output),
                    terminal_state,
                )
                transaction.insert_record(terminal)
                if transaction.next_domain_event_sequence(terminal.record_id) != 0:
                    raise IntegrityFailure("closed-loop terminal event already changed")
                transaction.append_event(
                    _terminal_event(plan, terminal, invocation.stage)
                )
            return RepositoryStepResult(
                invocation_record, result.output, receipt, terminal, False
            )

    def run(
        self, plan: ClosedLoopPlan, services: RepositoryClosedLoopServices
    ) -> RepositoryClosedLoopResult:
        run_record = self.start(plan)
        replayed = True
        while True:
            with self._repository.transaction() as transaction:
                state = _load_state(transaction, plan)
                if state.terminal_state is not None:
                    terminal = _load_terminal(transaction, plan)
                    if terminal is None:
                        raise IntegrityFailure("terminal closed-loop state has no completion")
                    return RepositoryClosedLoopResult(
                        run_record,
                        state.receipts,
                        state.outputs,
                        terminal,
                        replayed,
                    )
                sequence = len(state.receipts)
            step = self.execute_stage(
                plan, expected_sequence=sequence, services=services
            )
            replayed = replayed and step.replayed


def _transition(stage: str, decision: str) -> tuple[str | None, str | None]:
    if decision not in _DECISIONS.get(stage, ()):
        raise ClosedLoopError(f"{stage} returned a decision outside its branch contract")
    fixed = {
        "observation": "safe_analysis_view",
        "safe_analysis_view": "analysis_attempt",
        "analysis_attempt": "candidate_publication",
        "candidate_publication": "certified_replay",
        "certified_replay": "evidence_reduction",
        "canary_start": "canary_conclusion",
        "activation": "monitor_conclusion",
        "rollback": None,
    }
    if stage in fixed:
        next_stage = fixed[stage]
        return next_stage, "rolled_back" if stage == "rollback" else None
    if stage == "evidence_reduction":
        return {
            "promotion_ready": ("canary_start", None),
            "review_only": (None, "review_only"),
            "rejected": (None, "evidence_rejected"),
        }[decision]
    if stage == "canary_conclusion":
        return {
            "authoritative_canary_passed": ("activation", None),
            "authoritative_canary_failed": (None, "canary_failed"),
            "authoritative_canary_inconclusive": (None, "canary_inconclusive"),
            "authoritative_canary_stopped": (None, "canary_stopped"),
        }[decision]
    if stage == "monitor_conclusion":
        return {
            "retain": (None, "retained"),
            "rollback_required": ("rollback", None),
        }[decision]
    raise ClosedLoopError("unknown closed-loop transition")


def _require_plan(plan: ClosedLoopPlan) -> None:
    if type(plan) is not ClosedLoopPlan:
        raise ClosedLoopError("one exact ClosedLoopPlan is required")
    if any(not authority_set.authorities for authority_set in plan.stage_authorities):
        raise ClosedLoopError("every stage requires an explicit authority")


def _authorities(plan: ClosedLoopPlan, stage: str):
    return plan.stage_authorities[STAGES.index(stage)].authorities


def _require_exact(transaction: V3Transaction, exact: ExactTypedRecord) -> TypedRecord:
    record = transaction.get_record(exact.record_id)
    if record is None or ExactTypedRecord.of(record) != exact:
        raise ClosedLoopError("closed-loop exact record is missing or changed")
    return record


def _require_authorities(
    transaction: V3Transaction, plan: ClosedLoopPlan, stages: tuple[str, ...]
) -> None:
    for stage in stages:
        for authority in _authorities(plan, stage):
            record = transaction.get_record(authority.ref)
            if record is None or record.content_digest != authority.digest:
                raise ClosedLoopError("closed-loop stage authority is missing or changed")
            if record.context_ref not in (None, plan.context_ref):
                raise ClosedLoopError("closed-loop stage authority belongs to another context")


def _validate_stage_result(
    invocation: StageInvocation, result: RepositoryStageResult
) -> None:
    if type(result) is not RepositoryStageResult or type(result.output) is not TypedRecord:
        raise ClosedLoopError("stage service returned no materialized typed output")
    contract = STAGE_CONTRACTS[invocation.stage]
    if result.owner != contract.owner:
        raise ClosedLoopError("stage service returned under the wrong owner")
    _transition(invocation.stage, result.decision)
    output = result.output
    if (
        output.context_ref != invocation.context_ref
        or output.schema_id != contract.output_schema_id
        or output.record_kind != contract.output_record_kind
    ):
        raise ClosedLoopError("stage service returned the wrong schema or context")
    if invocation.stage in ("activation", "rollback") and result.owner == "analysis_worker":
        raise ClosedLoopError("workers have no activation or rollback authority")


def _run_id(run_ref: str) -> str:
    return _stable_id("closed-loop-run", run_ref)


def _invocation_id(run_ref: str, sequence: int) -> str:
    return _stable_id("closed-loop-invocation", run_ref, sequence)


def _receipt_id(run_ref: str, sequence: int) -> str:
    return _stable_id("closed-loop-step", run_ref, sequence)


def _terminal_id(run_ref: str) -> str:
    return _stable_id("closed-loop-terminal", run_ref)


def _stable_id(namespace: str, *parts: object) -> str:
    material = "\0".join(str(item) for item in parts).encode()
    return f"{namespace}:{sha256(namespace.encode() + b'\0' + material).hexdigest()}"


def _terminal_event(
    plan: ClosedLoopPlan, terminal: TypedRecord, terminal_stage: str
) -> DomainEvent:
    return DomainEvent(
        event_id=_stable_id("closed-loop-terminal-event", plan.run_ref),
        subject_id=terminal.record_id,
        subject_kind="closed_loop_terminal",
        sequence=0,
        event_type="closed_loop_terminal_reached",
        payload_record_id=terminal.record_id,
        actor_authority_ref=_authorities(plan, terminal_stage)[0].ref,
    )


def _build_run(plan: ClosedLoopPlan) -> TypedRecord:
    stage_authorities = [
        {
            "stage": item.stage,
            "authorities": [authority.payload() for authority in item.authorities],
        }
        for item in plan.stage_authorities
    ]
    links = [_link("initial_input", 0, plan.admitted_input.payload())]
    for stage_index, authority_set in enumerate(stage_authorities):
        links.extend(
            _link(f"stage_authority:{stage_index}", ordinal, authority)
            for ordinal, authority in enumerate(authority_set["authorities"])
        )
    return _record(
        _run_id(plan.run_ref),
        plan,
        "closed_loop_run",
        CLOSED_LOOP_RUN_SCHEMA_ID,
        {
            "record_type": "closed_loop_run",
            "run_ref": plan.run_ref,
            "context_ref": plan.context_ref,
            "initial_input": plan.admitted_input.payload(),
            "stage_authorities": stage_authorities,
            "worker_activation_authority": "none",
            "links": links,
        },
    )


def _build_invocation(plan: ClosedLoopPlan, invocation: StageInvocation) -> TypedRecord:
    predecessor = invocation.predecessor.payload()
    authorities = [authority.payload() for authority in invocation.authorities]
    return _record(
        _invocation_id(plan.run_ref, invocation.sequence),
        plan,
        "closed_loop_stage_invocation",
        CLOSED_LOOP_INVOCATION_SCHEMA_ID,
        {
            "record_type": "closed_loop_stage_invocation",
            "run_ref": plan.run_ref,
            "sequence": invocation.sequence,
            "stage": invocation.stage,
            "owner": STAGE_CONTRACTS[invocation.stage].owner,
            "predecessor": predecessor,
            "authorities": authorities,
            "worker_activation_authority": "none",
            "links": [
                _link("predecessor", 0, predecessor),
                *(
                    _link("authority", ordinal, authority)
                    for ordinal, authority in enumerate(authorities)
                ),
            ],
        },
    )


def _build_step_receipt(
    plan: ClosedLoopPlan,
    invocation: StageInvocation,
    invocation_record: TypedRecord,
    result: RepositoryStageResult,
) -> TypedRecord:
    predecessor = invocation.predecessor.payload()
    output = ExactTypedRecord.of(result.output).payload()
    authorities = [authority.payload() for authority in invocation.authorities]
    invocation_exact = {
        "record_id": invocation_record.record_id,
        "digest": invocation_record.content_digest,
    }
    next_stage, terminal = _transition(invocation.stage, result.decision)
    return _record(
        _receipt_id(plan.run_ref, invocation.sequence),
        plan,
        "closed_loop_step_receipt",
        CLOSED_LOOP_STEP_RECEIPT_SCHEMA_ID,
        {
            "record_type": "closed_loop_step_receipt",
            "run_ref": plan.run_ref,
            "sequence": invocation.sequence,
            "stage": invocation.stage,
            "owner": result.owner,
            "decision": result.decision,
            "invocation": invocation_exact,
            "predecessor": predecessor,
            "authorities": authorities,
            "output": output,
            "next_stage": next_stage,
            "terminal_state": terminal,
            "domain_mutation": STAGE_CONTRACTS[invocation.stage].committed,
            "worker_activation_authority": "none",
            "links": [
                _link("invocation", 0, invocation_exact),
                _link("predecessor", 0, predecessor),
                _link("output", 0, output),
                *(
                    _link("authority", ordinal, authority)
                    for ordinal, authority in enumerate(authorities)
                ),
            ],
        },
    )


def _build_terminal(
    plan: ClosedLoopPlan,
    receipts: tuple[TypedRecord, ...],
    outputs: tuple[TypedRecord, ...],
    terminal_state: str,
) -> TypedRecord:
    receipt_refs = [
        {"record_id": receipt.record_id, "digest": receipt.content_digest}
        for receipt in receipts
    ]
    output_refs = [ExactTypedRecord.of(output).payload() for output in outputs]
    return _record(
        _terminal_id(plan.run_ref),
        plan,
        "closed_loop_terminal",
        CLOSED_LOOP_TERMINAL_SCHEMA_ID,
        {
            "record_type": "closed_loop_terminal",
            "run_ref": plan.run_ref,
            "terminal_state": terminal_state,
            "completed_stages": [receipt.payload["stage"] for receipt in receipts],
            "initial_input": plan.admitted_input.payload(),
            "final_output": output_refs[-1],
            "step_receipts": receipt_refs,
            "stage_outputs": output_refs,
            "worker_activation_observed": False,
            "links": [
                *(
                    _link("step_receipt", ordinal, receipt)
                    for ordinal, receipt in enumerate(receipt_refs)
                ),
                *(
                    _link("stage_output", ordinal, output)
                    for ordinal, output in enumerate(output_refs)
                ),
            ],
        },
    )


def _record(
    record_id: str,
    plan: ClosedLoopPlan,
    record_kind: str,
    schema_id: str,
    payload: Mapping[str, Any],
) -> TypedRecord:
    return build_typed_record(
        record_id=record_id,
        context_ref=plan.context_ref,
        record_kind=record_kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=plan.key_epoch,
        registry=CLOSED_LOOP_REPOSITORY_REGISTRY,
    )


def _link(role: str, ordinal: int, exact: Mapping[str, Any]) -> dict[str, Any]:
    target_id = exact.get("record_id", exact.get("ref"))
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": target_id,
        "target_digest": exact["digest"],
    }


def _owner_authority_ref(invocation: StageInvocation) -> str:
    if not invocation.authorities:
        raise ClosedLoopError("stage has no explicit authority")
    return invocation.authorities[0].ref


def _load_state(transaction: V3Transaction, plan: ClosedLoopPlan) -> _DurableState:
    run = transaction.get_record(_run_id(plan.run_ref))
    expected_run = _build_run(plan)
    if run != expected_run:
        raise ClosedLoopError("durable run identity differs from the exact plan")
    receipts: list[TypedRecord] = []
    outputs: list[TypedRecord] = []
    next_stage: str | None = STAGES[0]
    predecessor = plan.admitted_input
    terminal_state = None
    for sequence in range(len(STAGES)):
        receipt = transaction.get_record(_receipt_id(plan.run_ref, sequence))
        if receipt is None:
            break
        receipt.verify(CLOSED_LOOP_REPOSITORY_REGISTRY)
        payload = receipt.payload
        if (
            payload["run_ref"] != plan.run_ref
            or payload["sequence"] != sequence
            or payload["stage"] != next_stage
            or payload["predecessor"] != predecessor.payload()
            or payload["authorities"]
            != [authority.payload() for authority in _authorities(plan, payload["stage"])]
        ):
            raise IntegrityFailure("durable closed-loop step broke its predecessor chain")
        invocation = transaction.get_record(payload["invocation"]["record_id"])
        output = transaction.get_record(payload["output"]["record_id"])
        expected_invocation = _build_invocation(
            plan,
            StageInvocation(
                plan.run_ref,
                plan.context_ref,
                sequence,
                payload["stage"],
                predecessor,
                _authorities(plan, payload["stage"]),
            ),
        )
        if (
            invocation != expected_invocation
            or invocation.content_digest != payload["invocation"]["digest"]
            or output is None
            or ExactTypedRecord.of(output).payload() != payload["output"]
        ):
            raise IntegrityFailure("durable closed-loop step lost materialized facts")
        expected_receipt = _build_step_receipt(
            plan,
            StageInvocation(
                plan.run_ref,
                plan.context_ref,
                sequence,
                payload["stage"],
                predecessor,
                _authorities(plan, payload["stage"]),
            ),
            expected_invocation,
            RepositoryStageResult(payload["owner"], payload["decision"], output),
        )
        if receipt != expected_receipt:
            raise IntegrityFailure("durable closed-loop step is not the exact receipt")
        event = transaction.get_domain_event(_run_id(plan.run_ref), sequence)
        expected_event = DomainEvent(
            event_id=_stable_id("closed-loop-event", plan.run_ref, sequence),
            subject_id=_run_id(plan.run_ref),
            subject_kind="closed_loop_run",
            sequence=sequence,
            event_type="closed_loop_step_completed",
            payload_record_id=receipt.record_id,
            actor_authority_ref=_authorities(plan, payload["stage"])[0].ref,
        )
        if event != expected_event:
            raise IntegrityFailure("durable closed-loop step event is missing or changed")
        receipts.append(receipt)
        outputs.append(output)
        predecessor = ExactTypedRecord.of(output)
        next_stage = payload["next_stage"]
        terminal_state = payload["terminal_state"]
        if terminal_state is not None:
            break
    terminal = _load_terminal(transaction, plan)
    if terminal_state is None:
        if terminal is not None:
            raise IntegrityFailure("non-terminal closed-loop run has a completion")
    elif terminal != _build_terminal(
        plan, tuple(receipts), tuple(outputs), terminal_state
    ):
        raise IntegrityFailure("terminal closed-loop completion differs from its steps")
    elif transaction.get_domain_event(terminal.record_id, 0) != _terminal_event(
        plan, terminal, receipts[-1].payload["stage"]
    ):
        raise IntegrityFailure("terminal closed-loop event is missing or changed")
    return _DurableState(
        tuple(receipts), tuple(outputs), next_stage, predecessor, terminal_state
    )


def _load_terminal(
    transaction: V3Transaction, plan: ClosedLoopPlan
) -> TypedRecord | None:
    terminal = transaction.get_record(_terminal_id(plan.run_ref))
    if terminal is not None:
        terminal.verify(CLOSED_LOOP_REPOSITORY_REGISTRY)
    return terminal


__all__ = [
    "CLOSED_LOOP_RUN_SCHEMA_ID",
    "CLOSED_LOOP_INVOCATION_SCHEMA_ID",
    "CLOSED_LOOP_STEP_RECEIPT_SCHEMA_ID",
    "CLOSED_LOOP_TERMINAL_SCHEMA_ID",
    "CLOSED_LOOP_REPOSITORY_REGISTRY",
    "RepositoryStageResult",
    "RepositoryStageService",
    "RepositoryClosedLoopServices",
    "RepositoryStepResult",
    "RepositoryClosedLoopResult",
    "RepositoryClosedLoopCoordinator",
    "build_monitor_conclusion",
]
