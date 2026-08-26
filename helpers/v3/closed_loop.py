"""Outside-in deterministic closed-loop sequencing for v3.

The service in this module owns no domain mutation and contains no provider,
replay, policy, canary, activation, or rollback algorithm.  Those authorities
are injected as exact stage services.  The orchestrator only enforces the
accepted ordering, typed output contracts, predecessor binding, frozen stage
authorities, and the separation between workers, pure reducers, and owning
coordinators.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Protocol

from .activation_transition import ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID
from .canary import CANARY_CONCLUSION_SCHEMA_ID, CANARY_TRIAL_SCHEMA_ID
from .candidate_publication import IMPROVEMENT_CANDIDATE_SCHEMA_ID
from .deterministic_analysis import (
    ANALYSIS_ATTEMPT_SCHEMA_ID,
    OBSERVATION_FACT_SCHEMA_ID,
    SAFE_ANALYSIS_VIEW_SCHEMA_ID,
)
from .evidence import ACTIVATION_DISPOSITION_SCHEMA_ID
from .replay_adapter import REPLAY_PAIR_RECEIPT_SCHEMA_ID
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    schema_digest,
    strict_boolean,
    strict_enum,
    strict_integer,
    strict_list,
    strict_literal,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


CLOSED_LOOP_STAGE_RECEIPT_SCHEMA_ID = "a0.closed-loop-stage-receipt.v1"
CLOSED_LOOP_COMPLETION_SCHEMA_ID = "a0.closed-loop-completion.v1"
MONITOR_CONCLUSION_SCHEMA_ID = "a0.post-promotion-monitor-conclusion.v1"

STAGES = (
    "observation",
    "safe_analysis_view",
    "analysis_attempt",
    "candidate_publication",
    "certified_replay",
    "evidence_reduction",
    "canary_start",
    "canary_conclusion",
    "activation",
    "monitor_conclusion",
    "rollback",
)


@dataclass(frozen=True, slots=True)
class _StageContract:
    owner: str
    decision: str
    output_schema_id: str
    output_record_kind: str
    committed: bool


STAGE_CONTRACTS: Mapping[str, _StageContract] = {
    "observation": _StageContract(
        "observation_coordinator",
        "observation_recorded",
        OBSERVATION_FACT_SCHEMA_ID,
        "analysis_observation_fact",
        True,
    ),
    "safe_analysis_view": _StageContract(
        "deterministic_analysis_service",
        "safe_view_built",
        SAFE_ANALYSIS_VIEW_SCHEMA_ID,
        "safe_analysis_view",
        False,
    ),
    "analysis_attempt": _StageContract(
        "analysis_worker",
        "deterministic_attempt_completed",
        ANALYSIS_ATTEMPT_SCHEMA_ID,
        "analysis_attempt",
        False,
    ),
    "candidate_publication": _StageContract(
        "work_coordinator",
        "candidate_locked",
        IMPROVEMENT_CANDIDATE_SCHEMA_ID,
        "improvement_candidate",
        True,
    ),
    "certified_replay": _StageContract(
        "replay_pair_orchestrator",
        "certified_pair_completed",
        REPLAY_PAIR_RECEIPT_SCHEMA_ID,
        "replay_pair_receipt",
        True,
    ),
    "evidence_reduction": _StageContract(
        "evidence_reducer",
        "promotion_ready",
        ACTIVATION_DISPOSITION_SCHEMA_ID,
        "activation_disposition",
        False,
    ),
    "canary_start": _StageContract(
        "canary_coordinator",
        "authoritative_canary_started",
        CANARY_TRIAL_SCHEMA_ID,
        "canary_trial",
        True,
    ),
    "canary_conclusion": _StageContract(
        "canary_coordinator",
        "authoritative_canary_passed",
        CANARY_CONCLUSION_SCHEMA_ID,
        "canary_conclusion",
        True,
    ),
    "activation": _StageContract(
        "activation_coordinator",
        "candidate_activated_monitor_started",
        ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID,
        "activation_transition_receipt",
        True,
    ),
    "monitor_conclusion": _StageContract(
        "activation_coordinator",
        "rollback_required",
        MONITOR_CONCLUSION_SCHEMA_ID,
        "post_promotion_monitor_conclusion",
        True,
    ),
    "rollback": _StageContract(
        "activation_coordinator",
        "predecessor_restored",
        ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID,
        "activation_transition_receipt",
        True,
    ),
}

OWNERS = tuple(sorted({contract.owner for contract in STAGE_CONTRACTS.values()}))
DECISIONS = tuple(contract.decision for contract in STAGE_CONTRACTS.values())
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")


class ClosedLoopError(RuntimeError):
    """A stage broke the frozen ordering, input, type, owner, or gate contract."""


@dataclass(frozen=True, slots=True)
class ExactTypedRecord:
    record_id: str
    digest: str
    schema_id: str
    record_kind: str
    context_ref: str

    def __post_init__(self) -> None:
        for name in ("record_id", "schema_id", "record_kind", "context_ref"):
            value = getattr(self, name)
            if type(value) is not str or _OPAQUE.fullmatch(value) is None:
                raise ClosedLoopError(f"{name} must be a bounded opaque value")
        try:
            validate_digest(self.digest, "digest")
        except SchemaValidationError as exc:
            raise ClosedLoopError("typed record digest is not exact") from exc

    @classmethod
    def of(cls, record: TypedRecord) -> "ExactTypedRecord":
        if type(record) is not TypedRecord or record.context_ref is None:
            raise ClosedLoopError("stage output must be one exact context-bound record")
        return cls(
            record.record_id,
            record.content_digest,
            record.schema_id,
            record.record_kind,
            record.context_ref,
        )

    def payload(self) -> dict[str, str]:
        return {
            "record_id": self.record_id,
            "digest": self.digest,
            "schema_id": self.schema_id,
            "record_kind": self.record_kind,
            "context_ref": self.context_ref,
        }


@dataclass(frozen=True, slots=True)
class ExactAuthority:
    ref: str
    digest: str

    def __post_init__(self) -> None:
        if type(self.ref) is not str or _OPAQUE.fullmatch(self.ref) is None:
            raise ClosedLoopError("authority ref must be bounded and opaque")
        try:
            validate_digest(self.digest, "authority.digest")
        except SchemaValidationError as exc:
            raise ClosedLoopError("authority digest is not exact") from exc

    def payload(self) -> dict[str, str]:
        return {"ref": self.ref, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class StageAuthorities:
    stage: str
    authorities: tuple[ExactAuthority, ...]

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise ClosedLoopError("authority set has an unknown stage")
        if type(self.authorities) is not tuple:
            raise ClosedLoopError("stage authorities must be a frozen tuple")
        if any(type(item) is not ExactAuthority for item in self.authorities):
            raise ClosedLoopError("stage authority set contains an invalid identity")
        refs = tuple(item.ref for item in self.authorities)
        if refs != tuple(sorted(refs)) or len(refs) != len(set(refs)):
            raise ClosedLoopError("stage authorities must be sorted and unique")


@dataclass(frozen=True, slots=True)
class ClosedLoopPlan:
    run_ref: str
    context_ref: str
    key_epoch: str
    admitted_input: ExactTypedRecord
    stage_authorities: tuple[StageAuthorities, ...]

    def __post_init__(self) -> None:
        for name in ("run_ref", "context_ref", "key_epoch"):
            value = getattr(self, name)
            if type(value) is not str or _OPAQUE.fullmatch(value) is None:
                raise ClosedLoopError(f"{name} must be bounded and opaque")
        if self.admitted_input.context_ref != self.context_ref:
            raise ClosedLoopError("initial admitted input belongs to another context")
        if tuple(item.stage for item in self.stage_authorities) != STAGES:
            raise ClosedLoopError("plan must explicitly freeze authorities for every stage")


@dataclass(frozen=True, slots=True)
class StageInvocation:
    run_ref: str
    context_ref: str
    sequence: int
    stage: str
    predecessor: ExactTypedRecord
    authorities: tuple[ExactAuthority, ...]


@dataclass(frozen=True, slots=True)
class StageResult:
    stage: str
    run_ref: str
    context_ref: str
    predecessor: ExactTypedRecord
    authorities: tuple[ExactAuthority, ...]
    owner: str
    decision: str
    output: ExactTypedRecord
    committed: bool


class StageService(Protocol):
    def __call__(self, invocation: StageInvocation) -> StageResult: ...


@dataclass(frozen=True, slots=True)
class ClosedLoopServices:
    observation: StageService
    safe_analysis_view: StageService
    analysis_attempt: StageService
    candidate_publication: StageService
    certified_replay: StageService
    evidence_reduction: StageService
    canary_start: StageService
    canary_conclusion: StageService
    activation: StageService
    monitor_conclusion: StageService
    rollback: StageService

    def ordered(self) -> tuple[StageService, ...]:
        result = tuple(getattr(self, stage) for stage in STAGES)
        if any(not callable(service) for service in result):
            raise ClosedLoopError("every closed-loop stage requires an injected service")
        return result


@dataclass(frozen=True, slots=True)
class ClosedLoopResult:
    stage_results: tuple[StageResult, ...]
    stage_receipts: tuple[TypedRecord, ...]
    completion: TypedRecord


_EXACT_RECORD_VALIDATOR = strict_object(
    {
        "record_id": strict_string(maximum=512),
        "digest": validate_digest,
        "schema_id": strict_string(maximum=512),
        "record_kind": strict_string(maximum=128),
        "context_ref": strict_string(maximum=512),
    }
)
_AUTHORITY_VALIDATOR = strict_object(
    {"ref": strict_string(maximum=512), "digest": validate_digest}
)


def _stage_receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("closed_loop_stage_receipt"),
            "run_ref": strict_string(maximum=512),
            "sequence": strict_integer(minimum=0, maximum=len(STAGES) - 1),
            "stage": strict_enum(STAGES),
            "owner": strict_enum(OWNERS),
            "decision": strict_enum(DECISIONS),
            "predecessor": _EXACT_RECORD_VALIDATOR,
            "authorities": strict_list(_AUTHORITY_VALIDATOR, maximum=128),
            "output": _EXACT_RECORD_VALIDATOR,
            "committed": strict_boolean(),
            "worker_activation_authority": strict_literal("none"),
            "links": validate_links,
        }
    )(value, path)
    contract = STAGE_CONTRACTS[payload["stage"]]
    if payload["sequence"] != STAGES.index(payload["stage"]):
        raise SchemaValidationError(f"{path}.sequence disagrees with the fixed flow")
    if (
        payload["owner"] != contract.owner
        or payload["decision"] != contract.decision
        or payload["committed"] != contract.committed
        or payload["output"]["schema_id"] != contract.output_schema_id
        or payload["output"]["record_kind"] != contract.output_record_kind
    ):
        raise SchemaValidationError(f"{path} violates the fixed stage contract")
    expected_links = [
        _link("predecessor", 0, payload["predecessor"]["record_id"], payload["predecessor"]["digest"]),
        _link("output", 0, payload["output"]["record_id"], payload["output"]["digest"]),
        *(
            _link("authority", ordinal, item["ref"], item["digest"])
            for ordinal, item in enumerate(payload["authorities"])
        ),
    ]
    if payload["links"] != expected_links:
        raise SchemaValidationError(f"{path}.links do not bind exact stage inputs and output")
    return payload


def _completion_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("closed_loop_completion"),
            "run_ref": strict_string(maximum=512),
            "terminal_state": strict_literal("rolled_back"),
            "completed_stages": strict_list(
                strict_enum(STAGES), minimum=len(STAGES), maximum=len(STAGES)
            ),
            "initial_input": _EXACT_RECORD_VALIDATOR,
            "final_output": _EXACT_RECORD_VALIDATOR,
            "stage_outputs": strict_list(
                _EXACT_RECORD_VALIDATOR, minimum=len(STAGES), maximum=len(STAGES)
            ),
            "stage_receipts": strict_list(
                _AUTHORITY_VALIDATOR, minimum=len(STAGES), maximum=len(STAGES)
            ),
            "worker_activation_observed": strict_literal(False),
            "links": validate_links,
        }
    )(value, path)
    if payload["completed_stages"] != list(STAGES):
        raise SchemaValidationError(f"{path}.completed_stages must be the exact closed loop")
    if payload["stage_outputs"][-1] != payload["final_output"]:
        raise SchemaValidationError(f"{path}.final_output is not the rollback result")
    expected_links = [
        *(
            _link("stage_receipt", ordinal, item["ref"], item["digest"])
            for ordinal, item in enumerate(payload["stage_receipts"])
        ),
        *(
            _link("stage_output", ordinal, item["record_id"], item["digest"])
            for ordinal, item in enumerate(payload["stage_outputs"])
        ),
    ]
    if payload["links"] != expected_links:
        raise SchemaValidationError(f"{path}.links do not bind every stage receipt and output")
    return payload


CLOSED_LOOP_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            CLOSED_LOOP_STAGE_RECEIPT_SCHEMA_ID,
            "closed_loop_stage_receipt",
            _stage_receipt_validator,
        ),
        RecordSchema(
            CLOSED_LOOP_COMPLETION_SCHEMA_ID,
            "closed_loop_completion",
            _completion_validator,
        ),
    )
)


def _link(role: str, ordinal: int, target_id: str, target_digest: str) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": target_id,
        "target_digest": target_digest,
    }


def _record(
    *,
    record_kind: str,
    schema_id: str,
    context_ref: str,
    key_epoch: str,
    payload: Mapping[str, Any],
) -> TypedRecord:
    encoded = canonical_json(dict(payload))
    return build_typed_record(
        record_id=record_kind + "_" + schema_digest("record-identity", schema_id, encoded),
        context_ref=context_ref,
        record_kind=record_kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=key_epoch,
        registry=CLOSED_LOOP_REGISTRY,
    )


def _validate_result(invocation: StageInvocation, result: StageResult) -> None:
    if type(result) is not StageResult:
        raise ClosedLoopError(f"{invocation.stage} returned no exact StageResult")
    contract = STAGE_CONTRACTS[invocation.stage]
    if (
        result.stage != invocation.stage
        or result.run_ref != invocation.run_ref
        or result.context_ref != invocation.context_ref
        or result.predecessor != invocation.predecessor
        or result.authorities != invocation.authorities
    ):
        raise ClosedLoopError(f"{invocation.stage} changed frozen invocation authority")
    if result.owner != contract.owner:
        raise ClosedLoopError(f"{invocation.stage} returned under the wrong authority owner")
    if result.decision != contract.decision:
        raise ClosedLoopError(f"{invocation.stage} did not satisfy its exact gate")
    if type(result.committed) is not bool or result.committed != contract.committed:
        raise ClosedLoopError(f"{invocation.stage} misstated its mutation boundary")
    if (
        result.output.schema_id != contract.output_schema_id
        or result.output.record_kind != contract.output_record_kind
        or result.output.context_ref != invocation.context_ref
    ):
        raise ClosedLoopError(f"{invocation.stage} returned the wrong typed output")
    if invocation.stage in ("activation", "rollback") and result.owner == "analysis_worker":
        raise ClosedLoopError("workers never own activation or rollback")


def _stage_receipt(invocation: StageInvocation, result: StageResult, key_epoch: str) -> TypedRecord:
    payload = {
        "record_type": "closed_loop_stage_receipt",
        "run_ref": invocation.run_ref,
        "sequence": invocation.sequence,
        "stage": invocation.stage,
        "owner": result.owner,
        "decision": result.decision,
        "predecessor": invocation.predecessor.payload(),
        "authorities": [item.payload() for item in invocation.authorities],
        "output": result.output.payload(),
        "committed": result.committed,
        "worker_activation_authority": "none",
        "links": [
            _link("predecessor", 0, invocation.predecessor.record_id, invocation.predecessor.digest),
            _link("output", 0, result.output.record_id, result.output.digest),
            *(
                _link("authority", ordinal, item.ref, item.digest)
                for ordinal, item in enumerate(invocation.authorities)
            ),
        ],
    }
    return _record(
        record_kind="closed_loop_stage_receipt",
        schema_id=CLOSED_LOOP_STAGE_RECEIPT_SCHEMA_ID,
        context_ref=invocation.context_ref,
        key_epoch=key_epoch,
        payload=payload,
    )


class DeterministicClosedLoopCoordinator:
    """Sequence already-admitted exact services through rollback, without fallback."""

    def __init__(self, services: ClosedLoopServices) -> None:
        if type(services) is not ClosedLoopServices:
            raise ClosedLoopError("closed loop requires explicit injected services")
        self._services = services

    def run(self, plan: ClosedLoopPlan) -> ClosedLoopResult:
        if type(plan) is not ClosedLoopPlan:
            raise ClosedLoopError("run requires one exact ClosedLoopPlan")
        services = self._services.ordered()
        predecessor = plan.admitted_input
        results: list[StageResult] = []
        receipts: list[TypedRecord] = []
        for sequence, (stage, authority_set, service) in enumerate(
            zip(STAGES, plan.stage_authorities, services, strict=True)
        ):
            invocation = StageInvocation(
                run_ref=plan.run_ref,
                context_ref=plan.context_ref,
                sequence=sequence,
                stage=stage,
                predecessor=predecessor,
                authorities=authority_set.authorities,
            )
            result = service(invocation)
            _validate_result(invocation, result)
            receipt = _stage_receipt(invocation, result, plan.key_epoch)
            results.append(result)
            receipts.append(receipt)
            predecessor = result.output

        outputs = [item.output.payload() for item in results]
        completion_payload = {
            "record_type": "closed_loop_completion",
            "run_ref": plan.run_ref,
            "terminal_state": "rolled_back",
            "completed_stages": list(STAGES),
            "initial_input": plan.admitted_input.payload(),
            "final_output": results[-1].output.payload(),
            "stage_outputs": outputs,
            "stage_receipts": [
                {"ref": receipt.record_id, "digest": receipt.content_digest}
                for receipt in receipts
            ],
            "worker_activation_observed": False,
            "links": [
                *(
                    _link("stage_receipt", ordinal, receipt.record_id, receipt.content_digest)
                    for ordinal, receipt in enumerate(receipts)
                ),
                *(
                    _link("stage_output", ordinal, result.output.record_id, result.output.digest)
                    for ordinal, result in enumerate(results)
                ),
            ],
        }
        completion = _record(
            record_kind="closed_loop_completion",
            schema_id=CLOSED_LOOP_COMPLETION_SCHEMA_ID,
            context_ref=plan.context_ref,
            key_epoch=plan.key_epoch,
            payload=completion_payload,
        )
        return ClosedLoopResult(tuple(results), tuple(receipts), completion)


__all__ = [name for name in globals() if not name.startswith("_")]
