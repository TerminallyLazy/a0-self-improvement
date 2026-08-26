"""Certified, fixture-only paired replay contracts.

This module is deliberately transport- and framework-agnostic.  A provider
adapter is injected, receives one frozen invocation snapshot per arm, and has
access only to an inert fixture continuation gateway.  The orchestrator emits
content-free receipts; fixture input, state, arguments, and provider output are
never copied into those receipts.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
import secrets
import time
from typing import Any, Callable, Mapping, Protocol, Sequence

from .fixtures import (
    FIXTURE_CONTENT_SCHEMA_ID,
    FIXTURE_REGISTRY,
    FixtureAdmission,
    FixtureDraft,
    _CONTENT_VALIDATOR,
)
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    TypedRecord,
    build_typed_record,
    canonical_json,
    schema_digest,
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


REPLAY_INVOCATION_SCHEMA_ID = "a0.replay-invocation.v1"
REPLAY_PAIR_RECEIPT_SCHEMA_ID = "a0.replay-pair-receipt.v1"

ARM_OUTCOMES = (
    "completed",
    "deterministic_failure",
    "availability_failure",
    "cancelled",
    "harness_failure",
)
REASON_CODES = (
    "completed",
    "expected_outcome_mismatch",
    "provider_unavailable",
    "provider_timeout",
    "cancelled",
    "budget_exhausted",
    "live_tool_dispatch_denied",
    "provider_hosted_tool_execution_denied",
    "fixture_contract_mismatch",
    "schema_invalid",
    "transport_invalid",
    "harness_error",
)

_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
_MAX_AUTHORITY_INTEGER = (1 << 63) - 1


class ReplayError(RuntimeError):
    """Base class for certified replay failures."""


class ReplayContractError(ReplayError):
    """Raised before dispatch when exact replay bindings are invalid."""


class FixtureToolViolation(ReplayError):
    """Raised when replay attempts anything except inert fixture continuation."""


@dataclass(frozen=True, slots=True)
class ExactIdentity:
    ref: str
    digest: str

    def __post_init__(self) -> None:
        _require_opaque_ref(self.ref, "identity.ref")
        _require_digest(self.digest, "identity.digest")


@dataclass(frozen=True, slots=True)
class LockedCandidateIdentity:
    artifact: ExactIdentity
    lock_receipt: ExactIdentity


@dataclass(frozen=True, slots=True)
class ReplayCapabilityIdentity:
    certificate: ExactIdentity
    runtime_digest: str
    replay_adapter_digest: str
    live_tool_dispatch_disabled: bool = True
    provider_hosted_tools_disabled: bool = True

    def __post_init__(self) -> None:
        _require_digest(self.runtime_digest, "capability.runtime_digest")
        _require_digest(self.replay_adapter_digest, "capability.replay_adapter_digest")
        if self.live_tool_dispatch_disabled is not True:
            raise ReplayContractError("capability must disable live tool dispatch")
        if self.provider_hosted_tools_disabled is not True:
            raise ReplayContractError("capability must disable provider-hosted tools")


@dataclass(frozen=True, slots=True)
class ReplayBounds:
    """Exact per-arm ceilings; all dimensions are integer authority inputs."""

    max_wall_time_ms: int
    max_model_calls: int
    max_turns: int
    max_fixture_calls: int
    max_tokens: int
    max_output_bytes: int
    max_cost_microunits: int

    def __post_init__(self) -> None:
        for field, minimum in (
            ("max_wall_time_ms", 1),
            ("max_model_calls", 0),
            ("max_turns", 1),
            ("max_fixture_calls", 0),
            ("max_tokens", 0),
            ("max_output_bytes", 1),
            ("max_cost_microunits", 0),
        ):
            _require_authority_integer(getattr(self, field), field, minimum=minimum)

    def as_dict(self) -> dict[str, int]:
        return {
            "max_wall_time_ms": self.max_wall_time_ms,
            "max_model_calls": self.max_model_calls,
            "max_turns": self.max_turns,
            "max_fixture_calls": self.max_fixture_calls,
            "max_tokens": self.max_tokens,
            "max_output_bytes": self.max_output_bytes,
            "max_cost_microunits": self.max_cost_microunits,
        }


@dataclass(frozen=True, slots=True)
class ReplayArmUsage:
    wall_time_ms: int
    model_calls: int
    turns: int
    fixture_calls: int
    tokens: int
    output_bytes: int
    cost_microunits: int

    def __post_init__(self) -> None:
        for field in (
            "wall_time_ms",
            "model_calls",
            "turns",
            "fixture_calls",
            "tokens",
            "output_bytes",
            "cost_microunits",
        ):
            _require_authority_integer(getattr(self, field), field, minimum=0)

    @classmethod
    def zero(cls, *, wall_time_ms: int = 0, fixture_calls: int = 0) -> "ReplayArmUsage":
        return cls(wall_time_ms, 0, 0, fixture_calls, 0, 0, 0)

    def as_dict(self) -> dict[str, int]:
        return {
            "wall_time_ms": self.wall_time_ms,
            "model_calls": self.model_calls,
            "turns": self.turns,
            "fixture_calls": self.fixture_calls,
            "tokens": self.tokens,
            "output_bytes": self.output_bytes,
            "cost_microunits": self.cost_microunits,
        }


@dataclass(frozen=True, slots=True)
class ProviderArmReport:
    """Strict content-free facts returned by an injected provider adapter."""

    arm: str
    subject: ExactIdentity
    outcome: str
    reason_code: str
    usage: ReplayArmUsage
    live_tool_dispatches: int = 0
    provider_hosted_tool_executions: int = 0

    def __post_init__(self) -> None:
        if self.arm not in ("candidate", "incumbent"):
            raise ReplayContractError("provider report has an invalid replay arm")
        if self.outcome not in ARM_OUTCOMES or self.reason_code not in REASON_CODES:
            raise ReplayContractError("provider report has an invalid outcome or reason")
        if self.reason_code not in _REASONS_BY_OUTCOME[self.outcome]:
            raise ReplayContractError("provider report outcome and reason do not agree")
        _require_authority_integer(
            self.live_tool_dispatches, "live_tool_dispatches", minimum=0
        )
        _require_authority_integer(
            self.provider_hosted_tool_executions,
            "provider_hosted_tool_executions",
            minimum=0,
        )


@dataclass(frozen=True, slots=True)
class ReplayObservedCounters:
    """Counters read from an injected observation boundary, not a report claim."""

    model_calls: int
    turns: int
    tokens: int
    output_bytes: int
    cost_microunits: int
    live_tool_dispatches: int
    provider_hosted_tool_executions: int

    def __post_init__(self) -> None:
        for field in (
            "model_calls",
            "turns",
            "tokens",
            "output_bytes",
            "cost_microunits",
            "live_tool_dispatches",
            "provider_hosted_tool_executions",
        ):
            _require_authority_integer(getattr(self, field), field, minimum=0)


@dataclass(frozen=True, slots=True)
class FrozenInvocationSnapshot:
    canonical_bytes: bytes
    digest: str

    def __post_init__(self) -> None:
        if type(self.canonical_bytes) is not bytes or not self.canonical_bytes:
            raise ReplayContractError("frozen invocation must be non-empty canonical bytes")
        _require_digest(self.digest, "snapshot.digest")
        expected = schema_digest(
            "replay-invocation", REPLAY_INVOCATION_SCHEMA_ID, self.canonical_bytes
        )
        if expected != self.digest:
            raise ReplayContractError("frozen invocation digest mismatch")


@dataclass(frozen=True, slots=True)
class ReplayArmInvocation:
    arm: str
    subject: ExactIdentity
    fresh_state_ref: str
    frozen_snapshot: bytes
    frozen_snapshot_digest: str
    bounds: ReplayBounds
    provider_hosted_tools_enabled: bool = False
    live_tool_dispatch_enabled: bool = False

    def __post_init__(self) -> None:
        if self.arm not in ("candidate", "incumbent"):
            raise ReplayContractError("invalid replay arm")
        _require_opaque_ref(self.fresh_state_ref, "fresh_state_ref")
        if type(self.frozen_snapshot) is not bytes or not self.frozen_snapshot:
            raise ReplayContractError("arm invocation has no frozen snapshot")
        _require_digest(self.frozen_snapshot_digest, "frozen_snapshot_digest")
        if self.provider_hosted_tools_enabled is not False:
            raise ReplayContractError("provider-hosted tools must be disabled")
        if self.live_tool_dispatch_enabled is not False:
            raise ReplayContractError("live tool dispatch must be disabled")


@dataclass(frozen=True, slots=True)
class FixtureToolContinuation:
    ordinal: int
    response_digest: str
    state_transition_ref: str


class FixtureToolGateway:
    """Ordered fixture continuation with no live dispatcher or response content."""

    def __init__(self, steps: Sequence[Mapping[str, Any]], *, call_limit: int) -> None:
        self._steps = tuple(dict(step) for step in steps)
        self._call_limit = call_limit
        self._next = 0
        self._violation_reason: str | None = None
        self._live_dispatch_attempts = 0

    @property
    def calls(self) -> int:
        return self._next

    @property
    def violation_reason(self) -> str | None:
        return self._violation_reason

    @property
    def live_dispatch_attempts(self) -> int:
        return self._live_dispatch_attempts

    def continue_fixture_tool(
        self, *, tool_contract_ref: str, arguments: Mapping[str, Any]
    ) -> FixtureToolContinuation:
        """Consume exactly the next inert fixture step."""

        if self._next >= self._call_limit:
            self._deny("budget_exhausted")
        if self._next >= len(self._steps):
            self._deny("fixture_contract_mismatch")
        step = self._steps[self._next]
        if tool_contract_ref != step["tool_contract_ref"]:
            self._deny("fixture_contract_mismatch")
        actual = fixture_argument_digest(tool_contract_ref, arguments)
        if actual != step["argument_matcher_digest"]:
            self._deny("fixture_contract_mismatch")
        ordinal = self._next
        self._next += 1
        return FixtureToolContinuation(
            ordinal=ordinal,
            response_digest=step["response_digest"],
            state_transition_ref=step["state_transition_ref"],
        )

    def dispatch_live_tool(self, *_args: Any, **_kwargs: Any) -> None:
        """Explicit fail-closed surface for adapters attempting live dispatch."""

        self._live_dispatch_attempts += 1
        self._deny("live_tool_dispatch_denied")

    def _deny(self, reason_code: str) -> None:
        self._violation_reason = reason_code
        raise FixtureToolViolation(reason_code)


class ReplayProvider(Protocol):
    def execute_arm(
        self, invocation: ReplayArmInvocation, fixture_tools: FixtureToolGateway
    ) -> ProviderArmReport: ...


ReplayCounterReader = Callable[[ReplayArmInvocation], ReplayObservedCounters]


@dataclass(frozen=True, slots=True)
class ReplayBindings:
    fixture: FixtureDraft
    admission: FixtureAdmission
    manifest: TypedRecord
    execution_profile: TypedRecord
    assessment_profile: TypedRecord
    candidate: LockedCandidateIdentity
    incumbent: ExactIdentity
    capability: ReplayCapabilityIdentity


@dataclass(frozen=True, slots=True)
class ReplayPairRequest:
    issuer_ref: str
    subject_ref: str
    context_ref: str
    pair_attempt_ref: str
    idempotency_key_digest: str
    bindings: ReplayBindings
    fixture_content: Mapping[str, Any]
    bounds: ReplayBounds
    retry_of: ExactIdentity | None = None

    def __post_init__(self) -> None:
        _require_opaque_ref(self.issuer_ref, "issuer_ref")
        _require_opaque_ref(self.subject_ref, "subject_ref")
        _require_opaque_ref(self.context_ref, "context_ref")
        _require_opaque_ref(self.pair_attempt_ref, "pair_attempt_ref")
        _require_digest(self.idempotency_key_digest, "idempotency_key_digest")
        if type(self.fixture_content) is not dict:
            raise ReplayContractError("fixture_content must be a strict mapping")


@dataclass(frozen=True, slots=True)
class ReplayPairResult:
    snapshot: FrozenInvocationSnapshot
    candidate: ProviderArmReport
    incumbent: ProviderArmReport
    receipt: TypedRecord


_REASONS_BY_OUTCOME = {
    "completed": frozenset(("completed",)),
    "deterministic_failure": frozenset(("expected_outcome_mismatch",)),
    "availability_failure": frozenset(("provider_unavailable", "provider_timeout")),
    "cancelled": frozenset(("cancelled",)),
    "harness_failure": frozenset(
        (
            "budget_exhausted",
            "live_tool_dispatch_denied",
            "provider_hosted_tool_execution_denied",
            "fixture_contract_mismatch",
            "schema_invalid",
            "transport_invalid",
            "harness_error",
        )
    ),
}


_USAGE_VALIDATOR = strict_object(
    {
        "wall_time_ms": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
        "model_calls": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
        "turns": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
        "fixture_calls": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
        "tokens": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
        "output_bytes": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
        "cost_microunits": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
    }
)


_ARM_RECEIPT_VALIDATOR = strict_object(
    {
        "arm": strict_enum(("candidate", "incumbent")),
        "subject_ref": strict_string(maximum=512),
        "subject_digest": validate_digest,
        "fresh_state_ref": strict_string(maximum=512),
        "outcome": strict_enum(ARM_OUTCOMES),
        "reason_code": strict_enum(REASON_CODES),
        "usage": _USAGE_VALIDATOR,
        "live_tool_dispatches": strict_integer(
            minimum=0, maximum=_MAX_AUTHORITY_INTEGER
        ),
        "provider_hosted_tool_executions": strict_integer(
            minimum=0, maximum=_MAX_AUTHORITY_INTEGER
        ),
        "activation_evidence_eligible": strict_boolean(),
    }
)


_PAIR_RECEIPT_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("replay_pair_receipt"),
        "issuer_ref": strict_string(maximum=512),
        "subject_ref": strict_string(maximum=512),
        "context_ref": strict_string(maximum=512),
        "pair_attempt_ref": strict_string(maximum=512),
        "idempotency_key_digest": validate_digest,
        "request_digest": validate_digest,
        "retry_of_receipt_ref": strict_nullable(strict_string(maximum=512)),
        "retry_of_receipt_digest": strict_nullable(validate_digest),
        "frozen_snapshot_digest": validate_digest,
        "arms": strict_list(_ARM_RECEIPT_VALIDATOR, minimum=2, maximum=2),
        "activation_evidence_eligible": strict_boolean(),
        "links": validate_links,
    }
)


REPLAY_REGISTRY = SchemaRegistry(
    (
        *FIXTURE_REGISTRY.schemas.values(),
        RecordSchema(
            REPLAY_PAIR_RECEIPT_SCHEMA_ID,
            "replay_pair_receipt",
            _PAIR_RECEIPT_VALIDATOR,
        ),
    )
)


class ReplayPairOrchestrator:
    """Run both replay arms from one snapshot and emit one paired receipt."""

    def __init__(
        self,
        provider: ReplayProvider,
        *,
        counter_reader: ReplayCounterReader,
        nonce_factory: Callable[[], str] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        key_epoch: str = "replay-v1",
    ) -> None:
        if not callable(getattr(provider, "execute_arm", None)):
            raise ReplayContractError("provider does not implement ReplayProvider")
        if not callable(counter_reader):
            raise ReplayContractError("counter_reader must be callable")
        self._provider = provider
        self._counter_reader = counter_reader
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(16))
        self._monotonic = monotonic
        self._key_epoch = _require_opaque_ref(key_epoch, "key_epoch")

    def run_pair(self, request: ReplayPairRequest) -> ReplayPairResult:
        """Run a new whole pair; there is intentionally no single-arm API."""

        fixture = _validate_bindings(request.bindings)
        content = _CONTENT_VALIDATOR(dict(request.fixture_content), "fixture_content")
        content_bytes = canonical_json(content)
        expected = fixture.record.payload["content_digest"]
        actual = schema_digest("fixture-content", FIXTURE_CONTENT_SCHEMA_ID, content_bytes)
        if actual != expected:
            raise ReplayContractError("fixture content does not bind the exact admitted draft")
        _validate_bounds_against_fixture(request.bounds, content["execution_bounds"])
        snapshot = _freeze_snapshot(request, content)

        state_refs = (self._fresh_state_ref(), self._fresh_state_ref())
        if state_refs[0] == state_refs[1]:
            raise ReplayContractError("both replay arms require distinct fresh state")
        candidate = self._run_arm(
            arm="candidate",
            subject=request.bindings.candidate.artifact,
            state_ref=state_refs[0],
            snapshot=snapshot,
            bounds=request.bounds,
            tool_steps=content["tool_steps"],
        )
        incumbent = self._run_arm(
            arm="incumbent",
            subject=request.bindings.incumbent,
            state_ref=state_refs[1],
            snapshot=snapshot,
            bounds=request.bounds,
            tool_steps=content["tool_steps"],
        )
        receipt = _build_receipt(request, snapshot, candidate, incumbent, state_refs, self._key_epoch)
        return ReplayPairResult(snapshot, candidate, incumbent, receipt)

    def retry_pair(
        self, previous_receipt: TypedRecord, request: ReplayPairRequest
    ) -> ReplayPairResult:
        """Retry a failed pair from scratch; partial-arm continuation is impossible."""

        previous_receipt.verify(REPLAY_REGISTRY)
        if previous_receipt.record_kind != "replay_pair_receipt":
            raise ReplayContractError("retry authority is not a replay pair receipt")
        expected = ExactIdentity(previous_receipt.record_id, previous_receipt.content_digest)
        if request.retry_of != expected:
            raise ReplayContractError("retry does not bind the exact prior pair receipt")
        _require_same_binding_links(previous_receipt, request.bindings)
        return self.run_pair(request)

    def _fresh_state_ref(self) -> str:
        value = self._nonce_factory()
        return _require_opaque_ref(value, "fresh_state_ref")

    def _run_arm(
        self,
        *,
        arm: str,
        subject: ExactIdentity,
        state_ref: str,
        snapshot: FrozenInvocationSnapshot,
        bounds: ReplayBounds,
        tool_steps: Sequence[Mapping[str, Any]],
    ) -> ProviderArmReport:
        gateway = FixtureToolGateway(tool_steps, call_limit=bounds.max_fixture_calls)
        invocation = ReplayArmInvocation(
            arm=arm,
            subject=subject,
            fresh_state_ref=state_ref,
            frozen_snapshot=bytes(bytearray(snapshot.canonical_bytes)),
            frozen_snapshot_digest=snapshot.digest,
            bounds=bounds,
        )
        started = self._monotonic()
        report: ProviderArmReport | None = None
        provider_failure: str | None = None
        try:
            report = self._provider.execute_arm(invocation, gateway)
        except FixtureToolViolation:
            provider_failure = gateway.violation_reason or "fixture_contract_mismatch"
        except Exception:
            provider_failure = "harness_error"
        elapsed = _elapsed_ms(started, self._monotonic())
        try:
            counters = self._counter_reader(invocation)
        except Exception:
            counters = None
        if gateway.live_dispatch_attempts:
            return _harness_report(
                arm, subject, "live_tool_dispatch_denied", elapsed, gateway.calls
            )
        if type(counters) is not ReplayObservedCounters:
            return _harness_report(arm, subject, "harness_error", elapsed, gateway.calls)
        if counters.live_tool_dispatches:
            return _harness_report(
                arm, subject, "live_tool_dispatch_denied", elapsed, gateway.calls
            )
        if counters.provider_hosted_tool_executions:
            return _harness_report(
                arm,
                subject,
                "provider_hosted_tool_execution_denied",
                elapsed,
                gateway.calls,
            )
        if provider_failure is not None:
            return _harness_report(
                arm, subject, provider_failure, elapsed, gateway.calls
            )
        if type(report) is not ProviderArmReport:
            return _harness_report(arm, subject, "schema_invalid", elapsed, gateway.calls)
        if report.arm != arm or report.subject != subject:
            return _harness_report(arm, subject, "transport_invalid", elapsed, gateway.calls)
        if gateway.violation_reason is not None:
            return _harness_report(arm, subject, gateway.violation_reason, elapsed, gateway.calls)
        declared = report.usage
        if (
            report.live_tool_dispatches != counters.live_tool_dispatches
            or report.provider_hosted_tool_executions
            != counters.provider_hosted_tool_executions
            or declared.model_calls != counters.model_calls
            or declared.turns != counters.turns
            or declared.tokens != counters.tokens
            or declared.output_bytes != counters.output_bytes
            or declared.cost_microunits != counters.cost_microunits
        ):
            return _harness_report(arm, subject, "transport_invalid", elapsed, gateway.calls)
        observed_usage = ReplayArmUsage(
            wall_time_ms=max(elapsed, declared.wall_time_ms),
            model_calls=counters.model_calls,
            turns=counters.turns,
            fixture_calls=gateway.calls,
            tokens=counters.tokens,
            output_bytes=counters.output_bytes,
            cost_microunits=counters.cost_microunits,
        )
        if declared.fixture_calls != gateway.calls:
            return _harness_report(arm, subject, "transport_invalid", elapsed, gateway.calls)
        if not _within_bounds(observed_usage, bounds):
            return _harness_report(arm, subject, "budget_exhausted", elapsed, gateway.calls)
        return ProviderArmReport(
            arm=arm,
            subject=subject,
            outcome=report.outcome,
            reason_code=report.reason_code,
            usage=observed_usage,
            live_tool_dispatches=counters.live_tool_dispatches,
            provider_hosted_tool_executions=counters.provider_hosted_tool_executions,
        )


def fixture_argument_digest(tool_contract_ref: str, arguments: Mapping[str, Any]) -> str:
    """Digest exact fixture arguments without dispatching a tool."""

    _require_opaque_ref(tool_contract_ref, "tool_contract_ref")
    if type(arguments) is not dict:
        raise ReplayContractError("fixture arguments must be a strict mapping")
    return schema_digest(
        "fixture-tool-arguments", tool_contract_ref, canonical_json(dict(arguments))
    )


def replay_request_digest(request: ReplayPairRequest) -> str:
    """Digest exact replay authority without copying fixture plaintext."""

    if type(request) is not ReplayPairRequest:
        raise ReplayContractError("replay request must be exact")
    fixture = _validate_bindings(request.bindings)
    content = _CONTENT_VALIDATOR(dict(request.fixture_content), "fixture_content")
    content_bytes = canonical_json(content)
    content_digest = schema_digest(
        "fixture-content", FIXTURE_CONTENT_SCHEMA_ID, content_bytes
    )
    if content_digest != fixture.record.payload["content_digest"]:
        raise ReplayContractError("fixture content does not bind the exact admitted draft")
    _validate_bounds_against_fixture(request.bounds, content["execution_bounds"])
    bindings = request.bindings
    payload = {
        "issuer_ref": request.issuer_ref,
        "subject_ref": request.subject_ref,
        "context_ref": request.context_ref,
        "pair_attempt_ref": request.pair_attempt_ref,
        "idempotency_key_digest": request.idempotency_key_digest,
        "retry_of": _identity_mapping(request.retry_of),
        "fixture": _record_identity(bindings.fixture.record),
        "admission": _record_identity(bindings.admission.receipt),
        "eligibility": _record_identity(bindings.admission.eligibility),
        "manifest": _record_identity(bindings.manifest),
        "execution_profile": _record_identity(bindings.execution_profile),
        "assessment_profile": _record_identity(bindings.assessment_profile),
        "candidate": _identity_mapping(bindings.candidate.artifact),
        "candidate_lock": _identity_mapping(bindings.candidate.lock_receipt),
        "incumbent": _identity_mapping(bindings.incumbent),
        "capability": _identity_mapping(bindings.capability.certificate),
        "runtime_digest": bindings.capability.runtime_digest,
        "replay_adapter_digest": bindings.capability.replay_adapter_digest,
        "bounds": request.bounds.as_dict(),
        "fixture_content_digest": content_digest,
    }
    return schema_digest(
        "replay-pair-request", "a0.replay-pair-request.v1", canonical_json(payload)
    )


def freeze_replay_snapshot(request: ReplayPairRequest) -> FrozenInvocationSnapshot:
    """Rebuild the exact in-memory invocation snapshot for durable replay."""

    replay_request_digest(request)
    content = _CONTENT_VALIDATOR(dict(request.fixture_content), "fixture_content")
    return _freeze_snapshot(request, content)


def replay_binding_links(request: ReplayPairRequest) -> tuple[dict[str, Any], ...]:
    """Return the exact content-free prerequisite links for repository admission."""

    replay_request_digest(request)
    bindings = request.bindings
    links = [
        _record_link("fixture_draft", 0, bindings.fixture.record),
        _record_link("fixture_admission", 0, bindings.admission.receipt),
        _record_link("fixture_eligibility", 0, bindings.admission.eligibility),
        _record_link("fixture_manifest", 0, bindings.manifest),
        _record_link("execution_profile", 0, bindings.execution_profile),
        _record_link("assessment_profile", 0, bindings.assessment_profile),
        _identity_link("candidate_artifact", 0, bindings.candidate.artifact),
        _identity_link("candidate_lock_receipt", 0, bindings.candidate.lock_receipt),
        _identity_link("incumbent_artifact", 0, bindings.incumbent),
        _identity_link("replay_capability", 0, bindings.capability.certificate),
    ]
    if request.retry_of is not None:
        links.append(_identity_link("retry_of_pair_receipt", 0, request.retry_of))
    return tuple(links)


def replay_result_from_receipt(
    request: ReplayPairRequest, receipt: TypedRecord
) -> ReplayPairResult:
    """Reconstruct a content-bearing process result from a content-free receipt."""

    receipt.verify(REPLAY_REGISTRY)
    if (
        receipt.record_kind != "replay_pair_receipt"
        or receipt.record_id != _replay_receipt_id(replay_request_digest(request))
        or receipt.context_ref != request.context_ref
    ):
        raise ReplayContractError("durable replay receipt has the wrong exact identity")
    payload = receipt.payload
    if (
        payload["issuer_ref"] != request.issuer_ref
        or payload["subject_ref"] != request.subject_ref
        or payload["context_ref"] != request.context_ref
        or payload["pair_attempt_ref"] != request.pair_attempt_ref
        or payload["idempotency_key_digest"] != request.idempotency_key_digest
        or payload["request_digest"] != replay_request_digest(request)
        or payload["retry_of_receipt_ref"]
        != (request.retry_of.ref if request.retry_of else None)
        or payload["retry_of_receipt_digest"]
        != (request.retry_of.digest if request.retry_of else None)
    ):
        raise ReplayContractError("durable replay receipt differs from the exact request")
    expected_links = _binding_link_identities(request)
    actual_links = {
        (link.role, link.ordinal, link.target_id, link.target_digest)
        for link in receipt.links
    }
    if actual_links != expected_links:
        raise ReplayContractError("durable replay receipt links differ from the request")
    arms = payload["arms"]
    if [item["arm"] for item in arms] != ["candidate", "incumbent"]:
        raise ReplayContractError("durable replay receipt arm order is invalid")
    snapshot = freeze_replay_snapshot(request)
    if payload["frozen_snapshot_digest"] != snapshot.digest:
        raise ReplayContractError("durable replay receipt snapshot changed")
    if arms[0]["fresh_state_ref"] == arms[1]["fresh_state_ref"]:
        raise ReplayContractError("durable replay receipt reused arm state")
    candidate = _report_from_receipt_arm(
        arms[0], request.bindings.candidate.artifact
    )
    incumbent = _report_from_receipt_arm(arms[1], request.bindings.incumbent)
    expected_eligible = all(
        item.outcome in ("completed", "deterministic_failure")
        for item in (candidate, incumbent)
    )
    if payload["activation_evidence_eligible"] is not expected_eligible:
        raise ReplayContractError("durable replay receipt eligibility is invalid")
    return ReplayPairResult(snapshot, candidate, incumbent, receipt)


def _validate_bindings(bindings: ReplayBindings) -> FixtureDraft:
    if type(bindings.fixture) is not FixtureDraft or type(bindings.admission) is not FixtureAdmission:
        raise ReplayContractError("replay requires an exact fixture draft and admission")
    records = (
        (bindings.fixture.record, "fixture_draft"),
        (bindings.fixture.family, "fixture_family"),
        (bindings.admission.receipt, "fixture_admission_receipt"),
        (bindings.admission.eligibility, "fixture_eligibility_event"),
        (bindings.manifest, "fixture_manifest"),
        (bindings.execution_profile, "execution_profile"),
        (bindings.assessment_profile, "assessment_profile"),
    )
    for record, kind in records:
        record.verify(FIXTURE_REGISTRY)
        if record.record_kind != kind:
            raise ReplayContractError(f"replay binding is not {kind}")
    draft = bindings.fixture.record
    admission = bindings.admission.receipt.payload
    eligibility = bindings.admission.eligibility.payload
    if (admission["draft_id"], admission["draft_digest"]) != (
        draft.record_id,
        draft.content_digest,
    ):
        raise ReplayContractError("admission does not bind the exact fixture")
    if eligibility["state"] != "admitted" or (
        eligibility["fixture_id"], eligibility["fixture_digest"]
    ) != (draft.record_id, draft.content_digest):
        raise ReplayContractError("fixture is not exactly admitted")
    manifest = bindings.manifest.payload
    execution = bindings.execution_profile
    assessment = bindings.assessment_profile
    if (manifest["execution_profile_id"], manifest["execution_profile_digest"]) != (
        execution.record_id,
        execution.content_digest,
    ) or (manifest["assessment_profile_id"], manifest["assessment_profile_digest"]) != (
        assessment.record_id,
        assessment.content_digest,
    ):
        raise ReplayContractError("manifest does not bind the exact replay profiles")
    matches = [
        item
        for item in manifest["entries"]
        if (item["draft_id"], item["draft_digest"]) == (draft.record_id, draft.content_digest)
    ]
    if len(matches) != 1 or (
        matches[0]["admission_id"], matches[0]["admission_digest"]
    ) != (bindings.admission.receipt.record_id, bindings.admission.receipt.content_digest):
        raise ReplayContractError("manifest does not select the exact fixture admission")
    capability = bindings.capability
    if capability.runtime_digest != execution.payload["runtime_digest"] or (
        capability.replay_adapter_digest != execution.payload["replay_adapter_digest"]
    ):
        raise ReplayContractError("capability does not certify the exact execution profile")
    if bindings.candidate.artifact == bindings.incumbent:
        raise ReplayContractError("candidate and incumbent identities must be distinct")
    return bindings.fixture


def _validate_bounds_against_fixture(bounds: ReplayBounds, fixture_bounds: Mapping[str, Any]) -> None:
    if bounds.max_turns > fixture_bounds["max_turns"]:
        raise ReplayContractError("replay turn bound exceeds the admitted fixture")
    if bounds.max_fixture_calls > fixture_bounds["max_tool_steps"]:
        raise ReplayContractError("replay fixture-call bound exceeds the admitted fixture")
    if bounds.max_output_bytes > fixture_bounds["max_output_bytes"]:
        raise ReplayContractError("replay output bound exceeds the admitted fixture")


def _freeze_snapshot(
    request: ReplayPairRequest, content: Mapping[str, Any]
) -> FrozenInvocationSnapshot:
    bindings = request.bindings
    payload = {
        "schema": REPLAY_INVOCATION_SCHEMA_ID,
        "issuer_ref": request.issuer_ref,
        "subject_ref": request.subject_ref,
        "context_ref": request.context_ref,
        "pair_attempt_ref": request.pair_attempt_ref,
        "idempotency_key_digest": request.idempotency_key_digest,
        "retry_of": _identity_mapping(request.retry_of),
        "fixture": _record_identity(bindings.fixture.record),
        "admission": _record_identity(bindings.admission.receipt),
        "manifest": _record_identity(bindings.manifest),
        "execution_profile": _record_identity(bindings.execution_profile),
        "assessment_profile": _record_identity(bindings.assessment_profile),
        "candidate": _identity_mapping(bindings.candidate.artifact),
        "candidate_lock": _identity_mapping(bindings.candidate.lock_receipt),
        "incumbent": _identity_mapping(bindings.incumbent),
        "capability": _identity_mapping(bindings.capability.certificate),
        "bounds": request.bounds.as_dict(),
        "provider_hosted_tools_enabled": False,
        "live_tool_dispatch_enabled": False,
        "fixture_content": dict(content),
    }
    encoded = canonical_json(payload)
    return FrozenInvocationSnapshot(
        encoded,
        schema_digest("replay-invocation", REPLAY_INVOCATION_SCHEMA_ID, encoded),
    )


def _build_receipt(
    request: ReplayPairRequest,
    snapshot: FrozenInvocationSnapshot,
    candidate: ProviderArmReport,
    incumbent: ProviderArmReport,
    state_refs: tuple[str, str],
    key_epoch: str,
) -> TypedRecord:
    bindings = request.bindings
    links = [
        _record_link("fixture_draft", 0, bindings.fixture.record),
        _record_link("fixture_admission", 0, bindings.admission.receipt),
        _record_link("fixture_eligibility", 0, bindings.admission.eligibility),
        _record_link("fixture_manifest", 0, bindings.manifest),
        _record_link("execution_profile", 0, bindings.execution_profile),
        _record_link("assessment_profile", 0, bindings.assessment_profile),
        _identity_link("candidate_artifact", 0, bindings.candidate.artifact),
        _identity_link("candidate_lock_receipt", 0, bindings.candidate.lock_receipt),
        _identity_link("incumbent_artifact", 0, bindings.incumbent),
        _identity_link("replay_capability", 0, bindings.capability.certificate),
    ]
    if request.retry_of is not None:
        links.append(_identity_link("retry_of_pair_receipt", 0, request.retry_of))
    arm_values = [
        _arm_receipt(candidate, state_refs[0]),
        _arm_receipt(incumbent, state_refs[1]),
    ]
    payload = {
        "record_type": "replay_pair_receipt",
        "issuer_ref": request.issuer_ref,
        "subject_ref": request.subject_ref,
        "context_ref": request.context_ref,
        "pair_attempt_ref": request.pair_attempt_ref,
        "idempotency_key_digest": request.idempotency_key_digest,
        "request_digest": replay_request_digest(request),
        "retry_of_receipt_ref": request.retry_of.ref if request.retry_of else None,
        "retry_of_receipt_digest": request.retry_of.digest if request.retry_of else None,
        "frozen_snapshot_digest": snapshot.digest,
        "arms": arm_values,
        "activation_evidence_eligible": all(
            arm["activation_evidence_eligible"] for arm in arm_values
        ),
        "links": links,
    }
    return build_typed_record(
        record_id=_replay_receipt_id(payload["request_digest"]),
        context_ref=request.context_ref,
        record_kind="replay_pair_receipt",
        schema_id=REPLAY_PAIR_RECEIPT_SCHEMA_ID,
        payload=payload,
        key_epoch=key_epoch,
        registry=REPLAY_REGISTRY,
    )


def _arm_receipt(report: ProviderArmReport, state_ref: str) -> dict[str, Any]:
    eligible = report.outcome in ("completed", "deterministic_failure")
    return {
        "arm": report.arm,
        "subject_ref": report.subject.ref,
        "subject_digest": report.subject.digest,
        "fresh_state_ref": state_ref,
        "outcome": report.outcome,
        "reason_code": report.reason_code,
        "usage": report.usage.as_dict(),
        "live_tool_dispatches": report.live_tool_dispatches,
        "provider_hosted_tool_executions": report.provider_hosted_tool_executions,
        "activation_evidence_eligible": eligible,
    }


def _within_bounds(usage: ReplayArmUsage, bounds: ReplayBounds) -> bool:
    return all(
        actual <= limit
        for actual, limit in (
            (usage.wall_time_ms, bounds.max_wall_time_ms),
            (usage.model_calls, bounds.max_model_calls),
            (usage.turns, bounds.max_turns),
            (usage.fixture_calls, bounds.max_fixture_calls),
            (usage.tokens, bounds.max_tokens),
            (usage.output_bytes, bounds.max_output_bytes),
            (usage.cost_microunits, bounds.max_cost_microunits),
        )
    )


def _harness_report(
    arm: str,
    subject: ExactIdentity,
    reason_code: str,
    elapsed_ms: int,
    fixture_calls: int,
) -> ProviderArmReport:
    return ProviderArmReport(
        arm=arm,
        subject=subject,
        outcome="harness_failure",
        reason_code=reason_code,
        usage=ReplayArmUsage.zero(wall_time_ms=elapsed_ms, fixture_calls=fixture_calls),
    )


def _elapsed_ms(started: float, finished: float) -> int:
    if type(started) not in (int, float) or type(finished) not in (int, float):
        raise ReplayContractError("monotonic clock returned an invalid value")
    if not math.isfinite(float(started)) or not math.isfinite(float(finished)):
        raise ReplayContractError("monotonic clock returned a non-finite value")
    return max(0, math.ceil((finished - started) * 1000))


def _require_same_binding_links(previous: TypedRecord, bindings: ReplayBindings) -> None:
    expected = {
        ("fixture_draft", bindings.fixture.record.record_id, bindings.fixture.record.content_digest),
        (
            "fixture_admission",
            bindings.admission.receipt.record_id,
            bindings.admission.receipt.content_digest,
        ),
        ("fixture_manifest", bindings.manifest.record_id, bindings.manifest.content_digest),
        (
            "execution_profile",
            bindings.execution_profile.record_id,
            bindings.execution_profile.content_digest,
        ),
        (
            "assessment_profile",
            bindings.assessment_profile.record_id,
            bindings.assessment_profile.content_digest,
        ),
        (
            "candidate_artifact",
            bindings.candidate.artifact.ref,
            bindings.candidate.artifact.digest,
        ),
        ("incumbent_artifact", bindings.incumbent.ref, bindings.incumbent.digest),
        (
            "replay_capability",
            bindings.capability.certificate.ref,
            bindings.capability.certificate.digest,
        ),
    }
    actual = {(item.role, item.target_id, item.target_digest) for item in previous.links}
    if not expected <= actual:
        raise ReplayContractError("retry changes an exact replay binding")


def _identity_mapping(identity: ExactIdentity | None) -> dict[str, str] | None:
    return None if identity is None else {"ref": identity.ref, "digest": identity.digest}


def _replay_receipt_id(request_digest: str) -> str:
    _require_digest(request_digest, "request_digest")
    return "replay_pair_receipt_" + request_digest


def _record_identity(record: TypedRecord) -> dict[str, str]:
    return {"ref": record.record_id, "digest": record.content_digest}


def _record_link(role: str, ordinal: int, record: TypedRecord) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": record.record_id,
        "target_digest": record.content_digest,
    }


def _binding_link_identities(
    request: ReplayPairRequest,
) -> set[tuple[str, int, str, str]]:
    return {
        (item["role"], item["ordinal"], item["target_id"], item["target_digest"])
        for item in replay_binding_links(request)
    }


def _report_from_receipt_arm(
    payload: Mapping[str, Any], subject: ExactIdentity
) -> ProviderArmReport:
    if (
        payload["subject_ref"] != subject.ref
        or payload["subject_digest"] != subject.digest
    ):
        raise ReplayContractError("durable replay arm subject changed")
    _require_opaque_ref(payload["fresh_state_ref"], "fresh_state_ref")
    report = ProviderArmReport(
        arm=payload["arm"],
        subject=subject,
        outcome=payload["outcome"],
        reason_code=payload["reason_code"],
        usage=ReplayArmUsage(**payload["usage"]),
        live_tool_dispatches=payload["live_tool_dispatches"],
        provider_hosted_tool_executions=payload[
            "provider_hosted_tool_executions"
        ],
    )
    expected = report.outcome in ("completed", "deterministic_failure")
    if payload["activation_evidence_eligible"] is not expected:
        raise ReplayContractError("durable replay arm eligibility is invalid")
    return report


def _identity_link(role: str, ordinal: int, identity: ExactIdentity) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": identity.ref,
        "target_digest": identity.digest,
    }


def _require_opaque_ref(value: Any, name: str) -> str:
    if type(value) is not str or _OPAQUE_REF.fullmatch(value) is None:
        raise ReplayContractError(f"{name} must be an opaque reference")
    return value


def _require_digest(value: Any, name: str) -> str:
    try:
        return validate_digest(value, name)
    except Exception as exc:
        raise ReplayContractError(f"{name} must be a lowercase SHA-256 digest") from exc


def _require_authority_integer(value: Any, name: str, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= _MAX_AUTHORITY_INTEGER:
        raise ReplayContractError(f"{name} must be a bounded integer >= {minimum}")
    return value
