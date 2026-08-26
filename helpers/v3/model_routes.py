"""Exact, content-free authority for provider-backed v3 model routes.

This module performs no provider calls and does not import Agent Zero or DSPy.
It freezes the identities a worker must receive, represents capability evidence
as strict records, and makes one pure admission decision for the route the
caller requested.  An unavailable model route is never replaced with another
route, model, transport, or provider.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Mapping

from .authority import AuthorityClass, VerifiedGrant
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
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


MODEL_USE_GRANT_SCHEMA_ID = "a0.model-use-grant.v1"
WORKER_DEPENDENCY_PROFILE_SCHEMA_ID = "a0.worker-dependency-profile.v1"
DEPENDENCY_CAPABILITY_SCHEMA_ID = "a0.worker-dependency-capability-certificate.v1"
PROVIDER_CAPABILITY_SCHEMA_ID = "a0.provider-capability-certificate.v1"
REPLAY_CAPABILITY_SCHEMA_ID = "a0.replay-capability-certificate.v1"
MODEL_ROUTE_ADMISSION_SCHEMA_ID = "a0.model-route-admission.v1"

MODEL_ROUTES = ("recursive_rlm", "typed_predict")
MODEL_ROUTE_BUDGET_DIMENSIONS = (
    "cases",
    "cost_microunits",
    "fixture_families",
    "host_concurrency",
    "input_bytes",
    "input_tokens",
    "judge_model_calls",
    "metric_invocations",
    "output_bytes",
    "output_tokens",
    "provider_concurrency",
    "reflection_model_calls",
    "retry_attempts",
    "rlm_iterations",
    "rlm_tool_queries",
    "root_model_calls",
    "submodel_calls",
    "task_model_calls",
    "unique_variants",
    "wall_time_ms",
)
DEPENDENCY_PROBES = (
    "cancellation",
    "cleanup",
    "metering",
    "recursive_rlm",
    "rlm_sandbox_limits",
    "typed_predict",
)
CAPABILITY_STATES = ("ready", "unavailable")
CAPABILITY_REASONS = (
    "ready",
    "behavioral_probe_failed",
    "cleanup_probe_failed",
    "contract_drift",
    "dependency_drift",
    "metering_unavailable",
    "provider_unavailable",
    "structural_probe_failed",
    "transport_unsupported",
    "unknown_price",
)
ADMISSION_REASONS = (
    "budget_insufficient",
    "budget_not_reserved",
    "capability_expired",
    "capability_revoked",
    "dependency_capability_unavailable",
    "dependency_profile_drift",
    "grant_binding_mismatch",
    "grant_expired",
    "grant_not_yet_valid",
    "grant_revoked",
    "provider_capability_unavailable",
    "provider_contract_drift",
    "route_capability_unavailable",
    "route_shape_invalid",
    "safe_view_too_large",
)

_MAX_AUTHORITY_INTEGER = (1 << 63) - 1
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")


class RouteAuthorityError(RuntimeError):
    """An exact route or replay authority is unavailable."""


@dataclass(frozen=True, slots=True)
class BoundIdentity:
    ref: str
    digest: str

    def __post_init__(self) -> None:
        _ref(self.ref, "identity.ref")
        validate_digest(self.digest, "identity.digest")


@dataclass(frozen=True, slots=True)
class ReservedBudgetAuthority:
    """One exact, already-created reservation under a cumulative ledger."""

    ledger_ref: str
    reservation_ref: str
    budget_profile: BoundIdentity
    limits: Mapping[str, int]
    reserved: Mapping[str, int]

    def __post_init__(self) -> None:
        _ref(self.ledger_ref, "budget.ledger_ref")
        _ref(self.reservation_ref, "budget.reservation_ref")
        if type(self.budget_profile) is not BoundIdentity:
            raise SchemaValidationError("budget_profile must be an exact identity")
        limits = _budget_vector(self.limits, "budget.limits")
        reserved = _budget_vector(self.reserved, "budget.reserved")
        if any(reserved[name] > limits[name] for name in MODEL_ROUTE_BUDGET_DIMENSIONS):
            raise SchemaValidationError("reserved budget cannot exceed a frozen limit")


@dataclass(frozen=True, slots=True)
class ModelRouteRequest:
    admission_ref: str
    context_ref: str
    key_epoch: str
    subject_ref: str
    action: str
    purpose: str
    target_ref: str
    target_revision: int
    requested_route: str
    selection_reason: str
    question: BoundIdentity
    safe_analysis_view: BoundIdentity
    safe_analysis_view_size_bytes: int
    requires_iterative_exploration: bool
    allowlisted_safe_tools: tuple[BoundIdentity, ...]
    runtime: BoundIdentity
    route_adapter: BoundIdentity
    model: BoundIdentity
    provider: BoundIdentity
    transport: BoundIdentity
    model_type_literal: str
    provider_config_signature_digest: str
    dependency_profile: TypedRecord
    dependency_capability: TypedRecord
    provider_capability: TypedRecord
    model_use_grant: TypedRecord
    budget: ReservedBudgetAuthority
    now: datetime
    revoked_grant_ids: frozenset[str]
    revoked_capability_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class ModelRouteAdmission:
    status: str
    requested_route: str
    selected_route: str | None
    reason_codes: tuple[str, ...]
    receipt: TypedRecord


@dataclass(frozen=True, slots=True)
class ReplayCapabilityExpectation:
    context_ref: str
    dependency_profile: BoundIdentity
    dependency_capability: BoundIdentity
    runtime: BoundIdentity
    replay_adapter: BoundIdentity
    transport: BoundIdentity
    now: datetime
    revoked_capability_ids: frozenset[str]


_IDENTITY_VALIDATOR = strict_object(
    {"ref": strict_string(maximum=512), "digest": validate_digest}
)


def _timestamp(value: Any, path: str) -> str:
    if type(value) is not str:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp") from exc
    if _format_time(parsed) != value:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    return value


def _python_version(value: Any, path: str) -> str:
    value = strict_string(maximum=64)(value, path)
    match = re.fullmatch(r"3\.(12|13|14)\.\d+", value)
    if match is None:
        raise SchemaValidationError(f"{path} must be an exact supported CPython version")
    return value


def _identity_list(value: Any, path: str) -> list[dict[str, Any]]:
    result = strict_list(_IDENTITY_VALIDATOR, minimum=1, maximum=128)(value, path)
    if result != sorted(result, key=lambda item: (item["ref"], item["digest"])):
        raise SchemaValidationError(f"{path} must be sorted by exact identity")
    if len({item["ref"] for item in result}) != len(result):
        raise SchemaValidationError(f"{path} repeats an identity")
    return result


_ROUTE_CAPABILITY_VALIDATOR = strict_object(
    {
        "route": strict_enum(MODEL_ROUTES),
        "state": strict_enum(CAPABILITY_STATES),
        "adapter_ref": strict_string(maximum=512),
        "adapter_digest": validate_digest,
    }
)


def _route_capabilities(value: Any, path: str) -> list[dict[str, Any]]:
    result = strict_list(_ROUTE_CAPABILITY_VALIDATOR, minimum=2, maximum=2)(value, path)
    if [item["route"] for item in result] != list(MODEL_ROUTES):
        raise SchemaValidationError(f"{path} must explicitly cover both model routes")
    return result


_PROBE_VALIDATOR = strict_object(
    {"probe": strict_enum(DEPENDENCY_PROBES), "state": strict_enum(CAPABILITY_STATES)}
)


def _probe_states(value: Any, path: str) -> list[dict[str, Any]]:
    result = strict_list(_PROBE_VALIDATOR, minimum=6, maximum=6)(value, path)
    if [item["probe"] for item in result] != list(DEPENDENCY_PROBES):
        raise SchemaValidationError(f"{path} must explicitly cover every dependency probe")
    return result


_BUDGET_ENTRY_VALIDATOR = strict_object(
    {
        "dimension": strict_enum(MODEL_ROUTE_BUDGET_DIMENSIONS),
        "limit": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
        "reserved": strict_integer(minimum=0, maximum=_MAX_AUTHORITY_INTEGER),
    }
)


def _budget_entries(value: Any, path: str) -> list[dict[str, Any]]:
    result = strict_list(
        _BUDGET_ENTRY_VALIDATOR,
        minimum=len(MODEL_ROUTE_BUDGET_DIMENSIONS),
        maximum=len(MODEL_ROUTE_BUDGET_DIMENSIONS),
    )(value, path)
    if [item["dimension"] for item in result] != list(MODEL_ROUTE_BUDGET_DIMENSIONS):
        raise SchemaValidationError(f"{path} must cover every frozen budget dimension")
    if any(item["reserved"] > item["limit"] for item in result):
        raise SchemaValidationError(f"{path} reserves beyond a frozen limit")
    return result


_MODEL_USE_GRANT_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("model_use_grant"),
        "grant_id": strict_string(maximum=128),
        "issuer_id": strict_string(maximum=512),
        "issuer_key_epoch": strict_integer(minimum=1),
        "subject_ref": strict_string(maximum=512),
        "action": strict_enum(("candidate_search", "model_analyze")),
        "purpose": strict_enum(("candidate_search", "model_analysis")),
        "target_ref": strict_string(maximum=512),
        "target_revision": strict_integer(minimum=0),
        "issued_at": _timestamp,
        "expires_at": _timestamp,
        "provider_ref": strict_string(maximum=512),
        "provider_digest": validate_digest,
        "model_ref": strict_string(maximum=512),
        "model_digest": validate_digest,
        "transport_ref": strict_string(maximum=512),
        "transport_digest": validate_digest,
        "allowed_routes": strict_list(strict_enum(MODEL_ROUTES), minimum=1, maximum=2),
        "safe_input_class": strict_literal("safe_analysis_view_only"),
        "safe_view_direct_input_ceiling_bytes": strict_integer(
            minimum=1, maximum=_MAX_AUTHORITY_INTEGER
        ),
        "budget_profile_ref": strict_string(maximum=512),
        "budget_profile_digest": validate_digest,
        "provider_storage_policy": strict_literal("disabled"),
        "provider_hosted_tools_policy": strict_literal("disabled"),
        "price_accounting": strict_enum(("known_reconcilable", "not_applicable_local")),
        "links": validate_links,
    }
)


_WORKER_PROFILE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("worker_dependency_profile"),
        "root_requirement": strict_literal("dspy[deno]==3.3.1"),
        "lock_digest": validate_digest,
        "package_hash_manifest_digest": validate_digest,
        "trusted_package_sources": _identity_list,
        "python_version": _python_version,
        "python_implementation": strict_literal("CPython"),
        "python_abi": strict_string(maximum=64),
        "os_name": strict_string(maximum=64),
        "architecture": strict_string(maximum=64),
        "agent_zero_build_digest": validate_digest,
        "framework_bridge_ref": strict_string(maximum=512),
        "framework_bridge_digest": validate_digest,
        "dspy_version": strict_literal("3.3.1"),
        "gepa_version": strict_literal("0.1.4"),
        "deno_version": strict_string(maximum=64),
        "predict_adapter_ref": strict_string(maximum=512),
        "predict_adapter_digest": validate_digest,
        "rlm_adapter_ref": strict_string(maximum=512),
        "rlm_adapter_digest": validate_digest,
        "metering_adapter_ref": strict_string(maximum=512),
        "metering_adapter_digest": validate_digest,
        "inherits_system_site_packages": strict_literal(False),
        "links": validate_links,
    }
)


_DEPENDENCY_CAPABILITY_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("worker_dependency_capability_certificate"),
        "dependency_profile_ref": strict_string(maximum=512),
        "dependency_profile_digest": validate_digest,
        "observed_lock_digest": validate_digest,
        "runtime_ref": strict_string(maximum=512),
        "runtime_digest": validate_digest,
        "route_capabilities": _route_capabilities,
        "probe_states": _probe_states,
        "issued_at": _timestamp,
        "expires_at": _timestamp,
        "links": validate_links,
    }
)


_PROVIDER_CAPABILITY_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("provider_capability_certificate"),
        "state": strict_enum(CAPABILITY_STATES),
        "reason_code": strict_enum(CAPABILITY_REASONS),
        "dependency_profile_ref": strict_string(maximum=512),
        "dependency_profile_digest": validate_digest,
        "dependency_capability_ref": strict_string(maximum=512),
        "dependency_capability_digest": validate_digest,
        "runtime_ref": strict_string(maximum=512),
        "runtime_digest": validate_digest,
        "provider_ref": strict_string(maximum=512),
        "provider_digest": validate_digest,
        "model_ref": strict_string(maximum=512),
        "model_digest": validate_digest,
        "transport_ref": strict_string(maximum=512),
        "transport_digest": validate_digest,
        "model_type_literal": strict_literal("chat"),
        "provider_config_signature_digest": validate_digest,
        "route_capabilities": _route_capabilities,
        "price_accounting": strict_enum(
            ("known_reconcilable", "not_applicable_local", "unavailable")
        ),
        "provider_storage_policy": strict_literal("disabled"),
        "provider_hosted_tools_policy": strict_literal("disabled"),
        "issued_at": _timestamp,
        "expires_at": _timestamp,
        "links": validate_links,
    }
)


_REPLAY_CAPABILITY_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("replay_capability_certificate"),
        "state": strict_enum(CAPABILITY_STATES),
        "reason_code": strict_enum(CAPABILITY_REASONS),
        "dependency_profile_ref": strict_string(maximum=512),
        "dependency_profile_digest": validate_digest,
        "dependency_capability_ref": strict_string(maximum=512),
        "dependency_capability_digest": validate_digest,
        "runtime_ref": strict_string(maximum=512),
        "runtime_digest": validate_digest,
        "replay_adapter_ref": strict_string(maximum=512),
        "replay_adapter_digest": validate_digest,
        "transport_ref": strict_string(maximum=512),
        "transport_digest": validate_digest,
        "structural_probe_digest": validate_digest,
        "behavioral_probe_digest": validate_digest,
        "live_tool_dispatch_policy": strict_literal("disabled"),
        "provider_hosted_tools_policy": strict_literal("disabled"),
        "issued_at": _timestamp,
        "expires_at": _timestamp,
        "links": validate_links,
    }
)


_MODEL_ROUTE_ADMISSION_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("model_route_admission"),
        "status": strict_enum(("admitted", "unavailable")),
        "requested_route": strict_enum(MODEL_ROUTES),
        "selected_route": strict_nullable(strict_enum(MODEL_ROUTES)),
        "selection_reason": strict_string(maximum=128),
        "reason_codes": strict_list(strict_enum(ADMISSION_REASONS), maximum=32),
        "subject_ref": strict_string(maximum=512),
        "action": strict_enum(("candidate_search", "model_analyze")),
        "purpose": strict_enum(("candidate_search", "model_analysis")),
        "target_ref": strict_string(maximum=512),
        "target_revision": strict_integer(minimum=0),
        "question_ref": strict_string(maximum=512),
        "question_digest": validate_digest,
        "safe_analysis_view_ref": strict_string(maximum=512),
        "safe_analysis_view_digest": validate_digest,
        "safe_analysis_view_size_bytes": strict_integer(
            minimum=0, maximum=_MAX_AUTHORITY_INTEGER
        ),
        "dependency_profile_ref": strict_string(maximum=512),
        "dependency_profile_digest": validate_digest,
        "dependency_capability_ref": strict_string(maximum=512),
        "dependency_capability_digest": validate_digest,
        "provider_capability_ref": strict_string(maximum=512),
        "provider_capability_digest": validate_digest,
        "model_use_grant_ref": strict_string(maximum=512),
        "model_use_grant_digest": validate_digest,
        "runtime_ref": strict_string(maximum=512),
        "runtime_digest": validate_digest,
        "route_adapter_ref": strict_string(maximum=512),
        "route_adapter_digest": validate_digest,
        "provider_ref": strict_string(maximum=512),
        "provider_digest": validate_digest,
        "model_ref": strict_string(maximum=512),
        "model_digest": validate_digest,
        "transport_ref": strict_string(maximum=512),
        "transport_digest": validate_digest,
        "budget_ledger_ref": strict_string(maximum=512),
        "budget_reservation_ref": strict_string(maximum=512),
        "budget_profile_ref": strict_string(maximum=512),
        "budget_profile_digest": validate_digest,
        "budget_dimensions": _budget_entries,
        "links": validate_links,
    }
)


MODEL_ROUTE_REGISTRY = SchemaRegistry(
    (
        RecordSchema(MODEL_USE_GRANT_SCHEMA_ID, "model_use_grant", _MODEL_USE_GRANT_VALIDATOR),
        RecordSchema(
            WORKER_DEPENDENCY_PROFILE_SCHEMA_ID,
            "worker_dependency_profile",
            _WORKER_PROFILE_VALIDATOR,
        ),
        RecordSchema(
            DEPENDENCY_CAPABILITY_SCHEMA_ID,
            "worker_dependency_capability_certificate",
            _DEPENDENCY_CAPABILITY_VALIDATOR,
        ),
        RecordSchema(
            PROVIDER_CAPABILITY_SCHEMA_ID,
            "provider_capability_certificate",
            _PROVIDER_CAPABILITY_VALIDATOR,
        ),
        RecordSchema(
            REPLAY_CAPABILITY_SCHEMA_ID,
            "replay_capability_certificate",
            _REPLAY_CAPABILITY_VALIDATOR,
        ),
        RecordSchema(
            MODEL_ROUTE_ADMISSION_SCHEMA_ID,
            "model_route_admission",
            _MODEL_ROUTE_ADMISSION_VALIDATOR,
        ),
    )
)


def build_model_use_grant_record(
    grant: VerifiedGrant,
    *,
    key_epoch: str,
    provider: BoundIdentity,
    model: BoundIdentity,
    transport: BoundIdentity,
    allowed_routes: tuple[str, ...],
    safe_view_direct_input_ceiling_bytes: int,
    budget_profile: BoundIdentity,
    provider_storage_policy: str,
    provider_hosted_tools_policy: str,
    price_accounting: str,
) -> TypedRecord:
    """Project a cryptographically verified grant into exact model-use scope."""

    if type(grant) is not VerifiedGrant:
        raise SchemaValidationError("grant must be a cryptographically VerifiedGrant")
    if grant.authority_class != AuthorityClass.MODEL_USE_GRANT.value:
        raise SchemaValidationError("grant is not a Model Use Grant")
    if (grant.action, grant.purpose) not in {
        ("model_analyze", "model_analysis"),
        ("candidate_search", "candidate_search"),
    }:
        raise SchemaValidationError("Model Use Grant action and purpose are incompatible")
    _require_window(grant.issued_at, grant.expires_at, "Model Use Grant")
    routes = tuple(sorted(allowed_routes))
    if not routes or len(set(routes)) != len(routes) or any(route not in MODEL_ROUTES for route in routes):
        raise SchemaValidationError("allowed_routes must be an explicit unique model-route set")
    payload = {
        "record_type": "model_use_grant",
        "grant_id": grant.grant_id,
        "issuer_id": grant.issuer_id,
        "issuer_key_epoch": grant.key_epoch,
        "subject_ref": grant.subject_ref,
        "action": grant.action,
        "purpose": grant.purpose,
        "target_ref": grant.target_ref,
        "target_revision": grant.target_revision,
        "issued_at": _format_time(grant.issued_at),
        "expires_at": _format_time(grant.expires_at),
        "provider_ref": provider.ref,
        "provider_digest": provider.digest,
        "model_ref": model.ref,
        "model_digest": model.digest,
        "transport_ref": transport.ref,
        "transport_digest": transport.digest,
        "allowed_routes": list(routes),
        "safe_input_class": "safe_analysis_view_only",
        "safe_view_direct_input_ceiling_bytes": safe_view_direct_input_ceiling_bytes,
        "budget_profile_ref": budget_profile.ref,
        "budget_profile_digest": budget_profile.digest,
        "provider_storage_policy": provider_storage_policy,
        "provider_hosted_tools_policy": provider_hosted_tools_policy,
        "price_accounting": price_accounting,
        "links": _links(
            ("budget_profile", budget_profile),
            ("model", model),
            ("provider", provider),
            ("transport", transport),
        ),
    }
    return _record(grant.grant_id, grant.context_ref, "model_use_grant", MODEL_USE_GRANT_SCHEMA_ID, payload, key_epoch)


def build_worker_dependency_profile(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    lock_digest: str,
    package_hash_manifest_digest: str,
    trusted_package_sources: tuple[BoundIdentity, ...],
    python_version: str,
    python_implementation: str,
    python_abi: str,
    os_name: str,
    architecture: str,
    agent_zero_build_digest: str,
    framework_bridge: BoundIdentity,
    deno_version: str,
    predict_adapter: BoundIdentity,
    rlm_adapter: BoundIdentity,
    metering_adapter: BoundIdentity,
) -> TypedRecord:
    sources = _sorted_identities(trusted_package_sources, "trusted_package_sources")
    payload = {
        "record_type": "worker_dependency_profile",
        "root_requirement": "dspy[deno]==3.3.1",
        "lock_digest": lock_digest,
        "package_hash_manifest_digest": package_hash_manifest_digest,
        "trusted_package_sources": [_identity(item) for item in sources],
        "python_version": python_version,
        "python_implementation": python_implementation,
        "python_abi": python_abi,
        "os_name": os_name,
        "architecture": architecture,
        "agent_zero_build_digest": agent_zero_build_digest,
        "framework_bridge_ref": framework_bridge.ref,
        "framework_bridge_digest": framework_bridge.digest,
        "dspy_version": "3.3.1",
        "gepa_version": "0.1.4",
        "deno_version": deno_version,
        "predict_adapter_ref": predict_adapter.ref,
        "predict_adapter_digest": predict_adapter.digest,
        "rlm_adapter_ref": rlm_adapter.ref,
        "rlm_adapter_digest": rlm_adapter.digest,
        "metering_adapter_ref": metering_adapter.ref,
        "metering_adapter_digest": metering_adapter.digest,
        "inherits_system_site_packages": False,
        "links": _links(
            ("framework_bridge", framework_bridge),
            ("metering_adapter", metering_adapter),
            ("predict_adapter", predict_adapter),
            ("rlm_adapter", rlm_adapter),
            *(("trusted_package_source", item) for item in sources),
        ),
    }
    return _record(record_id, context_ref, "worker_dependency_profile", WORKER_DEPENDENCY_PROFILE_SCHEMA_ID, payload, key_epoch)


def build_dependency_capability_certificate(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    dependency_profile: BoundIdentity,
    observed_lock_digest: str,
    runtime: BoundIdentity,
    route_capabilities: Mapping[str, BoundIdentity],
    probe_states: Mapping[str, str],
    issued_at: datetime,
    expires_at: datetime,
) -> TypedRecord:
    _require_window(issued_at, expires_at, "dependency capability")
    probes = _explicit_states(probe_states, DEPENDENCY_PROBES, "probe_states")
    routes = _route_entries(
        route_capabilities, {route: probes[route] for route in MODEL_ROUTES}
    )
    payload = {
        "record_type": "worker_dependency_capability_certificate",
        "dependency_profile_ref": dependency_profile.ref,
        "dependency_profile_digest": dependency_profile.digest,
        "observed_lock_digest": observed_lock_digest,
        "runtime_ref": runtime.ref,
        "runtime_digest": runtime.digest,
        "route_capabilities": routes,
        "probe_states": [
            {"probe": probe, "state": probes[probe]} for probe in DEPENDENCY_PROBES
        ],
        "issued_at": _format_time(issued_at),
        "expires_at": _format_time(expires_at),
        "links": _links(
            ("dependency_profile", dependency_profile),
            ("runtime", runtime),
            *((f"{item['route']}_adapter", BoundIdentity(item["adapter_ref"], item["adapter_digest"])) for item in routes),
        ),
    }
    return _record(record_id, context_ref, "worker_dependency_capability_certificate", DEPENDENCY_CAPABILITY_SCHEMA_ID, payload, key_epoch)


def build_provider_capability_certificate(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    dependency_profile: BoundIdentity,
    dependency_capability: BoundIdentity,
    runtime: BoundIdentity,
    provider: BoundIdentity,
    model: BoundIdentity,
    transport: BoundIdentity,
    model_type_literal: str,
    provider_config_signature_digest: str,
    route_capabilities: Mapping[str, BoundIdentity],
    route_states: Mapping[str, str],
    state: str,
    reason_code: str,
    price_accounting: str,
    provider_storage_policy: str,
    provider_hosted_tools_policy: str,
    issued_at: datetime,
    expires_at: datetime,
) -> TypedRecord:
    _require_window(issued_at, expires_at, "provider capability")
    if (state == "ready") != (reason_code == "ready"):
        raise SchemaValidationError("provider capability state and reason_code disagree")
    if state == "ready" and price_accounting == "unavailable":
        raise SchemaValidationError("ready provider capability requires usable price accounting")
    routes = _route_entries(route_capabilities, route_states)
    payload = {
        "record_type": "provider_capability_certificate",
        "state": state,
        "reason_code": reason_code,
        "dependency_profile_ref": dependency_profile.ref,
        "dependency_profile_digest": dependency_profile.digest,
        "dependency_capability_ref": dependency_capability.ref,
        "dependency_capability_digest": dependency_capability.digest,
        "runtime_ref": runtime.ref,
        "runtime_digest": runtime.digest,
        "provider_ref": provider.ref,
        "provider_digest": provider.digest,
        "model_ref": model.ref,
        "model_digest": model.digest,
        "transport_ref": transport.ref,
        "transport_digest": transport.digest,
        "model_type_literal": model_type_literal,
        "provider_config_signature_digest": provider_config_signature_digest,
        "route_capabilities": routes,
        "price_accounting": price_accounting,
        "provider_storage_policy": provider_storage_policy,
        "provider_hosted_tools_policy": provider_hosted_tools_policy,
        "issued_at": _format_time(issued_at),
        "expires_at": _format_time(expires_at),
        "links": _links(
            ("dependency_capability", dependency_capability),
            ("dependency_profile", dependency_profile),
            ("model", model),
            ("provider", provider),
            ("runtime", runtime),
            ("transport", transport),
            *((f"{item['route']}_adapter", BoundIdentity(item["adapter_ref"], item["adapter_digest"])) for item in routes),
        ),
    }
    return _record(record_id, context_ref, "provider_capability_certificate", PROVIDER_CAPABILITY_SCHEMA_ID, payload, key_epoch)


def build_replay_capability_certificate(
    *,
    record_id: str,
    context_ref: str,
    key_epoch: str,
    dependency_profile: BoundIdentity,
    dependency_capability: BoundIdentity,
    runtime: BoundIdentity,
    replay_adapter: BoundIdentity,
    transport: BoundIdentity,
    structural_probe_digest: str,
    behavioral_probe_digest: str,
    state: str,
    reason_code: str,
    live_tool_dispatch_policy: str,
    provider_hosted_tools_policy: str,
    issued_at: datetime,
    expires_at: datetime,
) -> TypedRecord:
    _require_window(issued_at, expires_at, "replay capability")
    if (state == "ready") != (reason_code == "ready"):
        raise SchemaValidationError("replay capability state and reason_code disagree")
    payload = {
        "record_type": "replay_capability_certificate",
        "state": state,
        "reason_code": reason_code,
        "dependency_profile_ref": dependency_profile.ref,
        "dependency_profile_digest": dependency_profile.digest,
        "dependency_capability_ref": dependency_capability.ref,
        "dependency_capability_digest": dependency_capability.digest,
        "runtime_ref": runtime.ref,
        "runtime_digest": runtime.digest,
        "replay_adapter_ref": replay_adapter.ref,
        "replay_adapter_digest": replay_adapter.digest,
        "transport_ref": transport.ref,
        "transport_digest": transport.digest,
        "structural_probe_digest": structural_probe_digest,
        "behavioral_probe_digest": behavioral_probe_digest,
        "live_tool_dispatch_policy": live_tool_dispatch_policy,
        "provider_hosted_tools_policy": provider_hosted_tools_policy,
        "issued_at": _format_time(issued_at),
        "expires_at": _format_time(expires_at),
        "links": _links(
            ("dependency_capability", dependency_capability),
            ("dependency_profile", dependency_profile),
            ("replay_adapter", replay_adapter),
            ("runtime", runtime),
            ("transport", transport),
        ),
    }
    return _record(record_id, context_ref, "replay_capability_certificate", REPLAY_CAPABILITY_SCHEMA_ID, payload, key_epoch)


def admit_model_route(request: ModelRouteRequest) -> ModelRouteAdmission:
    """Purely admit the exact requested route or return bounded unavailability."""

    _validate_request_shape(request)
    for record, kind in (
        (request.dependency_profile, "worker_dependency_profile"),
        (request.dependency_capability, "worker_dependency_capability_certificate"),
        (request.provider_capability, "provider_capability_certificate"),
        (request.model_use_grant, "model_use_grant"),
    ):
        record.verify(MODEL_ROUTE_REGISTRY)
        if record.record_kind != kind or record.context_ref != request.context_ref:
            raise SchemaValidationError(f"route binding is not the exact {kind}")

    reasons: list[str] = []
    now = _utc(request.now, "now")
    profile = request.dependency_profile.payload
    dependency = request.dependency_capability.payload
    provider = request.provider_capability.payload
    grant = request.model_use_grant.payload

    _check_grant(request, grant, now, reasons)
    _check_dependency(request, profile, dependency, now, reasons)
    _check_provider(request, provider, now, reasons)
    _check_route_shape(request, grant, reasons)
    _check_budget(request, grant, provider, reasons)

    reason_codes = tuple(dict.fromkeys(reasons))
    status = "admitted" if not reason_codes else "unavailable"
    selected_route = request.requested_route if status == "admitted" else None
    receipt = _build_admission_receipt(request, status, selected_route, reason_codes)
    return ModelRouteAdmission(
        status=status,
        requested_route=request.requested_route,
        selected_route=selected_route,
        reason_codes=reason_codes,
        receipt=receipt,
    )


def require_replay_capability(
    certificate: TypedRecord, expectation: ReplayCapabilityExpectation
) -> None:
    """Require one ready replay certificate for every exact expected identity."""

    certificate.verify(MODEL_ROUTE_REGISTRY)
    if certificate.record_kind != "replay_capability_certificate":
        raise RouteAuthorityError("replay_capability_binding_mismatch")
    payload = certificate.payload
    now = _utc(expectation.now, "now")
    if certificate.context_ref != expectation.context_ref or any(
        not _payload_identity(payload, prefix, identity)
        for prefix, identity in (
            ("dependency_profile", expectation.dependency_profile),
            ("dependency_capability", expectation.dependency_capability),
            ("runtime", expectation.runtime),
            ("replay_adapter", expectation.replay_adapter),
            ("transport", expectation.transport),
        )
    ):
        raise RouteAuthorityError("replay_capability_binding_mismatch")
    if certificate.record_id in expectation.revoked_capability_ids:
        raise RouteAuthorityError("replay_capability_revoked")
    if now < _parse_time(payload["issued_at"]) or now >= _parse_time(payload["expires_at"]):
        raise RouteAuthorityError("replay_capability_expired")
    if payload["state"] != "ready":
        raise RouteAuthorityError("replay_capability_unavailable")


def _check_grant(
    request: ModelRouteRequest,
    grant: Mapping[str, Any],
    now: datetime,
    reasons: list[str],
) -> None:
    if request.model_use_grant.record_id in request.revoked_grant_ids or grant["grant_id"] in request.revoked_grant_ids:
        reasons.append("grant_revoked")
    if now < _parse_time(grant["issued_at"]):
        reasons.append("grant_not_yet_valid")
    if now >= _parse_time(grant["expires_at"]):
        reasons.append("grant_expired")
    expected = (
        grant["subject_ref"] == request.subject_ref
        and grant["action"] == request.action
        and grant["purpose"] == request.purpose
        and grant["target_ref"] == request.target_ref
        and grant["target_revision"] == request.target_revision
        and request.requested_route in grant["allowed_routes"]
        and _payload_identity(grant, "provider", request.provider)
        and _payload_identity(grant, "model", request.model)
        and _payload_identity(grant, "transport", request.transport)
        and _payload_identity(grant, "budget_profile", request.budget.budget_profile)
    )
    if not expected:
        reasons.append("grant_binding_mismatch")


def _check_dependency(
    request: ModelRouteRequest,
    profile: Mapping[str, Any],
    dependency: Mapping[str, Any],
    now: datetime,
    reasons: list[str],
) -> None:
    profile_identity = BoundIdentity(
        request.dependency_profile.record_id, request.dependency_profile.content_digest
    )
    if (
        not _payload_identity(dependency, "dependency_profile", profile_identity)
        or dependency["observed_lock_digest"] != profile["lock_digest"]
        or not _payload_identity(dependency, "runtime", request.runtime)
    ):
        reasons.append("dependency_profile_drift")
    if request.dependency_capability.record_id in request.revoked_capability_ids:
        reasons.append("capability_revoked")
    if now < _parse_time(dependency["issued_at"]) or now >= _parse_time(dependency["expires_at"]):
        reasons.append("capability_expired")
    route = _route_entry(dependency, request.requested_route)
    required_probes = {"metering", "cancellation", "cleanup", request.requested_route}
    if request.requested_route == "recursive_rlm":
        required_probes.add("rlm_sandbox_limits")
    states = {item["probe"]: item["state"] for item in dependency["probe_states"]}
    if (
        route["state"] != "ready"
        or not _entry_adapter(route, request.route_adapter)
        or any(states[probe] != "ready" for probe in required_probes)
    ):
        reasons.append("dependency_capability_unavailable")


def _check_provider(
    request: ModelRouteRequest,
    provider: Mapping[str, Any],
    now: datetime,
    reasons: list[str],
) -> None:
    if request.provider_capability.record_id in request.revoked_capability_ids:
        reasons.append("capability_revoked")
    if now < _parse_time(provider["issued_at"]) or now >= _parse_time(provider["expires_at"]):
        reasons.append("capability_expired")
    if provider["state"] != "ready":
        reasons.append("provider_capability_unavailable")
    profile_identity = BoundIdentity(
        request.dependency_profile.record_id, request.dependency_profile.content_digest
    )
    dependency_identity = BoundIdentity(
        request.dependency_capability.record_id,
        request.dependency_capability.content_digest,
    )
    exact = (
        _payload_identity(provider, "dependency_profile", profile_identity)
        and _payload_identity(provider, "dependency_capability", dependency_identity)
        and _payload_identity(provider, "runtime", request.runtime)
        and _payload_identity(provider, "provider", request.provider)
        and _payload_identity(provider, "model", request.model)
        and _payload_identity(provider, "transport", request.transport)
        and provider["model_type_literal"] == request.model_type_literal
        and provider["provider_config_signature_digest"]
        == request.provider_config_signature_digest
    )
    if not exact:
        reasons.append("provider_contract_drift")
    route = _route_entry(provider, request.requested_route)
    if route["state"] != "ready" or not _entry_adapter(route, request.route_adapter):
        reasons.append("route_capability_unavailable")


def _check_route_shape(
    request: ModelRouteRequest, grant: Mapping[str, Any], reasons: list[str]
) -> None:
    if request.safe_analysis_view_size_bytes > grant["safe_view_direct_input_ceiling_bytes"]:
        reasons.append("safe_view_too_large")
    if request.requested_route == "typed_predict":
        if (
            request.requires_iterative_exploration is not False
            or request.allowlisted_safe_tools
            or request.selection_reason != "declared_single_structured_inference"
        ):
            reasons.append("route_shape_invalid")
    elif (
        request.requires_iterative_exploration is not True
        or request.selection_reason != "declared_iterative_exploration"
    ):
        reasons.append("route_shape_invalid")


def _check_budget(
    request: ModelRouteRequest,
    grant: Mapping[str, Any],
    provider: Mapping[str, Any],
    reasons: list[str],
) -> None:
    if grant["price_accounting"] != provider["price_accounting"]:
        reasons.append("grant_binding_mismatch")
    try:
        reserved = _budget_vector(request.budget.reserved, "budget.reserved")
        _budget_vector(request.budget.limits, "budget.limits")
    except SchemaValidationError:
        reasons.append("budget_not_reserved")
        return
    required_positive = {
        "wall_time_ms",
        "root_model_calls",
        "input_tokens",
        "output_tokens",
        "input_bytes",
        "output_bytes",
        "provider_concurrency",
        "host_concurrency",
    }
    if request.requested_route == "recursive_rlm":
        required_positive.update(("submodel_calls", "rlm_iterations"))
        if request.allowlisted_safe_tools:
            required_positive.add("rlm_tool_queries")
    if provider["price_accounting"] == "known_reconcilable":
        required_positive.add("cost_microunits")
    if (
        any(reserved[dimension] <= 0 for dimension in required_positive)
        or reserved["input_bytes"] < request.safe_analysis_view_size_bytes
        or not _payload_identity(grant, "budget_profile", request.budget.budget_profile)
    ):
        reasons.append("budget_insufficient")


def _build_admission_receipt(
    request: ModelRouteRequest,
    status: str,
    selected_route: str | None,
    reasons: tuple[str, ...],
) -> TypedRecord:
    records = (
        ("dependency_capability", request.dependency_capability),
        ("dependency_profile", request.dependency_profile),
        ("model_use_grant", request.model_use_grant),
        ("provider_capability", request.provider_capability),
    )
    payload = {
        "record_type": "model_route_admission",
        "status": status,
        "requested_route": request.requested_route,
        "selected_route": selected_route,
        "selection_reason": request.selection_reason,
        "reason_codes": list(reasons),
        "subject_ref": request.subject_ref,
        "action": request.action,
        "purpose": request.purpose,
        "target_ref": request.target_ref,
        "target_revision": request.target_revision,
        "question_ref": request.question.ref,
        "question_digest": request.question.digest,
        "safe_analysis_view_ref": request.safe_analysis_view.ref,
        "safe_analysis_view_digest": request.safe_analysis_view.digest,
        "safe_analysis_view_size_bytes": request.safe_analysis_view_size_bytes,
        "dependency_profile_ref": request.dependency_profile.record_id,
        "dependency_profile_digest": request.dependency_profile.content_digest,
        "dependency_capability_ref": request.dependency_capability.record_id,
        "dependency_capability_digest": request.dependency_capability.content_digest,
        "provider_capability_ref": request.provider_capability.record_id,
        "provider_capability_digest": request.provider_capability.content_digest,
        "model_use_grant_ref": request.model_use_grant.record_id,
        "model_use_grant_digest": request.model_use_grant.content_digest,
        "runtime_ref": request.runtime.ref,
        "runtime_digest": request.runtime.digest,
        "route_adapter_ref": request.route_adapter.ref,
        "route_adapter_digest": request.route_adapter.digest,
        "provider_ref": request.provider.ref,
        "provider_digest": request.provider.digest,
        "model_ref": request.model.ref,
        "model_digest": request.model.digest,
        "transport_ref": request.transport.ref,
        "transport_digest": request.transport.digest,
        "budget_ledger_ref": request.budget.ledger_ref,
        "budget_reservation_ref": request.budget.reservation_ref,
        "budget_profile_ref": request.budget.budget_profile.ref,
        "budget_profile_digest": request.budget.budget_profile.digest,
        "budget_dimensions": [
            {
                "dimension": name,
                "limit": request.budget.limits[name],
                "reserved": request.budget.reserved[name],
            }
            for name in MODEL_ROUTE_BUDGET_DIMENSIONS
        ],
        "links": _links(
            *((role, BoundIdentity(record.record_id, record.content_digest)) for role, record in records),
            ("model", request.model),
            ("provider", request.provider),
            ("question", request.question),
            ("route_adapter", request.route_adapter),
            ("runtime", request.runtime),
            ("safe_analysis_view", request.safe_analysis_view),
            *(("safe_tool_contract", item) for item in request.allowlisted_safe_tools),
            ("transport", request.transport),
        ),
    }
    return _record(
        request.admission_ref,
        request.context_ref,
        "model_route_admission",
        MODEL_ROUTE_ADMISSION_SCHEMA_ID,
        payload,
        request.key_epoch,
    )


def _validate_request_shape(request: ModelRouteRequest) -> None:
    if type(request) is not ModelRouteRequest:
        raise SchemaValidationError("request must be a ModelRouteRequest")
    for value, name in (
        (request.admission_ref, "admission_ref"),
        (request.context_ref, "context_ref"),
        (request.key_epoch, "key_epoch"),
        (request.subject_ref, "subject_ref"),
        (request.target_ref, "target_ref"),
    ):
        _ref(value, name)
    if request.requested_route not in MODEL_ROUTES:
        raise SchemaValidationError("requested_route is not an admitted model route")
    if (request.action, request.purpose) not in {
        ("model_analyze", "model_analysis"),
        ("candidate_search", "candidate_search"),
    }:
        raise SchemaValidationError("route action and purpose are incompatible")
    if type(request.target_revision) is not int or request.target_revision < 0:
        raise SchemaValidationError("target_revision must be a nonnegative integer")
    if type(request.safe_analysis_view_size_bytes) is not int or not 0 <= request.safe_analysis_view_size_bytes <= _MAX_AUTHORITY_INTEGER:
        raise SchemaValidationError("safe_analysis_view_size_bytes is invalid")
    if type(request.requires_iterative_exploration) is not bool:
        raise SchemaValidationError("requires_iterative_exploration must be boolean")
    _sorted_identities(request.allowlisted_safe_tools, "allowlisted_safe_tools")
    for identity in (
        request.question,
        request.safe_analysis_view,
        request.runtime,
        request.route_adapter,
        request.model,
        request.provider,
        request.transport,
    ):
        if type(identity) is not BoundIdentity:
            raise SchemaValidationError("route identities must be exact BoundIdentity values")
    if request.model_type_literal != "chat":
        raise SchemaValidationError("model_type_literal must match the pinned chat contract")
    validate_digest(
        request.provider_config_signature_digest, "provider_config_signature_digest"
    )
    if type(request.budget) is not ReservedBudgetAuthority:
        raise SchemaValidationError("budget must be explicit ReservedBudgetAuthority")
    _utc(request.now, "now")
    for values, name in (
        (request.revoked_grant_ids, "revoked_grant_ids"),
        (request.revoked_capability_ids, "revoked_capability_ids"),
    ):
        if type(values) is not frozenset or any(type(value) is not str for value in values):
            raise SchemaValidationError(f"{name} must be an explicit frozenset of identities")


def _route_entries(
    capabilities: Mapping[str, BoundIdentity], states: Mapping[str, str]
) -> list[dict[str, Any]]:
    if type(capabilities) is not dict or set(capabilities) != set(MODEL_ROUTES):
        raise SchemaValidationError("route_capabilities must explicitly cover both routes")
    admitted_states = _explicit_states(states, MODEL_ROUTES, "route_states")
    result = []
    for route in MODEL_ROUTES:
        identity = capabilities[route]
        if type(identity) is not BoundIdentity:
            raise SchemaValidationError("route adapter must be an exact identity")
        result.append(
            {
                "route": route,
                "state": admitted_states[route],
                "adapter_ref": identity.ref,
                "adapter_digest": identity.digest,
            }
        )
    return result


def _explicit_states(
    values: Mapping[str, str], expected: tuple[str, ...], name: str
) -> dict[str, str]:
    if type(values) is not dict or set(values) != set(expected):
        raise SchemaValidationError(f"{name} must explicitly cover the exact authority set")
    result = dict(values)
    if any(state not in CAPABILITY_STATES for state in result.values()):
        raise SchemaValidationError(f"{name} contains an unknown capability state")
    return result


def _budget_vector(value: Mapping[str, int], name: str) -> dict[str, int]:
    if type(value) is not dict or set(value) != set(MODEL_ROUTE_BUDGET_DIMENSIONS):
        raise SchemaValidationError(f"{name} must explicitly cover every budget dimension")
    result = dict(value)
    if any(type(amount) is not int or not 0 <= amount <= _MAX_AUTHORITY_INTEGER for amount in result.values()):
        raise SchemaValidationError(f"{name} must contain bounded nonnegative integers")
    return result


def _sorted_identities(
    values: tuple[BoundIdentity, ...], name: str
) -> tuple[BoundIdentity, ...]:
    if type(values) is not tuple or any(type(item) is not BoundIdentity for item in values):
        raise SchemaValidationError(f"{name} must be a tuple of exact identities")
    sorted_values = tuple(sorted(values, key=lambda item: (item.ref, item.digest)))
    if len({item.ref for item in sorted_values}) != len(sorted_values):
        raise SchemaValidationError(f"{name} repeats an identity")
    return sorted_values


def _links(*bindings: tuple[str, BoundIdentity]) -> list[dict[str, Any]]:
    counters: dict[str, int] = {}
    result: list[dict[str, Any]] = []
    for role, identity in bindings:
        if type(identity) is not BoundIdentity:
            raise SchemaValidationError("link target must be an exact identity")
        ordinal = counters.get(role, 0)
        counters[role] = ordinal + 1
        result.append(
            {
                "role": role,
                "ordinal": ordinal,
                "target_id": identity.ref,
                "target_digest": identity.digest,
            }
        )
    return result


def _identity(value: BoundIdentity) -> dict[str, str]:
    return {"ref": value.ref, "digest": value.digest}


def _payload_identity(
    payload: Mapping[str, Any], prefix: str, identity: BoundIdentity
) -> bool:
    return (
        payload.get(f"{prefix}_ref") == identity.ref
        and payload.get(f"{prefix}_digest") == identity.digest
    )


def _route_entry(payload: Mapping[str, Any], route: str) -> Mapping[str, Any]:
    matches = [item for item in payload["route_capabilities"] if item["route"] == route]
    if len(matches) != 1:
        raise SchemaValidationError("capability does not cover the exact route")
    return matches[0]


def _entry_adapter(entry: Mapping[str, Any], identity: BoundIdentity) -> bool:
    return entry["adapter_ref"] == identity.ref and entry["adapter_digest"] == identity.digest


def _record(
    record_id: str,
    context_ref: str,
    record_kind: str,
    schema_id: str,
    payload: Mapping[str, Any],
    key_epoch: str,
) -> TypedRecord:
    return build_typed_record(
        record_id=record_id,
        context_ref=context_ref,
        record_kind=record_kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=key_epoch,
        registry=MODEL_ROUTE_REGISTRY,
    )


def _ref(value: Any, name: str) -> str:
    if type(value) is not str or _OPAQUE_REF.fullmatch(value) is None:
        raise SchemaValidationError(f"{name} must be a bounded opaque reference")
    return value


def _utc(value: datetime, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise SchemaValidationError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return _utc(value, "timestamp").strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _require_window(issued_at: datetime, expires_at: datetime, name: str) -> None:
    if _utc(expires_at, "expires_at") <= _utc(issued_at, "issued_at"):
        raise SchemaValidationError(f"{name} expiry must be after issuance")


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
