from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from usr.plugins.dspy_rlm.helpers.v3.authority import VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.model_routes import (
    MODEL_ROUTE_BUDGET_DIMENSIONS,
    BoundIdentity,
    ModelRouteRequest,
    ReplayCapabilityExpectation,
    ReservedBudgetAuthority,
    RouteAuthorityError,
    admit_model_route,
    build_dependency_capability_certificate,
    build_model_use_grant_record,
    build_provider_capability_certificate,
    build_replay_capability_certificate,
    build_worker_dependency_profile,
    require_replay_capability,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import SchemaValidationError


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
DIGESTS = tuple(character * 64 for character in "abcdef0123456789")


def _identity(ref: str, index: int) -> BoundIdentity:
    return BoundIdentity(ref, DIGESTS[index])


def _authorities(route: str = "typed_predict") -> dict[str, object]:
    runtime = _identity("runtime-1", 0)
    model = _identity("model-1", 1)
    transport = _identity("transport-1", 2)
    predict_adapter = _identity("predict-adapter-1", 3)
    rlm_adapter = _identity("rlm-adapter-1", 4)
    profile = build_worker_dependency_profile(
        record_id="dependency-profile-1",
        context_ref="context-1",
        key_epoch="epoch-1",
        lock_digest=DIGESTS[5],
        package_hash_manifest_digest=DIGESTS[6],
        trusted_package_sources=(_identity("package-source-1", 7),),
        python_version="3.12.4",
        python_implementation="CPython",
        python_abi="cp312",
        os_name="linux",
        architecture="x86_64",
        agent_zero_build_digest=DIGESTS[8],
        framework_bridge=_identity("framework-bridge-1", 9),
        deno_version="2.4.5",
        predict_adapter=predict_adapter,
        rlm_adapter=rlm_adapter,
        metering_adapter=_identity("metering-adapter-1", 10),
    )
    dependency = build_dependency_capability_certificate(
        record_id="dependency-capability-1",
        context_ref="context-1",
        key_epoch="epoch-1",
        dependency_profile=BoundIdentity(profile.record_id, profile.content_digest),
        observed_lock_digest=DIGESTS[5],
        runtime=runtime,
        route_capabilities={"typed_predict": predict_adapter, "recursive_rlm": rlm_adapter},
        probe_states={
            "typed_predict": "ready",
            "recursive_rlm": "ready",
            "rlm_sandbox_limits": "ready",
            "metering": "ready",
            "cancellation": "ready",
            "cleanup": "ready",
        },
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=15),
    )
    provider = build_provider_capability_certificate(
        record_id="provider-capability-1",
        context_ref="context-1",
        key_epoch="epoch-1",
        dependency_profile=BoundIdentity(profile.record_id, profile.content_digest),
        dependency_capability=BoundIdentity(dependency.record_id, dependency.content_digest),
        runtime=runtime,
        provider=_identity("provider-1", 13),
        model=model,
        transport=transport,
        model_type_literal="chat",
        provider_config_signature_digest=DIGESTS[11],
        route_capabilities={"typed_predict": predict_adapter, "recursive_rlm": rlm_adapter},
        route_states={"typed_predict": "ready", "recursive_rlm": "ready"},
        state="ready",
        reason_code="ready",
        price_accounting="known_reconcilable",
        provider_storage_policy="disabled",
        provider_hosted_tools_policy="disabled",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=15),
    )
    verified = VerifiedGrant(
        grant_id="grant_" + "a" * 64,
        authority_class="model_use_grant",
        issuer_id="issuer-1",
        key_epoch=1,
        subject_ref="operator-1",
        context_ref="context-1",
        action="model_analyze",
        purpose="model_analysis",
        target_ref="analysis-run-1",
        target_revision=3,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
        idempotency_key_digest=DIGESTS[12],
        session_nonce="session-1",
    )
    budget = _budget()
    grant = build_model_use_grant_record(
        verified,
        key_epoch="epoch-1",
        provider=_identity("provider-1", 13),
        model=model,
        transport=transport,
        allowed_routes=("recursive_rlm", "typed_predict"),
        safe_view_direct_input_ceiling_bytes=4096,
        budget_profile=budget.budget_profile,
        provider_storage_policy="disabled",
        provider_hosted_tools_policy="disabled",
        price_accounting="known_reconcilable",
    )
    return {
        "runtime": runtime,
        "model": model,
        "transport": transport,
        "predict_adapter": predict_adapter,
        "rlm_adapter": rlm_adapter,
        "profile": profile,
        "dependency": dependency,
        "provider": provider,
        "grant": grant,
        "budget": budget,
        "route": route,
    }


def _budget() -> ReservedBudgetAuthority:
    limits = {name: 100 for name in MODEL_ROUTE_BUDGET_DIMENSIONS}
    reserved = {name: 1 for name in MODEL_ROUTE_BUDGET_DIMENSIONS}
    reserved.update(
        {
            "wall_time_ms": 10_000,
            "input_tokens": 200,
            "output_tokens": 100,
            "input_bytes": 4096,
            "output_bytes": 4096,
            "cost_microunits": 500,
        }
    )
    limits.update(reserved)
    return ReservedBudgetAuthority(
        ledger_ref="budget-ledger-1",
        reservation_ref="budget-reservation-1",
        budget_profile=_identity("budget-profile-1", 14),
        limits=limits,
        reserved=reserved,
    )


def _request(authorities: dict[str, object], route: str) -> ModelRouteRequest:
    return ModelRouteRequest(
        admission_ref=f"admission-{route}",
        context_ref="context-1",
        key_epoch="epoch-1",
        subject_ref="operator-1",
        action="model_analyze",
        purpose="model_analysis",
        target_ref="analysis-run-1",
        target_revision=3,
        requested_route=route,
        selection_reason=(
            "declared_iterative_exploration"
            if route == "recursive_rlm"
            else "declared_single_structured_inference"
        ),
        question=_identity("question-1", 15),
        safe_analysis_view=_identity("safe-view-1", 0),
        safe_analysis_view_size_bytes=1024,
        requires_iterative_exploration=route == "recursive_rlm",
        allowlisted_safe_tools=(
            (_identity("safe-aggregate-tool-1", 1),)
            if route == "recursive_rlm"
            else ()
        ),
        runtime=authorities["runtime"],
        route_adapter=(
            authorities["rlm_adapter"]
            if route == "recursive_rlm"
            else authorities["predict_adapter"]
        ),
        model=authorities["model"],
        provider=_identity("provider-1", 13),
        transport=authorities["transport"],
        model_type_literal="chat",
        provider_config_signature_digest=DIGESTS[11],
        dependency_profile=authorities["profile"],
        dependency_capability=authorities["dependency"],
        provider_capability=authorities["provider"],
        model_use_grant=authorities["grant"],
        budget=authorities["budget"],
        now=NOW,
        revoked_grant_ids=frozenset(),
        revoked_capability_ids=frozenset(),
    )


def test_typed_predict_admission_binds_exact_authorities_without_content() -> None:
    authorities = _authorities()

    result = admit_model_route(_request(authorities, "typed_predict"))

    assert result.status == "admitted"
    assert result.selected_route == "typed_predict"
    assert result.reason_codes == ()
    assert result.receipt.payload["requested_route"] == "typed_predict"
    assert b"prompt" not in result.receipt.canonical_bytes
    assert b"provider_response" not in result.receipt.canonical_bytes


def test_recursive_rlm_requires_declared_iteration_and_local_safe_tool_budget() -> None:
    authorities = _authorities("recursive_rlm")
    request = _request(authorities, "recursive_rlm")

    admitted = admit_model_route(request)
    denied = admit_model_route(
        replace(request, requires_iterative_exploration=False, admission_ref="rlm-denied")
    )

    assert admitted.selected_route == "recursive_rlm"
    assert admitted.status == "admitted"
    assert denied.status == "unavailable"
    assert denied.selected_route is None
    assert denied.reason_codes == ("route_shape_invalid",)


def test_missing_or_drifted_authority_is_unavailable_without_fallback() -> None:
    authorities = _authorities()
    base = _request(authorities, "typed_predict")
    drifted_dependency = build_dependency_capability_certificate(
        record_id="dependency-capability-drifted",
        context_ref="context-1",
        key_epoch="epoch-1",
        dependency_profile=BoundIdentity(
            base.dependency_profile.record_id, base.dependency_profile.content_digest
        ),
        observed_lock_digest=DIGESTS[4],
        runtime=base.runtime,
        route_capabilities={
            "typed_predict": authorities["predict_adapter"],
            "recursive_rlm": authorities["rlm_adapter"],
        },
        probe_states={
            "typed_predict": "ready",
            "recursive_rlm": "ready",
            "rlm_sandbox_limits": "ready",
            "metering": "ready",
            "cancellation": "ready",
            "cleanup": "ready",
        },
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=15),
    )
    cases = (
        (replace(base, admission_ref="expired", now=NOW + timedelta(minutes=11)), "grant_expired"),
        (
            replace(
                base,
                admission_ref="revoked",
                revoked_grant_ids=frozenset((base.model_use_grant.payload["grant_id"],)),
            ),
            "grant_revoked",
        ),
        (
            replace(base, admission_ref="transport", transport=_identity("transport-2", 3)),
            "grant_binding_mismatch",
        ),
        (
            replace(base, admission_ref="dependency", dependency_capability=drifted_dependency),
            "dependency_profile_drift",
        ),
        (
            replace(
                base,
                admission_ref="provider",
                provider_capability=_provider_with_state(
                    authorities, "unavailable", "contract_drift"
                ),
            ),
            "provider_capability_unavailable",
        ),
        (
            replace(
                base,
                admission_ref="route",
                provider_capability=_provider_with_state(
                    authorities, "ready", "ready", typed_predict="unavailable"
                ),
            ),
            "route_capability_unavailable",
        ),
    )
    for request, reason in cases:
        result = admit_model_route(request)
        assert result.status == "unavailable"
        assert result.selected_route is None
        assert reason in result.reason_codes


def test_budget_and_provider_policy_are_explicit_authority_not_defaults() -> None:
    authorities = _authorities()
    request = _request(authorities, "typed_predict")
    insufficient = replace(
        request,
        admission_ref="budget-denied",
        budget=replace(
            request.budget,
            reserved={**request.budget.reserved, "root_model_calls": 0},
        ),
    )
    assert admit_model_route(insufficient).reason_codes == ("budget_insufficient",)
    with pytest.raises(SchemaValidationError, match="provider_storage_policy"):
        _provider_with_policy(authorities, storage="enabled")


def test_replay_capability_requires_exact_runtime_adapter_dependency_and_live_policy() -> None:
    authorities = _authorities()
    replay_adapter = _identity("replay-adapter-1", 4)
    replay = build_replay_capability_certificate(
        record_id="replay-capability-1",
        context_ref="context-1",
        key_epoch="epoch-1",
        dependency_profile=BoundIdentity(
            authorities["profile"].record_id, authorities["profile"].content_digest
        ),
        dependency_capability=BoundIdentity(
            authorities["dependency"].record_id,
            authorities["dependency"].content_digest,
        ),
        runtime=authorities["runtime"],
        replay_adapter=replay_adapter,
        transport=authorities["transport"],
        structural_probe_digest=DIGESTS[5],
        behavioral_probe_digest=DIGESTS[6],
        state="ready",
        reason_code="ready",
        live_tool_dispatch_policy="disabled",
        provider_hosted_tools_policy="disabled",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=15),
    )
    expectation = ReplayCapabilityExpectation(
        context_ref="context-1",
        dependency_profile=BoundIdentity(
            authorities["profile"].record_id, authorities["profile"].content_digest
        ),
        dependency_capability=BoundIdentity(
            authorities["dependency"].record_id,
            authorities["dependency"].content_digest,
        ),
        runtime=authorities["runtime"],
        replay_adapter=replay_adapter,
        transport=authorities["transport"],
        now=NOW,
        revoked_capability_ids=frozenset(),
    )

    require_replay_capability(replay, expectation)
    with pytest.raises(RouteAuthorityError, match="replay_capability_binding_mismatch"):
        require_replay_capability(
            replay, replace(expectation, replay_adapter=_identity("replay-adapter-2", 7))
        )


def _provider_with_state(
    authorities: dict[str, object],
    state: str,
    reason: str,
    *,
    typed_predict: str = "ready",
):
    return build_provider_capability_certificate(
        record_id=f"provider-{state}-{typed_predict}",
        context_ref="context-1",
        key_epoch="epoch-1",
        dependency_profile=BoundIdentity(
            authorities["profile"].record_id, authorities["profile"].content_digest
        ),
        dependency_capability=BoundIdentity(
            authorities["dependency"].record_id,
            authorities["dependency"].content_digest,
        ),
        runtime=authorities["runtime"],
        provider=_identity("provider-1", 13),
        model=authorities["model"],
        transport=authorities["transport"],
        model_type_literal="chat",
        provider_config_signature_digest=DIGESTS[11],
        route_capabilities={
            "typed_predict": authorities["predict_adapter"],
            "recursive_rlm": authorities["rlm_adapter"],
        },
        route_states={"typed_predict": typed_predict, "recursive_rlm": "ready"},
        state=state,
        reason_code=reason,
        price_accounting="known_reconcilable",
        provider_storage_policy="disabled",
        provider_hosted_tools_policy="disabled",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=15),
    )


def _provider_with_policy(authorities: dict[str, object], *, storage: str):
    return build_provider_capability_certificate(
        record_id="provider-policy",
        context_ref="context-1",
        key_epoch="epoch-1",
        dependency_profile=BoundIdentity(
            authorities["profile"].record_id, authorities["profile"].content_digest
        ),
        dependency_capability=BoundIdentity(
            authorities["dependency"].record_id,
            authorities["dependency"].content_digest,
        ),
        runtime=authorities["runtime"],
        provider=_identity("provider-1", 13),
        model=authorities["model"],
        transport=authorities["transport"],
        model_type_literal="chat",
        provider_config_signature_digest=DIGESTS[11],
        route_capabilities={
            "typed_predict": authorities["predict_adapter"],
            "recursive_rlm": authorities["rlm_adapter"],
        },
        route_states={"typed_predict": "ready", "recursive_rlm": "ready"},
        state="ready",
        reason_code="ready",
        price_accounting="known_reconcilable",
        provider_storage_policy=storage,
        provider_hosted_tools_policy="disabled",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=15),
    )
