from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256

from usr.plugins.dspy_rlm.helpers.v3.activation_transition import (
    ActivationRequest,
    ActivationTransitionDenied,
    ActivationTransitionResult,
    RollbackRequest,
    SafetyBypassRequest,
)
from usr.plugins.dspy_rlm.helpers.v3.authority import digest_idempotency_key
from usr.plugins.dspy_rlm.helpers.v3.command_adapter import SafeCommandAdapter
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    ActivationScope,
    IdempotencyConflict,
    OperatorCommand,
    RevisionConflict,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import TypedRecord, canonical_json


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
CONTEXT = "context.local"
ISSUER = "issuer.local"
SUBJECT = "operator.local"


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _exact(label: str) -> dict[str, str]:
    return {"record_id": f"{label}.1", "digest": _digest(label)}


def _link(role: str, identity: dict[str, str]) -> dict[str, object]:
    return {
        "role": role,
        "ordinal": 0,
        "target_id": identity["record_id"],
        "target_digest": identity["digest"],
    }


def _monitor() -> dict[str, object]:
    identities = {
        name: _exact(name)
        for name in (
            "candidate",
            "incumbent",
            "conclusion",
            "policy",
            "calibration",
            "monitor-plan",
        )
    }
    return {
        "record_id": "monitor.1",
        "context_ref": CONTEXT,
        "record_kind": "post_promotion_monitor",
        "schema_id": "a0.self-improvement.post-promotion-monitor.v1",
        "key_epoch": "monitor-v1",
        "payload": {
            "fact_type": "post_promotion_monitor",
            "candidate_id": identities["candidate"]["record_id"],
            "candidate_digest": identities["candidate"]["digest"],
            "incumbent_profile_id": identities["incumbent"]["record_id"],
            "incumbent_profile_digest": identities["incumbent"]["digest"],
            "canary_conclusion_id": identities["conclusion"]["record_id"],
            "canary_conclusion_digest": identities["conclusion"]["digest"],
            "policy_id": identities["policy"]["record_id"],
            "policy_digest": identities["policy"]["digest"],
            "calibration_id": identities["calibration"]["record_id"],
            "calibration_digest": identities["calibration"]["digest"],
            "monitor_plan_id": identities["monitor-plan"]["record_id"],
            "monitor_plan_digest": identities["monitor-plan"]["digest"],
            "observed_scope_revision": 7,
            "resulting_scope_revision": 8,
            "links": [
                _link("candidate", identities["candidate"]),
                _link("incumbent_profile", identities["incumbent"]),
                _link("canary_conclusion", identities["conclusion"]),
                _link("activation_policy", identities["policy"]),
                _link("policy_calibration", identities["calibration"]),
                _link("monitor_plan", identities["monitor-plan"]),
            ],
        },
    }


def _slots(*, canary_occupied: bool = True) -> list[dict[str, object]]:
    return [
        {
            "operation_kind": "canary",
            "revision": 3,
            "occupant": _exact("trial") if canary_occupied else None,
        },
        {"operation_kind": "monitor", "revision": 0, "occupant": None},
        {"operation_kind": "requalification", "revision": 0, "occupant": None},
    ]


def _activate_payload() -> dict[str, object]:
    return {
        "schema": "a0.command.activate.v1",
        "action": "activate",
        "context_ref": CONTEXT,
        "expected_scope_revision": 7,
        "idempotency_key": "opaque-browser-command-01",
        "authority_grant_id": "grant.activate.1",
        "operator_reason_code": "operator_requested",
        "candidate": _exact("candidate"),
        "disposition": _exact("disposition"),
        "canary_conclusion": _exact("conclusion"),
        "policy": _exact("policy"),
        "calibration": _exact("calibration"),
        "successor_profile": _exact("successor"),
        "monitor": _monitor(),
        "eligibility": {
            "candidate": _exact("candidate"),
            "canary_conclusion": _exact("conclusion"),
            "policy": _exact("policy"),
            "calibration": _exact("calibration"),
            "environment_ref": "environment.test",
            "observed_scope_revision": 7,
            "resulting_scope_revision": 8,
            "activation_mode": "manual",
        },
        "authorities": {
            "dependency_profile": _exact("dependency"),
            "capability_certificate": _exact("capability"),
            "fixture_manifests": [_exact("fixture")],
        },
        "slots": _slots(),
    }


def _rollback_payload() -> dict[str, object]:
    return {
        "schema": "a0.command.rollback.v1",
        "action": "rollback",
        "context_ref": CONTEXT,
        "expected_scope_revision": 8,
        "idempotency_key": "opaque-browser-command-02",
        "authority_grant_id": "grant.rollback.1",
        "operator_reason_code": "monitor_failure",
        "predecessor_activation_receipt": _exact("activation-receipt"),
        "predecessor_profile": _exact("incumbent"),
        "slots": _slots(canary_occupied=False),
    }


def _safety_bypass_payload() -> dict[str, object]:
    return {
        "schema": "a0.command.safety-bypass.v1",
        "action": "safety_bypass",
        "context_ref": CONTEXT,
        "expected_scope_revision": 8,
        "idempotency_key": "opaque-browser-command-03",
        "authority_grant_id": "grant.safety.1",
        "operator_reason_code": "emergency_safety_bypass",
        "null_profile": _exact("null-profile"),
        "slots": _slots(canary_occupied=False),
    }


def _receipt(action: str, *, policy_ref: str | None) -> TypedRecord:
    payload = {
        "action": action,
        "observed_revision": 7 if action == "activate" else 8,
        "resulting_revision": 8 if action == "activate" else 9,
        "activation_policy": (
            None
            if policy_ref is None
            else {"record_id": policy_ref, "digest": _digest("policy")}
        ),
        "reason_codes": [{
            "activate": "candidate_activated",
            "rollback": "predecessor_restored",
            "safety_bypass": "safety_bypass_applied",
        }[action]],
    }
    return TypedRecord(
        record_id=f"{action}-receipt.1",
        context_ref=CONTEXT,
        record_kind="activation_transition_receipt",
        schema_id="a0.activation-transition-receipt.v1",
        canonical_bytes=canonical_json(payload),
        content_digest=_digest(f"{action}-receipt"),
        link_manifest_digest=_digest(f"{action}-links"),
        key_epoch="transition-v1",
        links=tuple(),
    )


def _result(
    action: str,
    request: ActivationRequest | RollbackRequest | SafetyBypassRequest,
) -> ActivationTransitionResult:
    revision = request.command.expected_scope_revision
    receipt = _receipt(action, policy_ref="policy.1" if action == "activate" else None)
    return ActivationTransitionResult(
        scope=ActivationScope(
            CONTEXT,
            "profile.current",
            _digest("profile.current"),
            revision + 1,
            "safety_bypass" if action == "safety_bypass" else "normal",
            "2026-08-26T12:00:00.000Z",
        ),
        receipt=receipt,
        command=OperatorCommand(
            f"command.{action}",
            ISSUER,
            SUBJECT,
            CONTEXT,
            action,
            request.command.idempotency_key_digest,
            _digest(f"request.{action}"),
            revision,
            "accepted",
            receipt.record_id,
        ),
        slots=(None, None, None),
        replayed=False,
    )


def _adapter(activate, rollback, safety_bypass=None) -> SafeCommandAdapter:
    return SafeCommandAdapter(
        activate_coordinator=activate,
        rollback_coordinator=rollback,
        activate_grant_revalidator=lambda _transaction: None,
        rollback_grant_revalidator=lambda _transaction: None,
        safety_bypass_coordinator=safety_bypass,
        safety_bypass_grant_revalidator=(
            None if safety_bypass is None else lambda _transaction: None
        ),
    )


def test_activate_admits_closed_request_and_projects_only_safe_receipt_fields() -> None:
    observed: dict[str, object] = {}

    def activate(*, request, revalidate_grant):
        observed["request"] = request
        observed["revalidator"] = revalidate_grant
        return _result("activate", request)

    response = _adapter(activate, lambda **_: None).handle(
        _activate_payload(),
        bound_context_ref=CONTEXT,
        issuer_ref=ISSUER,
        subject_ref=SUBJECT,
        now=NOW,
    )

    request = observed["request"]
    assert type(request) is ActivationRequest
    assert request.command.expected_scope_revision == 7
    assert request.command.idempotency_key_digest == digest_idempotency_key(
        "opaque-browser-command-01"
    )
    assert response.status_code == 200
    assert response.body == {
        "schema": "a0.command-response.v1",
        "accepted": True,
        "action": "activate",
        "receipt_ref": "activate-receipt.1",
        "observed_revision": 7,
        "resulting_revision": 8,
        "policy_ref": "policy.1",
        "action_state": "activated",
        "reason_codes": ["candidate_activated"],
    }
    assert "idempotency_key" not in repr(response.body)
    assert "grant.activate" not in repr(response.body)


def test_rollback_uses_exact_existing_request_type_and_action_revalidator() -> None:
    observed: dict[str, object] = {}

    def rollback(*, request, revalidate_grant):
        observed["request"] = request
        observed["revalidator"] = revalidate_grant
        return _result("rollback", request)

    adapter = _adapter(lambda **_: None, rollback)
    response = adapter.handle(
        _rollback_payload(),
        bound_context_ref=CONTEXT,
        issuer_ref=ISSUER,
        subject_ref=SUBJECT,
        now=NOW,
    )

    request = observed["request"]
    assert type(request) is RollbackRequest
    assert request.command.target_ref == CONTEXT
    assert observed["revalidator"] is adapter.rollback_grant_revalidator
    assert response.body["receipt_ref"] == "rollback-receipt.1"
    assert response.body["policy_ref"] is None


def test_safety_bypass_uses_exact_null_profile_and_dedicated_revalidator() -> None:
    observed: dict[str, object] = {}

    def safety_bypass(*, request, revalidate_grant):
        observed["request"] = request
        observed["revalidator"] = revalidate_grant
        return _result("safety_bypass", request)

    adapter = _adapter(lambda **_: None, lambda **_: None, safety_bypass)
    response = adapter.handle(
        _safety_bypass_payload(),
        bound_context_ref=CONTEXT,
        issuer_ref=ISSUER,
        subject_ref=SUBJECT,
        now=NOW,
    )

    request = observed["request"]
    assert type(request) is SafetyBypassRequest
    assert request.null_profile.record_id == "null-profile.1"
    assert observed["revalidator"] is adapter.safety_bypass_grant_revalidator
    assert response.body["action_state"] == "safety_bypass"
    assert response.body["reason_codes"] == ["safety_bypass_applied"]


def test_pre_domain_failures_are_closed_and_never_invoke_coordinator() -> None:
    called = False

    def coordinator(**_kwargs):
        nonlocal called
        called = True

    cases = (
        (lambda body: body.update(extra="not-admitted"), "schema_invalid", 400),
        (lambda body: body.update(context_ref="context.other"), "context_binding_mismatch", 422),
        (lambda body: body.update(operator_reason_code="because I said so"), "reason_code_invalid", 422),
    )
    for change, reason_code, status in cases:
        payload = _activate_payload()
        change(payload)
        response = _adapter(coordinator, coordinator).handle(
            payload,
            bound_context_ref=CONTEXT,
            issuer_ref=ISSUER,
            subject_ref=SUBJECT,
            now=NOW,
        )

        assert called is False
        assert response.status_code == status
        assert response.body["accepted"] is False
        assert response.body["receipt_ref"] is None
        assert response.body["reason_codes"] == [reason_code]


def test_domain_failures_are_safe_receipt_free_responses() -> None:
    cases = (
        (IdempotencyConflict("raw request leaked"), 409, "idempotency_conflict"),
        (RevisionConflict("database revision 99 leaked"), 409, "scope_revision_conflict"),
        (
            ActivationTransitionDenied("dependency_capability_unavailable"),
            503,
            "dependency_capability_unavailable",
        ),
        (RuntimeError("private-detail-do-not-return"), 503, "internal_error"),
    )
    for error, status, reason_code in cases:
        def activate(**_kwargs):
            raise error

        response = _adapter(activate, lambda **_: None).handle(
            _activate_payload(),
            bound_context_ref=CONTEXT,
            issuer_ref=ISSUER,
            subject_ref=SUBJECT,
            now=NOW,
        )

        assert response.status_code == status
        assert response.body["receipt_ref"] is None
        assert response.body["reason_codes"] == [reason_code]
        assert "leaked" not in repr(response.body)
        assert "private-detail" not in repr(response.body)
