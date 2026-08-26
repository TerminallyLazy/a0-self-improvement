from __future__ import annotations

from types import SimpleNamespace

import pytest

from usr.plugins.dspy_rlm.helpers.v3.post_activation_command_adapter import (
    MONITOR_CONCLUDE_COMMAND_SCHEMA,
    REQUALIFICATION_CONCLUDE_COMMAND_SCHEMA,
    REQUALIFICATION_START_COMMAND_SCHEMA,
    PostActivationCommandAdapter,
)
from usr.plugins.dspy_rlm.helpers.v3.post_activation_repository import (
    PostActivationCommitResult,
    PostActivationError,
    digest_post_activation_request,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
    IntegrityFailure,
    RevisionConflict,
)


CONTEXT = "context:adapter"
KEY_EPOCH = "adapter-v1"
DIGEST = "a" * 64


def _exact(label: str):
    return {"record_id": f"{label}:1", "digest": DIGEST}


def _payload(action: str):
    schema = {
        "monitor_conclude": MONITOR_CONCLUDE_COMMAND_SCHEMA,
        "requalification_start": REQUALIFICATION_START_COMMAND_SCHEMA,
        "requalification_conclude": REQUALIFICATION_CONCLUDE_COMMAND_SCHEMA,
    }[action]
    return {
        "schema": schema,
        "action": action,
        "context_ref": CONTEXT,
        "expected_scope_revision": 7,
        "key_epoch": KEY_EPOCH,
        "idempotency_key": f"idempotency:{action}",
        "authority_grant_id": "grant:post-activation",
        "monitor_slot": {
            "revision": 4,
            "occupant": None if action == "requalification_conclude" else _exact("monitor"),
        },
        "requalification_slot": {
            "revision": 2,
            "occupant": _exact("requalification") if action == "requalification_conclude" else None,
        },
        "subject": _exact("requalification" if action == "requalification_conclude" else "monitor"),
        "certified_outcome": _exact("outcome"),
        "eligibility": _exact("eligibility"),
        "activation_policy": _exact("policy"),
        "policy_calibration": _exact("calibration"),
        "conclusion_record_id": f"conclusion:{action}",
        "requalification_window_id": (
            "requalification:new" if action == "requalification_start" else None
        ),
    }


class _Coordinator:
    def __init__(self, *, error=None):
        self.error = error
        self.calls = []

    def commit(self, operation, *, revalidate_authority):
        self.calls.append(operation)
        if self.error is not None:
            raise self.error
        assert operation.request_digest == digest_post_activation_request(operation)
        assert revalidate_authority(None, operation) == operation.authority
        decision = {
            "monitor_conclude": "retain",
            "requalification_start": "requalify",
            "requalification_conclude": "rollback_required",
        }[operation.action]
        receipt = SimpleNamespace(
            record_id=f"receipt:{operation.action}",
            payload={
                "request_digest": operation.request_digest,
                "action": operation.action,
                "decision": decision,
                "observed_scope_revision": operation.expected_scope_revision,
                "resulting_scope_revision": operation.expected_scope_revision,
            },
        )
        conclusion = SimpleNamespace(
            record_id=operation.conclusion_record_id,
            payload={"decision": decision},
        )
        monitor_slot = SimpleNamespace(operation_revision=5)
        requalification_slot = SimpleNamespace(operation_revision=3)
        window = (
            SimpleNamespace(record_id=operation.requalification_window_id)
            if operation.requalification_window_id is not None
            else None
        )
        rollback = (
            SimpleNamespace(record_id="rollback-request:1")
            if decision == "rollback_required"
            else None
        )
        return PostActivationCommitResult(
            conclusion,
            receipt,
            monitor_slot,
            requalification_slot,
            window,
            rollback,
            SimpleNamespace(),
            False,
        )


def _adapter(coordinator):
    return PostActivationCommandAdapter(
        key_epoch=KEY_EPOCH,
        mutation_coordinator=coordinator,
        authority_revalidator=lambda _transaction, operation: operation.authority,
    )


def _handle(adapter, payload):
    return adapter.handle(
        payload,
        bound_context_ref=CONTEXT,
        actor_authority_ref="grant:post-activation",
        issuer_ref="issuer:operator",
        subject_ref="subject:operator",
    )


@pytest.mark.parametrize(
    ("action", "decision", "window_ref", "rollback_ref"),
    (
        ("monitor_conclude", "retain", None, None),
        ("requalification_start", "requalify", "requalification:new", None),
        (
            "requalification_conclude",
            "rollback_required",
            None,
            "rollback-request:1",
        ),
    ),
)
def test_exact_commands_delegate_without_outcome_inference(
    action, decision, window_ref, rollback_ref
):
    coordinator = _Coordinator()
    payload = _payload(action)
    assert "decision" not in payload
    response = _handle(_adapter(coordinator), payload)
    assert response.status_code == 200
    assert response.body["accepted"] is True
    assert response.body["decision"] == decision
    assert response.body["requalification_ref"] == window_ref
    assert response.body["rollback_request_ref"] == rollback_ref
    assert response.body["observed_revision"] == 7
    assert len(coordinator.calls) == 1


def test_closed_schema_and_framework_bindings_fail_before_mutation():
    coordinator = _Coordinator()
    payload = {**_payload("monitor_conclude"), "threshold": 0.75}
    malformed = _handle(_adapter(coordinator), payload)
    assert malformed.status_code == 400
    assert malformed.body["reason_codes"] == ["schema_invalid"]
    assert coordinator.calls == []

    wrong_epoch = {**_payload("monitor_conclude"), "key_epoch": "wrong-v1"}
    refused = _handle(_adapter(coordinator), wrong_epoch)
    assert refused.status_code == 422
    assert refused.body["reason_codes"] == ["key_epoch_binding_mismatch"]
    assert coordinator.calls == []

    wrong_grant = {
        **_payload("monitor_conclude"),
        "authority_grant_id": "grant:other",
    }
    refused = _handle(_adapter(coordinator), wrong_grant)
    assert refused.status_code == 422
    assert refused.body["reason_codes"] == ["authority_grant_binding_mismatch"]
    assert coordinator.calls == []


@pytest.mark.parametrize(
    ("error", "status", "reason"),
    (
        (IdempotencyConflict("secret-conflict-detail"), 409, "idempotency_conflict"),
        (RevisionConflict("secret-revision-detail"), 409, "post_activation_slot_conflict"),
        (PostActivationError("secret-authority-detail"), 422, "post_activation_authority_denied"),
        (IntegrityFailure("secret-integrity-detail"), 422, "post_activation_binding_denied"),
    ),
)
def test_conflict_and_authority_errors_are_content_free(error, status, reason):
    response = _handle(_adapter(_Coordinator(error=error)), _payload("monitor_conclude"))
    assert response.status_code == status
    assert response.body["accepted"] is False
    assert response.body["reason_codes"] == [reason]
    assert "secret-" not in str(response.body)
