from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

from usr.plugins.dspy_rlm.helpers.v3 import calibration_authority as lifecycle
from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    GrantRequest,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
)
from usr.plugins.dspy_rlm.helpers.v3.calibration_authority import (
    CALIBRATION_AUTHORITY_REGISTRY,
    CalibrationApprovalRequest,
    CalibrationWithdrawalRequest,
    ExactRecord,
)
from usr.plugins.dspy_rlm.helpers.v3.canary import (
    BucketCalibration,
    Rational,
    activation_policy,
    canary_plan,
    monitor_plan,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Repository
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json


CONTEXT = "context:calibration-cli"
ENVIRONMENT = "environment:local"
NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
EXPIRES = NOW + timedelta(minutes=5)
CLI = Path(__file__).resolve().parents[1] / "scripts" / "a0_local_authority.py"


def digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def setup_inputs(tmp_path: Path):
    store = tmp_path / "store.sqlite3"
    policy = activation_policy(
        record_id="policy:cli",
        context_ref=CONTEXT,
        policy_revision=4,
        activation_mode="canary_required",
        key_epoch="test-v1",
    )
    canary = canary_plan(
        record_id="canary-plan:cli",
        context_ref=CONTEXT,
        horizon_exposures=10,
        expiry_seconds=900,
        candidate_allocation=Rational(1, 2),
        assignment_key_commitment=digest("assignment"),
        hard_veto_failure_limit=0,
        buckets=(BucketCalibration("shell", 5, Rational(0, 1), Rational(0, 1)),),
        key_epoch="test-v1",
    )
    monitor = monitor_plan(
        record_id="monitor-plan:cli",
        context_ref=CONTEXT,
        horizon_exposures=20,
        look_interval_exposures=5,
        ordinary_regression_boundary=Rational(0, 1),
        hard_veto_failure_limit=0,
        key_epoch="test-v1",
    )
    with V3Repository.create(store, registry=CALIBRATION_AUTHORITY_REGISTRY) as repository:
        with repository.transaction() as transaction:
            for record in (policy, canary, monitor):
                transaction.insert_record(record)

    secret = tmp_path / "issuer.secret"
    profile_path = tmp_path / "issuer-profile.json"
    profile = bootstrap_local_issuer(
        secret,
        issuer_id="issuer:local",
        key_epoch=1,
        allowed_authority_classes=(
            AuthorityClass.POLICY_CALIBRATION_APPROVAL.value,
        ),
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    profile_path.write_bytes(canonical_json(profile.to_record()))
    profile_path.chmod(0o600)
    ledger = tmp_path / "revocations"
    ledger.mkdir(mode=0o700)
    return store, policy, canary, monitor, secret, profile_path, profile, ledger


def approval_request(policy, canary, monitor, *, subject: str = "operator:test"):
    return CalibrationApprovalRequest(
        calibration_id="calibration:cli",
        receipt_id="receipt:calibration-approve",
        context_ref=CONTEXT,
        expected_policy_revision=4,
        environment_ref=ENVIRONMENT,
        policy=ExactRecord.of(policy),
        canary_plan=ExactRecord.of(canary),
        monitor_plan=ExactRecord.of(monitor),
        activation_authorities=("manual",),
        soft_rollback_authorized=True,
        issuer_ref="issuer:local",
        subject_ref=subject,
        idempotency_key_digest=digest_idempotency_key("approve-key"),
        session_nonce="session:calibration",
        reason_code="calibration_approved",
        key_epoch="test-v1",
    )


def write_grant(path: Path, secret: Path, profile, binding) -> None:
    envelope = issue_grant(
        secret,
        profile,
        GrantRequest(
            authority_class=binding.authority_class,
            issuer_id=binding.issuer_ref,
            key_epoch=profile.key_epoch,
            subject_ref=binding.subject_ref,
            context_ref=binding.context_ref,
            action=binding.action,
            purpose=binding.purpose,
            target_ref=binding.target_ref,
            target_revision=binding.target_revision,
            issued_at=NOW,
            expires_at=EXPIRES,
            idempotency_key_digest=binding.idempotency_key_digest,
            session_nonce=binding.session_nonce,
        ),
    )
    path.write_bytes(canonical_json(envelope))


def mutation_args(
    store,
    policy,
    canary,
    monitor,
    secret,
    profile_path,
    ledger,
    grant_path,
) -> list[str]:
    return [
        "--store",
        str(store),
        "--context",
        CONTEXT,
        "--environment",
        ENVIRONMENT,
        "--policy-id",
        policy.record_id,
        "--policy-digest",
        policy.content_digest,
        "--canary-plan-id",
        canary.record_id,
        "--canary-plan-digest",
        canary.content_digest,
        "--monitor-plan-id",
        monitor.record_id,
        "--monitor-plan-digest",
        monitor.content_digest,
        "--policy-revision",
        "4",
        "--activation-authority",
        "manual",
        "--soft-rollback-authorized",
        "true",
        "--issuer",
        "issuer:local",
        "--subject",
        "operator:test",
        "--profile",
        str(profile_path),
        "--secret",
        str(secret),
        "--grant",
        str(grant_path),
        "--revocation-ledger",
        str(ledger),
        "--session-nonce",
        "session:calibration",
        "--authority-expires-at",
        EXPIRES.isoformat(),
        "--now",
        NOW.isoformat(),
        "--key-epoch",
        "test-v1",
    ]


def invoke(arguments: list[str]):
    completed = subprocess.run(
        [sys.executable, str(CLI), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout if completed.returncode == 0 else completed.stderr)
    return completed.returncode, payload


def test_calibration_approve_uses_exact_signed_binding_and_selected_store(
    tmp_path: Path,
):
    store, policy, canary, monitor, secret, profile_path, profile, ledger = setup_inputs(
        tmp_path
    )
    request = approval_request(policy, canary, monitor)
    grant = tmp_path / "approval-grant.json"
    write_grant(grant, secret, profile, lifecycle._approval_binding(request))
    args = mutation_args(
        store, policy, canary, monitor, secret, profile_path, ledger, grant
    )
    status, output = invoke(
        [
            "calibration-approve",
            *args,
            "--calibration-id",
            request.calibration_id,
            "--receipt-id",
            request.receipt_id,
            "--idempotency-key",
            "approve-key",
            "--reason-code",
            request.reason_code,
        ],
    )
    assert status == 0
    assert output == {
        "ok": True,
        "state": "approved",
        "calibration_ref": request.calibration_id,
        "receipt_ref": request.receipt_id,
        "eligibility": "approved",
    }
    with V3Repository.open(store, registry=CALIBRATION_AUTHORITY_REGISTRY) as repository:
        assert repository.get_record(request.calibration_id) is not None
        assert repository.get_record(request.receipt_id) is not None


def test_withdraw_and_read_only_inspect_report_only_lifecycle_refs(tmp_path: Path):
    store, policy, canary, monitor, secret, profile_path, profile, ledger = setup_inputs(
        tmp_path
    )
    approved_request = approval_request(policy, canary, monitor)
    approve_grant = tmp_path / "approval-grant.json"
    write_grant(
        approve_grant, secret, profile, lifecycle._approval_binding(approved_request)
    )
    common = mutation_args(
        store, policy, canary, monitor, secret, profile_path, ledger, approve_grant
    )
    assert invoke(
        [
            "calibration-approve",
            *common,
            "--calibration-id",
            approved_request.calibration_id,
            "--receipt-id",
            approved_request.receipt_id,
            "--idempotency-key",
            "approve-key",
            "--reason-code",
            "calibration_approved",
        ],
    )[0] == 0
    with V3Repository.open(store, registry=CALIBRATION_AUTHORITY_REGISTRY) as repository:
        calibration = repository.get_record(approved_request.calibration_id)
        assert calibration is not None
    withdrawal = CalibrationWithdrawalRequest(
        receipt_id="receipt:calibration-withdraw",
        context_ref=CONTEXT,
        expected_policy_revision=4,
        environment_ref=ENVIRONMENT,
        calibration=ExactRecord.of(calibration),
        issuer_ref="issuer:local",
        subject_ref="operator:test",
        idempotency_key_digest=digest_idempotency_key("withdraw-key"),
        session_nonce="session:calibration",
        reason_code="calibration_withdrawn",
        key_epoch="test-v1",
    )
    withdraw_grant = tmp_path / "withdraw-grant.json"
    write_grant(
        withdraw_grant,
        secret,
        profile,
        lifecycle._withdrawal_binding(withdrawal, calibration),
    )
    withdraw_common = mutation_args(
        store, policy, canary, monitor, secret, profile_path, ledger, withdraw_grant
    )
    status, output = invoke(
        [
            "calibration-withdraw",
            *withdraw_common,
            "--calibration-id",
            calibration.record_id,
            "--calibration-digest",
            calibration.content_digest,
            "--receipt-id",
            withdrawal.receipt_id,
            "--idempotency-key",
            "withdraw-key",
            "--reason-code",
            withdrawal.reason_code,
        ],
    )
    assert status == 0
    assert output["eligibility"] == "withdrawn"
    before = store.stat().st_mtime_ns
    status, inspected = invoke(
        [
            "calibration-inspect",
            "--store",
            str(store),
            "--context",
            CONTEXT,
            "--calibration-id",
            calibration.record_id,
            "--calibration-digest",
            calibration.content_digest,
            "--maximum-events",
            "2",
        ],
    )
    assert status == 0
    assert inspected == {
        "ok": True,
        "state": "inspected",
        "calibration_ref": calibration.record_id,
        "eligibility": "withdrawn",
        "reason_codes": ["calibration_withdrawn"],
        "receipt_refs": [approved_request.receipt_id, withdrawal.receipt_id],
    }
    assert store.stat().st_mtime_ns == before


def test_cli_subject_cannot_override_signed_grant_and_denial_writes_nothing(
    tmp_path: Path,
):
    store, policy, canary, monitor, secret, profile_path, profile, ledger = setup_inputs(
        tmp_path
    )
    signed = approval_request(policy, canary, monitor, subject="operator:signed")
    grant = tmp_path / "wrong-subject-grant.json"
    write_grant(grant, secret, profile, lifecycle._approval_binding(signed))
    args = mutation_args(
        store, policy, canary, monitor, secret, profile_path, ledger, grant
    )
    status, output = invoke(
        [
            "calibration-approve",
            *args,
            "--calibration-id",
            "calibration:denied",
            "--receipt-id",
            "receipt:denied",
            "--idempotency-key",
            "approve-key",
            "--reason-code",
            "calibration_approved",
        ],
    )
    assert status == 1
    assert output == {"ok": False, "reason_code": "AuthorityServiceError"}
    with V3Repository.open(store, registry=CALIBRATION_AUTHORITY_REGISTRY) as repository:
        assert repository.get_record("calibration:denied") is None
        assert repository.get_record("receipt:denied") is None
