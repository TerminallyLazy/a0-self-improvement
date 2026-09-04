"""One-time Autopilot opt-in translated into bounded standing authority.

The optimizer never receives issuer custody.  This coordinator runs in the
framework process after project Genesis, freezes the effective production
policy, and approves its exact canary and monitor plans.  Later transition
coordinators may use the same local issuer only to derive short-lived grants
bound to one candidate, action, and Activation Scope revision.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from hashlib import sha256
from contextlib import contextmanager
import fcntl
import hmac
import json
from math import ceil, exp, lgamma, log, log1p
import os
from pathlib import Path
import stat
import threading
from typing import Any, Iterator, Mapping

from .authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    AuthorityPurpose,
    GrantExpectation,
    GrantRequest,
    IssuerProfile,
    authorize_grant,
    bootstrap_local_issuer,
    canonical_json_bytes,
    digest_idempotency_key,
    issue_grant,
    require_local_issuer,
)
from .calibration_authority import (
    CalibrationApprovalRequest,
    CalibrationGrantBinding,
    ExactRecord,
    approve_policy_calibration,
)
from .canary import (
    BucketCalibration,
    Rational,
    activation_policy,
    canary_plan,
    monitor_plan,
)
from .repository import IntegrityFailure, V3Repository
from .schemas import TypedRecord, canonical_json


AUTOPILOT_ENVIRONMENT_REF = "agent-zero:local-production"
AUTOPILOT_AUTHORITY_CONSENT_REVISION = 1
AUTOPILOT_KEY_EPOCH = "autopilot-control-v1"
AUTOPILOT_PLAN_REVISION = "comparative-canary-v5"
AUTOPILOT_ISSUER_ID = "issuer_autopilot_transition_01"
AUTOPILOT_SUBJECT_REF = "autopilot_transition_coordinator"
AUTOPILOT_BUCKETS = ("reasoning",)
_GRANT_LIFETIME = timedelta(minutes=5)
_CANARY_TOTAL_SHORTFALL_RISK = 0.01
_CUSTODY_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class AutopilotControlPlaneResult:
    state: str
    policy: ExactRecord | None
    calibration: ExactRecord | None
    replayed: bool


@dataclass(frozen=True, slots=True)
class AutopilotTransitionSettings:
    minimum_observations: int
    maximum_observations: int
    candidate_percentage: int
    maximum_score_regression: float
    maximum_failure_rate_increase: float


def transition_settings(config: Mapping[str, Any]) -> AutopilotTransitionSettings:
    prompt = config.get("prompt_optimization")
    prompt = prompt if isinstance(prompt, Mapping) else {}
    rollback = prompt.get("rollback")
    rollback = rollback if isinstance(rollback, Mapping) else {}
    minimum = max(3, int(prompt.get("canary_min_observations", 10) or 10))
    maximum = max(minimum, int(prompt.get("canary_max_observations", 40) or 40))
    return AutopilotTransitionSettings(
        minimum,
        maximum,
        max(1, min(99, int(prompt.get("canary_percentage", 10) or 10))),
        max(0.0, min(1.0, float(rollback.get("maximum_score_regression", 0.05) or 0.0))),
        max(0.0, min(1.0, float(rollback.get("maximum_failure_rate_increase", 0.05) or 0.0))),
    )


def effective_config_digest(config: Mapping[str, Any]) -> str:
    """Bind completed worker evidence to one exact normalized config snapshot."""

    return sha256(canonical_json(dict(config))).hexdigest()


def _binomial_below_minimum_probability(
    trials: int, minimum: int, probability: float,
) -> float:
    """Return P[X < minimum] for X ~ Binomial(trials, probability)."""

    if type(trials) is not int or trials < 0:
        raise ValueError("trials must be a non-negative integer")
    if type(minimum) is not int or minimum < 0:
        raise ValueError("minimum must be a non-negative integer")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be between zero and one")
    if minimum == 0:
        return 0.0
    if trials < minimum or probability == 0.0:
        return 1.0
    if probability == 1.0:
        return 0.0
    terms = [
        lgamma(trials + 1)
        - lgamma(successes + 1)
        - lgamma(trials - successes + 1)
        + successes * log(probability)
        + (trials - successes) * log1p(-probability)
        for successes in range(minimum)
    ]
    largest = max(terms)
    return min(1.0, exp(largest) * sum(exp(term - largest) for term in terms))


def _reliable_canary_horizon(
    *, minimum: int, maximum: int, candidate_percentage: int,
) -> int:
    """Size a fixed horizon with at most 1% combined arm-shortfall risk."""

    candidate_probability = candidate_percentage / 100.0
    per_arm_risk = _CANARY_TOTAL_SHORTFALL_RISK / 2

    def sufficient(trials: int) -> bool:
        return (
            _binomial_below_minimum_probability(
                trials, minimum, candidate_probability
            )
            <= per_arm_risk
            and _binomial_below_minimum_probability(
                trials, minimum, 1.0 - candidate_probability
            )
            <= per_arm_risk
        )

    lower = max(
        maximum,
        ceil(minimum / candidate_probability),
        ceil(minimum / (1.0 - candidate_probability)),
    )
    upper = lower
    while not sufficient(upper):
        upper *= 2
    while lower < upper:
        middle = (lower + upper) // 2
        if sufficient(middle):
            upper = middle
        else:
            lower = middle + 1
    return lower


def issue_automatic_transition_grant(
    *,
    authority_root: Path,
    context_ref: str,
    action: str,
    target_ref: str,
    target_revision: int,
    now: datetime | None = None,
):
    """Issue and immediately verify one short-lived, exact transition grant."""

    if action not in {"activate", "rollback"}:
        raise ValueError("automatic transition action is not admitted")
    if type(target_revision) is not int or target_revision < 0:
        raise ValueError("target_revision must be non-negative")
    custody = _custody(authority_root)
    profile = _issuer(custody)
    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = reference + _GRANT_LIFETIME
    key_digest = digest_idempotency_key(
        f"autopilot-transition-v1:{context_ref}:{action}:{target_ref}:{target_revision}"
    )
    nonce = sha256(
        f"{context_ref}\0{action}\0{target_ref}\0{target_revision}".encode()
    ).hexdigest()[:32]
    request = GrantRequest(
        authority_class=AuthorityClass.AUTOMATIC_TRANSITION_GRANT.value,
        issuer_id=profile.issuer_id,
        key_epoch=profile.key_epoch,
        subject_ref=AUTOPILOT_SUBJECT_REF,
        context_ref=context_ref,
        action=action,
        purpose=AuthorityPurpose.AUTOMATIC_PROMOTION.value,
        target_ref=target_ref,
        target_revision=target_revision,
        issued_at=reference,
        expires_at=expires_at,
        idempotency_key_digest=key_digest,
        session_nonce=f"automatic_transition_{nonce}",
    )
    envelope = issue_grant(custody.secret, profile, request)
    grant_id = envelope["payload"]["grant_id"]
    grant_path = custody.grants / f"{grant_id}.json"
    _persist_grant(custody, grant_path, canonical_json_bytes(envelope))
    return authorize_grant(
        envelope,
        custody.secret,
        profile,
        GrantExpectation(
            authority_class=request.authority_class,
            issuer_id=request.issuer_id,
            subject_ref=request.subject_ref,
            context_ref=request.context_ref,
            action=request.action,
            purpose=request.purpose,
            target_ref=request.target_ref,
            target_revision=request.target_revision,
            expires_at=request.expires_at,
            idempotency_key_digest=request.idempotency_key_digest,
            session_nonce=request.session_nonce,
        ),
        now=reference,
    )


def canary_assignment_value(
    *, authority_root: Path, context_ref: str, candidate_ref: str,
    exposure_ref: str, assignment_key_commitment: str,
) -> int:
    """Return the keyed stable 0..99 canary assignment for one exposure."""

    custody = _custody(authority_root)
    secret = _read_private(custody.assignment_key, expected_size=32)
    committed = sha256(b"a0-canary-assignment-key\0" + secret).hexdigest()
    if not hmac.compare_digest(committed, assignment_key_commitment):
        raise PermissionError("Autopilot assignment key does not match the calibrated plan")
    payload = f"{context_ref}\0{candidate_ref}\0{exposure_ref}".encode()
    return int.from_bytes(hmac.digest(secret, payload, "sha256")[:8], "big") % 100


@dataclass(frozen=True, slots=True)
class _Custody:
    root: Path
    secret: Path
    profile: Path
    assignment_key: Path
    grants: Path
    lock: Path


def _custody(root: Path) -> _Custody:
    return _Custody(
        root=root,
        secret=root / "issuer-root.secret",
        profile=root / "issuer-profile.json",
        assignment_key=root / "canary-assignment.key",
        grants=root / "grants",
        lock=root / "coordinator.lock",
    )


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise PermissionError("Autopilot authority directory is unavailable")
    os.chmod(path, 0o700)


def _write_private_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("Autopilot authority write was incomplete")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    directory = os.open(path.parent, directory_flags)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_private(path: Path, *, expected_size: int | None = None) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise PermissionError("Autopilot authority file is not owner-only")
        chunks: list[bytes] = []
        remaining = metadata.st_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if expected_size is not None and len(payload) != expected_size:
        raise ValueError("Autopilot authority file has an invalid size")
    return payload


@contextmanager
def _coordinator_lock(custody: _Custody) -> Iterator[None]:
    _private_dir(custody.root)
    _private_dir(custody.grants)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(custody.lock, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise PermissionError("Autopilot coordinator lock is unavailable")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _persist_grant(custody: _Custody, path: Path, payload: bytes) -> None:
    """Create one immutable grant safely across framework processes."""

    with _CUSTODY_LOCK, _coordinator_lock(custody):
        try:
            _write_private_new(path, payload)
        except FileExistsError:
            if not hmac.compare_digest(_read_private(path), payload):
                raise IntegrityFailure("Autopilot grant identity contains different bytes")


def _issuer(custody: _Custody) -> IssuerProfile:
    with _CUSTODY_LOCK, _coordinator_lock(custody):
        return _issuer_unlocked(custody)


def autopilot_transition_runtime_ready(authority_root: Path) -> bool:
    """Read-only custody health check used by operator status surfaces."""

    try:
        custody = _custody(authority_root)
        for directory in (custody.root, custody.grants):
            metadata = directory.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                return False
        classes = tuple(
            sorted(
                (
                    AuthorityClass.AUTOMATIC_TRANSITION_GRANT.value,
                    AuthorityClass.POLICY_CALIBRATION_APPROVAL.value,
                )
            )
        )
        expected = IssuerProfile(
            issuer_id=AUTOPILOT_ISSUER_ID,
            key_epoch=1,
            allowed_authority_classes=classes,
        )
        profile = IssuerProfile.from_record(
            json.loads(_read_private(custody.profile).decode("utf-8"))
        )
        require_local_issuer(custody.secret, expected.to_record())
        _read_private(custody.assignment_key, expected_size=32)
        _read_private(custody.lock)
        return profile == expected
    except Exception:
        return False


def _issuer_unlocked(custody: _Custody) -> IssuerProfile:
    _private_dir(custody.root)
    _private_dir(custody.grants)
    classes = tuple(
        sorted(
            (
                AuthorityClass.AUTOMATIC_TRANSITION_GRANT.value,
                AuthorityClass.POLICY_CALIBRATION_APPROVAL.value,
            )
        )
    )
    expected = IssuerProfile(
        issuer_id=AUTOPILOT_ISSUER_ID,
        key_epoch=1,
        allowed_authority_classes=classes,
    )
    if not custody.secret.exists():
        if custody.profile.exists():
            raise RuntimeError("Autopilot issuer secret is unavailable")
        profile = bootstrap_local_issuer(
            custody.secret,
            issuer_id=expected.issuer_id,
            key_epoch=expected.key_epoch,
            allowed_authority_classes=classes,
            confirmation=BOOTSTRAP_CONFIRMATION,
        )
    else:
        profile = require_local_issuer(custody.secret, expected.to_record())
    if not custody.profile.exists():
        _write_private_new(custody.profile, canonical_json_bytes(profile.to_record()))
    loaded = IssuerProfile.from_record(
        json.loads(_read_private(custody.profile).decode("utf-8"))
    )
    if loaded != expected:
        raise RuntimeError("Autopilot issuer profile is not the bounded built-in profile")
    if not custody.assignment_key.exists():
        _write_private_new(custody.assignment_key, os.urandom(32))
    _read_private(custody.assignment_key, expected_size=32)
    return loaded


def _rational(value: float, *, negative: bool = False) -> Rational:
    fraction = Fraction(str(max(0.0, min(1.0, float(value))))).limit_denominator(10_000)
    numerator = -fraction.numerator if negative else fraction.numerator
    return Rational(numerator, fraction.denominator)


def _fingerprint(
    config: Mapping[str, Any], settings: AutopilotTransitionSettings
) -> str:
    automation = config.get("automation")
    automation = automation if isinstance(automation, Mapping) else {}
    optimization = config.get("optimization")
    optimization = optimization if isinstance(optimization, Mapping) else {}
    payload = {
        "control_plane_revision": AUTOPILOT_PLAN_REVISION,
        "risk_profile": automation.get("risk_profile"),
        "require_replay": automation.get("require_replay"),
        "require_canary": automation.get("require_canary"),
        "automatic_rollback": automation.get("automatic_rollback"),
        "minimum_samples": optimization.get("min_samples_for_promotion"),
        "canary_percentage": settings.candidate_percentage,
        "canary_minimum": settings.minimum_observations,
        "canary_maximum": settings.maximum_observations,
        "maximum_score_regression": settings.maximum_score_regression,
        "maximum_failure_rate_increase": settings.maximum_failure_rate_increase,
    }
    return sha256(canonical_json(payload)).hexdigest()


def expected_autopilot_policy_id(
    context_ref: str, config: Mapping[str, Any]
) -> str:
    """Return the policy identity prefix for current effective settings."""

    fingerprint = _fingerprint(config, transition_settings(config))
    scoped = sha256(canonical_json([context_ref, fingerprint])).hexdigest()
    return f"autopilot-policy:{scoped}"


def _exact_existing(
    repository: V3Repository, expected: TypedRecord
) -> TypedRecord | None:
    existing = repository.get_record(expected.record_id)
    if existing is not None and existing != expected:
        raise IntegrityFailure("Autopilot control identity contains different bytes")
    return existing


def _grant_revalidator(
    *,
    custody: _Custody,
    profile: IssuerProfile,
    now: datetime,
    expires_at: datetime,
):
    def revalidate(binding: CalibrationGrantBinding):
        envelope = issue_grant(
            custody.secret,
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
                issued_at=now,
                expires_at=expires_at,
                idempotency_key_digest=binding.idempotency_key_digest,
                session_nonce=binding.session_nonce,
            ),
        )
        grant_id = envelope["payload"]["grant_id"]
        grant_path = custody.grants / f"{grant_id}.json"
        _persist_grant(custody, grant_path, canonical_json_bytes(envelope))
        return authorize_grant(
            envelope,
            custody.secret,
            profile,
            GrantExpectation(
                authority_class=binding.authority_class,
                issuer_id=binding.issuer_ref,
                subject_ref=binding.subject_ref,
                context_ref=binding.context_ref,
                action=binding.action,
                purpose=binding.purpose,
                target_ref=binding.target_ref,
                target_revision=binding.target_revision,
                expires_at=expires_at,
                idempotency_key_digest=binding.idempotency_key_digest,
                session_nonce=binding.session_nonce,
            ),
            now=now,
        )

    return revalidate


def provision_autopilot_control_plane(
    repository: V3Repository,
    *,
    context_ref: str,
    config: Mapping[str, Any],
    authority_root: Path,
    now: datetime | None = None,
) -> AutopilotControlPlaneResult:
    """Freeze and approve the exact standing policy selected by Autopilot."""

    automation = config.get("automation")
    automation = automation if isinstance(automation, Mapping) else {}
    if (
        config.get("enabled") is not True
        or automation.get("mode") != "autopilot"
        or automation.get("authority_consent_revision")
        != AUTOPILOT_AUTHORITY_CONSENT_REVISION
    ):
        return AutopilotControlPlaneResult("not_authorized", None, None, False)
    if not isinstance(repository, V3Repository):
        raise TypeError("Autopilot control plane requires a V3Repository")
    if type(context_ref) is not str or not context_ref:
        raise ValueError("context_ref is required")
    if not isinstance(authority_root, Path) or not authority_root.is_absolute():
        raise ValueError("authority_root must be an absolute Path")
    repository.ensure_query_indexes()
    if repository.get_activation_scope(context_ref) is None:
        raise RuntimeError("Autopilot control plane requires project Genesis")

    settings = transition_settings(config)
    fingerprint = _fingerprint(config, settings)
    scoped_fingerprint = sha256(canonical_json([context_ref, fingerprint])).hexdigest()
    policy_id = expected_autopilot_policy_id(context_ref, config)
    canary_id = f"autopilot-canary-plan:{scoped_fingerprint}"
    monitor_id = f"autopilot-monitor-plan:{scoped_fingerprint}"
    calibration_id = f"autopilot-calibration:{scoped_fingerprint}"
    minimum = settings.minimum_observations
    maximum = settings.maximum_observations
    percentage = settings.candidate_percentage
    failure_regression = settings.maximum_failure_rate_increase
    custody = _custody(authority_root)
    profile = _issuer(custody)
    assignment_key = _read_private(custody.assignment_key, expected_size=32)
    # ``minimum`` is a per-arm comparable count. Size the fixed horizon so the
    # combined probability that either keyed-random arm misses it is <= 1%.
    # ``maximum`` remains the lower bound and the monitor horizon.
    canary_horizon = _reliable_canary_horizon(
        minimum=minimum,
        maximum=maximum,
        candidate_percentage=percentage,
    )
    # Allocate the policy occurrence while holding the v3 writer lock. A
    # settings rollback A -> B -> A must become a new, monotonically revised
    # occurrence rather than resurrecting A's stale revision.
    with repository.transaction() as transaction:
        record_ids = tuple(
            str(row["record_id"])
            for row in transaction._connection.execute(
                """SELECT record_id FROM typed_records
                     WHERE context_ref=? AND record_kind='activation_policy'""",
                (context_ref,),
            ).fetchall()
        )
        records = tuple(
            record
            for record_id in record_ids
            if (record := transaction.get_record(record_id)) is not None
        )
        policies = tuple(
            record for record in records if record.record_kind == "activation_policy"
        )
        latest_revision = max(
            (
                int(record.payload["policy_revision"])
                for record in policies
                if type(record.payload.get("policy_revision")) is int
            ),
            default=0,
        )
        matching = tuple(
            record
            for record in policies
            if record.record_id == policy_id
            or record.record_id.startswith(f"{policy_id}:")
        )
        current_matching = tuple(
            record
            for record in matching
            if int(record.payload["policy_revision"]) == latest_revision
        )
        if len(current_matching) > 1:
            raise IntegrityFailure("Autopilot policy authority is ambiguous")
        if current_matching:
            policy = current_matching[0]
            revision = int(policy.payload["policy_revision"])
        else:
            revision = latest_revision + 1
            occurrence_id = policy_id if not matching else f"{policy_id}:{revision}"
            policy = activation_policy(
                record_id=occurrence_id,
                context_ref=context_ref,
                policy_revision=revision,
                activation_mode="auto_after_canary",
                key_epoch=AUTOPILOT_KEY_EPOCH,
            )
        occurrence_suffix = policy.record_id.removeprefix(policy_id)
        trial_plan = canary_plan(
            record_id=f"{canary_id}{occurrence_suffix}",
            context_ref=context_ref,
            horizon_exposures=canary_horizon,
            expiry_seconds=max(3600, canary_horizon * 300),
            candidate_allocation=Rational(*Fraction(percentage, 100).as_integer_ratio()),
            assignment_key_commitment=sha256(
                b"a0-canary-assignment-key\0" + assignment_key
            ).hexdigest(),
            hard_veto_failure_limit=0,
            buckets=tuple(
                BucketCalibration(
                    bucket,
                    minimum,
                    _rational(failure_regression),
                    Rational(0, 1),
                )
                for bucket in AUTOPILOT_BUCKETS
            ),
            key_epoch=AUTOPILOT_KEY_EPOCH,
        )
        monitoring = monitor_plan(
            record_id=f"{monitor_id}{occurrence_suffix}",
            context_ref=context_ref,
            horizon_exposures=maximum,
            look_interval_exposures=minimum,
            ordinary_regression_boundary=_rational(failure_regression, negative=True),
            hard_veto_failure_limit=0,
            key_epoch=AUTOPILOT_KEY_EPOCH,
        )
        for record in (policy, trial_plan, monitoring):
            transaction.insert_record(record)

    calibration_id = f"{calibration_id}{occurrence_suffix}"

    existing_calibration = repository.get_record(calibration_id)
    if existing_calibration is not None:
        payload = existing_calibration.payload
        if (
            existing_calibration.record_kind != "policy_calibration"
            or existing_calibration.context_ref != context_ref
            or payload["status"] != "approved"
            or payload["environment_ref"] != AUTOPILOT_ENVIRONMENT_REF
            or payload["policy_id"] != policy.record_id
            or payload["policy_digest"] != policy.content_digest
            or payload["policy_revision"] != revision
            or payload["canary_plan_id"] != trial_plan.record_id
            or payload["canary_plan_digest"] != trial_plan.content_digest
            or payload["monitor_plan_id"] != monitoring.record_id
            or payload["monitor_plan_digest"] != monitoring.content_digest
            or payload["activation_authorities"] != ["automatic", "manual"]
            or payload["soft_rollback_authorized"] is not True
        ):
            raise IntegrityFailure("Autopilot calibration identity contains different bytes")
        return AutopilotControlPlaneResult(
            "authorized",
            ExactRecord.of(policy),
            ExactRecord.of(existing_calibration),
            True,
        )

    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = reference + _GRANT_LIFETIME
    idempotency = digest_idempotency_key(
        f"autopilot-calibration-v1:{context_ref}:{policy.record_id}"
    )
    request = CalibrationApprovalRequest(
        calibration_id=calibration_id,
        receipt_id=(
            f"autopilot-calibration-receipt:{scoped_fingerprint}"
            f"{occurrence_suffix}"
        ),
        context_ref=context_ref,
        expected_policy_revision=revision,
        environment_ref=AUTOPILOT_ENVIRONMENT_REF,
        policy=ExactRecord.of(policy),
        canary_plan=ExactRecord.of(trial_plan),
        monitor_plan=ExactRecord.of(monitoring),
        activation_authorities=("automatic", "manual"),
        soft_rollback_authorized=True,
        issuer_ref=profile.issuer_id,
        subject_ref=AUTOPILOT_SUBJECT_REF,
        idempotency_key_digest=idempotency,
        session_nonce="autopilot_calibration_"
        + sha256(policy.record_id.encode()).hexdigest()[:32],
        reason_code="calibration_approved",
        key_epoch=AUTOPILOT_KEY_EPOCH,
    )
    approved = approve_policy_calibration(
        repository,
        request=request,
        revalidate_grant=_grant_revalidator(
            custody=custody,
            profile=profile,
            now=reference,
            expires_at=expires_at,
        ),
    )
    return AutopilotControlPlaneResult(
        "authorized",
        ExactRecord.of(policy),
        ExactRecord.of(approved.calibration),
        approved.replayed,
    )


__all__ = [
    "AUTOPILOT_AUTHORITY_CONSENT_REVISION",
    "AUTOPILOT_ENVIRONMENT_REF",
    "AUTOPILOT_ISSUER_ID",
    "AUTOPILOT_KEY_EPOCH",
    "AUTOPILOT_PLAN_REVISION",
    "AUTOPILOT_SUBJECT_REF",
    "AutopilotControlPlaneResult",
    "AutopilotTransitionSettings",
    "autopilot_transition_runtime_ready",
    "canary_assignment_value",
    "effective_config_digest",
    "expected_autopilot_policy_id",
    "issue_automatic_transition_grant",
    "provision_autopilot_control_plane",
    "transition_settings",
]
