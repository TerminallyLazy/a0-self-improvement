"""Local, dependency-free authority primitives for the v3 trust boundary.

This module deliberately does not know about HTTP, Agent Zero sessions, or the
v3 repository.  It creates no authority implicitly: callers must bootstrap an
issuer at an explicit local path, persist the returned public profile, and
persist signed grants/revocations through the owning coordinator.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Mapping


BOOTSTRAP_CONFIRMATION = "BOOTSTRAP_LOCAL_AUTHORITY"
ALGORITHM = "hmac-sha256"
CUSTODY_CONTRACT = "local-file-0600"
ISSUER_PROFILE_SCHEMA = "a0.authority-issuer-profile.v1"
GRANT_SCHEMA = "a0.authority-grant.v1"
REVOCATION_SCHEMA = "a0.authority-revocation.v1"
SIGNED_ENVELOPE_SCHEMA = "a0.signed-authority-envelope.v1"
PROJECTION_SCHEMA = "a0.authority-projection.v1"
_CUSTODY_MAGIC = b"A0AUTH1\x00"
_CUSTODY_SIZE = len(_CUSTODY_MAGIC) + hashlib.sha256().digest_size * 2

_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


class AuthorityError(RuntimeError):
    """Base class for authority failures safe to map to bounded reason codes."""


class AuthorityUnavailable(AuthorityError):
    """Raised when explicit local authority has not been bootstrapped."""


class AuthorityValidationError(AuthorityError):
    """Raised for malformed, unknown, or cryptographically invalid records."""


class AuthorityDenied(AuthorityError):
    """Raised when a valid grant is not authoritative for an exact request."""


class AuthorityClass(StrEnum):
    OPERATOR_AUTHORITY_GRANT = "operator_authority_grant"
    OPERATOR_CONTENT_SESSION = "operator_content_session"
    FIXTURE_USE_GRANT = "fixture_use_grant"
    MODEL_USE_GRANT = "model_use_grant"
    POLICY_CALIBRATION_APPROVAL = "policy_calibration_approval"
    QUARANTINE_RELEASE_GRANT = "quarantine_release_grant"


class AuthorityAction(StrEnum):
    INITIALIZE_GENESIS = "initialize_genesis"
    OPTIMIZE = "optimize"
    WORK_CANCEL = "work_cancel"
    CANARY_START = "canary_start"
    CANARY_STOP = "canary_stop"
    ACTIVATE = "activate"
    ROLLBACK = "rollback"
    SAFETY_BYPASS = "safety_bypass"
    FEEDBACK_SUBMIT = "feedback_submit"
    FIXTURE_DRAFT = "fixture_draft"
    FIXTURE_REVIEW = "fixture_review"
    FIXTURE_ADMIT = "fixture_admit"
    FIXTURE_WITHDRAW = "fixture_withdraw"
    MODEL_ANALYZE = "model_analyze"
    CANDIDATE_SEARCH = "candidate_search"
    POLICY_CALIBRATE = "policy_calibrate"
    MIGRATION_PREFLIGHT = "migration_preflight"
    MIGRATION_START = "migration_start"
    MIGRATION_RESUME = "migration_resume"
    MIGRATION_CONFIRM_CUTOVER = "migration_confirm_cutover"
    QUARANTINE_EXPORT = "quarantine_export"
    QUARANTINE_DELETE = "quarantine_delete"
    QUARANTINE_RELEASE_DERIVE = "quarantine_release_derive"
    QUARANTINE_RELEASE_WITHDRAW = "quarantine_release_withdraw"


class AuthorityPurpose(StrEnum):
    GENESIS = "genesis"
    OPERATOR_MUTATION = "operator_mutation"
    FIXTURE_AUTHORING = "fixture_authoring"
    FIXTURE_REVIEW = "fixture_review"
    FIXTURE_REPLAY = "fixture_replay"
    MODEL_ANALYSIS = "model_analysis"
    CANDIDATE_SEARCH = "candidate_search"
    POLICY_CALIBRATION = "policy_calibration"
    DIAGNOSTIC_CANARY = "diagnostic_canary"
    MIGRATION = "migration"
    QUARANTINE_EXPORT = "quarantine_export"
    QUARANTINE_DELETION = "quarantine_deletion"
    QUARANTINE_RELEASE = "quarantine_release"


class RevocationReason(StrEnum):
    OPERATOR_REQUESTED = "operator_requested"
    GRANT_COMPROMISED = "grant_compromised"
    AUTHORITY_WITHDRAWN = "authority_withdrawn"
    SESSION_CLOSED = "session_closed"


@dataclass(frozen=True, slots=True)
class IssuerProfile:
    issuer_id: str
    key_epoch: int
    allowed_authority_classes: tuple[str, ...]
    schema: str = ISSUER_PROFILE_SCHEMA
    algorithm: str = ALGORITHM
    custody_contract: str = CUSTODY_CONTRACT

    def to_record(self) -> dict[str, Any]:
        """Return strict repository-ready public record bytes as a mapping."""

        return {
            "schema": self.schema,
            "issuer_id": self.issuer_id,
            "algorithm": self.algorithm,
            "key_epoch": self.key_epoch,
            "allowed_authority_classes": list(self.allowed_authority_classes),
            "custody_contract": self.custody_contract,
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "IssuerProfile":
        _require_exact_fields(
            record,
            {
                "schema",
                "issuer_id",
                "algorithm",
                "key_epoch",
                "allowed_authority_classes",
                "custody_contract",
            },
            "issuer profile",
        )
        if record["schema"] != ISSUER_PROFILE_SCHEMA:
            raise AuthorityValidationError("unsupported issuer profile schema")
        if record["algorithm"] != ALGORITHM:
            raise AuthorityValidationError("unsupported authority algorithm")
        if record["custody_contract"] != CUSTODY_CONTRACT:
            raise AuthorityValidationError("unsupported custody contract")
        issuer_id = _opaque_ref(record["issuer_id"], "issuer_id")
        key_epoch = _revision(record["key_epoch"], "key_epoch", minimum=1)
        raw_classes = record["allowed_authority_classes"]
        if not isinstance(raw_classes, list) or not raw_classes:
            raise AuthorityValidationError("allowed_authority_classes must be a non-empty list")
        classes = tuple(_enum_value(item, AuthorityClass, "authority class") for item in raw_classes)
        if tuple(sorted(set(classes))) != classes:
            raise AuthorityValidationError("allowed_authority_classes must be sorted and unique")
        return cls(
            issuer_id=issuer_id,
            key_epoch=key_epoch,
            allowed_authority_classes=classes,
        )


@dataclass(frozen=True, slots=True)
class GrantRequest:
    authority_class: str
    issuer_id: str
    key_epoch: int
    subject_ref: str
    context_ref: str
    action: str
    purpose: str
    target_ref: str
    target_revision: int
    issued_at: datetime
    expires_at: datetime
    idempotency_key_digest: str
    session_nonce: str


@dataclass(frozen=True, slots=True)
class GrantExpectation:
    """Every request-bound value required before a grant can authorize use."""

    authority_class: str
    issuer_id: str
    subject_ref: str
    context_ref: str
    action: str
    purpose: str
    target_ref: str
    target_revision: int
    expires_at: datetime
    idempotency_key_digest: str
    session_nonce: str


@dataclass(frozen=True, slots=True)
class VerifiedGrant:
    grant_id: str
    authority_class: str
    issuer_id: str
    key_epoch: int
    subject_ref: str
    context_ref: str
    action: str
    purpose: str
    target_ref: str
    target_revision: int
    issued_at: datetime
    expires_at: datetime
    idempotency_key_digest: str
    session_nonce: str

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["issued_at"] = _format_timestamp(self.issued_at)
        record["expires_at"] = _format_timestamp(self.expires_at)
        return record


@dataclass(frozen=True, slots=True)
class RevocationRequest:
    grant_id: str
    issuer_id: str
    key_epoch: int
    context_ref: str
    revoked_at: datetime
    reason_code: str
    idempotency_key_digest: str


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the strict canonical JSON subset used by authority signatures."""

    _validate_json_value(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuthorityValidationError("value is not canonical JSON") from exc


def digest_idempotency_key(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    if not isinstance(raw, bytes) or not raw:
        raise AuthorityValidationError("idempotency key must be non-empty bytes")
    return hashlib.sha256(b"a0.authority.idempotency.v1\x00" + raw).hexdigest()


def bootstrap_local_issuer(
    secret_path: str | Path,
    *,
    issuer_id: str,
    key_epoch: int,
    allowed_authority_classes: Iterable[str],
    confirmation: str,
) -> IssuerProfile:
    """Explicitly create one local issuer secret; never issue a grant."""

    if confirmation != BOOTSTRAP_CONFIRMATION:
        raise AuthorityDenied("explicit local bootstrap confirmation is required")
    path = _explicit_path(secret_path)
    if not path.parent.is_dir():
        raise AuthorityValidationError("authority secret parent directory must already exist")
    profile = IssuerProfile.from_record(
        {
            "schema": ISSUER_PROFILE_SCHEMA,
            "issuer_id": issuer_id,
            "algorithm": ALGORITHM,
            "key_epoch": key_epoch,
            "allowed_authority_classes": sorted(set(allowed_authority_classes)),
            "custody_contract": CUSTODY_CONTRACT,
        }
    )
    secret = os.urandom(32)
    custody_bytes = _CUSTODY_MAGIC + _profile_digest(profile) + secret
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise AuthorityDenied("authority issuer is already bootstrapped at this path") from exc
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(custody_bytes)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise AuthorityUnavailable("authority secret write was incomplete")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    _load_secret(path, profile)
    return profile


def require_local_issuer(secret_path: str | Path, profile_record: Mapping[str, Any]) -> IssuerProfile:
    """Load an explicitly bootstrapped issuer without creating any state."""

    profile = IssuerProfile.from_record(profile_record)
    _load_secret(_explicit_path(secret_path), profile)
    return profile


def issue_grant(
    secret_path: str | Path,
    profile_record: IssuerProfile | Mapping[str, Any],
    request: GrantRequest,
) -> dict[str, Any]:
    """Create a deterministic signed grant envelope for an exact request."""

    profile = _profile(profile_record)
    secret = _load_secret(_explicit_path(secret_path), profile)
    payload_without_id = _grant_payload_without_id(request, profile)
    grant_id = "grant_" + hashlib.sha256(
        b"a0.authority.grant.identity.v1\x00" + canonical_json_bytes(payload_without_id)
    ).hexdigest()
    payload = {**payload_without_id, "grant_id": grant_id}
    return _sign_payload(payload, secret, profile)


def authorize_grant(
    envelope: Mapping[str, Any],
    secret_path: str | Path,
    profile_record: IssuerProfile | Mapping[str, Any],
    expectation: GrantExpectation,
    *,
    now: datetime,
    revocations: Iterable[Mapping[str, Any]] = (),
) -> VerifiedGrant:
    """Verify signature, live state, revocation, and every exact use binding."""

    profile = _profile(profile_record)
    secret = _load_secret(_explicit_path(secret_path), profile)
    grant = _verify_grant_envelope(envelope, secret, profile)
    current = _utc_datetime(now, "now")
    if current < grant.issued_at:
        raise AuthorityDenied("grant is not yet valid")
    if current >= grant.expires_at:
        raise AuthorityDenied("grant has expired")
    if _is_revoked(grant, revocations, secret, profile, current):
        raise AuthorityDenied("grant has been revoked")

    expected = {
        "authority_class": _enum_value(expectation.authority_class, AuthorityClass, "authority class"),
        "issuer_id": _opaque_ref(expectation.issuer_id, "issuer_id"),
        "subject_ref": _opaque_ref(expectation.subject_ref, "subject_ref"),
        "context_ref": _opaque_ref(expectation.context_ref, "context_ref"),
        "action": _enum_value(expectation.action, AuthorityAction, "action"),
        "purpose": _enum_value(expectation.purpose, AuthorityPurpose, "purpose"),
        "target_ref": _opaque_ref(expectation.target_ref, "target_ref"),
        "target_revision": _revision(expectation.target_revision, "target_revision"),
        "expires_at": _utc_datetime(expectation.expires_at, "expires_at"),
        "idempotency_key_digest": _digest(expectation.idempotency_key_digest, "idempotency_key_digest"),
        "session_nonce": _opaque_ref(expectation.session_nonce, "session_nonce"),
    }
    actual = {name: getattr(grant, name) for name in expected}
    if actual != expected:
        raise AuthorityDenied("grant does not match the exact request binding")
    return grant


def issue_revocation(
    secret_path: str | Path,
    profile_record: IssuerProfile | Mapping[str, Any],
    request: RevocationRequest,
) -> dict[str, Any]:
    """Create a signed, persistence-ready revocation record."""

    profile = _profile(profile_record)
    secret = _load_secret(_explicit_path(secret_path), profile)
    issuer_id = _opaque_ref(request.issuer_id, "issuer_id")
    key_epoch = _revision(request.key_epoch, "key_epoch", minimum=1)
    if issuer_id != profile.issuer_id or key_epoch != profile.key_epoch:
        raise AuthorityDenied("revocation issuer does not match the local issuer")
    payload_without_id = {
        "schema": REVOCATION_SCHEMA,
        "issuer_id": issuer_id,
        "key_epoch": key_epoch,
        "grant_id": _grant_id(request.grant_id),
        "context_ref": _opaque_ref(request.context_ref, "context_ref"),
        "revoked_at": _format_timestamp(_utc_datetime(request.revoked_at, "revoked_at")),
        "reason_code": _enum_value(request.reason_code, RevocationReason, "revocation reason"),
        "idempotency_key_digest": _digest(request.idempotency_key_digest, "idempotency_key_digest"),
    }
    revocation_id = "revocation_" + hashlib.sha256(
        b"a0.authority.revocation.identity.v1\x00" + canonical_json_bytes(payload_without_id)
    ).hexdigest()
    return _sign_payload({**payload_without_id, "revocation_id": revocation_id}, secret, profile)


def project_grant(
    envelope: Mapping[str, Any],
    secret_path: str | Path,
    profile_record: IssuerProfile | Mapping[str, Any],
    *,
    now: datetime,
    revocations: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Return an authenticated content-free grant state for safe projections."""

    profile = _profile(profile_record)
    secret = _load_secret(_explicit_path(secret_path), profile)
    grant = _verify_grant_envelope(envelope, secret, profile)
    current = _utc_datetime(now, "now")
    revoked = _is_revoked(grant, revocations, secret, profile, current)
    if revoked:
        state, reasons = "revoked", ["grant_revoked"]
    elif current < grant.issued_at:
        state, reasons = "not_yet_valid", ["grant_not_yet_valid"]
    elif current >= grant.expires_at:
        state, reasons = "expired", ["grant_expired"]
    else:
        state, reasons = "active", []
    return {
        "schema": PROJECTION_SCHEMA,
        "authority_ref": grant.grant_id,
        "authority_class": grant.authority_class,
        "state": state,
        "expires_at": _format_timestamp(grant.expires_at),
        "reason_codes": reasons,
    }


def _grant_payload_without_id(request: GrantRequest, profile: IssuerProfile) -> dict[str, Any]:
    authority_class = _enum_value(request.authority_class, AuthorityClass, "authority class")
    if authority_class not in profile.allowed_authority_classes:
        raise AuthorityDenied("issuer is not permitted to issue this authority class")
    issuer_id = _opaque_ref(request.issuer_id, "issuer_id")
    key_epoch = _revision(request.key_epoch, "key_epoch", minimum=1)
    if issuer_id != profile.issuer_id or key_epoch != profile.key_epoch:
        raise AuthorityDenied("grant issuer does not match the local issuer")
    issued_at = _utc_datetime(request.issued_at, "issued_at")
    expires_at = _utc_datetime(request.expires_at, "expires_at")
    if expires_at <= issued_at:
        raise AuthorityValidationError("expires_at must be later than issued_at")
    return {
        "schema": GRANT_SCHEMA,
        "authority_class": authority_class,
        "issuer_id": issuer_id,
        "key_epoch": key_epoch,
        "subject_ref": _opaque_ref(request.subject_ref, "subject_ref"),
        "context_ref": _opaque_ref(request.context_ref, "context_ref"),
        "action": _enum_value(request.action, AuthorityAction, "action"),
        "purpose": _enum_value(request.purpose, AuthorityPurpose, "purpose"),
        "target_ref": _opaque_ref(request.target_ref, "target_ref"),
        "target_revision": _revision(request.target_revision, "target_revision"),
        "issued_at": _format_timestamp(issued_at),
        "expires_at": _format_timestamp(expires_at),
        "idempotency_key_digest": _digest(request.idempotency_key_digest, "idempotency_key_digest"),
        "session_nonce": _opaque_ref(request.session_nonce, "session_nonce"),
    }


def _verify_grant_envelope(
    envelope: Mapping[str, Any], secret: bytes, profile: IssuerProfile
) -> VerifiedGrant:
    payload = _verify_signed_payload(envelope, secret, profile, expected_schema=GRANT_SCHEMA)
    _require_exact_fields(
        payload,
        {
            "schema",
            "grant_id",
            "authority_class",
            "issuer_id",
            "key_epoch",
            "subject_ref",
            "context_ref",
            "action",
            "purpose",
            "target_ref",
            "target_revision",
            "issued_at",
            "expires_at",
            "idempotency_key_digest",
            "session_nonce",
        },
        "grant payload",
    )
    grant = VerifiedGrant(
        grant_id=_grant_id(payload["grant_id"]),
        authority_class=_enum_value(payload["authority_class"], AuthorityClass, "authority class"),
        issuer_id=_opaque_ref(payload["issuer_id"], "issuer_id"),
        key_epoch=_revision(payload["key_epoch"], "key_epoch", minimum=1),
        subject_ref=_opaque_ref(payload["subject_ref"], "subject_ref"),
        context_ref=_opaque_ref(payload["context_ref"], "context_ref"),
        action=_enum_value(payload["action"], AuthorityAction, "action"),
        purpose=_enum_value(payload["purpose"], AuthorityPurpose, "purpose"),
        target_ref=_opaque_ref(payload["target_ref"], "target_ref"),
        target_revision=_revision(payload["target_revision"], "target_revision"),
        issued_at=_parse_timestamp(payload["issued_at"], "issued_at"),
        expires_at=_parse_timestamp(payload["expires_at"], "expires_at"),
        idempotency_key_digest=_digest(payload["idempotency_key_digest"], "idempotency_key_digest"),
        session_nonce=_opaque_ref(payload["session_nonce"], "session_nonce"),
    )
    if grant.expires_at <= grant.issued_at:
        raise AuthorityValidationError("expires_at must be later than issued_at")
    if grant.issuer_id != profile.issuer_id or grant.key_epoch != profile.key_epoch:
        raise AuthorityDenied("grant issuer does not match trusted issuer profile")
    if grant.authority_class not in profile.allowed_authority_classes:
        raise AuthorityDenied("grant authority class is outside issuer profile")
    expected_id = "grant_" + hashlib.sha256(
        b"a0.authority.grant.identity.v1\x00"
        + canonical_json_bytes({key: value for key, value in payload.items() if key != "grant_id"})
    ).hexdigest()
    if not hmac.compare_digest(grant.grant_id, expected_id):
        raise AuthorityValidationError("grant identity does not match canonical payload")
    return grant


def _is_revoked(
    grant: VerifiedGrant,
    revocations: Iterable[Mapping[str, Any]],
    secret: bytes,
    profile: IssuerProfile,
    now: datetime,
) -> bool:
    revoked = False
    for envelope in revocations:
        payload = _verify_signed_payload(envelope, secret, profile, expected_schema=REVOCATION_SCHEMA)
        _require_exact_fields(
            payload,
            {
                "schema",
                "revocation_id",
                "issuer_id",
                "key_epoch",
                "grant_id",
                "context_ref",
                "revoked_at",
                "reason_code",
                "idempotency_key_digest",
            },
            "revocation payload",
        )
        issuer_id = _opaque_ref(payload["issuer_id"], "issuer_id")
        key_epoch = _revision(payload["key_epoch"], "key_epoch", minimum=1)
        grant_id = _grant_id(payload["grant_id"])
        context_ref = _opaque_ref(payload["context_ref"], "context_ref")
        revoked_at = _parse_timestamp(payload["revoked_at"], "revoked_at")
        _enum_value(payload["reason_code"], RevocationReason, "revocation reason")
        _digest(payload["idempotency_key_digest"], "idempotency_key_digest")
        revocation_id = _revocation_id(payload["revocation_id"])
        expected_id = "revocation_" + hashlib.sha256(
            b"a0.authority.revocation.identity.v1\x00"
            + canonical_json_bytes({key: value for key, value in payload.items() if key != "revocation_id"})
        ).hexdigest()
        if not hmac.compare_digest(revocation_id, expected_id):
            raise AuthorityValidationError("revocation identity does not match canonical payload")
        if issuer_id != profile.issuer_id or key_epoch != profile.key_epoch:
            raise AuthorityDenied("revocation issuer does not match trusted issuer profile")
        if revoked_at > now:
            raise AuthorityValidationError("revocation timestamp is in the future")
        if grant_id == grant.grant_id:
            if context_ref != grant.context_ref:
                raise AuthorityValidationError("revocation context does not match grant")
            revoked = True
    return revoked


def _sign_payload(payload: Mapping[str, Any], secret: bytes, profile: IssuerProfile) -> dict[str, Any]:
    payload_bytes = canonical_json_bytes(payload)
    signature = hmac.new(secret, b"a0.authority.signature.v1\x00" + payload_bytes, hashlib.sha256).hexdigest()
    return {
        "schema": SIGNED_ENVELOPE_SCHEMA,
        "algorithm": profile.algorithm,
        "key_epoch": profile.key_epoch,
        "payload": dict(payload),
        "signature": signature,
    }


def _verify_signed_payload(
    envelope: Mapping[str, Any],
    secret: bytes,
    profile: IssuerProfile,
    *,
    expected_schema: str,
) -> Mapping[str, Any]:
    _require_exact_fields(
        envelope, {"schema", "algorithm", "key_epoch", "payload", "signature"}, "signed envelope"
    )
    if envelope["schema"] != SIGNED_ENVELOPE_SCHEMA:
        raise AuthorityValidationError("unsupported signed envelope schema")
    if envelope["algorithm"] != ALGORITHM:
        raise AuthorityValidationError("unsupported signed envelope algorithm")
    if _revision(envelope["key_epoch"], "key_epoch", minimum=1) != profile.key_epoch:
        raise AuthorityDenied("signed envelope key epoch does not match trusted issuer")
    payload = envelope["payload"]
    if not isinstance(payload, Mapping):
        raise AuthorityValidationError("signed envelope payload must be an object")
    if payload.get("schema") != expected_schema:
        raise AuthorityValidationError("unexpected signed payload schema")
    signature = envelope["signature"]
    if not isinstance(signature, str) or not _HEX_DIGEST.fullmatch(signature):
        raise AuthorityValidationError("signature must be a lowercase SHA-256 digest")
    expected = hmac.new(
        secret,
        b"a0.authority.signature.v1\x00" + canonical_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise AuthorityValidationError("authority signature verification failed")
    return payload


def _profile(value: IssuerProfile | Mapping[str, Any]) -> IssuerProfile:
    if isinstance(value, IssuerProfile):
        return IssuerProfile.from_record(value.to_record())
    return IssuerProfile.from_record(value)


def _load_secret(path: Path, profile: IssuerProfile) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise AuthorityUnavailable("local authority issuer is not bootstrapped") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AuthorityUnavailable("authority secret is not a regular local file")
    if metadata.st_uid != os.geteuid():
        raise AuthorityUnavailable("authority secret is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AuthorityUnavailable("authority secret permissions must be exactly 0600")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AuthorityUnavailable("authority secret could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise AuthorityUnavailable("authority secret custody changed while opening")
        custody_bytes = os.read(descriptor, _CUSTODY_SIZE + 1)
    finally:
        os.close(descriptor)
    if len(custody_bytes) != _CUSTODY_SIZE or not custody_bytes.startswith(_CUSTODY_MAGIC):
        raise AuthorityUnavailable("authority secret has an invalid length")
    profile_digest_start = len(_CUSTODY_MAGIC)
    secret_start = profile_digest_start + hashlib.sha256().digest_size
    stored_profile_digest = custody_bytes[profile_digest_start:secret_start]
    if not hmac.compare_digest(stored_profile_digest, _profile_digest(profile)):
        raise AuthorityUnavailable("authority secret does not match the issuer profile")
    return custody_bytes[secret_start:]


def _profile_digest(profile: IssuerProfile) -> bytes:
    return hashlib.sha256(
        b"a0.authority.issuer-profile.v1\x00" + canonical_json_bytes(profile.to_record())
    ).digest()


def _explicit_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise AuthorityValidationError("authority secret path must be absolute")
    return path


def _require_exact_fields(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if not isinstance(value, Mapping):
        raise AuthorityValidationError(f"{label} must be an object")
    actual = set(value)
    if actual != fields:
        raise AuthorityValidationError(f"{label} fields are not exact")
    if any(not isinstance(key, str) for key in value):
        raise AuthorityValidationError(f"{label} keys must be strings")


def _validate_json_value(value: Any) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise AuthorityValidationError("floating-point values are forbidden in authority JSON")
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthorityValidationError("authority JSON keys must be strings")
            _validate_json_value(item)
        return
    raise AuthorityValidationError("unsupported value in authority JSON")


def _opaque_ref(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _OPAQUE_REF.fullmatch(value):
        raise AuthorityValidationError(f"{name} must be a bounded opaque reference")
    return value


def _grant_id(value: Any) -> str:
    value = _opaque_ref(value, "grant_id")
    if not value.startswith("grant_") or len(value) != 70:
        raise AuthorityValidationError("grant_id has an invalid format")
    return value


def _revocation_id(value: Any) -> str:
    value = _opaque_ref(value, "revocation_id")
    if not value.startswith("revocation_") or len(value) != 75:
        raise AuthorityValidationError("revocation_id has an invalid format")
    return value


def _revision(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuthorityValidationError(f"{name} must be an integer >= {minimum}")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HEX_DIGEST.fullmatch(value):
        raise AuthorityValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _enum_value(value: Any, enum_type: type[StrEnum], name: str) -> str:
    if not isinstance(value, str):
        raise AuthorityValidationError(f"{name} must be a string")
    try:
        return enum_type(value).value
    except ValueError as exc:
        raise AuthorityValidationError(f"unknown {name}") from exc


def _utc_datetime(value: Any, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AuthorityValidationError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise AuthorityValidationError(f"{name} must use canonical UTC timestamp format")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AuthorityValidationError(f"{name} is not a valid timestamp") from exc
    if _format_timestamp(parsed) != value:
        raise AuthorityValidationError(f"{name} is not canonical")
    return parsed
