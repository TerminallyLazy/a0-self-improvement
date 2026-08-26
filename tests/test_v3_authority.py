from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat

import pytest

from usr.plugins.dspy_rlm.helpers.v3.authority import (
    ALGORITHM,
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    AuthorityDenied,
    AuthorityUnavailable,
    AuthorityValidationError,
    GrantExpectation,
    GrantRequest,
    IssuerProfile,
    RevocationRequest,
    authorize_grant,
    bootstrap_local_issuer,
    canonical_json_bytes,
    digest_idempotency_key,
    issue_grant,
    issue_revocation,
    project_grant,
    require_local_issuer,
)


ISSUED_AT = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
EXPIRES_AT = ISSUED_AT + timedelta(minutes=15)


@pytest.fixture
def authority(tmp_path: Path) -> tuple[Path, IssuerProfile]:
    secret_path = tmp_path / "issuer.key"
    profile = bootstrap_local_issuer(
        secret_path,
        issuer_id="issuer_local_01",
        key_epoch=1,
        allowed_authority_classes=[
            AuthorityClass.OPERATOR_AUTHORITY_GRANT,
            AuthorityClass.OPERATOR_CONTENT_SESSION,
        ],
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    return secret_path, profile


@pytest.fixture
def grant_request() -> GrantRequest:
    return GrantRequest(
        authority_class="operator_authority_grant",
        issuer_id="issuer_local_01",
        key_epoch=1,
        subject_ref="subject_local_01",
        context_ref="context_01",
        action="initialize_genesis",
        purpose="genesis",
        target_ref="activation_scope_01",
        target_revision=0,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        idempotency_key_digest=digest_idempotency_key("command-01"),
        session_nonce="session_nonce_01",
    )


@pytest.fixture
def expectation(grant_request: GrantRequest) -> GrantExpectation:
    return GrantExpectation(
        authority_class=grant_request.authority_class,
        issuer_id=grant_request.issuer_id,
        subject_ref=grant_request.subject_ref,
        context_ref=grant_request.context_ref,
        action=grant_request.action,
        purpose=grant_request.purpose,
        target_ref=grant_request.target_ref,
        target_revision=grant_request.target_revision,
        expires_at=grant_request.expires_at,
        idempotency_key_digest=grant_request.idempotency_key_digest,
        session_nonce=grant_request.session_nonce,
    )


def test_missing_issuer_never_bootstraps_implicitly(tmp_path: Path) -> None:
    secret_path = tmp_path / "missing.key"
    profile = IssuerProfile(
        issuer_id="issuer_local_01",
        key_epoch=1,
        allowed_authority_classes=("operator_authority_grant",),
    )

    with pytest.raises(AuthorityUnavailable, match="not bootstrapped"):
        require_local_issuer(secret_path, profile.to_record())

    assert not secret_path.exists()


def test_bootstrap_requires_exact_confirmation_and_creates_no_grant(tmp_path: Path) -> None:
    secret_path = tmp_path / "issuer.key"

    with pytest.raises(AuthorityDenied, match="confirmation"):
        bootstrap_local_issuer(
            secret_path,
            issuer_id="issuer_local_01",
            key_epoch=1,
            allowed_authority_classes=["operator_authority_grant"],
            confirmation="yes",
        )

    assert not secret_path.exists()
    profile = bootstrap_local_issuer(
        secret_path,
        issuer_id="issuer_local_01",
        key_epoch=1,
        allowed_authority_classes=["operator_authority_grant"],
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    assert profile.to_record()["allowed_authority_classes"] == ["operator_authority_grant"]
    assert list(tmp_path.iterdir()) == [secret_path]


def test_bootstrap_secret_has_restrictive_custody_and_is_one_time(authority) -> None:
    secret_path, profile = authority

    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    assert len(secret_path.read_bytes()) == 72
    with pytest.raises(AuthorityDenied, match="already bootstrapped"):
        bootstrap_local_issuer(
            secret_path,
            issuer_id=profile.issuer_id,
            key_epoch=profile.key_epoch,
            allowed_authority_classes=profile.allowed_authority_classes,
            confirmation=BOOTSTRAP_CONFIRMATION,
        )


def test_permissive_or_symlinked_secret_is_unavailable(
    authority, grant_request: GrantRequest, tmp_path: Path
) -> None:
    secret_path, profile = authority
    os.chmod(secret_path, 0o640)
    with pytest.raises(AuthorityUnavailable, match="0600"):
        issue_grant(secret_path, profile, grant_request)

    os.chmod(secret_path, 0o600)
    link_path = tmp_path / "linked.key"
    link_path.symlink_to(secret_path)
    with pytest.raises(AuthorityUnavailable, match="regular local file"):
        issue_grant(link_path, profile, grant_request)


def test_secret_custody_is_bound_to_exact_issuer_profile(
    authority, grant_request: GrantRequest
) -> None:
    secret_path, profile = authority
    swapped_profile = IssuerProfile(
        issuer_id="issuer_local_02",
        key_epoch=profile.key_epoch,
        allowed_authority_classes=profile.allowed_authority_classes,
    )
    swapped_request = replace(grant_request, issuer_id=swapped_profile.issuer_id)

    with pytest.raises(AuthorityUnavailable, match="does not match"):
        issue_grant(secret_path, swapped_profile, swapped_request)


def test_issue_and_verify_exact_bound_grant(
    authority, grant_request: GrantRequest, expectation: GrantExpectation
) -> None:
    secret_path, profile = authority

    first = issue_grant(secret_path, profile.to_record(), grant_request)
    second = issue_grant(secret_path, profile, grant_request)
    verified = authorize_grant(
        first,
        secret_path,
        profile,
        expectation,
        now=ISSUED_AT + timedelta(seconds=1),
    )

    assert first == second
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert verified.grant_id.startswith("grant_")
    assert verified.context_ref == "context_01"
    assert verified.target_revision == 0


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("authority_class", "operator_content_session"),
        ("issuer_id", "issuer_local_02"),
        ("subject_ref", "subject_local_02"),
        ("context_ref", "context_02"),
        ("action", "rollback"),
        ("purpose", "operator_mutation"),
        ("target_ref", "activation_scope_02"),
        ("target_revision", 1),
        ("expires_at", EXPIRES_AT + timedelta(seconds=1)),
        ("idempotency_key_digest", digest_idempotency_key("command-02")),
        ("session_nonce", "session_nonce_02"),
    ],
)
def test_authorization_denies_every_wrong_exact_binding(
    authority,
    grant_request: GrantRequest,
    expectation: GrantExpectation,
    field: str,
    wrong_value,
) -> None:
    secret_path, profile = authority
    envelope = issue_grant(secret_path, profile, grant_request)

    with pytest.raises(AuthorityDenied, match="exact request binding"):
        authorize_grant(
            envelope,
            secret_path,
            profile,
            replace(expectation, **{field: wrong_value}),
            now=ISSUED_AT + timedelta(seconds=1),
        )


def test_authorization_denies_expired_and_not_yet_valid_grants(
    authority, grant_request: GrantRequest, expectation: GrantExpectation
) -> None:
    secret_path, profile = authority
    envelope = issue_grant(secret_path, profile, grant_request)

    with pytest.raises(AuthorityDenied, match="not yet valid"):
        authorize_grant(
            envelope, secret_path, profile, expectation, now=ISSUED_AT - timedelta(microseconds=1)
        )
    with pytest.raises(AuthorityDenied, match="expired"):
        authorize_grant(envelope, secret_path, profile, expectation, now=EXPIRES_AT)


def test_signed_revocation_immediately_blocks_use(
    authority, grant_request: GrantRequest, expectation: GrantExpectation
) -> None:
    secret_path, profile = authority
    envelope = issue_grant(secret_path, profile, grant_request)
    revocation = issue_revocation(
        secret_path,
        profile,
        RevocationRequest(
            grant_id=envelope["payload"]["grant_id"],
            issuer_id=profile.issuer_id,
            key_epoch=profile.key_epoch,
            context_ref=grant_request.context_ref,
            revoked_at=ISSUED_AT + timedelta(seconds=2),
            reason_code="operator_requested",
            idempotency_key_digest=digest_idempotency_key("revoke-01"),
        ),
    )

    with pytest.raises(AuthorityDenied, match="revoked"):
        authorize_grant(
            envelope,
            secret_path,
            profile,
            expectation,
            now=ISSUED_AT + timedelta(seconds=2),
            revocations=[revocation],
        )
    assert project_grant(
        envelope,
        secret_path,
        profile,
        now=ISSUED_AT + timedelta(seconds=2),
        revocations=[revocation],
    )["state"] == "revoked"


def test_tamper_and_foreign_revocation_fail_closed(
    authority, grant_request: GrantRequest, expectation: GrantExpectation
) -> None:
    secret_path, profile = authority
    envelope = issue_grant(secret_path, profile, grant_request)
    tampered = deepcopy(envelope)
    tampered["payload"]["target_revision"] = 7

    with pytest.raises(AuthorityValidationError, match="signature verification"):
        authorize_grant(
            tampered,
            secret_path,
            profile,
            expectation,
            now=ISSUED_AT + timedelta(seconds=1),
        )

    foreign = issue_revocation(
        secret_path,
        profile,
        RevocationRequest(
            grant_id=envelope["payload"]["grant_id"],
            issuer_id=profile.issuer_id,
            key_epoch=profile.key_epoch,
            context_ref="context_02",
            revoked_at=ISSUED_AT,
            reason_code="operator_requested",
            idempotency_key_digest=digest_idempotency_key("revoke-01"),
        ),
    )
    with pytest.raises(AuthorityValidationError, match="context"):
        authorize_grant(
            envelope,
            secret_path,
            profile,
            expectation,
            now=ISSUED_AT + timedelta(seconds=1),
            revocations=[foreign],
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda envelope: envelope.update({"unknown": True}),
        lambda envelope: envelope["payload"].update({"unknown": True}),
        lambda envelope: envelope.update({"schema": "a0.signed-authority-envelope.v2"}),
        lambda envelope: envelope["payload"].update({"action": "do_anything"}),
        lambda envelope: envelope["payload"].update({"authority_class": "administrator"}),
    ],
)
def test_unknown_fields_schemas_and_enums_fail_closed(
    authority,
    grant_request: GrantRequest,
    expectation: GrantExpectation,
    mutation,
) -> None:
    secret_path, profile = authority
    envelope = issue_grant(secret_path, profile, grant_request)
    candidate = deepcopy(envelope)
    mutation(candidate)
    if set(candidate) == {"schema", "algorithm", "key_epoch", "payload", "signature"}:
        candidate = _resign(candidate, secret_path)

    with pytest.raises(AuthorityValidationError):
        authorize_grant(
            candidate,
            secret_path,
            profile,
            expectation,
            now=ISSUED_AT + timedelta(seconds=1),
        )


def test_issuer_profile_unknown_fields_and_enums_fail_closed(authority) -> None:
    _, profile = authority
    unknown_field = {**profile.to_record(), "administrator": True}
    unknown_class = profile.to_record()
    unknown_class["allowed_authority_classes"] = ["administrator"]

    with pytest.raises(AuthorityValidationError, match="fields"):
        IssuerProfile.from_record(unknown_field)
    with pytest.raises(AuthorityValidationError, match="unknown authority class"):
        IssuerProfile.from_record(unknown_class)


def test_projection_is_content_free(
    authority, grant_request: GrantRequest
) -> None:
    secret_path, profile = authority
    envelope = issue_grant(secret_path, profile, grant_request)

    projection = project_grant(
        envelope,
        secret_path,
        profile,
        now=ISSUED_AT + timedelta(seconds=1),
    )

    assert set(projection) == {
        "schema",
        "authority_ref",
        "authority_class",
        "state",
        "expires_at",
        "reason_codes",
    }
    assert projection["state"] == "active"
    encoded = json.dumps(projection, sort_keys=True)
    for secret_value in (
        profile.issuer_id,
        grant_request.subject_ref,
        grant_request.context_ref,
        grant_request.action,
        grant_request.purpose,
        grant_request.target_ref,
        grant_request.idempotency_key_digest,
        grant_request.session_nonce,
        envelope["signature"],
        secret_path.read_bytes().hex(),
    ):
        assert secret_value not in encoded


def test_canonical_json_rejects_floats_and_non_string_keys() -> None:
    with pytest.raises(AuthorityValidationError, match="floating-point"):
        canonical_json_bytes({"score": 1.0})
    with pytest.raises(AuthorityValidationError, match="keys"):
        canonical_json_bytes({1: "value"})


def _resign(envelope: dict, secret_path: Path) -> dict:
    assert envelope["algorithm"] == ALGORITHM
    payload_bytes = canonical_json_bytes(envelope["payload"])
    envelope["signature"] = hmac.new(
        secret_path.read_bytes()[-32:],
        b"a0.authority.signature.v1\x00" + payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return envelope
