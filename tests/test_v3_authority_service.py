from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import pytest

from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    GrantExpectation,
    GrantRequest,
    RevocationRequest,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
    issue_revocation,
)
from usr.plugins.dspy_rlm.helpers.v3.authority_service import (
    AuthorityServiceError,
    LocalGrantVerifier,
    RevocationFileLedger,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


def _authority(tmp_path):
    secret = tmp_path / "issuer.secret"
    profile_path = tmp_path / "issuer.json"
    revocations_path = tmp_path / "revocations"
    revocations_path.mkdir(mode=0o700)
    profile = bootstrap_local_issuer(
        secret,
        issuer_id="issuer.local",
        key_epoch=1,
        allowed_authority_classes=(AuthorityClass.OPERATOR_AUTHORITY_GRANT,),
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    profile_path.write_bytes(canonical_json(profile.to_record()))
    os.chmod(profile_path, 0o600)
    idempotency = digest_idempotency_key("command-1")
    request = GrantRequest(
        authority_class="operator_authority_grant",
        issuer_id=profile.issuer_id,
        key_epoch=1,
        subject_ref="operator.local",
        context_ref="context.local",
        action="activate",
        purpose="operator_mutation",
        target_ref="context.local",
        target_revision=4,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=10),
        idempotency_key_digest=idempotency,
        session_nonce="browser.session",
    )
    expectation = GrantExpectation(
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
    )
    return secret, profile_path, profile, RevocationFileLedger(revocations_path), request, expectation


def test_ledger_append_is_immutable_and_idempotent(tmp_path) -> None:
    secret, _profile_path, profile, ledger, request, _expectation = _authority(tmp_path)
    revocation = issue_revocation(
        secret,
        profile,
        RevocationRequest(
            grant_id=issue_grant(secret, profile, request)["payload"]["grant_id"],
            issuer_id=profile.issuer_id,
            key_epoch=1,
            context_ref=request.context_ref,
            revoked_at=NOW,
            reason_code="operator_requested",
            idempotency_key_digest=digest_idempotency_key("revoke-1"),
        ),
    )

    identity = ledger.append(revocation)

    assert ledger.append(revocation) == identity
    assert ledger.load() == (revocation,)
    assert oct((ledger.directory / f"{identity}.json").stat().st_mode & 0o777) == "0o600"


def test_verifier_always_applies_durable_revocations(tmp_path) -> None:
    secret, profile_path, profile, ledger, request, expectation = _authority(tmp_path)
    grant = issue_grant(secret, profile, request)
    verifier = LocalGrantVerifier(secret, profile_path, ledger)
    assert verifier.authorize(grant, expectation, now=NOW).grant_id == grant["payload"]["grant_id"]
    ledger.append(
        issue_revocation(
            secret,
            profile,
            RevocationRequest(
                grant_id=grant["payload"]["grant_id"],
                issuer_id=profile.issuer_id,
                key_epoch=1,
                context_ref=request.context_ref,
                revoked_at=NOW,
                reason_code="operator_requested",
                idempotency_key_digest=digest_idempotency_key("revoke-1"),
            ),
        )
    )

    with pytest.raises(AuthorityServiceError, match="denied"):
        verifier.authorize(grant, expectation, now=NOW)


def test_unknown_or_permissive_ledger_entry_fails_closed(tmp_path) -> None:
    _secret, _profile_path, _profile, ledger, _request, _expectation = _authority(tmp_path)
    unknown = ledger.directory / "notes.txt"
    unknown.write_text("ignored?", encoding="utf-8")
    os.chmod(unknown, 0o600)

    with pytest.raises(AuthorityServiceError, match="unknown entry"):
        ledger.load()
