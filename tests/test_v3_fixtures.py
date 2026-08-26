from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

import pytest

from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    AuthorityClass,
    AuthorityDenied,
    GrantExpectation,
    GrantRequest,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
)
from usr.plugins.dspy_rlm.helpers.v3.fixtures import (
    ASSESSMENT_PROFILE_SCHEMA_ID,
    EXECUTION_PROFILE_SCHEMA_ID,
    FIXTURE_CONTENT_SCHEMA_ID,
    ContentAccessAuthority,
    FixtureAuthority,
    FixtureIneligible,
    FixtureValidationError,
    FixtureVaultReceipt,
    GrantAuthority,
    ManifestSelection,
    QuarantineReleaseBinding,
    assessment_profile,
    deterministic_family_partition,
    execution_profile,
)


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


class EncryptedTestVault:
    def __init__(self) -> None:
        self.content: dict[str, bytes] = {}

    def seal(
        self, content: bytes, *, fixture_ref: str, plaintext_digest: str
    ) -> FixtureVaultReceipt:
        vault_ref = "vault_" + hashlib.sha256(fixture_ref.encode()).hexdigest()[:16]
        self.content[vault_ref] = bytes(content)
        return FixtureVaultReceipt(
            vault_ref=vault_ref,
            encryption_profile_ref="encrypted-test-v1",
            plaintext_digest=plaintext_digest,
            ciphertext_digest=hashlib.sha256(b"ciphertext\0" + content).hexdigest(),
            plaintext_size=len(content),
        )

    def open(self, vault_ref: str, *, fixture_ref: str, plaintext_digest: str) -> bytes:
        del fixture_ref, plaintext_digest
        return self.content[vault_ref]

    def withdraw(self, vault_ref: str, *, fixture_ref: str) -> None:
        del fixture_ref
        self.content.pop(vault_ref, None)


@pytest.fixture
def fixture_system(tmp_path: Path):
    secret_path = tmp_path / "fixture-issuer.key"
    profile = bootstrap_local_issuer(
        secret_path,
        issuer_id="issuer_fixture_01",
        key_epoch=1,
        allowed_authority_classes=(
            AuthorityClass.FIXTURE_USE_GRANT,
            AuthorityClass.OPERATOR_CONTENT_SESSION,
        ),
        confirmation=BOOTSTRAP_CONFIRMATION,
    )
    vault = EncryptedTestVault()
    coordinator = FixtureAuthority(
        secret_path=secret_path,
        issuer_profile=profile,
        vault=vault,
        partition_secret=b"deterministic-fixture-partition-secret",
        partition_policy_ref="split-policy-v1",
        partition_weights={"training": 5, "tuning": 3, "certification_holdout": 2},
    )
    return coordinator, secret_path, profile, vault


def _grant(
    secret_path,
    profile,
    *,
    authority_class: str,
    action: str,
    purpose: str,
    target_ref: str,
    revision: int,
    subject_ref: str = "operator_01",
    nonce: str = "content_session_01",
) -> GrantAuthority:
    expires = NOW + timedelta(minutes=10)
    idempotency = digest_idempotency_key(
        f"{authority_class}:{action}:{purpose}:{target_ref}:{revision}:{subject_ref}:{nonce}"
    )
    request = GrantRequest(
        authority_class=authority_class,
        issuer_id=profile.issuer_id,
        key_epoch=profile.key_epoch,
        subject_ref=subject_ref,
        context_ref="context_01",
        action=action,
        purpose=purpose,
        target_ref=target_ref,
        target_revision=revision,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=expires,
        idempotency_key_digest=idempotency,
        session_nonce=nonce,
    )
    expectation = GrantExpectation(
        authority_class=authority_class,
        issuer_id=profile.issuer_id,
        subject_ref=subject_ref,
        context_ref="context_01",
        action=action,
        purpose=purpose,
        target_ref=target_ref,
        target_revision=revision,
        expires_at=expires,
        idempotency_key_digest=idempotency,
        session_nonce=nonce,
    )
    return GrantAuthority(issue_grant(secret_path, profile, request), expectation)


def _access(secret_path, profile, *, action, purpose, target_ref, revision, session_subject="operator_01"):
    return ContentAccessAuthority(
        fixture_use=_grant(
            secret_path,
            profile,
            authority_class="fixture_use_grant",
            action=action,
            purpose=purpose,
            target_ref=target_ref,
            revision=revision,
        ),
        content_session=_grant(
            secret_path,
            profile,
            authority_class="operator_content_session",
            action=action,
            purpose=purpose,
            target_ref=target_ref,
            revision=revision,
            subject_ref=session_subject,
        ),
    )


def _content(input_message: str = "Reproduce the bounded regression") -> dict:
    return {
        "schema": FIXTURE_CONTENT_SCHEMA_ID,
        "input_message": input_message,
        "initial_state": ["state:clean"],
        "tool_steps": [],
        "expected_outcome": ["result schema is valid", "no live tool dispatch"],
        "execution_bounds": {
            "max_turns": 4,
            "max_tool_steps": 0,
            "max_output_bytes": 4096,
        },
    }


def _draft(coordinator, secret_path, profile, *, fixture_ref="case_01", origin="operator_authored", release=None):
    return coordinator.create_draft(
        fixture_ref=fixture_ref,
        revision=1,
        family_ref="family_01",
        source_lineage_digest=DIGEST,
        author_ref="author_01",
        origin_class=origin,
        source_attestation_digest="b" * 64,
        protected=True,
        content=_content(),
        authority=_access(
            secret_path,
            profile,
            action="fixture_draft",
            purpose="fixture_authoring",
            target_ref=fixture_ref,
            revision=1,
        ),
        now=NOW,
        quarantine_release=release,
    )


def _admit(coordinator, secret_path, profile, draft):
    review = coordinator.review(
        draft,
        reviewer_ref="reviewer_02",
        authority=_access(
            secret_path,
            profile,
            action="fixture_review",
            purpose="fixture_review",
            target_ref=draft.record.record_id,
            revision=1,
        ),
        now=NOW,
    )
    admission = coordinator.admit(
        draft,
        review,
        fixture_use=_grant(
            secret_path,
            profile,
            authority_class="fixture_use_grant",
            action="fixture_admit",
            purpose="fixture_replay",
            target_ref=draft.record.record_id,
            revision=1,
        ),
        now=NOW,
    )
    return review, admission


def _profiles():
    execution = execution_profile(
        runtime_digest="1" * 64,
        model_configuration_digest="2" * 64,
        replay_adapter_digest="3" * 64,
        behavior_configuration_digest="4" * 64,
    )
    assessment = assessment_profile(
        validator_profile_digest="5" * 64,
        activation_policy_digest="6" * 64,
        threshold_profile_digest="7" * 64,
        freshness_policy_digest="8" * 64,
        replay_seed=17,
        required_buckets=["regression"],
    )
    return execution, assessment


def test_draft_review_admit_manifest_keeps_plaintext_out_of_normal_records(fixture_system) -> None:
    coordinator, secret_path, profile, _vault = fixture_system
    draft = _draft(coordinator, secret_path, profile)
    review, admission = _admit(coordinator, secret_path, profile, draft)
    execution, assessment = _profiles()
    manifest = coordinator.build_manifest(
        [ManifestSelection(admission, draft)],
        selection_policy_ref="selection-v1",
        execution_profile=execution,
        assessment_profile=assessment,
    )

    assert review.record.payload["reviewer_ref"] == "reviewer_02"
    assert admission.event.event_type == "fixture_admitted"
    assert manifest.payload["entries"][0]["partition"] == draft.family.payload["partition"]
    assert execution.schema_id == EXECUTION_PROFILE_SCHEMA_ID
    assert assessment.schema_id == ASSESSMENT_PROFILE_SCHEMA_ID
    assert b"Reproduce the bounded regression" not in draft.record.canonical_bytes
    assert draft.record.payload["vault_ref"].startswith("vault_")


def test_author_cannot_review_own_fixture(fixture_system) -> None:
    coordinator, secret_path, profile, _vault = fixture_system
    draft = _draft(coordinator, secret_path, profile)

    with pytest.raises(FixtureValidationError, match="independent"):
        coordinator.review(
            draft,
            reviewer_ref="author_01",
            authority=_access(
                secret_path,
                profile,
                action="fixture_review",
                purpose="fixture_review",
                target_ref=draft.record.record_id,
                revision=1,
            ),
            now=NOW,
        )


def test_content_access_denies_grant_and_session_identity_mismatch(fixture_system) -> None:
    coordinator, secret_path, profile, _vault = fixture_system
    access = _access(
        secret_path,
        profile,
        action="fixture_draft",
        purpose="fixture_authoring",
        target_ref="case_01",
        revision=1,
        session_subject="operator_02",
    )

    with pytest.raises(AuthorityDenied, match="same access"):
        coordinator.create_draft(
            fixture_ref="case_01",
            revision=1,
            family_ref="family_01",
            source_lineage_digest=DIGEST,
            author_ref="author_01",
            origin_class="operator_authored",
            source_attestation_digest="b" * 64,
            protected=False,
            content=_content(),
            authority=access,
            now=NOW,
        )


def test_family_partition_is_deterministic_and_family_wide() -> None:
    arguments = {
        "family_ref": "shared_lineage_family",
        "policy_ref": "split-policy-v1",
        "partition_secret": b"deterministic-fixture-partition-secret",
        "partition_weights": {"training": 5, "tuning": 3, "certification_holdout": 2},
    }

    assert deterministic_family_partition(**arguments) == deterministic_family_partition(**arguments)
    assert deterministic_family_partition(**arguments) in {
        "training",
        "tuning",
        "certification_holdout",
    }


def test_withdrawal_stales_prior_manifest_and_denies_future_use(fixture_system) -> None:
    coordinator, secret_path, profile, vault = fixture_system
    draft = _draft(coordinator, secret_path, profile)
    _review, admission = _admit(coordinator, secret_path, profile, draft)
    execution, assessment = _profiles()
    selection = ManifestSelection(admission, draft)
    manifest = coordinator.build_manifest(
        [selection],
        selection_policy_ref="selection-v1",
        execution_profile=execution,
        assessment_profile=assessment,
    )

    withdrawal = coordinator.withdraw(
        draft,
        fixture_use=_grant(
            secret_path,
            profile,
            authority_class="fixture_use_grant",
            action="fixture_withdraw",
            purpose="fixture_replay",
            target_ref=draft.record.record_id,
            revision=1,
        ),
        now=NOW,
    )

    assert withdrawal.event.event_type == "fixture_withdrawn"
    assert draft.record.payload["vault_ref"] in vault.content
    assert coordinator.manifest_is_stale(manifest)
    with pytest.raises(FixtureIneligible, match="withdrawn"):
        coordinator.build_manifest(
            [selection],
            selection_policy_ref="selection-v1",
            execution_profile=execution,
            assessment_profile=assessment,
        )
    with pytest.raises(FixtureIneligible, match="withdrawn"):
        coordinator.read_content(
            draft,
            authority=_access(
                secret_path,
                profile,
                action="fixture_review",
                purpose="fixture_replay",
                target_ref=draft.record.record_id,
                revision=1,
            ),
            action="fixture_review",
            purpose="fixture_replay",
            now=NOW,
        )
    coordinator.finalize_withdrawal(draft.record.record_id)
    assert draft.record.payload["vault_ref"] not in vault.content


def test_quarantine_release_must_bind_receipt_then_pass_ordinary_admission(fixture_system) -> None:
    coordinator, secret_path, profile, _vault = fixture_system
    release = QuarantineReleaseBinding("release_receipt_01", "e" * 64)
    draft = _draft(
        coordinator,
        secret_path,
        profile,
        fixture_ref="released_case_01",
        origin="quarantine_release",
        release=release,
    )
    review, admission = _admit(coordinator, secret_path, profile, draft)

    assert review.record.payload["truth_review"] == "passed"
    assert admission.receipt.payload["release_receipt_ref"] == "release_receipt_01"
    assert admission.receipt.payload["release_receipt_digest"] == "e" * 64
    with pytest.raises(FixtureValidationError, match="release receipt"):
        _draft(
            coordinator,
            secret_path,
            profile,
            fixture_ref="released_case_02",
            origin="quarantine_release",
        )
