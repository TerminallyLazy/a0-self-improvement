from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import stat

import pytest

from usr.plugins.dspy_rlm.helpers.v3.authority import GrantExpectation, VerifiedGrant
from usr.plugins.dspy_rlm.helpers.v3.privacy_lifecycle import (
    ChallengeConsumption,
    DELETION_METHOD,
    DeletionEvidenceRef,
    DeletionProgress,
    ExportReceipt,
    ExportWaiver,
    PrivacyLifecycleDenied,
    WAIVER_ACKNOWLEDGEMENT,
    delete_quarantine,
    export_quarantine,
    issue_deletion_challenge,
    issue_export_waiver,
    resume_cryptographic_deletion,
)
from usr.plugins.dspy_rlm.helpers.v3.quarantine import (
    AES256GCMKeyCustody,
    EncryptedQuarantine,
    QuarantineIntegrityError,
    QuarantineValidationError,
    RetainedQuarantine,
    encrypt_quarantine,
)
from usr.plugins.dspy_rlm.helpers.v3.schemas import canonical_json


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


class DeterministicCipher:
    algorithm = "TEST-AUTHENTICATED-CIPHER"
    key_size = 32
    nonce_size = 12

    def __init__(self) -> None:
        self.counter = 0

    def _fresh(self, label: bytes, size: int) -> bytes:
        self.counter += 1
        return hashlib.sha256(label + self.counter.to_bytes(4, "big")).digest()[:size]

    def generate_key(self) -> bytes:
        return self._fresh(b"key", self.key_size)

    def generate_nonce(self) -> bytes:
        return self._fresh(b"nonce", self.nonce_size)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        stream = hashlib.sha256(key + nonce).digest()
        body = bytes(value ^ stream[index % len(stream)] for index, value in enumerate(plaintext))
        return body + hmac.new(key, aad + nonce + body, hashlib.sha256).digest()

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        body, tag = ciphertext[:-32], ciphertext[-32:]
        if not hmac.compare_digest(tag, hmac.new(key, aad + nonce + body, hashlib.sha256).digest()):
            raise QuarantineIntegrityError("test authentication failed")
        stream = hashlib.sha256(key + nonce).digest()
        return bytes(value ^ stream[index % len(stream)] for index, value in enumerate(body))


class RetainedLedger:
    def __init__(self, retained: RetainedQuarantine) -> None:
        self.retained = retained

    def resolve_retained(self, quarantine_ref: str, revision: int) -> RetainedQuarantine:
        if (quarantine_ref, revision) != (
            self.retained.quarantine_ref,
            self.retained.revision,
        ):
            raise KeyError("wrong retained quarantine")
        return self.retained


class Authorizer:
    def __init__(self, action: str, purpose: str, *, expires_at: datetime | None = None) -> None:
        self.grant = VerifiedGrant(
            grant_id=f"grant_{action}",
            authority_class="operator_authority_grant",
            issuer_id="issuer_local",
            key_epoch=1,
            subject_ref="operator_local",
            context_ref="context_01",
            action=action,
            purpose=purpose,
            target_ref="quarantine_01",
            target_revision=1,
            issued_at=NOW - timedelta(minutes=1),
            expires_at=expires_at or NOW + timedelta(minutes=30),
            idempotency_key_digest="a" * 64,
            session_nonce="session_01",
        )

    def authorize(self, envelope, expectation, *, now: datetime) -> VerifiedGrant:
        if envelope != {"grant_id": self.grant.grant_id}:
            raise RuntimeError("wrong grant")
        return self.grant


class LifecycleLedger:
    def __init__(self) -> None:
        self.exports: dict[str, ExportReceipt] = {}
        self.waivers: dict[str, ExportWaiver] = {}
        self.challenges = {}
        self.consumed: set[str] = set()
        self.operations: dict[str, DeletionProgress] = {}
        self.fail_after_key_marker = False

    def append_export_receipt(self, receipt: ExportReceipt) -> ExportReceipt:
        self.exports[receipt.receipt_ref] = receipt
        return receipt

    def append_deletion_challenge(self, challenge):
        self.challenges[challenge.challenge_ref] = challenge
        return challenge

    def append_export_waiver(self, waiver: ExportWaiver) -> ExportWaiver:
        self.waivers[waiver.waiver_ref] = waiver
        return waiver

    def resolve_export_receipt(self, receipt_ref: str) -> ExportReceipt:
        return self.exports[receipt_ref]

    def resolve_export_waiver(self, waiver_ref: str) -> ExportWaiver:
        return self.waivers[waiver_ref]

    def consume_challenge_and_begin(self, consumption: ChallengeConsumption, intent):
        challenge = self.challenges[consumption.challenge_ref]
        consumed_at = datetime.strptime(
            consumption.consumed_at, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=timezone.utc)
        expires_at = datetime.strptime(
            challenge.expires_at, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=timezone.utc)
        if consumption.challenge_ref in self.consumed:
            raise PrivacyLifecycleDenied("challenge already consumed")
        if consumed_at >= expires_at:
            raise PrivacyLifecycleDenied("challenge expired")
        if (
            consumption.quarantine_ref != challenge.quarantine_ref
            or consumption.revision != challenge.revision
            or consumption.authority_ref != challenge.authority_ref
            or consumption.confirmation_digest != challenge.required_confirmation_digest
        ):
            raise PrivacyLifecycleDenied("challenge binding does not match")
        self.consumed.add(consumption.challenge_ref)
        progress = DeletionProgress(intent)
        self.operations[intent.operation_ref] = progress
        return progress

    def load_deletion(self, operation_ref: str) -> DeletionProgress:
        return self.operations[operation_ref]

    def mark_wrapped_key_unlinked(self, operation_ref: str) -> DeletionProgress:
        old = self.operations[operation_ref]
        progress = replace(old, wrapped_key_unlinked=True)
        self.operations[operation_ref] = progress
        if self.fail_after_key_marker:
            self.fail_after_key_marker = False
            raise RuntimeError("simulated process crash")
        return progress

    def mark_ciphertext_unlinked(self, operation_ref: str) -> DeletionProgress:
        old = self.operations[operation_ref]
        progress = replace(old, ciphertext_unlinked=True)
        self.operations[operation_ref] = progress
        return progress

    def complete_deletion(self, receipt):
        old = self.operations[receipt.operation_ref]
        self.operations[receipt.operation_ref] = replace(old, receipt=receipt)
        return receipt


def expectation(action: str, purpose: str, *, revision: int = 1) -> GrantExpectation:
    return GrantExpectation(
        authority_class="operator_authority_grant",
        issuer_id="issuer_local",
        subject_ref="operator_local",
        context_ref="context_01",
        action=action,
        purpose=purpose,
        target_ref="quarantine_01",
        target_revision=revision,
        expires_at=NOW + timedelta(minutes=30),
        idempotency_key_digest="a" * 64,
        session_nonce="session_01",
    )


def retained_bundle(tmp_path: Path):
    cipher = DeterministicCipher()
    custody = AES256GCMKeyCustody("custody_epoch_1", b"K" * 32, cipher=cipher)
    encrypted = encrypt_quarantine(
        b"legacy secret bytes",
        quarantine_ref="quarantine_01",
        revision=1,
        cipher=cipher,
        custody=custody,
    )
    ciphertext_path = tmp_path / "retained.enc"
    wrapped_key_path = tmp_path / "retained.key"
    ciphertext_path.write_bytes(encrypted.ciphertext_envelope)
    wrapped_key_path.write_bytes(encrypted.wrapped_key_envelope)
    retained = RetainedQuarantine(
        quarantine_ref="quarantine_01",
        revision=1,
        ciphertext_path=ciphertext_path,
        wrapped_key_path=wrapped_key_path,
        ciphertext_digest=hashlib.sha256(encrypted.ciphertext_envelope).hexdigest(),
    )
    return encrypted, cipher, custody, RetainedLedger(retained)


def issue_challenge(ledger: LifecycleLedger, authorizer: Authorizer):
    return issue_deletion_challenge(
        "quarantine_01",
        1,
        grant_envelope={"grant_id": authorizer.grant.grant_id},
        grant_expectation=expectation("quarantine_delete", "quarantine_deletion"),
        authorizer=authorizer,
        lifecycle_ledger=ledger,
        now=NOW,
        expires_at=NOW + timedelta(minutes=5),
        random_bytes=lambda size: b"N" * size,
    )


def test_export_is_exact_0600_content_free_and_archive_survives_deletion(tmp_path: Path) -> None:
    encrypted, cipher, custody, retained = retained_bundle(tmp_path)
    lifecycle = LifecycleLedger()
    export_authorizer = Authorizer("quarantine_export", "quarantine_export")
    archive = tmp_path / "archive"
    archive.mkdir()
    receipt = export_quarantine(
        "quarantine_01",
        1,
        grant_envelope={"grant_id": export_authorizer.grant.grant_id},
        grant_expectation=expectation("quarantine_export", "quarantine_export"),
        authorizer=export_authorizer,
        quarantine_ledger=retained,
        lifecycle_ledger=lifecycle,
        cipher=cipher,
        custody=custody,
        destination=archive,
        now=NOW,
    )

    archived = sorted(archive.iterdir())
    assert {path.read_bytes() for path in archived} == {
        encrypted.ciphertext_envelope,
        encrypted.wrapped_key_envelope,
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in archived)
    assert b"legacy secret" not in canonical_json(asdict(receipt))
    assert str(tmp_path).encode() not in canonical_json(asdict(receipt))
    assert receipt.contains_plaintext is False

    delete_authorizer = Authorizer("quarantine_delete", "quarantine_deletion")
    challenge = issue_challenge(lifecycle, delete_authorizer)
    deletion = delete_quarantine(
        "quarantine_01",
        1,
        grant_envelope={"grant_id": delete_authorizer.grant.grant_id},
        grant_expectation=expectation("quarantine_delete", "quarantine_deletion"),
        authorizer=delete_authorizer,
        quarantine_ledger=retained,
        lifecycle_ledger=lifecycle,
        cipher=cipher,
        custody=custody,
        challenge_ref=challenge.challenge_ref,
        typed_confirmation=challenge.required_confirmation,
        evidence=DeletionEvidenceRef("export_receipt", receipt.receipt_ref),
        now=NOW + timedelta(minutes=1),
    )

    assert not retained.retained.wrapped_key_path.exists()
    assert not retained.retained.ciphertext_path.exists()
    assert all(path.exists() for path in archived)
    assert deletion.deletion_method == DELETION_METHOD
    assert deletion.physical_overwrite_claimed is False


def test_export_tampering_blocks_before_any_archive_copy(tmp_path: Path) -> None:
    _, cipher, custody, retained = retained_bundle(tmp_path)
    retained.retained.wrapped_key_path.write_bytes(
        retained.retained.wrapped_key_path.read_bytes() + b"tampered"
    )
    archive = tmp_path / "archive"
    archive.mkdir()
    authorizer = Authorizer("quarantine_export", "quarantine_export")

    with pytest.raises((QuarantineIntegrityError, QuarantineValidationError)):
        export_quarantine(
            "quarantine_01",
            1,
            grant_envelope={"grant_id": authorizer.grant.grant_id},
            grant_expectation=expectation("quarantine_export", "quarantine_export"),
            authorizer=authorizer,
            quarantine_ledger=retained,
            lifecycle_ledger=LifecycleLedger(),
            cipher=cipher,
            custody=custody,
            destination=archive,
            now=NOW,
        )

    assert list(archive.iterdir()) == []


def test_wrong_grant_revision_challenge_and_export_receipt_all_block(tmp_path: Path) -> None:
    encrypted, cipher, custody, retained = retained_bundle(tmp_path)
    lifecycle = LifecycleLedger()
    authorizer = Authorizer("quarantine_delete", "quarantine_deletion")
    with pytest.raises(PrivacyLifecycleDenied, match="not active"):
        issue_deletion_challenge(
            "quarantine_01",
            1,
            grant_envelope={"grant_id": "grant_foreign"},
            grant_expectation=expectation("quarantine_delete", "quarantine_deletion"),
            authorizer=authorizer,
            lifecycle_ledger=lifecycle,
            now=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(PrivacyLifecycleDenied, match="expectation"):
        issue_deletion_challenge(
            "quarantine_01",
            1,
            grant_envelope={"grant_id": authorizer.grant.grant_id},
            grant_expectation=expectation("quarantine_delete", "quarantine_deletion", revision=2),
            authorizer=authorizer,
            lifecycle_ledger=lifecycle,
            now=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )

    challenge = issue_challenge(lifecycle, authorizer)
    wrong_receipt = ExportReceipt(
        receipt_ref="receipt_wrong",
        quarantine_ref="quarantine_01",
        revision=2,
        authority_ref="grant_export",
        archive_ref="archive_wrong",
        ciphertext_digest=hashlib.sha256(encrypted.ciphertext_envelope).hexdigest(),
        wrapped_key_digest=hashlib.sha256(encrypted.wrapped_key_envelope).hexdigest(),
        archive_digest="b" * 64,
        exported_at="2026-08-26T12:00:00.000000Z",
    )
    lifecycle.exports[wrong_receipt.receipt_ref] = wrong_receipt
    common = dict(
        grant_envelope={"grant_id": authorizer.grant.grant_id},
        grant_expectation=expectation("quarantine_delete", "quarantine_deletion"),
        authorizer=authorizer,
        quarantine_ledger=retained,
        lifecycle_ledger=lifecycle,
        cipher=cipher,
        custody=custody,
        challenge_ref=challenge.challenge_ref,
        evidence=DeletionEvidenceRef("export_receipt", wrong_receipt.receipt_ref),
        now=NOW + timedelta(seconds=1),
    )
    with pytest.raises(PrivacyLifecycleDenied, match="receipt"):
        delete_quarantine(
            "quarantine_01", 1, typed_confirmation=challenge.required_confirmation, **common
        )
    lifecycle.exports[wrong_receipt.receipt_ref] = replace(wrong_receipt, revision=1)
    lifecycle.challenges[challenge.challenge_ref] = replace(
        challenge, expires_at="2026-08-26T12:00:00.000000Z"
    )
    with pytest.raises(PrivacyLifecycleDenied, match="expired"):
        delete_quarantine(
            "quarantine_01", 1, typed_confirmation=challenge.required_confirmation, **common
        )
    lifecycle.challenges[challenge.challenge_ref] = challenge
    with pytest.raises(PrivacyLifecycleDenied, match="challenge"):
        delete_quarantine("quarantine_01", 1, typed_confirmation="DELETE IT", **common)

    assert retained.retained.wrapped_key_path.exists()
    assert retained.retained.ciphertext_path.exists()
    assert lifecycle.consumed == set()


def test_explicit_immutable_waiver_allows_exact_deletion(tmp_path: Path) -> None:
    _, cipher, custody, retained = retained_bundle(tmp_path)
    lifecycle = LifecycleLedger()
    authorizer = Authorizer("quarantine_delete", "quarantine_deletion")
    waiver = issue_export_waiver(
        "quarantine_01",
        1,
        grant_envelope={"grant_id": authorizer.grant.grant_id},
        grant_expectation=expectation("quarantine_delete", "quarantine_deletion"),
        authorizer=authorizer,
        lifecycle_ledger=lifecycle,
        acknowledgement=WAIVER_ACKNOWLEDGEMENT,
        now=NOW,
    )
    challenge = issue_challenge(lifecycle, authorizer)

    receipt = delete_quarantine(
        "quarantine_01",
        1,
        grant_envelope={"grant_id": authorizer.grant.grant_id},
        grant_expectation=expectation("quarantine_delete", "quarantine_deletion"),
        authorizer=authorizer,
        quarantine_ledger=retained,
        lifecycle_ledger=lifecycle,
        cipher=cipher,
        custody=custody,
        challenge_ref=challenge.challenge_ref,
        typed_confirmation=challenge.required_confirmation,
        evidence=DeletionEvidenceRef("export_waiver", waiver.waiver_ref),
        now=NOW + timedelta(seconds=1),
    )

    assert receipt.evidence_kind == "export_waiver"
    assert receipt.wrapped_key_unlinked and receipt.ciphertext_unlinked
    assert receipt.physical_overwrite_claimed is False


def test_crash_after_key_unlink_resumes_without_restoring_or_retargeting(tmp_path: Path) -> None:
    _, cipher, custody, retained = retained_bundle(tmp_path)
    lifecycle = LifecycleLedger()
    authorizer = Authorizer("quarantine_delete", "quarantine_deletion")
    waiver = ExportWaiver(
        waiver_ref="waiver_01",
        quarantine_ref="quarantine_01",
        revision=1,
        authority_ref=authorizer.grant.grant_id,
        acknowledged_at="2026-08-26T12:00:00.000000Z",
    )
    lifecycle.waivers[waiver.waiver_ref] = waiver
    challenge = issue_challenge(lifecycle, authorizer)
    lifecycle.fail_after_key_marker = True

    with pytest.raises(RuntimeError, match="simulated process crash"):
        delete_quarantine(
            "quarantine_01",
            1,
            grant_envelope={"grant_id": authorizer.grant.grant_id},
            grant_expectation=expectation("quarantine_delete", "quarantine_deletion"),
            authorizer=authorizer,
            quarantine_ledger=retained,
            lifecycle_ledger=lifecycle,
            cipher=cipher,
            custody=custody,
            challenge_ref=challenge.challenge_ref,
            typed_confirmation=challenge.required_confirmation,
            evidence=DeletionEvidenceRef("export_waiver", waiver.waiver_ref),
            now=NOW + timedelta(seconds=1),
        )

    progress = next(iter(lifecycle.operations.values()))
    assert progress.wrapped_key_unlinked
    assert not retained.retained.wrapped_key_path.exists()
    assert retained.retained.ciphertext_path.exists()
    receipt = resume_cryptographic_deletion(
        progress.intent.operation_ref,
        quarantine_ledger=retained,
        lifecycle_ledger=lifecycle,
        now=NOW + timedelta(seconds=2),
    )

    assert not retained.retained.ciphertext_path.exists()
    assert resume_cryptographic_deletion(
        progress.intent.operation_ref,
        quarantine_ledger=retained,
        lifecycle_ledger=lifecycle,
        now=NOW + timedelta(seconds=3),
    ) == receipt
