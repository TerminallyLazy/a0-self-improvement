from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import sqlite3

import pytest

from usr.plugins.dspy_rlm.helpers.v3.migration_repository import (
    MigrationIdentityConflict,
    MigrationLedgerError,
    MigrationRepository,
)
from usr.plugins.dspy_rlm.helpers.v3.privacy_lifecycle import (
    ChallengeConsumption,
    DeletionChallenge,
    DeletionIntent,
    DeletionReceipt,
    ExportReceipt,
    ExportWaiver,
    PrivacyLifecycleDenied,
    PrivacyLifecycleStateError,
)


ISSUED = "2026-08-26T12:00:00.000000Z"
CONSUMED = "2026-08-26T12:01:00.000000Z"
EXPIRES = "2026-08-26T12:05:00.000000Z"
CONFIRMATION = "DELETE QUARANTINE quarantine_01 REVISION 1 CHALLENGE challenge_01"


def _confirmation_digest(value: str) -> str:
    return sha256(
        b"a0.quarantine.deletion-confirmation.v1\x00" + value.encode("utf-8")
    ).hexdigest()


def _challenge(*, challenge_ref: str = "challenge_01", expires_at: str = EXPIRES):
    confirmation = CONFIRMATION.replace("challenge_01", challenge_ref)
    return DeletionChallenge(
        challenge_ref=challenge_ref,
        quarantine_ref="quarantine_01",
        revision=1,
        authority_ref="grant_delete_01",
        issued_at=ISSUED,
        expires_at=expires_at,
        required_confirmation=confirmation,
        required_confirmation_digest=_confirmation_digest(confirmation),
    )


def _consumption(*, challenge_ref: str = "challenge_01", consumed_at: str = CONSUMED):
    challenge = _challenge(challenge_ref=challenge_ref)
    return ChallengeConsumption(
        challenge_ref=challenge_ref,
        quarantine_ref="quarantine_01",
        revision=1,
        authority_ref="grant_delete_01",
        confirmation_digest=challenge.required_confirmation_digest,
        consumed_at=consumed_at,
    )


def _intent(*, challenge_ref: str = "challenge_01", operation_ref: str = "deletion_01", begun_at: str = CONSUMED):
    return DeletionIntent(
        operation_ref=operation_ref,
        quarantine_ref="quarantine_01",
        revision=1,
        authority_ref="grant_delete_01",
        challenge_ref=challenge_ref,
        evidence_kind="export_receipt",
        evidence_ref="export_01",
        ciphertext_digest="a" * 64,
        wrapped_key_digest="b" * 64,
        begun_at=begun_at,
    )


def _completion(*, completed_at: str = "2026-08-26T12:02:00.000000Z"):
    return DeletionReceipt(
        receipt_ref="deletion_receipt_01",
        operation_ref="deletion_01",
        quarantine_ref="quarantine_01",
        revision=1,
        authority_ref="grant_delete_01",
        evidence_kind="export_receipt",
        evidence_ref="export_01",
        completed_at=completed_at,
    )


def test_export_evidence_is_exactly_idempotent_and_immutable(tmp_path: Path) -> None:
    repository = MigrationRepository.create(tmp_path / "ledger.sqlite")
    receipt = ExportReceipt(
        receipt_ref="export_01",
        quarantine_ref="quarantine_01",
        revision=1,
        authority_ref="grant_export_01",
        archive_ref="archive_01",
        ciphertext_digest="a" * 64,
        wrapped_key_digest="b" * 64,
        archive_digest="c" * 64,
        exported_at=ISSUED,
    )
    waiver = ExportWaiver(
        waiver_ref="waiver_01",
        quarantine_ref="quarantine_01",
        revision=1,
        authority_ref="grant_delete_01",
        acknowledged_at=ISSUED,
    )

    assert repository.append_export_receipt(receipt) == receipt
    assert repository.append_export_receipt(receipt) == receipt
    assert repository.resolve_export_receipt(receipt.receipt_ref) == receipt
    assert repository.append_export_waiver(waiver) == waiver
    assert repository.append_export_waiver(waiver) == waiver
    assert repository.resolve_export_waiver(waiver.waiver_ref) == waiver
    with pytest.raises(MigrationIdentityConflict):
        repository.append_export_receipt(replace(receipt, archive_digest="d" * 64))
    repository.close()

    connection = sqlite3.connect(tmp_path / "ledger.sqlite")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute(
            "UPDATE privacy_export_waivers SET record_digest=? WHERE waiver_ref=?",
            ("d" * 64, waiver.waiver_ref),
        )
    connection.close()


def test_challenge_consumption_and_intent_are_atomic_exact_and_expiring(tmp_path: Path) -> None:
    repository = MigrationRepository.create(tmp_path / "ledger.sqlite")
    challenge = _challenge()
    consumption = _consumption()
    intent = _intent()
    repository.append_deletion_challenge(challenge)

    assert repository.consume_challenge_and_begin(consumption, intent).intent == intent
    assert repository.consume_challenge_and_begin(consumption, intent).intent == intent
    with pytest.raises(MigrationIdentityConflict):
        repository.consume_challenge_and_begin(
            replace(consumption, consumed_at="2026-08-26T12:01:01.000000Z"),
            replace(intent, begun_at="2026-08-26T12:01:01.000000Z"),
        )

    expired = _challenge(
        challenge_ref="challenge_expired",
        expires_at="2026-08-26T12:00:30.000000Z",
    )
    repository.append_deletion_challenge(expired)
    expired_consumption = _consumption(
        challenge_ref="challenge_expired", consumed_at=CONSUMED
    )
    expired_intent = _intent(
        challenge_ref="challenge_expired",
        operation_ref="deletion_expired",
        begun_at=CONSUMED,
    )
    with pytest.raises(PrivacyLifecycleDenied, match="expired"):
        repository.consume_challenge_and_begin(expired_consumption, expired_intent)
    with pytest.raises(PrivacyLifecycleStateError, match="not in"):
        repository.load_deletion("deletion_expired")
    repository.close()


def test_unlink_markers_are_monotonic_and_completion_is_exact(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite"
    repository = MigrationRepository.create(path)
    repository.append_deletion_challenge(_challenge())
    repository.consume_challenge_and_begin(_consumption(), _intent())

    direct = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="wrapped key"):
        direct.execute(
            "INSERT INTO privacy_deletion_steps VALUES (?,?,?)",
            ("deletion_01", "ciphertext_unlinked", 2),
        )
    direct.close()
    with pytest.raises(PrivacyLifecycleStateError, match="wrapped key"):
        repository.mark_ciphertext_unlinked("deletion_01")
    with pytest.raises(PrivacyLifecycleStateError, match="both"):
        repository.complete_deletion(_completion())
    assert repository.mark_wrapped_key_unlinked("deletion_01").wrapped_key_unlinked
    assert repository.mark_wrapped_key_unlinked("deletion_01").wrapped_key_unlinked
    repository.close()

    with MigrationRepository.open(path) as resumed:
        progress = resumed.load_deletion("deletion_01")
        assert progress.wrapped_key_unlinked and not progress.ciphertext_unlinked
        assert resumed.mark_ciphertext_unlinked("deletion_01").ciphertext_unlinked
        receipt = _completion()
        assert resumed.complete_deletion(receipt) == receipt
        assert resumed.complete_deletion(receipt) == receipt
        assert resumed.load_deletion("deletion_01").receipt == receipt
        with pytest.raises(MigrationIdentityConflict):
            resumed.complete_deletion(
                replace(receipt, completed_at="2026-08-26T12:03:00.000000Z")
            )


def test_open_rejects_any_schema_drift(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite"
    MigrationRepository.create(path).close()
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE unexpected_privacy_state (value TEXT)")
    connection.commit()
    connection.close()

    with pytest.raises(MigrationLedgerError, match="fingerprint"):
        MigrationRepository.open(path)
