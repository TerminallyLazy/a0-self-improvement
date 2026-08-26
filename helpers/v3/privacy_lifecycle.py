"""Local-only export and cryptographic-deletion lifecycle for v3 quarantine.

The module owns coordination, not persistence.  A migration-authority process
injects the signed-grant verifier, retained-quarantine ledger, and append-only
lifecycle ledger.  Normal runtime code must never receive any of those handles.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import stat
from typing import Literal, Mapping, Protocol

from .authority import GrantExpectation, VerifiedGrant
from .quarantine import (
    EncryptedQuarantine,
    KeyCustody,
    QuarantineCipher,
    QuarantineLedger,
    exact_ciphertext_export,
    plan_cryptographic_deletion,
)
from .schemas import canonical_json


EXPORT_RECEIPT_SCHEMA = "a0.quarantine-export-receipt.v1"
EXPORT_WAIVER_SCHEMA = "a0.quarantine-export-waiver.v1"
DELETION_CHALLENGE_SCHEMA = "a0.quarantine-deletion-challenge.v1"
DELETION_INTENT_SCHEMA = "a0.quarantine-deletion-intent.v1"
DELETION_RECEIPT_SCHEMA = "a0.quarantine-deletion-receipt.v1"
EXPORT_ACTION = "quarantine_export"
EXPORT_PURPOSE = "quarantine_export"
DELETE_ACTION = "quarantine_delete"
DELETE_PURPOSE = "quarantine_deletion"
WAIVER_ACKNOWLEDGEMENT = "EXPORT_WAIVED_FOR_IRREVERSIBLE_QUARANTINE_DELETION"
DELETION_METHOD = "cryptographic_erasure_plus_unlink"


class PrivacyLifecycleError(RuntimeError):
    """Base class for safe, local quarantine-lifecycle failures."""


class PrivacyLifecycleDenied(PrivacyLifecycleError):
    """Raised when authority, challenge, or prerequisite evidence is wrong."""


class PrivacyLifecycleIntegrityError(PrivacyLifecycleError):
    """Raised when exact retained or copied encrypted bytes do not match."""


class PrivacyLifecycleStateError(PrivacyLifecycleError):
    """Raised when durable lifecycle state violates the coordinator contract."""


@dataclass(frozen=True, slots=True)
class ExportReceipt:
    receipt_ref: str
    quarantine_ref: str
    revision: int
    authority_ref: str
    archive_ref: str
    ciphertext_digest: str
    wrapped_key_digest: str
    archive_digest: str
    exported_at: str
    contains_plaintext: bool = False
    schema: str = EXPORT_RECEIPT_SCHEMA


@dataclass(frozen=True, slots=True)
class ExportWaiver:
    waiver_ref: str
    quarantine_ref: str
    revision: int
    authority_ref: str
    acknowledged_at: str
    acknowledgement: str = WAIVER_ACKNOWLEDGEMENT
    schema: str = EXPORT_WAIVER_SCHEMA


@dataclass(frozen=True, slots=True)
class DeletionChallenge:
    challenge_ref: str
    quarantine_ref: str
    revision: int
    authority_ref: str
    issued_at: str
    expires_at: str
    required_confirmation: str
    required_confirmation_digest: str
    schema: str = DELETION_CHALLENGE_SCHEMA


@dataclass(frozen=True, slots=True)
class DeletionEvidenceRef:
    kind: Literal["export_receipt", "export_waiver"]
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class DeletionIntent:
    operation_ref: str
    quarantine_ref: str
    revision: int
    authority_ref: str
    challenge_ref: str
    evidence_kind: str
    evidence_ref: str
    ciphertext_digest: str
    wrapped_key_digest: str
    begun_at: str
    schema: str = DELETION_INTENT_SCHEMA


@dataclass(frozen=True, slots=True)
class ChallengeConsumption:
    challenge_ref: str
    quarantine_ref: str
    revision: int
    authority_ref: str
    confirmation_digest: str
    consumed_at: str


@dataclass(frozen=True, slots=True)
class DeletionReceipt:
    receipt_ref: str
    operation_ref: str
    quarantine_ref: str
    revision: int
    authority_ref: str
    evidence_kind: str
    evidence_ref: str
    completed_at: str
    deletion_method: str = DELETION_METHOD
    wrapped_key_unlinked: bool = True
    ciphertext_unlinked: bool = True
    physical_overwrite_claimed: bool = False
    schema: str = DELETION_RECEIPT_SCHEMA


@dataclass(frozen=True, slots=True)
class DeletionProgress:
    intent: DeletionIntent
    wrapped_key_unlinked: bool = False
    ciphertext_unlinked: bool = False
    receipt: DeletionReceipt | None = None


class GrantAuthorizer(Protocol):
    """Adapter around the owning issuer's signature and revocation checks."""

    def authorize(
        self,
        envelope: Mapping[str, object],
        expectation: GrantExpectation,
        *,
        now: datetime,
    ) -> VerifiedGrant: ...


class PrivacyLifecycleLedger(Protocol):
    """Append-only persistence contract implemented by Migration Authority.

    ``consume_challenge_and_begin`` must validate and consume the challenge and
    append the exact intent in one durable transaction.  Step markers and
    completion must be idempotent for the same operation identity.
    """

    def append_export_receipt(self, receipt: ExportReceipt) -> ExportReceipt: ...

    def append_export_waiver(self, waiver: ExportWaiver) -> ExportWaiver: ...

    def append_deletion_challenge(self, challenge: DeletionChallenge) -> DeletionChallenge: ...

    def resolve_export_receipt(self, receipt_ref: str) -> ExportReceipt: ...

    def resolve_export_waiver(self, waiver_ref: str) -> ExportWaiver: ...

    def consume_challenge_and_begin(
        self,
        consumption: ChallengeConsumption,
        intent: DeletionIntent,
    ) -> DeletionProgress: ...

    def load_deletion(self, operation_ref: str) -> DeletionProgress: ...

    def mark_wrapped_key_unlinked(self, operation_ref: str) -> DeletionProgress: ...

    def mark_ciphertext_unlinked(self, operation_ref: str) -> DeletionProgress: ...

    def complete_deletion(self, receipt: DeletionReceipt) -> DeletionReceipt: ...


def export_quarantine(
    quarantine_ref: str,
    revision: int,
    *,
    grant_envelope: Mapping[str, object],
    grant_expectation: GrantExpectation,
    authorizer: GrantAuthorizer,
    quarantine_ledger: QuarantineLedger,
    lifecycle_ledger: PrivacyLifecycleLedger,
    cipher: QuarantineCipher,
    custody: KeyCustody,
    destination: Path,
    now: datetime,
) -> ExportReceipt:
    """Authenticate and copy both exact encrypted files without plaintext output."""

    current = _utc(now)
    grant = _authorize_exact(
        grant_envelope,
        grant_expectation,
        authorizer=authorizer,
        action=EXPORT_ACTION,
        purpose=EXPORT_PURPOSE,
        quarantine_ref=quarantine_ref,
        revision=revision,
        now=current,
    )
    plan = plan_cryptographic_deletion(quarantine_ref, revision, ledger=quarantine_ledger)
    ciphertext = _read_exact_file(plan.ciphertext_path)
    wrapped_key = _read_exact_file(plan.wrapped_key_path)
    if _sha256(ciphertext) != plan.ciphertext_digest:
        raise PrivacyLifecycleIntegrityError("retained ciphertext digest does not match ledger")
    encrypted = exact_ciphertext_export(
        EncryptedQuarantine(ciphertext, wrapped_key), cipher=cipher, custody=custody
    )
    ciphertext_digest = _sha256(encrypted.ciphertext_envelope)
    wrapped_key_digest = _sha256(encrypted.wrapped_key_envelope)
    archive_ref = _identity(
        "archive",
        quarantine_ref,
        str(revision),
        ciphertext_digest,
        wrapped_key_digest,
        _timestamp(current),
    )
    destination_dir = _exact_directory(destination)
    ciphertext_target = destination_dir / f"{archive_ref}.ciphertext.enc"
    wrapped_key_target = destination_dir / f"{archive_ref}.wrapped-key.enc"
    created: list[Path] = []
    try:
        _exclusive_copy(ciphertext_target, encrypted.ciphertext_envelope)
        created.append(ciphertext_target)
        _exclusive_copy(wrapped_key_target, encrypted.wrapped_key_envelope)
        created.append(wrapped_key_target)
        _fsync_directory(destination_dir)
        if _read_exact_file(ciphertext_target, expected_mode=0o600) != encrypted.ciphertext_envelope:
            raise PrivacyLifecycleIntegrityError("exported ciphertext byte verification failed")
        if _read_exact_file(wrapped_key_target, expected_mode=0o600) != encrypted.wrapped_key_envelope:
            raise PrivacyLifecycleIntegrityError("exported wrapped-key byte verification failed")
    except BaseException:
        for path in reversed(created):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        if created:
            _fsync_directory(destination_dir)
        raise

    archive_digest = _archive_digest(encrypted)
    receipt = ExportReceipt(
        receipt_ref=_identity("export_receipt", archive_ref, archive_digest, grant.grant_id),
        quarantine_ref=plan.quarantine_ref,
        revision=plan.revision,
        authority_ref=grant.grant_id,
        archive_ref=archive_ref,
        ciphertext_digest=ciphertext_digest,
        wrapped_key_digest=wrapped_key_digest,
        archive_digest=archive_digest,
        exported_at=_timestamp(current),
    )
    persisted = lifecycle_ledger.append_export_receipt(receipt)
    if persisted != receipt:
        raise PrivacyLifecycleStateError("export ledger returned different receipt bytes")
    return receipt


def issue_deletion_challenge(
    quarantine_ref: str,
    revision: int,
    *,
    grant_envelope: Mapping[str, object],
    grant_expectation: GrantExpectation,
    authorizer: GrantAuthorizer,
    lifecycle_ledger: PrivacyLifecycleLedger,
    now: datetime,
    expires_at: datetime,
    random_bytes=os.urandom,
) -> DeletionChallenge:
    """Append one expiring challenge bound to the exact grant and quarantine."""

    current = _utc(now)
    expiry = _utc(expires_at)
    grant = _authorize_exact(
        grant_envelope,
        grant_expectation,
        authorizer=authorizer,
        action=DELETE_ACTION,
        purpose=DELETE_PURPOSE,
        quarantine_ref=quarantine_ref,
        revision=revision,
        now=current,
    )
    if expiry <= current or expiry > grant.expires_at:
        raise PrivacyLifecycleDenied("challenge expiry must be live and no later than grant expiry")
    nonce = random_bytes(32)
    if type(nonce) is not bytes or len(nonce) != 32:
        raise PrivacyLifecycleStateError("challenge entropy source must return exactly 32 bytes")
    challenge_ref = _identity(
        "deletion_challenge",
        quarantine_ref,
        str(revision),
        grant.grant_id,
        nonce.hex(),
    )
    confirmation = (
        f"DELETE QUARANTINE {quarantine_ref} REVISION {revision} CHALLENGE {challenge_ref}"
    )
    challenge = DeletionChallenge(
        challenge_ref=challenge_ref,
        quarantine_ref=quarantine_ref,
        revision=revision,
        authority_ref=grant.grant_id,
        issued_at=_timestamp(current),
        expires_at=_timestamp(expiry),
        required_confirmation=confirmation,
        required_confirmation_digest=_confirmation_digest(confirmation),
    )
    persisted = lifecycle_ledger.append_deletion_challenge(challenge)
    if persisted != challenge:
        raise PrivacyLifecycleStateError("challenge ledger returned different challenge bytes")
    return challenge


def issue_export_waiver(
    quarantine_ref: str,
    revision: int,
    *,
    grant_envelope: Mapping[str, object],
    grant_expectation: GrantExpectation,
    authorizer: GrantAuthorizer,
    lifecycle_ledger: PrivacyLifecycleLedger,
    acknowledgement: str,
    now: datetime,
) -> ExportWaiver:
    """Persist the explicit irreversible-deletion waiver under delete authority."""

    current = _utc(now)
    grant = _authorize_exact(
        grant_envelope,
        grant_expectation,
        authorizer=authorizer,
        action=DELETE_ACTION,
        purpose=DELETE_PURPOSE,
        quarantine_ref=quarantine_ref,
        revision=revision,
        now=current,
    )
    if acknowledgement != WAIVER_ACKNOWLEDGEMENT:
        raise PrivacyLifecycleDenied("exact export-waiver acknowledgement is required")
    waiver = ExportWaiver(
        waiver_ref=_identity(
            "export_waiver",
            quarantine_ref,
            str(revision),
            grant.grant_id,
            _timestamp(current),
        ),
        quarantine_ref=quarantine_ref,
        revision=revision,
        authority_ref=grant.grant_id,
        acknowledged_at=_timestamp(current),
    )
    persisted = lifecycle_ledger.append_export_waiver(waiver)
    if persisted != waiver:
        raise PrivacyLifecycleStateError("waiver ledger returned different waiver bytes")
    return waiver


def delete_quarantine(
    quarantine_ref: str,
    revision: int,
    *,
    grant_envelope: Mapping[str, object],
    grant_expectation: GrantExpectation,
    authorizer: GrantAuthorizer,
    quarantine_ledger: QuarantineLedger,
    lifecycle_ledger: PrivacyLifecycleLedger,
    cipher: QuarantineCipher,
    custody: KeyCustody,
    challenge_ref: str,
    typed_confirmation: str,
    evidence: DeletionEvidenceRef,
    now: datetime,
) -> DeletionReceipt:
    """Authorize, atomically consume the challenge, then delete key before ciphertext."""

    current = _utc(now)
    grant = _authorize_exact(
        grant_envelope,
        grant_expectation,
        authorizer=authorizer,
        action=DELETE_ACTION,
        purpose=DELETE_PURPOSE,
        quarantine_ref=quarantine_ref,
        revision=revision,
        now=current,
    )
    plan = plan_cryptographic_deletion(quarantine_ref, revision, ledger=quarantine_ledger)
    ciphertext = _read_exact_file(plan.ciphertext_path)
    wrapped_key = _read_exact_file(plan.wrapped_key_path)
    if _sha256(ciphertext) != plan.ciphertext_digest:
        raise PrivacyLifecycleIntegrityError("retained ciphertext digest does not match ledger")
    exact_ciphertext_export(
        EncryptedQuarantine(ciphertext, wrapped_key), cipher=cipher, custody=custody
    )
    wrapped_key_digest = _sha256(wrapped_key)
    _require_deletion_evidence(
        evidence,
        lifecycle_ledger=lifecycle_ledger,
        quarantine_ref=plan.quarantine_ref,
        revision=plan.revision,
        ciphertext_digest=plan.ciphertext_digest,
        wrapped_key_digest=wrapped_key_digest,
        now=current,
    )
    operation_ref = _identity(
        "deletion",
        challenge_ref,
        grant.grant_id,
        evidence.kind,
        evidence.evidence_ref,
        plan.ciphertext_digest,
        wrapped_key_digest,
    )
    intent = DeletionIntent(
        operation_ref=operation_ref,
        quarantine_ref=plan.quarantine_ref,
        revision=plan.revision,
        authority_ref=grant.grant_id,
        challenge_ref=challenge_ref,
        evidence_kind=evidence.kind,
        evidence_ref=evidence.evidence_ref,
        ciphertext_digest=plan.ciphertext_digest,
        wrapped_key_digest=wrapped_key_digest,
        begun_at=_timestamp(current),
    )
    consumption = ChallengeConsumption(
        challenge_ref=challenge_ref,
        quarantine_ref=plan.quarantine_ref,
        revision=plan.revision,
        authority_ref=grant.grant_id,
        confirmation_digest=_confirmation_digest(typed_confirmation),
        consumed_at=_timestamp(current),
    )
    progress = lifecycle_ledger.consume_challenge_and_begin(consumption, intent)
    if progress.intent != intent:
        raise PrivacyLifecycleStateError("deletion ledger returned a different intent")
    return _resume_progress(
        progress,
        quarantine_ledger=quarantine_ledger,
        lifecycle_ledger=lifecycle_ledger,
        now=current,
    )


def resume_cryptographic_deletion(
    operation_ref: str,
    *,
    quarantine_ledger: QuarantineLedger,
    lifecycle_ledger: PrivacyLifecycleLedger,
    now: datetime,
) -> DeletionReceipt:
    """Resume only the exact durable intent; no caller supplies deletion paths."""

    progress = lifecycle_ledger.load_deletion(operation_ref)
    if progress.intent.operation_ref != operation_ref:
        raise PrivacyLifecycleStateError("deletion ledger returned a different operation")
    return _resume_progress(
        progress,
        quarantine_ledger=quarantine_ledger,
        lifecycle_ledger=lifecycle_ledger,
        now=_utc(now),
    )


def _resume_progress(
    progress: DeletionProgress,
    *,
    quarantine_ledger: QuarantineLedger,
    lifecycle_ledger: PrivacyLifecycleLedger,
    now: datetime,
) -> DeletionReceipt:
    intent = progress.intent
    if progress.receipt is not None:
        _validate_completed_receipt(progress.receipt, intent)
        return progress.receipt
    plan = plan_cryptographic_deletion(
        intent.quarantine_ref, intent.revision, ledger=quarantine_ledger
    )
    if plan.ciphertext_digest != intent.ciphertext_digest:
        raise PrivacyLifecycleIntegrityError("retained quarantine changed after deletion intent")

    if not progress.wrapped_key_unlinked:
        _unlink_exact(plan.wrapped_key_path, expected_digest=intent.wrapped_key_digest)
        progress = lifecycle_ledger.mark_wrapped_key_unlinked(intent.operation_ref)
        _validate_progress(progress, intent, wrapped_key=True)

    if not progress.ciphertext_unlinked:
        _unlink_exact(plan.ciphertext_path, expected_digest=intent.ciphertext_digest)
        progress = lifecycle_ledger.mark_ciphertext_unlinked(intent.operation_ref)
        _validate_progress(progress, intent, wrapped_key=True, ciphertext=True)

    receipt = DeletionReceipt(
        receipt_ref=_identity("deletion_receipt", intent.operation_ref),
        operation_ref=intent.operation_ref,
        quarantine_ref=intent.quarantine_ref,
        revision=intent.revision,
        authority_ref=intent.authority_ref,
        evidence_kind=intent.evidence_kind,
        evidence_ref=intent.evidence_ref,
        completed_at=_timestamp(now),
    )
    persisted = lifecycle_ledger.complete_deletion(receipt)
    _validate_completed_receipt(persisted, intent)
    return persisted


def _authorize_exact(
    envelope: Mapping[str, object],
    expectation: GrantExpectation,
    *,
    authorizer: GrantAuthorizer,
    action: str,
    purpose: str,
    quarantine_ref: str,
    revision: int,
    now: datetime,
) -> VerifiedGrant:
    if (
        expectation.action != action
        or expectation.purpose != purpose
        or expectation.target_ref != quarantine_ref
        or expectation.target_revision != revision
    ):
        raise PrivacyLifecycleDenied("grant expectation is not exact for quarantine operation")
    try:
        grant = authorizer.authorize(envelope, expectation, now=now)
    except Exception as exc:
        raise PrivacyLifecycleDenied("quarantine authority grant is not active") from exc
    if not isinstance(grant, VerifiedGrant):
        raise PrivacyLifecycleDenied("authority verifier returned an invalid grant")
    if (
        grant.action != action
        or grant.purpose != purpose
        or grant.target_ref != quarantine_ref
        or grant.target_revision != revision
        or now < grant.issued_at
        or now >= grant.expires_at
    ):
        raise PrivacyLifecycleDenied("authority grant is not active for exact quarantine")
    return grant


def _require_deletion_evidence(
    evidence: DeletionEvidenceRef,
    *,
    lifecycle_ledger: PrivacyLifecycleLedger,
    quarantine_ref: str,
    revision: int,
    ciphertext_digest: str,
    wrapped_key_digest: str,
    now: datetime,
) -> None:
    if not isinstance(evidence, DeletionEvidenceRef):
        raise PrivacyLifecycleDenied("deletion requires export receipt or immutable waiver")
    try:
        if evidence.kind == "export_receipt":
            receipt = lifecycle_ledger.resolve_export_receipt(evidence.evidence_ref)
            if (
                type(receipt) is not ExportReceipt
                or receipt.schema != EXPORT_RECEIPT_SCHEMA
                or receipt.receipt_ref != evidence.evidence_ref
                or receipt.quarantine_ref != quarantine_ref
                or receipt.revision != revision
                or receipt.ciphertext_digest != ciphertext_digest
                or receipt.wrapped_key_digest != wrapped_key_digest
                or receipt.contains_plaintext
                or _parse_timestamp(receipt.exported_at) > now
            ):
                raise PrivacyLifecycleDenied("export receipt does not match exact quarantine")
        elif evidence.kind == "export_waiver":
            waiver = lifecycle_ledger.resolve_export_waiver(evidence.evidence_ref)
            if (
                type(waiver) is not ExportWaiver
                or waiver.schema != EXPORT_WAIVER_SCHEMA
                or waiver.waiver_ref != evidence.evidence_ref
                or waiver.quarantine_ref != quarantine_ref
                or waiver.revision != revision
                or waiver.acknowledgement != WAIVER_ACKNOWLEDGEMENT
                or _parse_timestamp(waiver.acknowledged_at) > now
            ):
                raise PrivacyLifecycleDenied("export waiver does not match exact quarantine")
        else:
            raise PrivacyLifecycleDenied("unknown deletion evidence kind")
    except PrivacyLifecycleDenied:
        raise
    except Exception as exc:
        raise PrivacyLifecycleDenied("deletion evidence is unavailable") from exc


def _validate_progress(
    progress: DeletionProgress,
    intent: DeletionIntent,
    *,
    wrapped_key: bool = False,
    ciphertext: bool = False,
) -> None:
    if progress.intent != intent:
        raise PrivacyLifecycleStateError("deletion step returned a different intent")
    if wrapped_key and not progress.wrapped_key_unlinked:
        raise PrivacyLifecycleStateError("wrapped-key deletion was not durably recorded")
    if ciphertext and not progress.ciphertext_unlinked:
        raise PrivacyLifecycleStateError("ciphertext deletion was not durably recorded")


def _validate_completed_receipt(receipt: DeletionReceipt, intent: DeletionIntent) -> None:
    if (
        receipt.operation_ref != intent.operation_ref
        or receipt.quarantine_ref != intent.quarantine_ref
        or receipt.revision != intent.revision
        or receipt.authority_ref != intent.authority_ref
        or receipt.evidence_kind != intent.evidence_kind
        or receipt.evidence_ref != intent.evidence_ref
        or receipt.deletion_method != DELETION_METHOD
        or not receipt.wrapped_key_unlinked
        or not receipt.ciphertext_unlinked
        or receipt.physical_overwrite_claimed
    ):
        raise PrivacyLifecycleStateError("deletion receipt does not match exact durable intent")


def _exclusive_copy(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(value)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise PrivacyLifecycleIntegrityError("export write was incomplete")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unlink_exact(path: Path, *, expected_digest: str) -> None:
    try:
        value = _read_exact_file(path)
    except FileNotFoundError:
        value = None
    if value is not None:
        if not hmac.compare_digest(_sha256(value), expected_digest):
            raise PrivacyLifecycleIntegrityError("deletion target digest changed")
        path.unlink()
    _fsync_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise PrivacyLifecycleIntegrityError("deletion target still exists after unlink")


def _read_exact_file(path: Path, *, expected_mode: int | None = None) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PrivacyLifecycleIntegrityError("encrypted file is not a regular file")
        if expected_mode is not None and stat.S_IMODE(opened.st_mode) != expected_mode:
            raise PrivacyLifecycleIntegrityError("exported file mode is not exactly 0600")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _exact_directory(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise PrivacyLifecycleDenied("export destination must be an exact absolute path")
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PrivacyLifecycleDenied("export destination must be a real local directory")
    return path


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _archive_digest(encrypted: EncryptedQuarantine) -> str:
    manifest = canonical_json(
        {
            "ciphertext_digest": _sha256(encrypted.ciphertext_envelope),
            "ciphertext_size": len(encrypted.ciphertext_envelope),
            "wrapped_key_digest": _sha256(encrypted.wrapped_key_envelope),
            "wrapped_key_size": len(encrypted.wrapped_key_envelope),
        }
    )
    return hashlib.sha256(b"a0.quarantine.archive.v1\x00" + manifest).hexdigest()


def _confirmation_digest(value: str) -> str:
    if type(value) is not str:
        raise PrivacyLifecycleDenied("typed confirmation must be text")
    return hashlib.sha256(
        b"a0.quarantine.deletion-confirmation.v1\x00" + value.encode("utf-8")
    ).hexdigest()


def _identity(kind: str, *parts: str) -> str:
    payload = canonical_json({"kind": kind, "parts": list(parts)})
    return f"{kind}_" + hashlib.sha256(b"a0.privacy-lifecycle.identity.v1\x00" + payload).hexdigest()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise PrivacyLifecycleDenied("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value: str) -> datetime:
    if type(value) is not str:
        raise PrivacyLifecycleDenied("receipt timestamp is invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PrivacyLifecycleDenied("receipt timestamp is invalid") from exc


__all__ = [
    "ChallengeConsumption",
    "DELETION_METHOD",
    "DeletionChallenge",
    "DeletionEvidenceRef",
    "DeletionIntent",
    "DeletionProgress",
    "DeletionReceipt",
    "ExportReceipt",
    "ExportWaiver",
    "GrantAuthorizer",
    "PrivacyLifecycleDenied",
    "PrivacyLifecycleError",
    "PrivacyLifecycleIntegrityError",
    "PrivacyLifecycleLedger",
    "PrivacyLifecycleStateError",
    "WAIVER_ACKNOWLEDGEMENT",
    "delete_quarantine",
    "export_quarantine",
    "issue_deletion_challenge",
    "issue_export_waiver",
    "resume_cryptographic_deletion",
]
