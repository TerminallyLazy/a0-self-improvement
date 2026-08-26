"""Governed, content-separated replay fixtures for the v3 safe store.

Fixture content belongs to an injected encrypted vault.  This module emits
strict typed metadata records and append-only eligibility events; it never
places fixture plaintext in a normal-store record and never infers authority
from an authenticated user or from the presence of an earlier grant.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .activation import ACTIVATION_REGISTRY
from .authority import (
    AuthorityAction,
    AuthorityClass,
    AuthorityDenied,
    AuthorityPurpose,
    GrantExpectation,
    IssuerProfile,
    VerifiedGrant,
    authorize_grant,
)
from .repository import DomainEvent
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    canonical_loads,
    schema_digest,
    strict_boolean,
    strict_enum,
    strict_integer,
    strict_list,
    strict_literal,
    strict_nullable,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


FIXTURE_CONTENT_SCHEMA_ID = "a0.replay-case-content.v1"
FIXTURE_FAMILY_SCHEMA_ID = "a0.fixture-family.v1"
FIXTURE_AUTHORITY_USE_SCHEMA_ID = "a0.fixture-authority-use.v1"
FIXTURE_DRAFT_SCHEMA_ID = "a0.fixture-draft.v1"
FIXTURE_REVIEW_SCHEMA_ID = "a0.fixture-review.v1"
FIXTURE_ADMISSION_SCHEMA_ID = "a0.fixture-admission-receipt.v1"
FIXTURE_ELIGIBILITY_SCHEMA_ID = "a0.fixture-eligibility-event.v1"
EXECUTION_PROFILE_SCHEMA_ID = "a0.execution-profile.v1"
ASSESSMENT_PROFILE_SCHEMA_ID = "a0.assessment-profile.v1"
FIXTURE_MANIFEST_SCHEMA_ID = "a0.fixture-manifest.v1"

PARTITIONS = ("training", "tuning", "certification_holdout")
ORIGINS = (
    "system_curated",
    "operator_authored",
    "deterministic_template",
    "licensed_public",
    "model_proposed",
    "quarantine_release",
)


class FixtureError(RuntimeError):
    """Base class for governed-fixture failures."""


class FixtureValidationError(FixtureError):
    """Raised when content, vault, or provenance is not exact and strict."""


class FixtureIneligible(FixtureError):
    """Raised when a withdrawn or incomplete fixture is selected or opened."""


@dataclass(frozen=True, slots=True)
class FixtureVaultReceipt:
    """Content-free proof returned by an encrypted fixture vault."""

    vault_ref: str
    encryption_profile_ref: str
    plaintext_digest: str
    ciphertext_digest: str
    plaintext_size: int


@runtime_checkable
class FixtureVault(Protocol):
    """Injected encrypted custody boundary; implementations own all plaintext.

    ``withdraw`` is a post-commit cleanup operation and must be idempotent for
    the same exact vault and fixture reference.  Durable eligibility, not
    physical cleanup, is the authority that denies future fixture use.
    """

    def seal(
        self, content: bytes, *, fixture_ref: str, plaintext_digest: str
    ) -> FixtureVaultReceipt: ...

    def open(
        self, vault_ref: str, *, fixture_ref: str, plaintext_digest: str
    ) -> bytes: ...

    def withdraw(self, vault_ref: str, *, fixture_ref: str) -> None: ...


@dataclass(frozen=True, slots=True)
class GrantAuthority:
    envelope: Mapping[str, Any]
    expectation: GrantExpectation
    revocations: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class ContentAccessAuthority:
    fixture_use: GrantAuthority
    content_session: GrantAuthority


@dataclass(frozen=True, slots=True)
class QuarantineReleaseBinding:
    release_receipt_ref: str
    release_receipt_digest: str


@dataclass(frozen=True, slots=True)
class FixtureDraft:
    family: TypedRecord
    authority_uses: tuple[TypedRecord, TypedRecord]
    record: TypedRecord


@dataclass(frozen=True, slots=True)
class FixtureReview:
    authority_uses: tuple[TypedRecord, TypedRecord]
    record: TypedRecord


@dataclass(frozen=True, slots=True)
class FixtureAdmission:
    fixture_use: TypedRecord
    receipt: TypedRecord
    eligibility: TypedRecord
    event: DomainEvent


@dataclass(frozen=True, slots=True)
class FixtureWithdrawal:
    eligibility: TypedRecord
    event: DomainEvent


@dataclass(frozen=True, slots=True)
class ManifestSelection:
    admission: FixtureAdmission
    draft: FixtureDraft


def _timestamp(value: Any, path: str) -> str:
    if type(value) is not str:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    return value


def _canonical_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise FixtureValidationError("now must be a timezone-aware datetime")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_CONTENT_VALIDATOR = strict_object(
    {
        "schema": strict_literal(FIXTURE_CONTENT_SCHEMA_ID),
        "input_message": strict_string(maximum=32_768),
        "initial_state": strict_list(strict_string(maximum=4_096), maximum=256),
        "tool_steps": strict_list(
            strict_object(
                {
                    "ordinal": strict_integer(minimum=0),
                    "tool_contract_ref": strict_string(maximum=128),
                    "argument_matcher_digest": validate_digest,
                    "response_digest": validate_digest,
                    "state_transition_ref": strict_string(maximum=128),
                }
            ),
            maximum=128,
        ),
        "expected_outcome": strict_list(strict_string(maximum=4_096), minimum=1, maximum=256),
        "execution_bounds": strict_object(
            {
                "max_turns": strict_integer(minimum=1, maximum=1_000),
                "max_tool_steps": strict_integer(minimum=0, maximum=1_000),
                "max_output_bytes": strict_integer(minimum=1, maximum=16_777_216),
            }
        ),
    }
)


_FAMILY_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("fixture_family"),
        "family_ref": strict_string(maximum=128),
        "source_lineage_digest": validate_digest,
        "partition_policy_ref": strict_string(maximum=128),
        "partition_weights": strict_object(
            {
                "training": strict_integer(minimum=1, maximum=1_000_000),
                "tuning": strict_integer(minimum=1, maximum=1_000_000),
                "certification_holdout": strict_integer(minimum=1, maximum=1_000_000),
            }
        ),
        "partition": strict_enum(PARTITIONS),
        "links": validate_links,
    }
)


_AUTHORITY_USE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("fixture_authority_use"),
        "grant_id": strict_string(maximum=128),
        "authority_class": strict_enum(
            (
                AuthorityClass.FIXTURE_USE_GRANT.value,
                AuthorityClass.OPERATOR_CONTENT_SESSION.value,
            )
        ),
        "issuer_id": strict_string(maximum=128),
        "subject_ref": strict_string(maximum=128),
        "context_ref": strict_string(maximum=128),
        "action": strict_enum(
            (
                AuthorityAction.FIXTURE_DRAFT.value,
                AuthorityAction.FIXTURE_REVIEW.value,
                AuthorityAction.FIXTURE_ADMIT.value,
                AuthorityAction.FIXTURE_WITHDRAW.value,
            )
        ),
        "purpose": strict_enum(
            (
                AuthorityPurpose.FIXTURE_AUTHORING.value,
                AuthorityPurpose.FIXTURE_REVIEW.value,
                AuthorityPurpose.FIXTURE_REPLAY.value,
            )
        ),
        "target_ref": strict_string(maximum=128),
        "target_revision": strict_integer(minimum=0),
        "expires_at": _timestamp,
        "session_nonce": strict_string(maximum=128),
        "links": validate_links,
    }
)


_DRAFT_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("fixture_draft"),
        "fixture_ref": strict_string(maximum=128),
        "revision": strict_integer(minimum=1),
        "author_ref": strict_string(maximum=128),
        "origin_class": strict_enum(ORIGINS),
        "source_attestation_digest": validate_digest,
        "content_schema_id": strict_literal(FIXTURE_CONTENT_SCHEMA_ID),
        "content_digest": validate_digest,
        "content_size": strict_integer(minimum=1, maximum=16_777_216),
        "vault_ref": strict_string(maximum=128),
        "encryption_profile_ref": strict_string(maximum=128),
        "ciphertext_digest": validate_digest,
        "family_ref": strict_string(maximum=128),
        "partition": strict_enum(PARTITIONS),
        "protected": strict_boolean(),
        "release_receipt_ref": strict_nullable(strict_string(maximum=128)),
        "release_receipt_digest": strict_nullable(validate_digest),
        "links": validate_links,
    }
)


_REVIEW_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("fixture_review"),
        "draft_id": strict_string(maximum=512),
        "draft_digest": validate_digest,
        "reviewer_ref": strict_string(maximum=128),
        "truth_review": strict_literal("passed"),
        "source_review": strict_literal("passed"),
        "redaction_review": strict_literal("passed"),
        "family_review": strict_literal("passed"),
        "reviewed_at": _timestamp,
        "links": validate_links,
    }
)


_ADMISSION_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("fixture_admission_receipt"),
        "draft_id": strict_string(maximum=512),
        "draft_digest": validate_digest,
        "review_id": strict_string(maximum=512),
        "review_digest": validate_digest,
        "family_id": strict_string(maximum=512),
        "family_digest": validate_digest,
        "partition": strict_enum(PARTITIONS),
        "fixture_use_grant_id": strict_string(maximum=128),
        "admitted_at": _timestamp,
        "release_receipt_ref": strict_nullable(strict_string(maximum=128)),
        "release_receipt_digest": strict_nullable(validate_digest),
        "links": validate_links,
    }
)


_ELIGIBILITY_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("fixture_eligibility_event"),
        "fixture_id": strict_string(maximum=512),
        "fixture_digest": validate_digest,
        "state": strict_enum(("admitted", "withdrawn")),
        "effective_at": _timestamp,
        "authority_ref": strict_string(maximum=128),
        "reason_code": strict_enum(("admission_complete", "authority_withdrawn")),
        "links": validate_links,
    }
)


_EXECUTION_PROFILE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("execution_profile"),
        "runtime_digest": validate_digest,
        "model_configuration_digest": validate_digest,
        "replay_adapter_digest": validate_digest,
        "behavior_configuration_digest": validate_digest,
        "links": validate_links,
    }
)


_ASSESSMENT_PROFILE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("assessment_profile"),
        "validator_profile_digest": validate_digest,
        "activation_policy_digest": validate_digest,
        "threshold_profile_digest": validate_digest,
        "freshness_policy_digest": validate_digest,
        "replay_seed": strict_integer(minimum=0),
        "required_buckets": strict_list(strict_string(maximum=128), minimum=1, maximum=256),
        "links": validate_links,
    }
)


_MANIFEST_ENTRY = strict_object(
    {
        "ordinal": strict_integer(minimum=0),
        "draft_id": strict_string(maximum=512),
        "draft_digest": validate_digest,
        "admission_id": strict_string(maximum=512),
        "admission_digest": validate_digest,
        "family_id": strict_string(maximum=512),
        "family_digest": validate_digest,
        "partition": strict_enum(PARTITIONS),
    }
)


_MANIFEST_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("fixture_manifest"),
        "selection_policy_ref": strict_string(maximum=128),
        "execution_profile_id": strict_string(maximum=512),
        "execution_profile_digest": validate_digest,
        "assessment_profile_id": strict_string(maximum=512),
        "assessment_profile_digest": validate_digest,
        "entries": strict_list(_MANIFEST_ENTRY, minimum=1, maximum=10_000),
        "links": validate_links,
    }
)


FIXTURE_REGISTRY = SchemaRegistry(
    (
        *ACTIVATION_REGISTRY.schemas.values(),
        RecordSchema(FIXTURE_FAMILY_SCHEMA_ID, "fixture_family", _FAMILY_VALIDATOR),
        RecordSchema(FIXTURE_AUTHORITY_USE_SCHEMA_ID, "fixture_authority_use", _AUTHORITY_USE_VALIDATOR),
        RecordSchema(FIXTURE_DRAFT_SCHEMA_ID, "fixture_draft", _DRAFT_VALIDATOR),
        RecordSchema(FIXTURE_REVIEW_SCHEMA_ID, "fixture_review", _REVIEW_VALIDATOR),
        RecordSchema(FIXTURE_ADMISSION_SCHEMA_ID, "fixture_admission_receipt", _ADMISSION_VALIDATOR),
        RecordSchema(FIXTURE_ELIGIBILITY_SCHEMA_ID, "fixture_eligibility_event", _ELIGIBILITY_VALIDATOR),
        RecordSchema(EXECUTION_PROFILE_SCHEMA_ID, "execution_profile", _EXECUTION_PROFILE_VALIDATOR),
        RecordSchema(ASSESSMENT_PROFILE_SCHEMA_ID, "assessment_profile", _ASSESSMENT_PROFILE_VALIDATOR),
        RecordSchema(FIXTURE_MANIFEST_SCHEMA_ID, "fixture_manifest", _MANIFEST_VALIDATOR),
    )
)


def deterministic_family_partition(
    family_ref: str,
    *,
    policy_ref: str,
    partition_secret: bytes,
    partition_weights: Mapping[str, int],
) -> str:
    """Assign a whole family to one stable partition under a versioned policy."""

    _bounded_ref(family_ref, "family_ref")
    _bounded_ref(policy_ref, "policy_ref")
    if type(partition_secret) is not bytes or len(partition_secret) < 16:
        raise FixtureValidationError("partition_secret must contain at least 16 bytes")
    if type(partition_weights) is not dict or set(partition_weights) != set(PARTITIONS):
        raise FixtureValidationError("partition_weights must explicitly cover every partition")
    admitted_weights: dict[str, int] = {}
    for partition in PARTITIONS:
        weight = partition_weights[partition]
        if type(weight) is not int or not 1 <= weight <= 1_000_000:
            raise FixtureValidationError("partition weights must be explicit positive integers")
        admitted_weights[partition] = weight
    digest = hmac.new(
        partition_secret,
        b"a0.fixture-family-partition.v1\x00"
        + policy_ref.encode("utf-8")
        + b"\x00"
        + family_ref.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    point = int.from_bytes(digest[:8], "big") % sum(admitted_weights.values())
    cumulative = 0
    for partition in PARTITIONS:
        cumulative += admitted_weights[partition]
        if point < cumulative:
            return partition
    raise AssertionError("partition weights did not cover the deterministic point")


class FixtureAuthority:
    """Single-process fixture coordinator producing persistence-ready records."""

    def __init__(
        self,
        *,
        secret_path: str | Path,
        issuer_profile: IssuerProfile | Mapping[str, Any],
        vault: FixtureVault,
        partition_secret: bytes,
        partition_policy_ref: str,
        partition_weights: Mapping[str, int],
        key_epoch: str = "fixture-v1",
    ) -> None:
        if not isinstance(vault, FixtureVault):
            raise FixtureValidationError("vault does not implement the encrypted FixtureVault contract")
        self._secret_path = Path(secret_path)
        self._issuer_profile = issuer_profile
        self._vault = vault
        self._partition_secret = bytes(partition_secret)
        self._partition_policy_ref = _bounded_ref(partition_policy_ref, "partition_policy_ref")
        if type(partition_weights) is not dict or set(partition_weights) != set(PARTITIONS):
            raise FixtureValidationError("partition_weights must explicitly cover every partition")
        self._partition_weights = {
            partition: partition_weights[partition] for partition in PARTITIONS
        }
        if any(
            type(weight) is not int or not 1 <= weight <= 1_000_000
            for weight in self._partition_weights.values()
        ):
            raise FixtureValidationError("partition weights must be explicit positive integers")
        self._key_epoch = _bounded_ref(key_epoch, "key_epoch")
        self._families: dict[str, TypedRecord] = {}
        self._drafts: dict[str, FixtureDraft] = {}
        self._content_owners: dict[str, str] = {}
        self._reviews: dict[str, FixtureReview] = {}
        self._admissions: dict[str, FixtureAdmission] = {}
        self._withdrawn: set[str] = set()
        self._vault_withdrawn: set[str] = set()

    def create_draft(
        self,
        *,
        fixture_ref: str,
        revision: int,
        family_ref: str,
        source_lineage_digest: str,
        author_ref: str,
        origin_class: str,
        source_attestation_digest: str,
        protected: bool,
        content: Mapping[str, Any],
        authority: ContentAccessAuthority,
        now: datetime,
        quarantine_release: QuarantineReleaseBinding | None = None,
    ) -> FixtureDraft:
        """Validate authority/content, seal plaintext, and emit an immutable draft."""

        fixture_ref = _bounded_ref(fixture_ref, "fixture_ref")
        family_ref = _bounded_ref(family_ref, "family_ref")
        author_ref = _bounded_ref(author_ref, "author_ref")
        if type(revision) is not int or revision < 1:
            raise FixtureValidationError("revision must be an integer >= 1")
        if origin_class not in ORIGINS:
            raise FixtureValidationError("origin_class is not admitted")
        if (origin_class == "quarantine_release") != (quarantine_release is not None):
            raise FixtureValidationError(
                "quarantine release origin requires one exact release receipt binding"
            )
        _require_digest(source_lineage_digest, "source_lineage_digest")
        _require_digest(source_attestation_digest, "source_attestation_digest")
        verified = self._authorize_content(
            authority,
            action=AuthorityAction.FIXTURE_DRAFT.value,
            purpose=AuthorityPurpose.FIXTURE_AUTHORING.value,
            target_ref=fixture_ref,
            target_revision=revision,
            now=now,
        )
        content_value = _CONTENT_VALIDATOR(dict(content), "content")
        content_bytes = canonical_json(content_value)
        content_digest = schema_digest(
            "fixture-content", FIXTURE_CONTENT_SCHEMA_ID, content_bytes
        )
        content_owner = self._content_owners.get(content_digest)
        if content_owner is not None and content_owner != fixture_ref:
            raise FixtureValidationError("exact duplicate fixture content is already governed")
        vault_receipt = self._vault.seal(
            content_bytes, fixture_ref=fixture_ref, plaintext_digest=content_digest
        )
        self._validate_vault_receipt(vault_receipt, content_digest, len(content_bytes))

        family = self._family(family_ref, source_lineage_digest)
        uses = tuple(self._authority_use(item) for item in verified)
        release_ref = quarantine_release.release_receipt_ref if quarantine_release else None
        release_digest = quarantine_release.release_receipt_digest if quarantine_release else None
        if quarantine_release:
            _bounded_ref(release_ref, "release_receipt_ref")
            _require_digest(release_digest, "release_receipt_digest")
        links = [_link("fixture_family", 0, family)]
        links.extend(_link("authority_use", index, use) for index, use in enumerate(uses))
        if quarantine_release:
            links.append(
                {
                    "role": "quarantine_release_receipt",
                    "ordinal": 0,
                    "target_id": release_ref,
                    "target_digest": release_digest,
                }
            )
        payload = {
            "record_type": "fixture_draft",
            "fixture_ref": fixture_ref,
            "revision": revision,
            "author_ref": author_ref,
            "origin_class": origin_class,
            "source_attestation_digest": source_attestation_digest,
            "content_schema_id": FIXTURE_CONTENT_SCHEMA_ID,
            "content_digest": content_digest,
            "content_size": len(content_bytes),
            "vault_ref": vault_receipt.vault_ref,
            "encryption_profile_ref": vault_receipt.encryption_profile_ref,
            "ciphertext_digest": vault_receipt.ciphertext_digest,
            "family_ref": family_ref,
            "partition": family.payload["partition"],
            "protected": protected,
            "release_receipt_ref": release_ref,
            "release_receipt_digest": release_digest,
            "links": links,
        }
        record = _record("fixture_draft", FIXTURE_DRAFT_SCHEMA_ID, payload, self._key_epoch)
        result = FixtureDraft(family=family, authority_uses=(uses[0], uses[1]), record=record)
        existing = self._drafts.get(record.record_id)
        if existing is not None and existing != result:
            raise FixtureValidationError("fixture draft identity collision")
        self._drafts[record.record_id] = result
        self._content_owners[content_digest] = fixture_ref
        return result

    def review(
        self,
        draft: FixtureDraft,
        *,
        reviewer_ref: str,
        authority: ContentAccessAuthority,
        now: datetime,
    ) -> FixtureReview:
        """Open exact content under dual authority and append independent review."""

        reviewer_ref = _bounded_ref(reviewer_ref, "reviewer_ref")
        author_ref = draft.record.payload["author_ref"]
        if hmac.compare_digest(reviewer_ref, author_ref):
            raise FixtureValidationError("fixture review must be independent of its author")
        self._require_current_draft(draft)
        verified = self._authorize_content(
            authority,
            action=AuthorityAction.FIXTURE_REVIEW.value,
            purpose=AuthorityPurpose.FIXTURE_REVIEW.value,
            target_ref=draft.record.record_id,
            target_revision=draft.record.payload["revision"],
            now=now,
        )
        self._open_and_verify(draft)
        uses = tuple(self._authority_use(item) for item in verified)
        payload = {
            "record_type": "fixture_review",
            "draft_id": draft.record.record_id,
            "draft_digest": draft.record.content_digest,
            "reviewer_ref": reviewer_ref,
            "truth_review": "passed",
            "source_review": "passed",
            "redaction_review": "passed",
            "family_review": "passed",
            "reviewed_at": _canonical_timestamp(now),
            "links": [
                _link("fixture_draft", 0, draft.record),
                _link("authority_use", 0, uses[0]),
                _link("authority_use", 1, uses[1]),
            ],
        }
        record = _record("fixture_review", FIXTURE_REVIEW_SCHEMA_ID, payload, self._key_epoch)
        result = FixtureReview(authority_uses=(uses[0], uses[1]), record=record)
        self._reviews[record.record_id] = result
        return result

    def admit(
        self,
        draft: FixtureDraft,
        review: FixtureReview,
        *,
        fixture_use: GrantAuthority,
        now: datetime,
    ) -> FixtureAdmission:
        """Admit one exact reviewed draft and append its initial eligibility event."""

        self._require_current_draft(draft)
        if review.record.payload["draft_id"] != draft.record.record_id:
            raise FixtureValidationError("review does not bind the exact fixture draft")
        verified = self._authorize_one(
            fixture_use,
            authority_class=AuthorityClass.FIXTURE_USE_GRANT.value,
            action=AuthorityAction.FIXTURE_ADMIT.value,
            purpose=AuthorityPurpose.FIXTURE_REPLAY.value,
            target_ref=draft.record.record_id,
            target_revision=draft.record.payload["revision"],
            now=now,
        )
        use = self._authority_use(verified)
        release_ref = draft.record.payload["release_receipt_ref"]
        release_digest = draft.record.payload["release_receipt_digest"]
        links = [
            _link("fixture_draft", 0, draft.record),
            _link("fixture_review", 0, review.record),
            _link("fixture_family", 0, draft.family),
            _link("authority_use", 0, use),
        ]
        if release_ref is not None:
            links.append(
                {
                    "role": "quarantine_release_receipt",
                    "ordinal": 0,
                    "target_id": release_ref,
                    "target_digest": release_digest,
                }
            )
        payload = {
            "record_type": "fixture_admission_receipt",
            "draft_id": draft.record.record_id,
            "draft_digest": draft.record.content_digest,
            "review_id": review.record.record_id,
            "review_digest": review.record.content_digest,
            "family_id": draft.family.record_id,
            "family_digest": draft.family.content_digest,
            "partition": draft.family.payload["partition"],
            "fixture_use_grant_id": verified.grant_id,
            "admitted_at": _canonical_timestamp(now),
            "release_receipt_ref": release_ref,
            "release_receipt_digest": release_digest,
            "links": links,
        }
        receipt = _record(
            "fixture_admission_receipt", FIXTURE_ADMISSION_SCHEMA_ID, payload, self._key_epoch
        )
        eligibility = self._eligibility(
            draft.record,
            state="admitted",
            effective_at=now,
            authority_ref=verified.grant_id,
            reason_code="admission_complete",
        )
        event = _domain_event(draft.record, eligibility, sequence=0, event_type="fixture_admitted", actor=verified.grant_id)
        admission = FixtureAdmission(use, receipt, eligibility, event)
        self._admissions[draft.record.record_id] = admission
        return admission

    def withdraw(
        self,
        draft: FixtureDraft,
        *,
        fixture_use: GrantAuthority,
        now: datetime,
    ) -> FixtureWithdrawal:
        """Withdraw future eligibility without changing any historical record."""

        self._require_current_draft(draft)
        if draft.record.record_id not in self._admissions:
            raise FixtureIneligible("only an admitted fixture can be withdrawn")
        if draft.record.record_id in self._withdrawn:
            raise FixtureIneligible("fixture authority was already withdrawn")
        verified = self._authorize_one(
            fixture_use,
            authority_class=AuthorityClass.FIXTURE_USE_GRANT.value,
            action=AuthorityAction.FIXTURE_WITHDRAW.value,
            purpose=AuthorityPurpose.FIXTURE_REPLAY.value,
            target_ref=draft.record.record_id,
            target_revision=draft.record.payload["revision"],
            now=now,
        )
        eligibility = self._eligibility(
            draft.record,
            state="withdrawn",
            effective_at=now,
            authority_ref=verified.grant_id,
            reason_code="authority_withdrawn",
        )
        event = _domain_event(
            draft.record,
            eligibility,
            sequence=1,
            event_type="fixture_withdrawn",
            actor=verified.grant_id,
        )
        self._withdrawn.add(draft.record.record_id)
        return FixtureWithdrawal(eligibility, event)

    def hydrate_draft(self, draft: FixtureDraft) -> FixtureDraft:
        """Admit one strictly verified durable draft into process-local state."""

        if type(draft) is not FixtureDraft or len(draft.authority_uses) != 2:
            raise FixtureValidationError("durable fixture draft has an invalid shape")
        family = _verified_record(draft.family, "fixture_family", FIXTURE_FAMILY_SCHEMA_ID)
        record = _verified_record(draft.record, "fixture_draft", FIXTURE_DRAFT_SCHEMA_ID)
        uses = tuple(
            _verified_record(item, "fixture_authority_use", FIXTURE_AUTHORITY_USE_SCHEMA_ID)
            for item in draft.authority_uses
        )
        release_ref = record.payload["release_receipt_ref"]
        release_digest = record.payload["release_receipt_digest"]
        release_count = 1 if release_ref is not None else 0
        if (
            record.payload["family_ref"] != family.payload["family_ref"]
            or record.payload["partition"] != family.payload["partition"]
            or bool(family.links)
            or any(bool(use.links) for use in uses)
            or len(record.links) != 3 + release_count
            or (release_ref is None) != (release_digest is None)
            or not _has_exact_link(record, "fixture_family", 0, family)
            or any(
                not _has_exact_link(record, "authority_use", ordinal, use)
                for ordinal, use in enumerate(uses)
            )
            or (
                release_ref is not None
                and not _has_identity_link(
                    record,
                    "quarantine_release_receipt",
                    0,
                    release_ref,
                    release_digest,
                )
            )
        ):
            raise FixtureValidationError("durable fixture draft lost an exact dependency")
        _require_authority_pair(
            uses,
            action=AuthorityAction.FIXTURE_DRAFT.value,
            purpose=AuthorityPurpose.FIXTURE_AUTHORING.value,
            target_ref=record.payload["fixture_ref"],
            target_revision=record.payload["revision"],
        )
        prior_family = self._families.get(family.payload["family_ref"])
        if prior_family is not None and prior_family != family:
            raise FixtureValidationError("durable fixture family identity was rebound")
        prior_owner = self._content_owners.get(record.payload["content_digest"])
        if prior_owner is not None and prior_owner != record.payload["fixture_ref"]:
            raise FixtureValidationError("durable fixture content has multiple owners")
        prior_draft = self._drafts.get(record.record_id)
        if prior_draft is not None and prior_draft != draft:
            raise FixtureValidationError("durable fixture draft identity was rebound")
        self._families[family.payload["family_ref"]] = family
        self._drafts[record.record_id] = draft
        self._content_owners[record.payload["content_digest"]] = record.payload[
            "fixture_ref"
        ]
        return draft

    def hydrate_review(self, draft: FixtureDraft, review: FixtureReview) -> FixtureReview:
        """Admit one strictly verified durable independent review."""

        self.hydrate_draft(draft)
        if type(review) is not FixtureReview or len(review.authority_uses) != 2:
            raise FixtureValidationError("durable fixture review has an invalid shape")
        record = _verified_record(review.record, "fixture_review", FIXTURE_REVIEW_SCHEMA_ID)
        uses = tuple(
            _verified_record(item, "fixture_authority_use", FIXTURE_AUTHORITY_USE_SCHEMA_ID)
            for item in review.authority_uses
        )
        if (
            record.payload["draft_id"] != draft.record.record_id
            or record.payload["draft_digest"] != draft.record.content_digest
            or record.payload["reviewer_ref"] == draft.record.payload["author_ref"]
            or any(bool(use.links) for use in uses)
            or len(record.links) != 3
            or not _has_exact_link(record, "fixture_draft", 0, draft.record)
            or any(
                not _has_exact_link(record, "authority_use", ordinal, use)
                for ordinal, use in enumerate(uses)
            )
        ):
            raise FixtureValidationError("durable fixture review lost an exact dependency")
        _require_authority_pair(
            uses,
            action=AuthorityAction.FIXTURE_REVIEW.value,
            purpose=AuthorityPurpose.FIXTURE_REVIEW.value,
            target_ref=draft.record.record_id,
            target_revision=draft.record.payload["revision"],
        )
        prior = self._reviews.get(record.record_id)
        if prior is not None and prior != review:
            raise FixtureValidationError("durable fixture review identity was rebound")
        self._reviews[record.record_id] = review
        return review

    def hydrate_admission(
        self,
        draft: FixtureDraft,
        review: FixtureReview,
        admission: FixtureAdmission,
    ) -> FixtureAdmission:
        """Admit a verified durable admission and its first ordered event."""

        self.hydrate_review(draft, review)
        if type(admission) is not FixtureAdmission:
            raise FixtureValidationError("durable fixture admission has an invalid shape")
        use = _verified_record(
            admission.fixture_use,
            "fixture_authority_use",
            FIXTURE_AUTHORITY_USE_SCHEMA_ID,
        )
        receipt = _verified_record(
            admission.receipt,
            "fixture_admission_receipt",
            FIXTURE_ADMISSION_SCHEMA_ID,
        )
        eligibility = _verified_record(
            admission.eligibility,
            "fixture_eligibility_event",
            FIXTURE_ELIGIBILITY_SCHEMA_ID,
        )
        event = admission.event
        release_ref = receipt.payload["release_receipt_ref"]
        release_digest = receipt.payload["release_receipt_digest"]
        release_count = 1 if release_ref is not None else 0
        if (
            receipt.payload["draft_id"] != draft.record.record_id
            or receipt.payload["draft_digest"] != draft.record.content_digest
            or receipt.payload["review_id"] != review.record.record_id
            or receipt.payload["review_digest"] != review.record.content_digest
            or receipt.payload["family_id"] != draft.family.record_id
            or receipt.payload["family_digest"] != draft.family.content_digest
            or receipt.payload["partition"] != draft.family.payload["partition"]
            or receipt.payload["fixture_use_grant_id"] != use.payload["grant_id"]
            or receipt.payload["release_receipt_ref"]
            != draft.record.payload["release_receipt_ref"]
            or receipt.payload["release_receipt_digest"]
            != draft.record.payload["release_receipt_digest"]
            or eligibility.payload["fixture_id"] != draft.record.record_id
            or eligibility.payload["fixture_digest"] != draft.record.content_digest
            or eligibility.payload["state"] != "admitted"
            or eligibility.payload["reason_code"] != "admission_complete"
            or bool(use.links)
            or len(receipt.links) != 4 + release_count
            or len(eligibility.links) != 1
            or (release_ref is None) != (release_digest is None)
            or eligibility.payload["authority_ref"] != use.payload["grant_id"]
            or use.payload["action"] != AuthorityAction.FIXTURE_ADMIT.value
            or use.payload["purpose"] != AuthorityPurpose.FIXTURE_REPLAY.value
            or use.payload["target_ref"] != draft.record.record_id
            or use.payload["target_revision"] != draft.record.payload["revision"]
            or not _has_exact_link(receipt, "fixture_draft", 0, draft.record)
            or not _has_exact_link(receipt, "fixture_review", 0, review.record)
            or not _has_exact_link(receipt, "fixture_family", 0, draft.family)
            or not _has_exact_link(receipt, "authority_use", 0, use)
            or not _has_exact_link(eligibility, "fixture_draft", 0, draft.record)
            or (
                release_ref is not None
                and not _has_identity_link(
                    receipt,
                    "quarantine_release_receipt",
                    0,
                    release_ref,
                    release_digest,
                )
            )
            or not _is_fixture_event(
                event,
                draft=draft.record,
                eligibility=eligibility,
                sequence=0,
                event_type="fixture_admitted",
            )
            or event.actor_authority_ref != eligibility.payload["authority_ref"]
        ):
            raise FixtureValidationError("durable fixture admission lost an exact dependency")
        prior = self._admissions.get(draft.record.record_id)
        if prior is not None and prior != admission:
            raise FixtureValidationError("durable fixture admission identity was rebound")
        self._admissions[draft.record.record_id] = admission
        return admission

    def hydrate_withdrawal(
        self, draft: FixtureDraft, withdrawal: FixtureWithdrawal
    ) -> FixtureWithdrawal:
        """Apply durable withdrawal state without performing vault cleanup."""

        self._require_current_draft(draft)
        if draft.record.record_id not in self._admissions:
            raise FixtureValidationError("durable withdrawal has no admitted fixture")
        if type(withdrawal) is not FixtureWithdrawal:
            raise FixtureValidationError("durable fixture withdrawal has an invalid shape")
        eligibility = _verified_record(
            withdrawal.eligibility,
            "fixture_eligibility_event",
            FIXTURE_ELIGIBILITY_SCHEMA_ID,
        )
        if (
            eligibility.payload["fixture_id"] != draft.record.record_id
            or eligibility.payload["fixture_digest"] != draft.record.content_digest
            or eligibility.payload["state"] != "withdrawn"
            or eligibility.payload["reason_code"] != "authority_withdrawn"
            or len(eligibility.links) != 1
            or not _has_exact_link(eligibility, "fixture_draft", 0, draft.record)
            or not _is_fixture_event(
                withdrawal.event,
                draft=draft.record,
                eligibility=eligibility,
                sequence=1,
                event_type="fixture_withdrawn",
            )
            or withdrawal.event.actor_authority_ref
            != eligibility.payload["authority_ref"]
        ):
            raise FixtureValidationError("durable fixture withdrawal lost an exact dependency")
        self._withdrawn.add(draft.record.record_id)
        return withdrawal

    def finalize_withdrawal(self, fixture_id: str) -> None:
        """Idempotently destroy vault content only after durable commit."""

        fixture_id = _bounded_ref(fixture_id, "fixture_id")
        draft = self._drafts.get(fixture_id)
        if draft is None or fixture_id not in self._withdrawn:
            raise FixtureIneligible("vault cleanup requires a durable withdrawn fixture")
        if fixture_id in self._vault_withdrawn:
            return
        self._vault.withdraw(
            draft.record.payload["vault_ref"],
            fixture_ref=draft.record.payload["fixture_ref"],
        )
        self._vault_withdrawn.add(fixture_id)

    def read_content(
        self,
        draft: FixtureDraft,
        *,
        authority: ContentAccessAuthority,
        action: str,
        purpose: str,
        now: datetime,
    ) -> Mapping[str, Any]:
        """Open exact content only under a current grant and current content session."""

        self._require_current_draft(draft)
        if draft.record.record_id in self._withdrawn:
            raise FixtureIneligible("fixture authority was withdrawn")
        self._authorize_content(
            authority,
            action=action,
            purpose=purpose,
            target_ref=draft.record.record_id,
            target_revision=draft.record.payload["revision"],
            now=now,
        )
        return canonical_loads(self._open_and_verify(draft))

    def build_manifest(
        self,
        selections: Sequence[ManifestSelection],
        *,
        selection_policy_ref: str,
        execution_profile: TypedRecord,
        assessment_profile: TypedRecord,
    ) -> TypedRecord:
        """Bind an ordered, eligible selection to exact evaluation profiles."""

        _bounded_ref(selection_policy_ref, "selection_policy_ref")
        if not selections:
            raise FixtureValidationError("fixture manifest requires at least one selection")
        entries: list[dict[str, Any]] = []
        links = [
            _link("execution_profile", 0, execution_profile),
            _link("assessment_profile", 0, assessment_profile),
        ]
        seen: set[str] = set()
        for ordinal, selection in enumerate(selections):
            draft = selection.draft
            self._require_current_draft(draft)
            if draft.record.record_id in self._withdrawn:
                raise FixtureIneligible("withdrawn fixture cannot enter a new manifest")
            if self._admissions.get(draft.record.record_id) != selection.admission:
                raise FixtureIneligible("selection is not the current exact admission")
            if draft.record.record_id in seen:
                raise FixtureValidationError("manifest repeats an exact fixture")
            seen.add(draft.record.record_id)
            entries.append(
                {
                    "ordinal": ordinal,
                    "draft_id": draft.record.record_id,
                    "draft_digest": draft.record.content_digest,
                    "admission_id": selection.admission.receipt.record_id,
                    "admission_digest": selection.admission.receipt.content_digest,
                    "family_id": draft.family.record_id,
                    "family_digest": draft.family.content_digest,
                    "partition": draft.family.payload["partition"],
                }
            )
            links.extend(
                (
                    _link("fixture_draft", ordinal, draft.record),
                    _link("fixture_admission", ordinal, selection.admission.receipt),
                    _link("fixture_family", ordinal, draft.family),
                )
            )
        payload = {
            "record_type": "fixture_manifest",
            "selection_policy_ref": selection_policy_ref,
            "execution_profile_id": execution_profile.record_id,
            "execution_profile_digest": execution_profile.content_digest,
            "assessment_profile_id": assessment_profile.record_id,
            "assessment_profile_digest": assessment_profile.content_digest,
            "entries": entries,
            "links": links,
        }
        return _record("fixture_manifest", FIXTURE_MANIFEST_SCHEMA_ID, payload, self._key_epoch)

    def manifest_is_stale(self, manifest: TypedRecord) -> bool:
        if manifest.record_kind != "fixture_manifest":
            raise FixtureValidationError("record is not a fixture manifest")
        return any(entry["draft_id"] in self._withdrawn for entry in manifest.payload["entries"])

    def _family(self, family_ref: str, source_lineage_digest: str) -> TypedRecord:
        partition = deterministic_family_partition(
            family_ref,
            policy_ref=self._partition_policy_ref,
            partition_secret=self._partition_secret,
            partition_weights=self._partition_weights,
        )
        payload = {
            "record_type": "fixture_family",
            "family_ref": family_ref,
            "source_lineage_digest": source_lineage_digest,
            "partition_policy_ref": self._partition_policy_ref,
            "partition_weights": self._partition_weights,
            "partition": partition,
            "links": [],
        }
        record = _record("fixture_family", FIXTURE_FAMILY_SCHEMA_ID, payload, self._key_epoch)
        prior = self._families.get(family_ref)
        if prior is not None and prior != record:
            raise FixtureValidationError("fixture family identity cannot be split or rebound")
        self._families[family_ref] = record
        return record

    def _authorize_content(
        self,
        authority: ContentAccessAuthority,
        *,
        action: str,
        purpose: str,
        target_ref: str,
        target_revision: int,
        now: datetime,
    ) -> tuple[VerifiedGrant, VerifiedGrant]:
        fixture_grant = self._authorize_one(
            authority.fixture_use,
            authority_class=AuthorityClass.FIXTURE_USE_GRANT.value,
            action=action,
            purpose=purpose,
            target_ref=target_ref,
            target_revision=target_revision,
            now=now,
        )
        content_session = self._authorize_one(
            authority.content_session,
            authority_class=AuthorityClass.OPERATOR_CONTENT_SESSION.value,
            action=action,
            purpose=purpose,
            target_ref=target_ref,
            target_revision=target_revision,
            now=now,
        )
        shared = (
            "issuer_id",
            "subject_ref",
            "context_ref",
            "action",
            "purpose",
            "target_ref",
            "target_revision",
            "session_nonce",
        )
        if any(getattr(fixture_grant, key) != getattr(content_session, key) for key in shared):
            raise AuthorityDenied("fixture grant and content session do not bind the same access")
        return fixture_grant, content_session

    def _authorize_one(
        self,
        authority: GrantAuthority,
        *,
        authority_class: str,
        action: str,
        purpose: str,
        target_ref: str,
        target_revision: int,
        now: datetime,
    ) -> VerifiedGrant:
        expected = authority.expectation
        required = {
            "authority_class": authority_class,
            "action": action,
            "purpose": purpose,
            "target_ref": target_ref,
            "target_revision": target_revision,
        }
        if any(getattr(expected, key) != value for key, value in required.items()):
            raise AuthorityDenied("authority expectation does not describe the exact fixture operation")
        return authorize_grant(
            authority.envelope,
            self._secret_path,
            self._issuer_profile,
            expected,
            now=now,
            revocations=authority.revocations,
        )

    def _authority_use(self, grant: VerifiedGrant) -> TypedRecord:
        payload = {
            "record_type": "fixture_authority_use",
            "grant_id": grant.grant_id,
            "authority_class": grant.authority_class,
            "issuer_id": grant.issuer_id,
            "subject_ref": grant.subject_ref,
            "context_ref": grant.context_ref,
            "action": grant.action,
            "purpose": grant.purpose,
            "target_ref": grant.target_ref,
            "target_revision": grant.target_revision,
            "expires_at": _canonical_timestamp(grant.expires_at),
            "session_nonce": grant.session_nonce,
            "links": [],
        }
        return _record(
            "fixture_authority_use", FIXTURE_AUTHORITY_USE_SCHEMA_ID, payload, self._key_epoch
        )

    def _eligibility(
        self,
        draft: TypedRecord,
        *,
        state: str,
        effective_at: datetime,
        authority_ref: str,
        reason_code: str,
    ) -> TypedRecord:
        payload = {
            "record_type": "fixture_eligibility_event",
            "fixture_id": draft.record_id,
            "fixture_digest": draft.content_digest,
            "state": state,
            "effective_at": _canonical_timestamp(effective_at),
            "authority_ref": authority_ref,
            "reason_code": reason_code,
            "links": [_link("fixture_draft", 0, draft)],
        }
        return _record(
            "fixture_eligibility_event", FIXTURE_ELIGIBILITY_SCHEMA_ID, payload, self._key_epoch
        )

    def _validate_vault_receipt(
        self, receipt: FixtureVaultReceipt, expected_digest: str, expected_size: int
    ) -> None:
        if type(receipt) is not FixtureVaultReceipt:
            raise FixtureValidationError("vault did not return a strict FixtureVaultReceipt")
        _bounded_ref(receipt.vault_ref, "vault_ref")
        _bounded_ref(receipt.encryption_profile_ref, "encryption_profile_ref")
        _require_digest(receipt.ciphertext_digest, "ciphertext_digest")
        if receipt.plaintext_digest != expected_digest or receipt.plaintext_size != expected_size:
            raise FixtureValidationError("vault receipt does not bind the exact fixture content")

    def _open_and_verify(self, draft: FixtureDraft) -> bytes:
        payload = draft.record.payload
        content = self._vault.open(
            payload["vault_ref"],
            fixture_ref=payload["fixture_ref"],
            plaintext_digest=payload["content_digest"],
        )
        if type(content) is not bytes:
            raise FixtureValidationError("vault returned non-byte fixture content")
        actual = schema_digest("fixture-content", FIXTURE_CONTENT_SCHEMA_ID, content)
        if not hmac.compare_digest(actual, payload["content_digest"]):
            raise FixtureValidationError("vault content digest does not match fixture metadata")
        admitted = _CONTENT_VALIDATOR(canonical_loads(content), "content")
        if canonical_json(admitted) != content:
            raise FixtureValidationError("vault content is not exact canonical fixture content")
        return content

    def _require_current_draft(self, draft: FixtureDraft) -> None:
        if type(draft) is not FixtureDraft or self._drafts.get(draft.record.record_id) != draft:
            raise FixtureValidationError("fixture draft is not owned by this authority")


def execution_profile(
    *,
    runtime_digest: str,
    model_configuration_digest: str,
    replay_adapter_digest: str,
    behavior_configuration_digest: str,
    key_epoch: str = "fixture-v1",
) -> TypedRecord:
    payload = {
        "record_type": "execution_profile",
        "runtime_digest": runtime_digest,
        "model_configuration_digest": model_configuration_digest,
        "replay_adapter_digest": replay_adapter_digest,
        "behavior_configuration_digest": behavior_configuration_digest,
        "links": [],
    }
    return _record("execution_profile", EXECUTION_PROFILE_SCHEMA_ID, payload, key_epoch)


def assessment_profile(
    *,
    validator_profile_digest: str,
    activation_policy_digest: str,
    threshold_profile_digest: str,
    freshness_policy_digest: str,
    replay_seed: int,
    required_buckets: Sequence[str],
    key_epoch: str = "fixture-v1",
) -> TypedRecord:
    payload = {
        "record_type": "assessment_profile",
        "validator_profile_digest": validator_profile_digest,
        "activation_policy_digest": activation_policy_digest,
        "threshold_profile_digest": threshold_profile_digest,
        "freshness_policy_digest": freshness_policy_digest,
        "replay_seed": replay_seed,
        "required_buckets": list(required_buckets),
        "links": [],
    }
    return _record("assessment_profile", ASSESSMENT_PROFILE_SCHEMA_ID, payload, key_epoch)


def _record(kind: str, schema_id: str, payload: Mapping[str, Any], key_epoch: str) -> TypedRecord:
    encoded = canonical_json(dict(payload))
    record_id = kind + "_" + schema_digest("record-identity", schema_id, encoded)
    return build_typed_record(
        record_id=record_id,
        context_ref="fixture-authority",
        record_kind=kind,
        schema_id=schema_id,
        payload=payload,
        key_epoch=key_epoch,
        registry=FIXTURE_REGISTRY,
    )


def _link(role: str, ordinal: int, record: TypedRecord) -> dict[str, Any]:
    return {
        "role": role,
        "ordinal": ordinal,
        "target_id": record.record_id,
        "target_digest": record.content_digest,
    }


def _domain_event(
    draft: TypedRecord,
    eligibility: TypedRecord,
    *,
    sequence: int,
    event_type: str,
    actor: str,
) -> DomainEvent:
    identity = canonical_json(
        {
            "draft_id": draft.record_id,
            "eligibility_id": eligibility.record_id,
            "sequence": sequence,
            "event_type": event_type,
        }
    )
    return DomainEvent(
        event_id="fixture_event_" + hashlib.sha256(identity).hexdigest(),
        subject_id=draft.record_id,
        subject_kind="fixture_draft",
        sequence=sequence,
        event_type=event_type,
        payload_record_id=eligibility.record_id,
        actor_authority_ref=actor,
    )


def _verified_record(record: Any, kind: str, schema_id: str) -> TypedRecord:
    if (
        type(record) is not TypedRecord
        or record.record_kind != kind
        or record.schema_id != schema_id
    ):
        raise FixtureValidationError(f"durable {kind} record has the wrong exact type")
    try:
        record.verify(FIXTURE_REGISTRY)
    except ValueError as exc:
        raise FixtureValidationError(f"durable {kind} record failed verification") from exc
    return record


def _has_exact_link(
    source: TypedRecord,
    role: str,
    ordinal: int,
    target: TypedRecord,
) -> bool:
    return any(
        link.role == role
        and link.ordinal == ordinal
        and link.target_id == target.record_id
        and link.target_digest == target.content_digest
        for link in source.links
    )


def _has_identity_link(
    source: TypedRecord,
    role: str,
    ordinal: int,
    target_id: str,
    target_digest: str,
) -> bool:
    return any(
        link.role == role
        and link.ordinal == ordinal
        and link.target_id == target_id
        and link.target_digest == target_digest
        for link in source.links
    )


def _require_authority_pair(
    uses: tuple[TypedRecord, TypedRecord],
    *,
    action: str,
    purpose: str,
    target_ref: str,
    target_revision: int,
) -> None:
    if [item.payload["authority_class"] for item in uses] != [
        AuthorityClass.FIXTURE_USE_GRANT.value,
        AuthorityClass.OPERATOR_CONTENT_SESSION.value,
    ]:
        raise FixtureValidationError("durable fixture authority pair has wrong classes")
    shared = (
        "issuer_id",
        "subject_ref",
        "context_ref",
        "action",
        "purpose",
        "target_ref",
        "target_revision",
        "session_nonce",
    )
    if any(uses[0].payload[field] != uses[1].payload[field] for field in shared):
        raise FixtureValidationError("durable fixture authority pair does not bind one access")
    expected = {
        "action": action,
        "purpose": purpose,
        "target_ref": target_ref,
        "target_revision": target_revision,
    }
    if any(uses[0].payload[field] != value for field, value in expected.items()):
        raise FixtureValidationError("durable fixture authority pair binds another operation")


def _is_fixture_event(
    event: Any,
    *,
    draft: TypedRecord,
    eligibility: TypedRecord,
    sequence: int,
    event_type: str,
) -> bool:
    if (
        type(event) is not DomainEvent
        or type(event.actor_authority_ref) is not str
        or not event.actor_authority_ref
    ):
        return False
    return event == _domain_event(
        draft,
        eligibility,
        sequence=sequence,
        event_type=event_type,
        actor=event.actor_authority_ref,
    )


def _bounded_ref(value: Any, name: str) -> str:
    if type(value) is not str or not value or len(value) > 128:
        raise FixtureValidationError(f"{name} must be a bounded opaque reference")
    if any(not (character.isalnum() or character in "._:-") for character in value):
        raise FixtureValidationError(f"{name} must be a bounded opaque reference")
    return value


def _require_digest(value: Any, name: str) -> str:
    try:
        return validate_digest(value, name)
    except SchemaValidationError as exc:
        raise FixtureValidationError(str(exc)) from exc


__all__ = [name for name in globals() if not name.startswith("_")]
