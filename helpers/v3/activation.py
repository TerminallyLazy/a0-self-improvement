"""Authorized, atomic initialization of the inert v3 Genesis profile.

This module is the only Slice 1 write coordinator.  Runtime composition and
status projections deliberately receive only :class:`V3Reader` and cannot
reach this API.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifacts import (
    DEFAULT_REGISTRY,
    activation_profile,
    null_guidance_artifact,
    null_prompt_patch_artifact,
)
from .authority import (
    AuthorityAction,
    AuthorityClass,
    AuthorityDenied,
    AuthorityPurpose,
    AuthorityUnavailable,
    GrantExpectation,
    IssuerProfile,
    VerifiedGrant,
    authorize_grant,
    digest_idempotency_key,
)
from .opaque import opaque_reference
from .repository import (
    ActivationScope,
    DomainEvent,
    IntegrityFailure,
    OperatorCommand,
    RevisionConflict,
    V3Repository,
)
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    schema_digest,
    strict_enum,
    strict_integer,
    strict_list,
    strict_literal,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)


GENESIS_COMMAND_SCHEMA_ID = "a0.self-improvement.initialize-genesis-command.v1"
AUTHORITY_GRANT_USE_SCHEMA_ID = "a0.self-improvement.authority-grant-use.v1"
ACTIVATION_RECEIPT_SCHEMA_ID = "a0.self-improvement.activation-receipt.v1"
OPERATOR_MUTATION_RECEIPT_SCHEMA_ID = (
    "a0.self-improvement.operator-mutation-receipt.v1"
)

GENESIS_REASON_CODES = frozenset(
    {"operator_requested", "recovery_requested", "automatic_project_enrollment"}
)

_ACTION = AuthorityAction.INITIALIZE_GENESIS.value
_PURPOSE = AuthorityPurpose.GENESIS.value
_AUTHORITY_CLASS = AuthorityClass.OPERATOR_AUTHORITY_GRANT.value


def _timestamp(value: Any, path: str) -> str:
    if type(value) is not str:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise SchemaValidationError(f"{path} must be a canonical UTC timestamp")
    return value


def _no_links(value: Any, path: str) -> list[dict[str, Any]]:
    links = validate_links(value, path)
    if links:
        raise SchemaValidationError(f"{path} must be empty")
    return links


_GRANT_USE_VALIDATOR = strict_object(
    {
        "record_type": strict_literal("authority_grant_use"),
        "grant_id": strict_string(maximum=128),
        "authority_class": strict_literal(_AUTHORITY_CLASS),
        "issuer_id": strict_string(maximum=128),
        "key_epoch": strict_integer(minimum=1),
        "subject_ref": strict_string(maximum=128),
        "context_ref": strict_string(maximum=128),
        "action": strict_literal(_ACTION),
        "purpose": strict_literal(_PURPOSE),
        "target_ref": strict_string(maximum=128),
        "target_revision": strict_literal(0),
        "issued_at": _timestamp,
        "expires_at": _timestamp,
        "idempotency_key_digest": validate_digest,
        "session_nonce": strict_string(maximum=128),
        "links": _no_links,
    }
)


def _activation_receipt(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "receipt_type": strict_literal("genesis_activation"),
            "action": strict_literal(_ACTION),
            "context_ref": strict_string(maximum=128),
            "target_ref": strict_string(maximum=128),
            "observed_revision": strict_literal(0),
            "resulting_revision": strict_literal(0),
            "mode": strict_literal("normal"),
            "profile_id": strict_string(maximum=512),
            "profile_digest": validate_digest,
            "authority_ref": strict_string(maximum=128),
            "authority_record_id": strict_string(maximum=512),
            "authority_record_digest": validate_digest,
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "reason_codes": strict_list(
                strict_literal("genesis_initialized"), minimum=1, maximum=1
            ),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        {
            "role": "activated_profile",
            "ordinal": 0,
            "target_id": payload["profile_id"],
            "target_digest": payload["profile_digest"],
        },
        {
            "role": "authority_grant_use",
            "ordinal": 0,
            "target_id": payload["authority_record_id"],
            "target_digest": payload["authority_record_digest"],
        },
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact activation inputs")
    return payload


def _mutation_receipt(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "receipt_type": strict_literal("operator_mutation"),
            "accepted": strict_literal(True),
            "action": strict_literal(_ACTION),
            "context_ref": strict_string(maximum=128),
            "target_ref": strict_string(maximum=128),
            "observed_revision": strict_literal(0),
            "resulting_revision": strict_literal(0),
            "issuer_ref": strict_string(maximum=128),
            "subject_ref": strict_string(maximum=128),
            "authority_ref": strict_string(maximum=128),
            "activation_receipt_id": strict_string(maximum=512),
            "activation_receipt_digest": validate_digest,
            "authority_record_id": strict_string(maximum=512),
            "authority_record_digest": validate_digest,
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "reason_codes": strict_list(
                strict_literal("genesis_initialized"), minimum=1, maximum=1
            ),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        {
            "role": "activation_receipt",
            "ordinal": 0,
            "target_id": payload["activation_receipt_id"],
            "target_digest": payload["activation_receipt_digest"],
        },
        {
            "role": "authority_grant_use",
            "ordinal": 0,
            "target_id": payload["authority_record_id"],
            "target_digest": payload["authority_record_digest"],
        },
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the exact mutation inputs")
    return payload


ACTIVATION_REGISTRY = SchemaRegistry(
    (
        *DEFAULT_REGISTRY.schemas.values(),
        RecordSchema(
            schema_id=AUTHORITY_GRANT_USE_SCHEMA_ID,
            record_kind="authority_grant_use",
            payload_validator=_GRANT_USE_VALIDATOR,
        ),
        RecordSchema(
            schema_id=ACTIVATION_RECEIPT_SCHEMA_ID,
            record_kind="activation_receipt",
            payload_validator=_activation_receipt,
        ),
        RecordSchema(
            schema_id=OPERATOR_MUTATION_RECEIPT_SCHEMA_ID,
            record_kind="operator_mutation_receipt",
            payload_validator=_mutation_receipt,
        ),
    )
)


@dataclass(frozen=True, slots=True)
class GenesisCommand:
    """Exact local operator intent required for one Genesis CAS."""

    subject_ref: str
    context_ref: str
    target_ref: str
    idempotency_key: str | bytes
    session_nonce: str
    authority_expires_at: datetime
    expected_revision: int = 0
    reason_code: str = "operator_requested"


@dataclass(frozen=True, slots=True)
class GenesisResult:
    scope: ActivationScope
    activation_receipt: TypedRecord
    mutation_receipt: TypedRecord
    command: OperatorCommand
    replayed: bool


def _canonical_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SchemaValidationError("authority_expires_at must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical_request(
    command: GenesisCommand,
    *,
    issuer_ref: str,
    authority_ref: str,
    idempotency_key_digest: str,
) -> bytes:
    payload = strict_object(
        {
            "schema": strict_literal(GENESIS_COMMAND_SCHEMA_ID),
            "action": strict_literal(_ACTION),
            "purpose": strict_literal(_PURPOSE),
            "issuer_ref": strict_string(maximum=128),
            "subject_ref": strict_string(maximum=128),
            "context_ref": strict_string(maximum=128),
            "target_ref": strict_string(maximum=128),
            "expected_revision": strict_literal(0),
            "idempotency_key_digest": validate_digest,
            "session_nonce": strict_string(maximum=128),
            "authority_ref": strict_string(maximum=128),
            "authority_expires_at": _timestamp,
            "reason_code": strict_enum(GENESIS_REASON_CODES),
        }
    )(
        {
            "schema": GENESIS_COMMAND_SCHEMA_ID,
            "action": _ACTION,
            "purpose": _PURPOSE,
            "issuer_ref": issuer_ref,
            "subject_ref": command.subject_ref,
            "context_ref": command.context_ref,
            "target_ref": command.target_ref,
            "expected_revision": command.expected_revision,
            "idempotency_key_digest": idempotency_key_digest,
            "session_nonce": command.session_nonce,
            "authority_ref": authority_ref,
            "authority_expires_at": _canonical_timestamp(command.authority_expires_at),
            "reason_code": command.reason_code,
        },
        "request",
    )
    return canonical_json(payload)


def _record_id(
    opaque_key: bytes,
    *,
    key_epoch: str,
    purpose: str,
    context_ref: str,
    request_digest: str,
) -> str:
    return opaque_reference(
        opaque_key,
        key_epoch=key_epoch,
        purpose=purpose,
        context_ref=context_ref,
        identity={"canonical_request_digest": request_digest},
    )


def _grant_use_record(
    grant: VerifiedGrant,
    *,
    record_id: str,
    key_epoch: str,
) -> TypedRecord:
    payload = grant.to_record()
    payload.update({"record_type": "authority_grant_use", "links": []})
    return build_typed_record(
        record_id=record_id,
        context_ref=grant.context_ref,
        record_kind="authority_grant_use",
        schema_id=AUTHORITY_GRANT_USE_SCHEMA_ID,
        payload=payload,
        key_epoch=key_epoch,
        registry=ACTIVATION_REGISTRY,
    )


def initialize_genesis(
    repository: V3Repository,
    *,
    command: GenesisCommand,
    authority_envelope: Mapping[str, Any] | None,
    authority_secret_path: str | Path,
    issuer_profile: IssuerProfile | Mapping[str, Any] | None,
    opaque_key: bytes,
    opaque_key_epoch: str,
    now: datetime,
    revocations: Iterable[Mapping[str, Any]] = (),
) -> GenesisResult:
    """Authorize and atomically establish the exact inert revision-zero scope.

    The caller must explicitly create/open ``repository`` with
    :data:`ACTIVATION_REGISTRY`.  This function never creates a store, issuer,
    grant, context, worker, or runtime state implicitly.
    """

    if issuer_profile is None:
        raise AuthorityUnavailable("local authority issuer profile is required")
    if authority_envelope is None:
        raise AuthorityDenied("explicit operator authority grant is required")

    idempotency_digest = digest_idempotency_key(command.idempotency_key)
    profile = (
        issuer_profile
        if isinstance(issuer_profile, IssuerProfile)
        else IssuerProfile.from_record(issuer_profile)
    )
    verified = authorize_grant(
        authority_envelope,
        authority_secret_path,
        profile,
        GrantExpectation(
            authority_class=_AUTHORITY_CLASS,
            issuer_id=profile.issuer_id,
            subject_ref=command.subject_ref,
            context_ref=command.context_ref,
            action=_ACTION,
            purpose=_PURPOSE,
            target_ref=command.target_ref,
            target_revision=command.expected_revision,
            expires_at=command.authority_expires_at,
            idempotency_key_digest=idempotency_digest,
            session_nonce=command.session_nonce,
        ),
        now=now,
        revocations=revocations,
    )
    request_bytes = _canonical_request(
        command,
        issuer_ref=verified.issuer_id,
        authority_ref=verified.grant_id,
        idempotency_key_digest=idempotency_digest,
    )
    request_digest = schema_digest(
        "operator-request", GENESIS_COMMAND_SCHEMA_ID, request_bytes
    )

    def identity(purpose: str) -> str:
        return _record_id(
            opaque_key,
            key_epoch=opaque_key_epoch,
            purpose=purpose,
            context_ref=command.context_ref,
            request_digest=request_digest,
        )

    guidance = null_guidance_artifact()
    prompt_patch = null_prompt_patch_artifact()
    activation_profile_record = activation_profile(
        record_id=identity("genesis-activation-profile"),
        context_ref=command.context_ref,
        guidance_artifact=guidance,
        prompt_patch_artifact=prompt_patch,
        key_epoch=opaque_key_epoch,
    )
    grant_use = _grant_use_record(
        verified,
        record_id=identity("genesis-authority-grant-use"),
        key_epoch=opaque_key_epoch,
    )
    activation_receipt = build_typed_record(
        record_id=identity("genesis-activation-receipt"),
        context_ref=command.context_ref,
        record_kind="activation_receipt",
        schema_id=ACTIVATION_RECEIPT_SCHEMA_ID,
        payload={
            "receipt_type": "genesis_activation",
            "action": _ACTION,
            "context_ref": command.context_ref,
            "target_ref": command.target_ref,
            "observed_revision": 0,
            "resulting_revision": 0,
            "mode": "normal",
            "profile_id": activation_profile_record.record_id,
            "profile_digest": activation_profile_record.content_digest,
            "authority_ref": verified.grant_id,
            "authority_record_id": grant_use.record_id,
            "authority_record_digest": grant_use.content_digest,
            "idempotency_key_digest": idempotency_digest,
            "request_digest": request_digest,
            "reason_codes": ["genesis_initialized"],
            "links": [
                {
                    "role": "activated_profile",
                    "ordinal": 0,
                    "target_id": activation_profile_record.record_id,
                    "target_digest": activation_profile_record.content_digest,
                },
                {
                    "role": "authority_grant_use",
                    "ordinal": 0,
                    "target_id": grant_use.record_id,
                    "target_digest": grant_use.content_digest,
                },
            ],
        },
        key_epoch=opaque_key_epoch,
        registry=ACTIVATION_REGISTRY,
    )
    mutation_receipt = build_typed_record(
        record_id=identity("genesis-operator-mutation-receipt"),
        context_ref=command.context_ref,
        record_kind="operator_mutation_receipt",
        schema_id=OPERATOR_MUTATION_RECEIPT_SCHEMA_ID,
        payload={
            "receipt_type": "operator_mutation",
            "accepted": True,
            "action": _ACTION,
            "context_ref": command.context_ref,
            "target_ref": command.target_ref,
            "observed_revision": 0,
            "resulting_revision": 0,
            "issuer_ref": verified.issuer_id,
            "subject_ref": verified.subject_ref,
            "authority_ref": verified.grant_id,
            "activation_receipt_id": activation_receipt.record_id,
            "activation_receipt_digest": activation_receipt.content_digest,
            "authority_record_id": grant_use.record_id,
            "authority_record_digest": grant_use.content_digest,
            "idempotency_key_digest": idempotency_digest,
            "request_digest": request_digest,
            "reason_codes": ["genesis_initialized"],
            "links": [
                {
                    "role": "activation_receipt",
                    "ordinal": 0,
                    "target_id": activation_receipt.record_id,
                    "target_digest": activation_receipt.content_digest,
                },
                {
                    "role": "authority_grant_use",
                    "ordinal": 0,
                    "target_id": grant_use.record_id,
                    "target_digest": grant_use.content_digest,
                },
            ],
        },
        key_epoch=opaque_key_epoch,
        registry=ACTIVATION_REGISTRY,
    )
    operator_command = OperatorCommand(
        command_id=identity("genesis-operator-command"),
        issuer_ref=verified.issuer_id,
        subject_ref=verified.subject_ref,
        context_ref=verified.context_ref,
        action=_ACTION,
        idempotency_key_digest=idempotency_digest,
        request_digest=request_digest,
        observed_revision=0,
        state="accepted",
        mutation_receipt_id=mutation_receipt.record_id,
    )
    event = DomainEvent(
        event_id=identity("genesis-domain-event"),
        subject_id=activation_profile_record.record_id,
        subject_kind="activation_profile",
        sequence=0,
        event_type="genesis_initialized",
        payload_record_id=activation_receipt.record_id,
        actor_authority_ref=verified.grant_id,
    )

    with repository.transaction() as transaction:
        transaction.insert_record(guidance)
        transaction.insert_record(prompt_patch)
        profile_result = transaction.insert_record(activation_profile_record).record
        transaction.insert_record(grant_use)
        activation_result = transaction.insert_record(activation_receipt).record
        mutation_result = transaction.insert_record(mutation_receipt).record
        admission = transaction.admit_command(operator_command)

        if admission.replayed:
            scope = transaction.get_activation_scope(command.context_ref)
            if (
                scope is None
                or scope.current_profile_id != profile_result.record_id
                or scope.current_profile_digest != profile_result.content_digest
                or scope.scope_revision != 0
                or scope.mode != "normal"
            ):
                raise IntegrityFailure("Genesis command replay does not match its activation scope")
            return GenesisResult(
                scope=scope,
                activation_receipt=activation_result,
                mutation_receipt=mutation_result,
                command=admission.command,
                replayed=True,
            )

        if transaction.get_activation_scope(command.context_ref) is not None:
            raise RevisionConflict("Genesis requires an absent revision-zero activation scope")
        transaction.append_event(event)
        scope = transaction.initialize_activation_scope(
            context_ref=command.context_ref,
            profile_id=profile_result.record_id,
            profile_digest=profile_result.content_digest,
            mode="normal",
        )
        return GenesisResult(
            scope=scope,
            activation_receipt=activation_result,
            mutation_receipt=mutation_result,
            command=admission.command,
            replayed=False,
        )
