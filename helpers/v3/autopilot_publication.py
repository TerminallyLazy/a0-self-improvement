"""Publish legacy optimizer output into v3 as non-activatable review work.

The optimizer's compatibility store predates the v3 authority model.  This
bridge copies only content-free identities into the safe store and deliberately
uses a distinct candidate schema that activation coordinators do not admit.
It therefore makes Autopilot work visible without manufacturing promotion or
activation authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from ..store import Store
from .candidate_publication import ENGINE_SEMANTIC_IDS
from .repository import DomainEvent
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
    strict_literal,
    strict_object,
    strict_string,
    validate_digest,
    validate_links,
)
from .store_selection import open_runtime_repository, resolve_runtime_store


AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID = "a0.autopilot-review-candidate.v1"
AUTOPILOT_REVIEW_RECEIPT_SCHEMA_ID = "a0.autopilot-review-receipt.v1"
AUTOPILOT_REVIEW_CANDIDATE_KIND = "improvement_candidate"
AUTOPILOT_REVIEW_RECEIPT_KIND = "autopilot_review_receipt"
_DETERMINISTIC_ENGINE_SEMANTIC_ID = ENGINE_SEMANTIC_IDS[0]
AUTOPILOT_ENGINE_SEMANTIC_ID = ENGINE_SEMANTIC_IDS[1]
_OUTCOME_ENGINE_SEMANTIC_ID = ENGINE_SEMANTIC_IDS[2]
AUTOPILOT_AUTHORITY_CEILING = "no_promotion_authority"
_KEY_EPOCH = "autopilot-review-bridge-v1"
_ACTOR_REF = "autopilot_review_bridge"
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CURSOR_STATE_KEY = "autopilot_candidate_publication_cursors"
_PAGE_SIZE = 128


class AutopilotPublicationError(RuntimeError):
    """Legacy candidate output cannot be safely projected into v3."""


@dataclass(frozen=True, slots=True)
class AutopilotSyncResult:
    context_ref: str
    discovered_count: int
    published_count: int
    already_published_count: int
    skipped_count: int


def _candidate_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("autopilot_review_candidate"),
            "source": strict_literal("legacy_optimizer"),
            "source_candidate_digest": validate_digest,
            "artifact_id": strict_string(maximum=128),
            "incumbent_profile_id": strict_string(maximum=512),
            "incumbent_profile_digest": validate_digest,
            "activation_scope_ref": strict_string(maximum=512),
            "observed_scope_revision": strict_integer(minimum=0),
            "objective_bucket": strict_string(maximum=128),
            "engine_semantic_id": strict_enum(ENGINE_SEMANTIC_IDS),
            "authority_ceiling": strict_literal(AUTOPILOT_AUTHORITY_CEILING),
            "review_disposition": strict_enum(("review_only", "rejected")),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        {
            "role": "incumbent_profile",
            "ordinal": 0,
            "target_id": payload["incumbent_profile_id"],
            "target_digest": payload["incumbent_profile_digest"],
        }
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the incumbent profile")
    return payload


def _receipt_payload(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal(AUTOPILOT_REVIEW_RECEIPT_KIND),
            "candidate_id": strict_string(maximum=512),
            "candidate_digest": validate_digest,
            "source_candidate_digest": validate_digest,
            "result": strict_enum(("review_only", "rejected")),
            "authority_ceiling": strict_literal(AUTOPILOT_AUTHORITY_CEILING),
            "links": validate_links,
        }
    )(value, path)
    expected = [
        {
            "role": "candidate",
            "ordinal": 0,
            "target_id": payload["candidate_id"],
            "target_digest": payload["candidate_digest"],
        }
    ]
    if payload["links"] != expected:
        raise SchemaValidationError(f"{path}.links do not bind the review candidate")
    return payload


AUTOPILOT_PUBLICATION_REGISTRY = SchemaRegistry(
    (
        RecordSchema(
            AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID,
            AUTOPILOT_REVIEW_CANDIDATE_KIND,
            _candidate_payload,
        ),
        RecordSchema(
            AUTOPILOT_REVIEW_RECEIPT_SCHEMA_ID,
            AUTOPILOT_REVIEW_RECEIPT_KIND,
            _receipt_payload,
        ),
    )
)


def _identity(prefix: str, *parts: str) -> str:
    encoded = canonical_json(list(parts))
    return f"{prefix}_{sha256(encoded).hexdigest()}"


def _safe_bucket(value: object) -> str:
    return value if type(value) is str and _SAFE_TOKEN.fullmatch(value) else "unknown"


def _candidate_records(
    row: Mapping[str, Any], *, context_ref: str, profile_id: str,
    profile_digest: str, scope_revision: int,
) -> tuple[TypedRecord, TypedRecord, DomainEvent]:
    source_digest = validate_digest(row.get("candidate_digest"), "legacy.candidate_digest")
    source_candidate = row.get("candidate")
    if type(source_candidate) is not dict:
        raise SchemaValidationError("legacy.candidate must be an object")
    if sha256(canonical_json(source_candidate)).hexdigest() != source_digest:
        raise SchemaValidationError("legacy candidate digest does not match its payload")
    validation = source_candidate.get("validation")
    validation = validation if type(validation) is dict else {}
    metadata = source_candidate.get("guidance_metadata")
    metadata = metadata if type(metadata) is dict else {}
    replay = metadata.get("replay")
    replay = replay if type(replay) is dict else {}
    guidance_artifact = source_candidate.get("guidance_artifact")
    guidance_artifact = guidance_artifact if type(guidance_artifact) is dict else {}
    engine = guidance_artifact.get("engine")
    engine = engine if type(engine) is dict else {}
    engine_semantic_id = {
        "heuristic": _DETERMINISTIC_ENGINE_SEMANTIC_ID,
        "gepa": _OUTCOME_ENGINE_SEMANTIC_ID,
    }.get(engine.get("kind"), AUTOPILOT_ENGINE_SEMANTIC_ID)
    review_disposition = (
        "rejected"
        if validation.get("passed") is False
        or replay.get("decision") in {"reject", "rejected"}
        else "review_only"
    )
    candidate_id = _identity("autopilot_candidate", context_ref, source_digest)
    artifact_id = _identity(
        "autopilot_artifact",
        context_ref,
        str(row.get("guidance_version") or "none"),
        source_digest,
    )
    candidate_payload = {
        "record_type": "autopilot_review_candidate",
        "source": "legacy_optimizer",
        "source_candidate_digest": source_digest,
        "artifact_id": artifact_id,
        "incumbent_profile_id": profile_id,
        "incumbent_profile_digest": profile_digest,
        "activation_scope_ref": context_ref,
        "observed_scope_revision": scope_revision,
        "objective_bucket": _safe_bucket(row.get("objective_bucket")),
        "engine_semantic_id": engine_semantic_id,
        "authority_ceiling": AUTOPILOT_AUTHORITY_CEILING,
        "review_disposition": review_disposition,
        "links": [
            {
                "role": "incumbent_profile",
                "ordinal": 0,
                "target_id": profile_id,
                "target_digest": profile_digest,
            }
        ],
    }
    candidate = build_typed_record(
        record_id=candidate_id,
        context_ref=context_ref,
        record_kind=AUTOPILOT_REVIEW_CANDIDATE_KIND,
        schema_id=AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID,
        payload=candidate_payload,
        key_epoch=_KEY_EPOCH,
        registry=AUTOPILOT_PUBLICATION_REGISTRY,
    )
    receipt_payload = {
        "record_type": AUTOPILOT_REVIEW_RECEIPT_KIND,
        "candidate_id": candidate.record_id,
        "candidate_digest": candidate.content_digest,
        "source_candidate_digest": source_digest,
        "result": review_disposition,
        "authority_ceiling": AUTOPILOT_AUTHORITY_CEILING,
        "links": [
            {
                "role": "candidate",
                "ordinal": 0,
                "target_id": candidate.record_id,
                "target_digest": candidate.content_digest,
            }
        ],
    }
    receipt = build_typed_record(
        record_id=_identity("autopilot_receipt", candidate.record_id),
        context_ref=context_ref,
        record_kind=AUTOPILOT_REVIEW_RECEIPT_KIND,
        schema_id=AUTOPILOT_REVIEW_RECEIPT_SCHEMA_ID,
        payload=receipt_payload,
        key_epoch=_KEY_EPOCH,
        registry=AUTOPILOT_PUBLICATION_REGISTRY,
    )
    event_body = {
        "subject_id": candidate.record_id,
        "subject_kind": candidate.record_kind,
        "sequence": 0,
        "event_type": "candidate_staged_for_review",
        "payload_record_id": receipt.record_id,
        "actor_authority_ref": _ACTOR_REF,
        "fence_token": None,
    }
    event = DomainEvent(
        event_id="autopilot_event_"
        + schema_digest(
            "domain-event",
            "a0.autopilot-review-event.v1",
            canonical_json(event_body),
        ),
        **event_body,
    )
    return candidate, receipt, event


def _target_ref(*, pre_cutover_path: Path, manifest_path: Path) -> str:
    selection = resolve_runtime_store(
        pre_cutover_path=pre_cutover_path,
        manifest_path=manifest_path,
    )
    identity = (
        selection.manifest.generation_ref
        if selection.manifest is not None
        else str(selection.path.resolve())
    )
    return "target_" + sha256(identity.encode("utf-8")).hexdigest()


def _publication_cursor(
    legacy_store: Store, *, context_ref: str, target_ref: str
) -> tuple[float, str] | None:
    state, _revision = legacy_store.get_context_state(context_ref)
    cursors = state.get(_CURSOR_STATE_KEY) if type(state) is dict else None
    cursor = cursors.get(target_ref) if type(cursors) is dict else None
    if type(cursor) is not dict:
        return None
    created_at = cursor.get("created_at")
    candidate_id = cursor.get("candidate_id")
    if type(created_at) not in {int, float} or type(candidate_id) is not str:
        return None
    if created_at < 0 or not candidate_id:
        return None
    return float(created_at), candidate_id


def _advance_publication_cursor(
    legacy_store: Store,
    *,
    context_ref: str,
    target_ref: str,
    cursor: tuple[float, str],
) -> None:
    for _attempt in range(3):
        state, revision = legacy_store.get_context_state(context_ref)
        state = dict(state) if type(state) is dict else {}
        existing_cursors = state.get(_CURSOR_STATE_KEY)
        cursors = dict(existing_cursors) if type(existing_cursors) is dict else {}
        existing = cursors.get(target_ref)
        if type(existing) is dict:
            existing_created_at = existing.get("created_at")
            existing_candidate_id = existing.get("candidate_id")
            if type(existing_created_at) in {int, float} and type(
                existing_candidate_id
            ) is str:
                existing_cursor = float(existing_created_at), existing_candidate_id
                if existing_cursor >= cursor:
                    return
        cursors[target_ref] = {
            "created_at": cursor[0],
            "candidate_id": cursor[1],
        }
        state[_CURSOR_STATE_KEY] = cursors
        applied, _next_revision = legacy_store.put_context_state(
            context_ref,
            state,
            expected_revision=revision,
        )
        if applied:
            return
    # A lost cursor write is safe: the next retry replays immutable rows and the
    # v3 identity checks make that replay idempotent.


def _publish_rows(
    rows: list[dict[str, Any]],
    *,
    context_ref: str,
    pre_cutover_path: Path,
    manifest_path: Path,
) -> tuple[int, int, int]:
    published = 0
    already = 0
    skipped = 0
    try:
        with open_runtime_repository(
            pre_cutover_path=pre_cutover_path,
            manifest_path=manifest_path,
        ) as repository:
            with repository.transaction() as transaction:
                scope = transaction.get_activation_scope(context_ref)
                if scope is None:
                    raise AutopilotPublicationError(
                        "activation scope is not initialized"
                    )
                for row in rows:
                    try:
                        source_digest = validate_digest(
                            row.get("candidate_digest"), "legacy.candidate_digest"
                        )
                        candidate_id = _identity(
                            "autopilot_candidate", context_ref, source_digest
                        )
                        existing = transaction.get_record(candidate_id)
                        if existing is not None:
                            if (
                                existing.context_ref != context_ref
                                or existing.schema_id
                                != AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID
                            ):
                                raise AutopilotPublicationError(
                                    "autopilot candidate identity is occupied"
                                )
                            already += 1
                            continue
                        candidate, receipt, event = _candidate_records(
                            row,
                            context_ref=context_ref,
                            profile_id=scope.current_profile_id,
                            profile_digest=scope.current_profile_digest,
                            scope_revision=scope.scope_revision,
                        )
                    except (TypeError, ValueError):
                        skipped += 1
                        continue
                    transaction.insert_record(candidate)
                    transaction.insert_record(receipt)
                    transaction.append_event(event)
                    published += 1
    except AutopilotPublicationError:
        raise
    except Exception as exc:
        raise AutopilotPublicationError("safe review publication failed") from exc
    return published, already, skipped


def sync_legacy_candidates(
    *,
    context_ref: str,
    legacy_store: Store,
    pre_cutover_path: Path,
    manifest_path: Path,
) -> AutopilotSyncResult:
    """Idempotently expose every valid legacy candidate as review-only v3 work."""

    if type(context_ref) is not str or _SAFE_TOKEN.fullmatch(context_ref) is None:
        raise AutopilotPublicationError("context_ref must be a bounded opaque reference")
    if not isinstance(legacy_store, Store):
        raise AutopilotPublicationError("legacy_store must be a Store")
    target_ref = _target_ref(
        pre_cutover_path=pre_cutover_path,
        manifest_path=manifest_path,
    )
    cursor = _publication_cursor(
        legacy_store,
        context_ref=context_ref,
        target_ref=target_ref,
    )
    discovered = 0
    published = 0
    already = 0
    skipped = 0
    while True:
        rows = legacy_store.list_candidates(
            context_ref,
            after=cursor,
            limit=_PAGE_SIZE,
        )
        if not rows:
            break
        batch_published, batch_already, batch_skipped = _publish_rows(
            rows,
            context_ref=context_ref,
            pre_cutover_path=pre_cutover_path,
            manifest_path=manifest_path,
        )
        discovered += len(rows)
        published += batch_published
        already += batch_already
        skipped += batch_skipped
        final_row = rows[-1]
        cursor = float(final_row["created_at"]), str(final_row["candidate_id"])
        _advance_publication_cursor(
            legacy_store,
            context_ref=context_ref,
            target_ref=target_ref,
            cursor=cursor,
        )
        if len(rows) < _PAGE_SIZE:
            break
    return AutopilotSyncResult(
        context_ref,
        discovered,
        published,
        already,
        skipped,
    )


def publish_legacy_candidate(
    *,
    context_ref: str,
    candidate_id: str,
    legacy_store: Store,
    pre_cutover_path: Path,
    manifest_path: Path,
) -> AutopilotSyncResult:
    """Publish one newly persisted optimizer candidate without scanning history."""

    if type(context_ref) is not str or _SAFE_TOKEN.fullmatch(context_ref) is None:
        raise AutopilotPublicationError("context_ref must be a bounded opaque reference")
    if type(candidate_id) is not str or not candidate_id:
        raise AutopilotPublicationError("candidate_id is required")
    if not isinstance(legacy_store, Store):
        raise AutopilotPublicationError("legacy_store must be a Store")
    row = legacy_store.get_candidate(candidate_id, context_id=context_ref)
    if row is None:
        raise AutopilotPublicationError("legacy candidate is unavailable")
    published, already, skipped = _publish_rows(
        [row],
        context_ref=context_ref,
        pre_cutover_path=pre_cutover_path,
        manifest_path=manifest_path,
    )
    return AutopilotSyncResult(context_ref, 1, published, already, skipped)


__all__ = [
    "AUTOPILOT_AUTHORITY_CEILING",
    "AUTOPILOT_ENGINE_SEMANTIC_ID",
    "AUTOPILOT_PUBLICATION_REGISTRY",
    "AUTOPILOT_REVIEW_CANDIDATE_SCHEMA_ID",
    "AUTOPILOT_REVIEW_RECEIPT_KIND",
    "AUTOPILOT_REVIEW_RECEIPT_SCHEMA_ID",
    "AutopilotPublicationError",
    "AutopilotSyncResult",
    "publish_legacy_candidate",
    "sync_legacy_candidates",
]
