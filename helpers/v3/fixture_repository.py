"""Durable repository authority for governed fixture commands and hydration."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Mapping

from .fixture_command_adapter import (
    ExactFixtureRecord,
    FixtureAcceptedMutation,
    FixtureCommandAdmission,
    FixtureLedgerResult,
    FixtureLedgerUnavailable,
)
from .fixtures import (
    FIXTURE_ADMISSION_SCHEMA_ID,
    FIXTURE_AUTHORITY_USE_SCHEMA_ID,
    FIXTURE_DRAFT_SCHEMA_ID,
    FIXTURE_ELIGIBILITY_SCHEMA_ID,
    FIXTURE_FAMILY_SCHEMA_ID,
    FIXTURE_REGISTRY,
    FIXTURE_REVIEW_SCHEMA_ID,
    FixtureAdmission,
    FixtureAuthority,
    FixtureDraft,
    FixtureReview,
    FixtureValidationError,
    FixtureWithdrawal,
)
from .repository import (
    DomainEvent,
    IdempotencyConflict,
    IntegrityFailure,
    OperatorCommand,
    V3Reader,
    V3Repository,
    V3Transaction,
)
from .schemas import (
    RecordSchema,
    SchemaRegistry,
    SchemaValidationError,
    TypedRecord,
    build_typed_record,
    canonical_json,
    merge_schema_registries,
    schema_digest,
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


FIXTURE_COMMAND_MUTATION_RECEIPT_SCHEMA_ID = "a0.fixture-command-mutation-receipt.v1"
_ACTIONS = ("fixture_draft", "fixture_review", "fixture_admit", "fixture_withdraw")
_EXACT = strict_object(
    {"record_id": strict_string(maximum=512), "digest": validate_digest}
)
_OPTIONAL_DIGEST = strict_nullable(validate_digest)
_MUTATED_RECORD = strict_object(
    {
        "record_id": strict_string(maximum=512),
        "digest": validate_digest,
        "record_kind": strict_enum(
            (
                "fixture_family",
                "fixture_authority_use",
                "fixture_draft",
                "fixture_review",
                "fixture_admission_receipt",
                "fixture_eligibility_event",
            )
        ),
    }
)
_MUTATED_EVENT = strict_object(
    {
        "event_id": strict_string(maximum=512),
        "subject_id": strict_string(maximum=512),
        "subject_kind": strict_literal("fixture_draft"),
        "sequence": strict_integer(minimum=0, maximum=1),
        "event_type": strict_enum(("fixture_admitted", "fixture_withdrawn")),
        "payload_record_id": strict_string(maximum=512),
        "actor_authority_ref": strict_string(maximum=128),
        "fence_token": strict_nullable(strict_integer(minimum=0)),
    }
)
_RECORD_KINDS = {
    "fixture_draft": (
        "fixture_family",
        "fixture_authority_use",
        "fixture_authority_use",
        "fixture_draft",
    ),
    "fixture_review": (
        "fixture_authority_use",
        "fixture_authority_use",
        "fixture_review",
    ),
    "fixture_admit": (
        "fixture_authority_use",
        "fixture_admission_receipt",
        "fixture_eligibility_event",
    ),
    "fixture_withdraw": ("fixture_eligibility_event",),
}


def _receipt_validator(value: Any, path: str) -> dict[str, Any]:
    payload = strict_object(
        {
            "record_type": strict_literal("fixture_command_mutation_receipt"),
            "accepted": strict_literal(True),
            "issuer_ref": strict_string(maximum=128),
            "subject_ref": strict_string(maximum=128),
            "context_ref": strict_string(maximum=128),
            "action": strict_enum(_ACTIONS),
            "target": strict_object(
                {
                    "record_id": strict_string(maximum=512),
                    "digest": _OPTIONAL_DIGEST,
                }
            ),
            "observed_revision": strict_integer(minimum=0),
            "idempotency_key_digest": validate_digest,
            "request_digest": validate_digest,
            "domain_result": _EXACT,
            "records": strict_list(_MUTATED_RECORD, minimum=1, maximum=4),
            "events": strict_list(_MUTATED_EVENT, minimum=0, maximum=1),
            "vault_cleanup_mode": strict_enum(
                ("not_applicable", "post_commit_separate")
            ),
            "links": validate_links,
        }
    )(value, path)
    expected_kinds = _RECORD_KINDS[payload["action"]]
    if tuple(item["record_kind"] for item in payload["records"]) != expected_kinds:
        raise SchemaValidationError(f"{path}.records do not match the fixture action")
    exact_records = [
        {"record_id": item["record_id"], "digest": item["digest"]}
        for item in payload["records"]
    ]
    if payload["domain_result"] not in exact_records:
        raise SchemaValidationError(f"{path}.domain_result is not a mutated record")
    expected_event = {
        "fixture_draft": (),
        "fixture_review": (),
        "fixture_admit": ((0, "fixture_admitted"),),
        "fixture_withdraw": ((1, "fixture_withdrawn"),),
    }[payload["action"]]
    actual_event = tuple(
        (item["sequence"], item["event_type"]) for item in payload["events"]
    )
    if actual_event != expected_event:
        raise SchemaValidationError(f"{path}.events do not match the fixture action")
    eligibility_ids = {
        item["record_id"]
        for item in payload["records"]
        if item["record_kind"] == "fixture_eligibility_event"
    }
    if any(
        item["subject_id"] != payload["target"]["record_id"]
        or item["payload_record_id"] not in eligibility_ids
        for item in payload["events"]
    ):
        raise SchemaValidationError(f"{path}.events do not bind the exact eligibility")
    cleanup = (
        "post_commit_separate"
        if payload["action"] == "fixture_withdraw"
        else "not_applicable"
    )
    if payload["vault_cleanup_mode"] != cleanup:
        raise SchemaValidationError(f"{path}.vault_cleanup_mode is not truthful")
    expected_links = [
        {
            "role": "mutated_record",
            "ordinal": ordinal,
            "target_id": item["record_id"],
            "target_digest": item["digest"],
        }
        for ordinal, item in enumerate(payload["records"])
    ]
    if payload["links"] != expected_links:
        raise SchemaValidationError(f"{path}.links do not bind exact mutated records")
    return payload


FIXTURE_REPOSITORY_REGISTRY = merge_schema_registries(
    FIXTURE_REGISTRY,
    SchemaRegistry(
        (
            RecordSchema(
                FIXTURE_COMMAND_MUTATION_RECEIPT_SCHEMA_ID,
                "fixture_command_mutation_receipt",
                _receipt_validator,
            ),
        )
    ),
)


WithdrawalFinalizer = Callable[[ExactFixtureRecord], None]


class RepositoryFixtureCommandLedger:
    """Persist a fixture mutation and its command admission in one transaction.

    Vault destruction is intentionally outside that transaction.  Withdrawal
    receipts truthfully record ``post_commit_separate`` and a required injected
    finalizer runs only after SQLite commits.  A failed finalizer produces no
    success response; an exact replay retries it without rerunning the domain
    executor.
    """

    def __init__(
        self,
        repository: V3Repository,
        *,
        withdrawal_finalizer: WithdrawalFinalizer | None = None,
    ) -> None:
        if not isinstance(repository, V3Repository):
            raise TypeError("fixture command ledger requires a V3Repository")
        if withdrawal_finalizer is not None and not callable(withdrawal_finalizer):
            raise TypeError("withdrawal_finalizer must be callable")
        self._repository = repository
        self._withdrawal_finalizer = withdrawal_finalizer

    def execute(
        self,
        admission: FixtureCommandAdmission,
        executor: Callable[[], FixtureAcceptedMutation],
    ) -> FixtureLedgerResult:
        _validate_admission(admission)
        if not callable(executor):
            raise TypeError("fixture executor must be callable")
        if admission.action == "fixture_withdraw" and self._withdrawal_finalizer is None:
            raise FixtureLedgerUnavailable(
                "withdrawal requires a post-commit vault finalizer"
            )

        with self._repository.transaction() as transaction:
            prior = _existing_command(transaction, admission)
            if prior is not None:
                result = _replay(transaction, admission, prior)
            else:
                mutation = executor()
                ordered_records, events = _validate_mutation(admission, mutation)
                for record in ordered_records:
                    transaction.insert_record(record)
                for event in events:
                    if transaction.next_domain_event_sequence(event.subject_id) != event.sequence:
                        raise IntegrityFailure(
                            "fixture event is not the next durable subject event"
                        )
                    transaction.append_event(event)
                receipt = _build_receipt(admission, mutation, ordered_records, events)
                transaction.insert_record(receipt)
                command = OperatorCommand(
                    command_id=_stable_id("fixture-command", admission.request_digest),
                    issuer_ref=admission.issuer_ref,
                    subject_ref=admission.subject_ref,
                    context_ref=admission.context_ref,
                    action=admission.action,
                    idempotency_key_digest=admission.idempotency_key_digest,
                    request_digest=admission.request_digest,
                    observed_revision=admission.target_revision,
                    state="accepted",
                    mutation_receipt_id=receipt.record_id,
                )
                command_result = transaction.admit_command(command)
                if command_result.replayed:
                    raise IntegrityFailure(
                        "fixture command admission changed during one transaction"
                    )
                result = FixtureLedgerResult(admission, receipt.record_id, False)

        if admission.action == "fixture_withdraw":
            assert self._withdrawal_finalizer is not None
            try:
                self._withdrawal_finalizer(
                    ExactFixtureRecord(admission.target_ref, admission.target_digest or "")
                )
            except FixtureLedgerUnavailable:
                raise
            except Exception as exc:
                raise FixtureLedgerUnavailable(
                    "post-commit fixture vault cleanup is incomplete"
                ) from exc
        return result


@dataclass(frozen=True, slots=True)
class _FixtureSnapshot:
    records: Mapping[str, TypedRecord]
    events: tuple[DomainEvent, ...]


class RepositoryFixtureResolvers:
    """Reconstruct and hydrate strict fixture state from committed repository facts."""

    def __init__(
        self,
        repository: V3Repository,
        coordinator: FixtureAuthority,
        *,
        context_ref: str,
        record_maximum: int,
        event_maximum: int,
    ) -> None:
        if not isinstance(repository, V3Repository):
            raise TypeError("fixture resolvers require a V3Repository")
        if not isinstance(coordinator, FixtureAuthority):
            raise TypeError("fixture resolvers require a FixtureAuthority")
        if type(context_ref) is not str or not context_ref or len(context_ref) > 128:
            raise ValueError("context_ref must be an explicit bounded reference")
        for value, name in (
            (record_maximum, "record_maximum"),
            (event_maximum, "event_maximum"),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be an explicit positive integer")
        self._repository = repository
        self._coordinator = coordinator
        self._context_ref = context_ref
        self._record_maximum = record_maximum
        self._event_maximum = event_maximum

    def resolve_draft(self, identity: ExactFixtureRecord) -> FixtureDraft | None:
        _require_exact_identity(identity)
        snapshot = self._snapshot()
        record = snapshot.records.get(identity.record_id)
        if record is None or record.content_digest != identity.digest:
            return None
        if record.record_kind != "fixture_draft":
            return None
        draft = self._draft(record, snapshot)
        self._hydrate_current(draft, snapshot)
        return draft

    def resolve_review(self, identity: ExactFixtureRecord) -> FixtureReview | None:
        _require_exact_identity(identity)
        snapshot = self._snapshot()
        record = snapshot.records.get(identity.record_id)
        if record is None or record.content_digest != identity.digest:
            return None
        if record.record_kind != "fixture_review":
            return None
        draft_record = _record_exact(
            snapshot,
            record.payload["draft_id"],
            record.payload["draft_digest"],
            "fixture_draft",
        )
        draft = self._draft(draft_record, snapshot)
        review = self._review(draft, record, snapshot)
        self._hydrate_current(draft, snapshot)
        return review

    def resolve_admission(
        self, identity: ExactFixtureRecord
    ) -> FixtureAdmission | None:
        _require_exact_identity(identity)
        snapshot = self._snapshot()
        receipt = snapshot.records.get(identity.record_id)
        if receipt is None or receipt.content_digest != identity.digest:
            return None
        if receipt.record_kind != "fixture_admission_receipt":
            return None
        draft_record = _record_exact(
            snapshot,
            receipt.payload["draft_id"],
            receipt.payload["draft_digest"],
            "fixture_draft",
        )
        draft = self._draft(draft_record, snapshot)
        admission = self._admission(draft, receipt, snapshot)
        self._hydrate_withdrawal_if_present(draft, snapshot)
        return admission

    def current_eligibility(
        self, identity: ExactFixtureRecord
    ) -> TypedRecord | None:
        draft = self.resolve_draft(identity)
        if draft is None:
            return None
        snapshot = self._snapshot()
        events = _ordered_fixture_events(snapshot, draft.record.record_id)
        if not events:
            return None
        event = events[-1]
        if event.payload_record_id is None:
            raise IntegrityFailure("fixture eligibility event has no payload record")
        return _record_exact(
            snapshot,
            event.payload_record_id,
            None,
            "fixture_eligibility_event",
        )

    def finalize_withdrawal(self, identity: ExactFixtureRecord) -> None:
        draft = self.resolve_draft(identity)
        if draft is None:
            raise FixtureValidationError("withdrawn fixture identity is unavailable")
        current = self.current_eligibility(identity)
        if current is None or current.payload["state"] != "withdrawn":
            raise FixtureValidationError("fixture is not durably withdrawn")
        self._coordinator.finalize_withdrawal(draft.record.record_id)

    def _snapshot(self) -> _FixtureSnapshot:
        with V3Reader.open(
            self._repository.path, registry=FIXTURE_REPOSITORY_REGISTRY
        ) as reader:
            records = reader.list_records_for_context(
                "fixture-authority", maximum=self._record_maximum
            )
            events = reader.list_domain_events_for_context(
                "fixture-authority", maximum=self._event_maximum
            )
        return _FixtureSnapshot(
            {item.record.record_id: item.record for item in records},
            tuple(item.event for item in events),
        )

    def _draft(self, record: TypedRecord, snapshot: _FixtureSnapshot) -> FixtureDraft:
        if record.schema_id != FIXTURE_DRAFT_SCHEMA_ID:
            raise IntegrityFailure("fixture draft has the wrong schema")
        family = _linked(snapshot, record, "fixture_family", 0, "fixture_family")
        uses = (
            _linked(snapshot, record, "authority_use", 0, "fixture_authority_use"),
            _linked(snapshot, record, "authority_use", 1, "fixture_authority_use"),
        )
        _require_context(uses, self._context_ref)
        return self._coordinator.hydrate_draft(FixtureDraft(family, uses, record))

    def _review(
        self,
        draft: FixtureDraft,
        record: TypedRecord,
        snapshot: _FixtureSnapshot,
    ) -> FixtureReview:
        if record.schema_id != FIXTURE_REVIEW_SCHEMA_ID:
            raise IntegrityFailure("fixture review has the wrong schema")
        uses = (
            _linked(snapshot, record, "authority_use", 0, "fixture_authority_use"),
            _linked(snapshot, record, "authority_use", 1, "fixture_authority_use"),
        )
        _require_context(uses, self._context_ref)
        return self._coordinator.hydrate_review(draft, FixtureReview(uses, record))

    def _admission(
        self,
        draft: FixtureDraft,
        receipt: TypedRecord,
        snapshot: _FixtureSnapshot,
    ) -> FixtureAdmission:
        if receipt.schema_id != FIXTURE_ADMISSION_SCHEMA_ID:
            raise IntegrityFailure("fixture admission has the wrong schema")
        review_record = _record_exact(
            snapshot,
            receipt.payload["review_id"],
            receipt.payload["review_digest"],
            "fixture_review",
        )
        review = self._review(draft, review_record, snapshot)
        use = _linked(snapshot, receipt, "authority_use", 0, "fixture_authority_use")
        _require_context((use,), self._context_ref)
        events = _ordered_fixture_events(snapshot, draft.record.record_id)
        if not events or events[0].event_type != "fixture_admitted":
            raise IntegrityFailure("fixture admission event is missing")
        event = events[0]
        if event.payload_record_id is None:
            raise IntegrityFailure("fixture admission event has no eligibility payload")
        eligibility = _record_exact(
            snapshot,
            event.payload_record_id,
            None,
            "fixture_eligibility_event",
        )
        return self._coordinator.hydrate_admission(
            draft,
            review,
            FixtureAdmission(use, receipt, eligibility, event),
        )

    def _hydrate_current(
        self, draft: FixtureDraft, snapshot: _FixtureSnapshot
    ) -> None:
        events = _ordered_fixture_events(snapshot, draft.record.record_id)
        if not events:
            return
        receipts = [
            record
            for record in snapshot.records.values()
            if record.record_kind == "fixture_admission_receipt"
            and record.payload["draft_id"] == draft.record.record_id
            and record.payload["draft_digest"] == draft.record.content_digest
        ]
        if len(receipts) != 1:
            raise IntegrityFailure("fixture admission receipt is missing or ambiguous")
        self._admission(draft, receipts[0], snapshot)
        self._hydrate_withdrawal_if_present(draft, snapshot)

    def _hydrate_withdrawal_if_present(
        self, draft: FixtureDraft, snapshot: _FixtureSnapshot
    ) -> None:
        events = _ordered_fixture_events(snapshot, draft.record.record_id)
        if len(events) < 2:
            return
        event = events[1]
        if event.event_type != "fixture_withdrawn" or event.payload_record_id is None:
            raise IntegrityFailure("fixture withdrawal event is invalid")
        eligibility = _record_exact(
            snapshot,
            event.payload_record_id,
            None,
            "fixture_eligibility_event",
        )
        self._coordinator.hydrate_withdrawal(
            draft, FixtureWithdrawal(eligibility, event)
        )


def _validate_admission(admission: FixtureCommandAdmission) -> None:
    if type(admission) is not FixtureCommandAdmission or admission.action not in _ACTIONS:
        raise SchemaValidationError("fixture command admission has an invalid shape")
    for value, name in (
        (admission.issuer_ref, "issuer_ref"),
        (admission.subject_ref, "subject_ref"),
        (admission.context_ref, "context_ref"),
        (admission.target_ref, "target_ref"),
    ):
        maximum = 512 if name == "target_ref" else 128
        if type(value) is not str or not value or len(value) > maximum:
            raise SchemaValidationError(f"{name} must be an explicit bounded reference")
    if type(admission.target_revision) is not int or admission.target_revision < 0:
        raise SchemaValidationError("target_revision must be non-negative")
    validate_digest(admission.idempotency_key_digest, "idempotency_key_digest")
    validate_digest(admission.request_digest, "request_digest")
    if admission.action == "fixture_draft":
        if admission.target_digest is not None:
            raise SchemaValidationError("fixture draft target digest must be null")
    else:
        validate_digest(admission.target_digest, "target_digest")


def _existing_command(
    transaction: V3Transaction,
    admission: FixtureCommandAdmission,
) -> OperatorCommand | None:
    existing = transaction.get_operator_command(
        issuer_ref=admission.issuer_ref,
        subject_ref=admission.subject_ref,
        context_ref=admission.context_ref,
        action=admission.action,
        idempotency_key_digest=admission.idempotency_key_digest,
    )
    if existing is not None and existing.request_digest != admission.request_digest:
        raise IdempotencyConflict("idempotency key was reused with a different request")
    return existing


def _replay(
    transaction: V3Transaction,
    admission: FixtureCommandAdmission,
    command: OperatorCommand,
) -> FixtureLedgerResult:
    receipt = transaction.get_record(command.mutation_receipt_id)
    if (
        command.state != "accepted"
        or command.observed_revision != admission.target_revision
        or receipt is None
        or receipt.record_kind != "fixture_command_mutation_receipt"
        or receipt.schema_id != FIXTURE_COMMAND_MUTATION_RECEIPT_SCHEMA_ID
    ):
        raise IntegrityFailure("fixture command replay lost its durable receipt")
    payload = receipt.payload
    expected_target = {
        "record_id": admission.target_ref,
        "digest": admission.target_digest,
    }
    if (
        receipt.context_ref != admission.context_ref
        or payload["issuer_ref"] != admission.issuer_ref
        or payload["subject_ref"] != admission.subject_ref
        or payload["context_ref"] != admission.context_ref
        or payload["action"] != admission.action
        or payload["target"] != expected_target
        or payload["observed_revision"] != admission.target_revision
        or payload["idempotency_key_digest"] != admission.idempotency_key_digest
        or payload["request_digest"] != admission.request_digest
    ):
        raise IntegrityFailure("fixture command replay differs from its durable receipt")
    return FixtureLedgerResult(admission, receipt.record_id, True)


def _validate_mutation(
    admission: FixtureCommandAdmission,
    mutation: FixtureAcceptedMutation,
) -> tuple[tuple[TypedRecord, ...], tuple[DomainEvent, ...]]:
    if type(mutation) is not FixtureAcceptedMutation:
        raise IntegrityFailure("fixture executor returned an invalid mutation")
    records = _dependency_order(mutation.records)
    events = tuple(mutation.events)
    expected_kinds = _RECORD_KINDS[admission.action]
    if tuple(record.record_kind for record in records) != expected_kinds:
        raise IntegrityFailure("fixture mutation records do not match the command action")
    if not any(record.record_id == mutation.domain_result_ref for record in records):
        raise IntegrityFailure("fixture mutation domain result is not persisted")
    expected_events = {
        "fixture_draft": (),
        "fixture_review": (),
        "fixture_admit": ((0, "fixture_admitted"),),
        "fixture_withdraw": ((1, "fixture_withdrawn"),),
    }[admission.action]
    if tuple((event.sequence, event.event_type) for event in events) != expected_events:
        raise IntegrityFailure("fixture mutation events do not match the command action")
    for record in records:
        record.verify(FIXTURE_REPOSITORY_REGISTRY)
    for event in events:
        if (
            event.subject_id != admission.target_ref
            or event.subject_kind != "fixture_draft"
            or event.payload_record_id not in {record.record_id for record in records}
        ):
            raise IntegrityFailure("fixture event does not bind the exact command mutation")
    return records, events


def _dependency_order(records: tuple[TypedRecord, ...]) -> tuple[TypedRecord, ...]:
    if type(records) is not tuple:
        raise IntegrityFailure("fixture mutation records must be an immutable tuple")
    by_id: dict[str, TypedRecord] = {}
    for record in records:
        if type(record) is not TypedRecord:
            raise IntegrityFailure("fixture mutation contains a non-record value")
        prior = by_id.get(record.record_id)
        if prior is not None and prior != record:
            raise IntegrityFailure("fixture mutation reused a record identity")
        by_id[record.record_id] = record
    if len(by_id) != len(records):
        raise IntegrityFailure("fixture mutation repeats a record")
    ordered: list[TypedRecord] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(record: TypedRecord) -> None:
        if record.record_id in visited:
            return
        if record.record_id in visiting:
            raise IntegrityFailure("fixture mutation record links contain a cycle")
        visiting.add(record.record_id)
        for link in record.links:
            dependency = by_id.get(link.target_id)
            if dependency is not None:
                if dependency.content_digest != link.target_digest:
                    raise IntegrityFailure("fixture mutation dependency digest changed")
                visit(dependency)
        visiting.remove(record.record_id)
        visited.add(record.record_id)
        ordered.append(record)

    for item in records:
        visit(item)
    return tuple(ordered)


def _build_receipt(
    admission: FixtureCommandAdmission,
    mutation: FixtureAcceptedMutation,
    records: tuple[TypedRecord, ...],
    events: tuple[DomainEvent, ...],
) -> TypedRecord:
    record_entries = [
        {
            "record_id": record.record_id,
            "digest": record.content_digest,
            "record_kind": record.record_kind,
        }
        for record in records
    ]
    event_entries = [
        {
            "event_id": event.event_id,
            "subject_id": event.subject_id,
            "subject_kind": event.subject_kind,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "payload_record_id": event.payload_record_id,
            "actor_authority_ref": event.actor_authority_ref,
            "fence_token": event.fence_token,
        }
        for event in events
    ]
    domain_record = next(
        record for record in records if record.record_id == mutation.domain_result_ref
    )
    payload = {
        "record_type": "fixture_command_mutation_receipt",
        "accepted": True,
        "issuer_ref": admission.issuer_ref,
        "subject_ref": admission.subject_ref,
        "context_ref": admission.context_ref,
        "action": admission.action,
        "target": {
            "record_id": admission.target_ref,
            "digest": admission.target_digest,
        },
        "observed_revision": admission.target_revision,
        "idempotency_key_digest": admission.idempotency_key_digest,
        "request_digest": admission.request_digest,
        "domain_result": {
            "record_id": domain_record.record_id,
            "digest": domain_record.content_digest,
        },
        "records": record_entries,
        "events": event_entries,
        "vault_cleanup_mode": (
            "post_commit_separate"
            if admission.action == "fixture_withdraw"
            else "not_applicable"
        ),
        "links": [
            {
                "role": "mutated_record",
                "ordinal": ordinal,
                "target_id": item["record_id"],
                "target_digest": item["digest"],
            }
            for ordinal, item in enumerate(record_entries)
        ],
    }
    encoded = canonical_json(payload)
    return build_typed_record(
        record_id="fixture-command-receipt:" + schema_digest(
            "fixture-command-receipt",
            FIXTURE_COMMAND_MUTATION_RECEIPT_SCHEMA_ID,
            encoded,
        ),
        context_ref=admission.context_ref,
        record_kind="fixture_command_mutation_receipt",
        schema_id=FIXTURE_COMMAND_MUTATION_RECEIPT_SCHEMA_ID,
        payload=payload,
        key_epoch="fixture-command-v1",
        registry=FIXTURE_REPOSITORY_REGISTRY,
    )


def _stable_id(namespace: str, request_digest: str) -> str:
    material = f"{namespace}\0{request_digest}".encode("ascii")
    return f"{namespace}:{sha256(material).hexdigest()}"


def _require_exact_identity(identity: ExactFixtureRecord) -> None:
    if type(identity) is not ExactFixtureRecord:
        raise TypeError("fixture resolution requires an exact identity")
    if not identity.record_id or len(identity.record_id) > 512:
        raise SchemaValidationError("record_id must be an explicit bounded reference")
    validate_digest(identity.digest, "digest")


def _record_exact(
    snapshot: _FixtureSnapshot,
    record_id: str,
    digest: str | None,
    kind: str,
) -> TypedRecord:
    record = snapshot.records.get(record_id)
    if (
        record is None
        or (digest is not None and record.content_digest != digest)
        or record.record_kind != kind
    ):
        raise IntegrityFailure("durable fixture record identity or kind mismatch")
    return record


def _linked(
    snapshot: _FixtureSnapshot,
    source: TypedRecord,
    role: str,
    ordinal: int,
    kind: str,
) -> TypedRecord:
    matches = [
        link
        for link in source.links
        if link.role == role and link.ordinal == ordinal
    ]
    if len(matches) != 1:
        raise IntegrityFailure("durable fixture link is missing or ambiguous")
    link = matches[0]
    return _record_exact(snapshot, link.target_id, link.target_digest, kind)


def _require_context(records: tuple[TypedRecord, ...], context_ref: str) -> None:
    if any(record.payload["context_ref"] != context_ref for record in records):
        raise IntegrityFailure("durable fixture authority belongs to another context")


def _ordered_fixture_events(
    snapshot: _FixtureSnapshot, fixture_id: str
) -> tuple[DomainEvent, ...]:
    events = tuple(
        sorted(
            (event for event in snapshot.events if event.subject_id == fixture_id),
            key=lambda item: item.sequence,
        )
    )
    if len(events) > 2 or [event.sequence for event in events] != list(range(len(events))):
        raise IntegrityFailure("fixture eligibility events are not complete and ordered")
    expected_types = ("fixture_admitted", "fixture_withdrawn")[: len(events)]
    if tuple(event.event_type for event in events) != expected_types:
        raise IntegrityFailure("fixture eligibility event order is invalid")
    payload_ids = {
        event.payload_record_id for event in events if event.payload_record_id is not None
    }
    eligibility_ids = {
        record.record_id
        for record in snapshot.records.values()
        if record.record_kind == "fixture_eligibility_event"
        and record.payload["fixture_id"] == fixture_id
    }
    if len(payload_ids) != len(events) or eligibility_ids != payload_ids:
        raise IntegrityFailure("fixture eligibility records and events are not exact")
    return events


__all__ = [
    "FIXTURE_COMMAND_MUTATION_RECEIPT_SCHEMA_ID",
    "FIXTURE_REPOSITORY_REGISTRY",
    "RepositoryFixtureCommandLedger",
    "RepositoryFixtureResolvers",
    "WithdrawalFinalizer",
]
