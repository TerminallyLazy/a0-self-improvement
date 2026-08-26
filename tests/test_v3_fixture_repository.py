from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

import pytest

from usr.plugins.dspy_rlm.helpers.v3.authority import (
    BOOTSTRAP_CONFIRMATION,
    GrantExpectation,
    GrantRequest,
    bootstrap_local_issuer,
    digest_idempotency_key,
    issue_grant,
)
from usr.plugins.dspy_rlm.helpers.v3.fixture_command_adapter import (
    ExactFixtureRecord,
    FixtureAcceptedMutation,
    FixtureCommandAdmission,
)
from usr.plugins.dspy_rlm.helpers.v3.fixture_repository import (
    FIXTURE_REPOSITORY_REGISTRY,
    RepositoryFixtureCommandLedger,
    RepositoryFixtureResolvers,
)
from usr.plugins.dspy_rlm.helpers.v3.fixtures import (
    FIXTURE_CONTENT_SCHEMA_ID,
    FIXTURE_REGISTRY,
    ContentAccessAuthority,
    FixtureAuthority,
    FixtureVaultReceipt,
    GrantAuthority,
    ManifestSelection,
    assessment_profile,
    execution_profile,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import (
    IdempotencyConflict,
    IntegrityFailure,
    V3Reader,
    V3Repository,
)


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
CONTEXT = "context:fixture-repository"
ISSUER = "issuer:fixture-repository"
AUTHOR = "operator:author"
REVIEWER = "operator:reviewer"


class _Vault:
    def __init__(self) -> None:
        self.content: dict[str, bytes] = {}

    def seal(self, content: bytes, *, fixture_ref: str, plaintext_digest: str):
        ref = "vault:" + hashlib.sha256(fixture_ref.encode()).hexdigest()[:16]
        self.content[ref] = bytes(content)
        return FixtureVaultReceipt(
            ref,
            "encryption:test-v1",
            plaintext_digest,
            hashlib.sha256(b"cipher\0" + content).hexdigest(),
            len(content),
        )

    def open(self, vault_ref: str, *, fixture_ref: str, plaintext_digest: str):
        del fixture_ref, plaintext_digest
        return self.content[vault_ref]

    def withdraw(self, vault_ref: str, *, fixture_ref: str):
        del fixture_ref
        self.content.pop(vault_ref, None)


def _coordinator(tmp_path: Path, vault: _Vault | None = None, existing_profile=None):
    secret = tmp_path / "fixture-repository-authority.key"
    if existing_profile is None:
        profile = bootstrap_local_issuer(
            secret,
            issuer_id=ISSUER,
            key_epoch=1,
            allowed_authority_classes=(
                "fixture_use_grant",
                "operator_content_session",
            ),
            confirmation=BOOTSTRAP_CONFIRMATION,
        )
    else:
        profile = existing_profile
    selected_vault = vault or _Vault()
    return (
        FixtureAuthority(
            secret_path=secret,
            issuer_profile=profile,
            vault=selected_vault,
            partition_secret=b"fixture-repository-partition-secret",
            partition_policy_ref="fixture-split:v1",
            partition_weights={
                "training": 1,
                "tuning": 1,
                "certification_holdout": 1,
            },
        ),
        secret,
        profile,
        selected_vault,
    )


def _grant(
    secret,
    profile,
    *,
    authority_class: str,
    action: str,
    purpose: str,
    target_ref: str,
    subject_ref: str,
    nonce: str,
) -> GrantAuthority:
    expires = NOW + timedelta(minutes=10)
    idempotency = digest_idempotency_key(
        f"{authority_class}:{action}:{target_ref}:{subject_ref}:{nonce}"
    )
    request = GrantRequest(
        authority_class=authority_class,
        issuer_id=ISSUER,
        key_epoch=1,
        subject_ref=subject_ref,
        context_ref=CONTEXT,
        action=action,
        purpose=purpose,
        target_ref=target_ref,
        target_revision=1,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=expires,
        idempotency_key_digest=idempotency,
        session_nonce=nonce,
    )
    expectation = GrantExpectation(
        authority_class=authority_class,
        issuer_id=ISSUER,
        subject_ref=subject_ref,
        context_ref=CONTEXT,
        action=action,
        purpose=purpose,
        target_ref=target_ref,
        target_revision=1,
        expires_at=expires,
        idempotency_key_digest=idempotency,
        session_nonce=nonce,
    )
    return GrantAuthority(issue_grant(secret, profile, request), expectation)


def _access(secret, profile, *, action, purpose, target_ref, subject_ref):
    nonce = "session:" + action
    return ContentAccessAuthority(
        _grant(
            secret,
            profile,
            authority_class="fixture_use_grant",
            action=action,
            purpose=purpose,
            target_ref=target_ref,
            subject_ref=subject_ref,
            nonce=nonce,
        ),
        _grant(
            secret,
            profile,
            authority_class="operator_content_session",
            action=action,
            purpose=purpose,
            target_ref=target_ref,
            subject_ref=subject_ref,
            nonce=nonce,
        ),
    )


def _fixture_facts(coordinator, secret, profile):
    draft = coordinator.create_draft(
        fixture_ref="case:repository-1",
        revision=1,
        family_ref="family:repository-1",
        source_lineage_digest="a" * 64,
        author_ref=AUTHOR,
        origin_class="operator_authored",
        source_attestation_digest="b" * 64,
        protected=True,
        content={
            "schema": FIXTURE_CONTENT_SCHEMA_ID,
            "input_message": "private fixture content",
            "initial_state": ["state:clean"],
            "tool_steps": [],
            "expected_outcome": ["typed result"],
            "execution_bounds": {
                "max_turns": 2,
                "max_tool_steps": 0,
                "max_output_bytes": 2048,
            },
        },
        authority=_access(
            secret,
            profile,
            action="fixture_draft",
            purpose="fixture_authoring",
            target_ref="case:repository-1",
            subject_ref=AUTHOR,
        ),
        now=NOW,
    )
    review = coordinator.review(
        draft,
        reviewer_ref=REVIEWER,
        authority=_access(
            secret,
            profile,
            action="fixture_review",
            purpose="fixture_review",
            target_ref=draft.record.record_id,
            subject_ref=REVIEWER,
        ),
        now=NOW,
    )
    admission = coordinator.admit(
        draft,
        review,
        fixture_use=_grant(
            secret,
            profile,
            authority_class="fixture_use_grant",
            action="fixture_admit",
            purpose="fixture_replay",
            target_ref=draft.record.record_id,
            subject_ref=AUTHOR,
            nonce="session:fixture_admit",
        ),
        now=NOW,
    )
    return draft, review, admission


def _command(action: str, draft, *, request_seed: str | None = None):
    seed = action if request_seed is None else request_seed
    return FixtureCommandAdmission(
        issuer_ref=ISSUER,
        subject_ref=REVIEWER if action == "fixture_review" else AUTHOR,
        context_ref=CONTEXT,
        action=action,
        target_ref=(
            draft.record.payload["fixture_ref"]
            if action == "fixture_draft"
            else draft.record.record_id
        ),
        target_digest=None if action == "fixture_draft" else draft.record.content_digest,
        target_revision=1,
        idempotency_key_digest=hashlib.sha256(("idem:" + action).encode()).hexdigest(),
        request_digest=hashlib.sha256(("request:" + seed).encode()).hexdigest(),
    )


def _mutations(draft, review, admission):
    return {
        "fixture_draft": FixtureAcceptedMutation(
            draft.record.record_id,
            (draft.family, *draft.authority_uses, draft.record),
            (),
        ),
        "fixture_review": FixtureAcceptedMutation(
            review.record.record_id,
            (*review.authority_uses, review.record),
            (),
        ),
        "fixture_admit": FixtureAcceptedMutation(
            admission.receipt.record_id,
            (admission.fixture_use, admission.receipt, admission.eligibility),
            (admission.event,),
        ),
    }


def _persist_lifecycle(repository, draft, review, admission):
    ledger = RepositoryFixtureCommandLedger(repository)
    mutations = _mutations(draft, review, admission)
    for action in ("fixture_draft", "fixture_review", "fixture_admit"):
        ledger.execute(_command(action, draft), lambda item=mutations[action]: item)


def test_ledger_replays_exact_command_after_repository_reopen(tmp_path: Path) -> None:
    coordinator, secret, profile, _vault = _coordinator(tmp_path)
    draft, review, admission = _fixture_facts(coordinator, secret, profile)
    mutation = _mutations(draft, review, admission)["fixture_draft"]
    command = _command("fixture_draft", draft)
    path = tmp_path / "fixture-ledger.sqlite3"

    with V3Repository.create(path, registry=FIXTURE_REPOSITORY_REGISTRY) as repository:
        first = RepositoryFixtureCommandLedger(repository).execute(
            command, lambda: mutation
        )
    with V3Repository.open(path, registry=FIXTURE_REPOSITORY_REGISTRY) as repository:
        ledger = RepositoryFixtureCommandLedger(repository)
        replay = ledger.execute(
            command,
            lambda: (_ for _ in ()).throw(AssertionError("executor ran on replay")),
        )
        with pytest.raises(IdempotencyConflict):
            ledger.execute(
                replace(command, request_digest="f" * 64),
                lambda: mutation,
            )

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.mutation_receipt_ref == first.mutation_receipt_ref


def test_receipt_failure_rolls_back_domain_records_and_command(tmp_path: Path) -> None:
    coordinator, secret, profile, _vault = _coordinator(tmp_path)
    draft, review, admission = _fixture_facts(coordinator, secret, profile)
    mutation = _mutations(draft, review, admission)["fixture_draft"]
    command = _command("fixture_draft", draft)

    with V3Repository.create(
        tmp_path / "fixture-rollback.sqlite3", registry=FIXTURE_REGISTRY
    ) as repository:
        with pytest.raises(IntegrityFailure):
            RepositoryFixtureCommandLedger(repository).execute(
                command, lambda: mutation
            )
        assert repository.get_record(draft.record.record_id) is None
        assert (
            repository.get_operator_command(
                issuer_ref=command.issuer_ref,
                subject_ref=command.subject_ref,
                context_ref=command.context_ref,
                action=command.action,
                idempotency_key_digest=command.idempotency_key_digest,
            )
            is None
        )


def test_repository_resolvers_hydrate_restart_state(tmp_path: Path) -> None:
    coordinator, secret, profile, vault = _coordinator(tmp_path)
    draft, review, admission = _fixture_facts(coordinator, secret, profile)
    path = tmp_path / "fixture-hydration.sqlite3"
    with V3Repository.create(path, registry=FIXTURE_REPOSITORY_REGISTRY) as repository:
        _persist_lifecycle(repository, draft, review, admission)

    restarted, _, _, _ = _coordinator(tmp_path, vault, profile)
    with V3Repository.open(path, registry=FIXTURE_REPOSITORY_REGISTRY) as repository:
        resolvers = RepositoryFixtureResolvers(
            repository,
            restarted,
            context_ref=CONTEXT,
            record_maximum=32,
            event_maximum=8,
        )
        restored_draft = resolvers.resolve_draft(
            ExactFixtureRecord(draft.record.record_id, draft.record.content_digest)
        )
        restored_review = resolvers.resolve_review(
            ExactFixtureRecord(review.record.record_id, review.record.content_digest)
        )
        restored_admission = resolvers.resolve_admission(
            ExactFixtureRecord(
                admission.receipt.record_id, admission.receipt.content_digest
            )
        )
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
            replay_seed=1,
            required_buckets=["regression"],
        )
        manifest = restarted.build_manifest(
            [ManifestSelection(restored_admission, restored_draft)],
            selection_policy_ref="selection:v1",
            execution_profile=execution,
            assessment_profile=assessment,
        )

    assert restored_draft == draft
    assert restored_review == review
    assert restored_admission == admission
    assert manifest.payload["entries"][0]["draft_id"] == draft.record.record_id


def test_withdrawal_finalizes_vault_only_after_durable_commit(tmp_path: Path) -> None:
    coordinator, secret, profile, vault = _coordinator(tmp_path)
    draft, review, admission = _fixture_facts(coordinator, secret, profile)
    path = tmp_path / "fixture-withdrawal.sqlite3"
    with V3Repository.create(path, registry=FIXTURE_REPOSITORY_REGISTRY) as repository:
        _persist_lifecycle(repository, draft, review, admission)

        restarted, _, _, _ = _coordinator(tmp_path, vault, profile)
        resolvers = RepositoryFixtureResolvers(
            repository,
            restarted,
            context_ref=CONTEXT,
            record_maximum=32,
            event_maximum=8,
        )
        identity = ExactFixtureRecord(draft.record.record_id, draft.record.content_digest)
        restored = resolvers.resolve_draft(identity)
        withdrawal = restarted.withdraw(
            restored,
            fixture_use=_grant(
                secret,
                profile,
                authority_class="fixture_use_grant",
                action="fixture_withdraw",
                purpose="fixture_replay",
                target_ref=draft.record.record_id,
                subject_ref=AUTHOR,
                nonce="session:fixture_withdraw",
            ),
            now=NOW,
        )
        assert draft.record.payload["vault_ref"] in vault.content
        command = _command("fixture_withdraw", draft)
        observed_committed: list[bool] = []

        def finalize(exact: ExactFixtureRecord) -> None:
            with V3Reader.open(path, registry=FIXTURE_REPOSITORY_REGISTRY) as reader:
                observed_committed.append(
                    reader.get_operator_command(
                        issuer_ref=command.issuer_ref,
                        subject_ref=command.subject_ref,
                        context_ref=command.context_ref,
                        action=command.action,
                        idempotency_key_digest=command.idempotency_key_digest,
                    )
                    is not None
                )
            resolvers.finalize_withdrawal(exact)

        result = RepositoryFixtureCommandLedger(
            repository, withdrawal_finalizer=finalize
        ).execute(
            command,
            lambda: FixtureAcceptedMutation(
                withdrawal.eligibility.record_id,
                (withdrawal.eligibility,),
                (withdrawal.event,),
            ),
        )
        receipt = repository.get_record(result.mutation_receipt_ref)

    replay_coordinator, _, _, _ = _coordinator(tmp_path, vault, profile)
    with V3Repository.open(path, registry=FIXTURE_REPOSITORY_REGISTRY) as repository:
        replay_resolvers = RepositoryFixtureResolvers(
            repository,
            replay_coordinator,
            context_ref=CONTEXT,
            record_maximum=32,
            event_maximum=8,
        )
        current = replay_resolvers.current_eligibility(identity)
        replay = RepositoryFixtureCommandLedger(
            repository, withdrawal_finalizer=replay_resolvers.finalize_withdrawal
        ).execute(
            command,
            lambda: (_ for _ in ()).throw(AssertionError("executor ran on replay")),
        )

    assert observed_committed == [True]
    assert draft.record.payload["vault_ref"] not in vault.content
    assert receipt.payload["vault_cleanup_mode"] == "post_commit_separate"
    assert current.payload["state"] == "withdrawn"
    assert replay.replayed is True
