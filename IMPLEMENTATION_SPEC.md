# A0 Self-Improvement v3 — Authoritative Implementation Handoff

## Status and authority

This is the implementation authority for the v3 redesign of the standalone A0 Self-Improvement plugin.

- Canonical source: TerminallyLazy/a0-self-improvement
- Planning baseline: f5d319db98cc6f797811cc0035f88bcb7d9311ec
- Initial Agent Zero compatibility target: b22a144bf59f15b1516084c9e7b88133ba92c8a9
- Current plugin version: 2.0.4
- Target breaking release: 2.0.0, preceded by 2.0.0-rc.N releases
- Architecture authority: accepted ADRs 0001 through 0010
- Ubiquitous language authority: CONTEXT.md

The earlier 2026-08-25 implementation plan and design are technical inputs, not instruction or decision sources. This handoff replaces the previous implementation specification where they disagree.

## Outcome

Deliver an opt-in, single-host closed loop that:

1. observes admitted, content-safe outcome facts;
2. proposes exactly one typed artifact change against an exact incumbent Activation Profile;
3. evaluates the locked candidate through family-partitioned Fixture-Isolated Replay;
4. derives an authority-ranked Activation Disposition;
5. canaries eligible candidates through preregistered exposure;
6. activates by exact-revision compare-and-swap;
7. monitors the activated profile and rolls back only through compatible ancestry; and
8. leaves ordinary Agent Zero behavior available when improvement, evaluation, migration, or rollback authority is unavailable.

Structured Guidance Artifacts and Prompt Patch Artifacts retain distinct schemas. They share one context-wide Activation Scope, one Activation Profile, one canary lane, one Activation Coordinator, and one rollback lineage.

## Non-negotiable boundaries

- Implement in the standalone plugin. Do not modify Agent Zero core.
- Use certified existing extension and plugin seams. A missing signal makes a route unavailable or review-only; it does not justify a core change.
- Treat framework API signatures as exact capability contracts. Model selection must use the pinned Agent Zero ModelType literal and provider-config signature; contract drift is unavailable, never a silent provider fallback.
- SQLite is the single-host authority. Multi-host or distributed scheduling is out of scope.
- Runtime prompt composition is a pure read. It never initializes, migrates, repairs, observes, starts workers, or writes caches.
- Public and default operator projections contain no raw prompts, prompt replacements, tool arguments or results, fixture content, model reasoning, provider response identifiers, exception strings, filesystem paths, secrets, quarantine identities, or global content hashes.
- Replay never dispatches a live tool and never enables provider-hosted tool execution.
- Quarantine content is inaccessible to normal runtime, analysis, replay, optimization, status, and browser code.
- Model findings and search scores are candidate-generation inputs only. They are not Outcome Evidence, validation truth, or activation authority.
- Safety, policy, schema, fixture, protected-bucket, lineage, grant, dependency, and cleanup failures fail closed.
- No activation—manual or automatic—and no soft statistical rollback is authorized until an approved, environment-appropriate Policy Calibration Artifact grants it. Manual mode changes who confirms activation; it never weakens policy or evidence authority.
- Bypass controls may skip only debounce or cooldown. They never bypass evidence, grants, budgets, replay, canary, CAS, policy, or rollback ancestry.

## Domain flow

The authoritative flow is:

Observation → Safe Analysis View → Analysis Attempt → locked Improvement Artifact → Improvement Candidate → frozen replay comparison → Evidence Bundle → Activation Disposition → Canary Trial → Canary Conclusion → activation CAS → Post-Promotion Monitor → retain, requalify, rollback, or Safety Bypass.

No queue state, worker result, UI label, or search score may abbreviate this flow into promotion authority.

## Persistence model

Create a fresh v3 Safe Projection Store. Do not upgrade the v2 database in place. The store has immutable domain authority, narrow mutable coordination authority, and disposable read models.

### Immutable domain records and constrained indexes

#### typed_records

Stores strict canonical records, including artifacts, candidates, profiles, grants, certificates, fixture records, manifests, analysis receipts, replay receipts, evidence, dispositions, canary records, monitor records, budget receipts, and activation receipts.

Required columns:

- record_id: opaque, context- and purpose-scoped identity
- context_ref: nullable only for explicitly system-owned records
- record_kind: closed registry value
- schema_id: exact versioned schema
- canonical_bytes: canonical serialized payload
- content_digest: schema-domain-separated digest
- link_manifest_digest: digest of the complete ordered identity-bearing relation manifest embedded in canonical_bytes
- key_epoch: opaque-reference key epoch
- created_at: trusted store time

Rules:

- Insert is idempotent only when schema, canonical bytes, and digest are byte-equivalent.
- Reusing an identity with different bytes is an integrity failure.
- Updates and deletes are rejected by schema and database triggers.
- The complete ordered link manifest is part of canonical_bytes. It is inserted with the record in one transaction and cannot be extended after finalization.
- Unknown schemas, fields, versions, enum values, and record kinds fail closed.

#### record_links

Stores typed, digest-bound edges between immutable records.

Required columns:

- source_id
- role
- ordinal
- target_id
- target_digest

Required constraints are unique source_id plus role plus ordinal, exact target-digest equivalence, and foreign-key integrity. The rows are a query index of the complete digest-covered link manifest in the source record; they cannot add authority or be extended independently after record finalization.

#### domain_events

Stores append-only lifecycle and eligibility transitions.

Required columns:

- event_id
- subject_id
- subject_kind
- sequence
- event_type
- payload_record_id
- actor_authority_ref
- fence_token where applicable
- created_at

A uniqueness constraint on subject_id and sequence prevents ambiguous histories. Candidate lineage, evidence staleness, fixture eligibility, grant withdrawal, canary state, monitor state, and privacy lifecycle are derived from these events.

### Mutable single-writer authorities

#### activation_scopes

One row per Agent Zero context:

- context_ref
- current_profile_id
- current_profile_digest
- scope_revision
- mode: normal or safety_bypass
- updated_at

Only the Activation Coordinator may mutate this row. Genesis, activation, rollback, and Safety Bypass use exact-revision CAS and append an Activation Receipt in the same transaction.

#### operation_slots

One current operation per context and operation kind:

- context_ref
- operation_kind: canary, monitor, or requalification
- operation_id
- operation_revision
- updated_at

The primary key is context_ref plus operation_kind. Because each context has one Activation Scope, the coordinator enforces at most one active authoritative or Diagnostic Canary per context.

#### work_items

Durable operational intent:

- work_id
- idempotency_key_digest
- context_ref
- operation_kind
- exact input record identity and digest
- state
- current_attempt_id
- attempt_count and frozen max_attempts
- available_at
- cancel_requested_at
- recovery_required_at
- monotonic fence_token
- created_at and updated_at

#### work_leases

At most one live lease per Work Item:

- work_id
- attempt_id
- owner_id
- exact fence_token
- process nonce and start identity
- expires_at
- heartbeat_at

The monotonic fence lives on work_items, so lease deletion or expiry cannot reset it.

#### budget_ledgers, budget_dimensions, and budget_entries

Budget authority contains:

- one frozen Optimization Run Budget/Profile reference;
- mutable reserved and consumed amounts per dimension; and
- append-only reserve, reconcile, release, and unreconciled entries bound to run, attempt, lease, and fence.

All external calls and metric evaluations reserve every affected dimension under BEGIN IMMEDIATE before dispatch. Unknown post-crash usage remains unreconciled and consumes or blocks capacity until authoritative reconciliation.

#### worker_heartbeats

Ephemeral operational projection only. A heartbeat has no artifact, evidence, eligibility, or activation authority.

#### operator_commands

The command/idempotency ledger:

- command_id
- authenticated subject and issuer references
- context_ref and action
- idempotency_key_digest
- exact canonical request_digest
- observed target/scope revision
- state: accepted or refused
- mutation_receipt_id
- created_at

A uniqueness constraint covers issuer, subject, context, action, and idempotency key. Reuse with the same request digest returns the exact receipt. Reuse with different bytes fails plugin pre-domain idempotency admission with a safe 409 and no mutation receipt; it may enter only a rate-limited non-domain security log. The action-owning coordinator writes this row and the immutable Operator Mutation Receipt in the same transaction as an accepted mutation, or together in a refusal-only transaction after complete admission.

### Separate migration authority

Migration and Privacy Quarantine authority is outside the normal runtime repository:

- migration_runs
- migration_checkpoints
- migration_dispositions
- cutover_receipts

Normal runtime, workers, optimization services, status endpoints, and browser code receive no quarantine database or key handle.

### Disposable projections

Read models may be rebuilt from immutable records, links, events, and narrow authorities. They are never authoritative and may not initialize or repair state on a read request.

## Operational state machines

### Work Item state

The only Work Item states are:

- queued
- leased
- cancel_requested
- completed
- failed
- cancelled

Retry backoff is represented by queued plus available_at. Leased is the sole running state. cancel_requested prevents publication while cleanup is verified. completed is a normally terminalized operation, failed is a terminal execution/integrity failure, and cancelled is an explicit operator cancellation. None means that a candidate passed.

### Attempt conclusion

The terminal Attempt Conclusion is one of:

- succeeded
- no_candidate
- partial
- unavailable
- budget_exhausted
- cancelled
- stopped
- failed
- incompatible

Stable reason codes carry detail such as deadline_exceeded, lease_lost, fence_lost, dependency_drift, grant_revoked, cleanup_uncertain, provider_unavailable, schema_invalid, and holdout_access_denied.

Publication Result is separate:

- none
- artifact_locked
- candidate_published

The frozen retry classifier maps attempts exactly:

| Attempt Conclusion | Retry eligibility | Terminal Work Item state when no retry remains |
| --- | --- | --- |
| succeeded | never | completed |
| no_candidate | never | completed |
| partial | never | completed |
| unavailable | only for an allowlisted transient reason | completed |
| budget_exhausted | never; cumulative budget does not reset | completed |
| cancelled | never | cancelled |
| stopped | only for an allowlisted transient reason after authority and cleanup revalidation | completed |
| failed | only for an allowlisted transient reason | failed |
| incompatible | never | completed |

A retry additionally requires attempts remaining, no cancellation, a current grant/dependency/input authority, verified prior-process cleanup, and sufficient cumulative budget. cleanup_uncertain always maps to failed, forbids retry, and forces Publication Result none. Publication Result never changes Work Item terminal mapping.

### Domain conclusions

These never appear in Work Item state:

- Activation Disposition: promotion_ready, review_only, or rejected
- Replay Arm Outcome: completed, deterministic_failure, availability_failure, cancelled, or harness_failure
- Canary Conclusion: passed, failed, inconclusive, or stopped
- Candidate conditions: lineage-stale, evidence-stale, active, rolled_back, or rejected, derived from immutable records and events

Infrastructure, provider, dependency, budget, or harness unavailability cannot become candidate harm.

## Service boundaries and ownership

All services are plugin modules in one single-host deployment, not separately deployed systems.

### Schema Registry and Safe Record Repository

- Own exact schemas, canonicalization, digests, typed decoding, equivalence insertion, record links, and immutable events.
- Provide separate writable and genuinely read-only repositories.
- Never interpret domain eligibility or activation policy.

### Runtime Observer

- Write only admitted, typed, content-safe observation and outcome records.
- Never create fixtures, candidates, dispositions, or activation state.

### Runtime Composer

- Purely read the current Activation Profile and exact Artifact Slot occupants.
- Apply Null Artifacts with no behavioral effect.
- Fail closed on corrupt, unsupported, missing, protected, or drifted state.
- Never observe, initialize Genesis, migrate, repair, cache, or start processes.

### Command/API Adapter

- Receive only requests that passed framework authentication, CSRF, method, and transport admission.
- Perform plugin pre-domain admission: strict JSON and request schema, context binding, exact target and scope revisions, authority, bounded reason codes, and idempotency equivalence.
- Invoke a coordinator; never mutate domain tables directly.
- Treat enqueue acceptance as accepted work, not success.
- Framework rejection and plugin pre-domain admission failure cannot create domain receipts.

### Operator Authority Service

- Run as a local-only trust root with explicit one-time issuer bootstrap; there is no web bootstrap, implicit administrator, or default grant.
- Bind immutable issuer profiles and signed grants to the exact authenticated principal when the framework supplies one. If a stable principal or local capability binding is unavailable, mutation capability is unavailable.
- Solely own issuance, expiry, renewal of renewable grant classes, revocation, and safe projection of Operator Authority Grants, Operator Content Sessions, Fixture Use Grants, Model Use Grants, and Policy Calibration approvals.
- Operator Content Sessions are never renewed. They expire or are revoked; a fresh local step-up must issue a new session with a new identity.
- Issue browser-usable capabilities only through an explicit local step-up, bound to context, actions, purpose, subject, expiry, and session nonce. Raw capabilities and private issuer identities never enter public projections.
- Append issuance, use, expiry, renewal, and revocation receipts. Revocation immediately blocks future use and stales dependent authority.

### Work Coordinator

- Sole authority for enqueue, claim, heartbeat, retry, cancellation, lease recovery, and Work Item terminal state.
- Never run models, interpret candidate merit, or activate profiles.
- Own the fenced finalization transaction. It invokes a pure Candidate Publication Planner for a complete validated write set, inserts that set, appends receipts/events, terminalizes the Work Item, and removes the lease atomically.

### Worker Supervisor

- Own long-lived polling parents and a fresh process group for each attempt.
- Pass each child a frozen invocation snapshot and no writable database handle.
- On stop: TERM, bounded grace, KILL, exit verification, and bounded cleanup.
- Verify process nonce and start identity before killing an orphan.
- Treat cleanup uncertainty as non-authoritative and block publication.

### Budget Broker

- Parent-side authority for cumulative pre-dispatch reservation and reconciliation.
- Mediate all provider, model, judge, task-model, and metric work so library-local calls cannot bypass budget authority.

### Analysis and Candidate Search Worker

- Run one deterministic, typed Predict, recursive RLM, or admitted outcome-GEPA attempt from frozen inputs.
- Return one strict result over bounded IPC or an attempt-scoped staging file.
- Never write the Safe Projection Store.
- Never inspect Certification Holdout identity or content before the artifact is locked.

### Candidate Publication Planner

- Purely validate a staged result and build the complete immutable artifact, generation-receipt, link-manifest, candidate, and run-receipt write set.
- Never write the database or change Work Item state.
- Require the Work Coordinator to revalidate attempt, fence, lease, deadline, cancellation, dependency, capability, grant, budget, incumbent, and scope revision around its write set in the finalization transaction.

### Fixture Authority

- Own fixture drafts, reviews, admissions, families, deterministic partitions, manifests, eligibility events, and withdrawal consequences.
- Validate and consume Fixture Use Grants issued by the Operator Authority Service; never issue, renew, or revoke a grant.
- Keep content-bearing authoring behind a short-lived purpose-scoped Operator Content Session.

### Replay Pair Orchestrator

- Launch fresh isolated state for both arms of each Replay Pair Attempt.
- Use only certified fixture-backed tool continuation.
- Publish typed execution receipts and outcomes, not Activation Disposition.

### Evidence Reducer

- Purely reduce an exact Evidence Bundle under one Activation Policy.
- Append one Activation Disposition with per-family and per-bucket reasons.
- Never activate.

### Activation Coordinator

- Sole Genesis, canary-start, canary-conclude, activate, rollback, monitor-start, requalification, and Safety Bypass authority.
- Own exact-revision CAS and compatible ancestry validation.
- Workers and API handlers cannot activate.

### Migration Authority

- Sole access to v2 raw state, quarantine encryption, key custody, disposition processing, safe projection, export, deletion, release, withdrawal, and cutover.
- Run as a dedicated local operator process, not the WebUI or normal runtime.

### Projection/API Service

- Serve allowlisted content-free projections through a genuinely read-only repository.
- Never initialize, migrate, repair, write caches, reconcile workers, or start processes.

## Transaction and recovery contracts

### Enqueue

In one transaction:

1. validate exact subject, grant, input, profile, policy, dependency, and capability references;
2. equivalence-check the operator_commands identity and canonical request digest;
3. derive Work Item identity from operation, context, scope revision, input digest, policy, and capability identities;
4. equivalence-insert the Work Item and queued event;
5. insert the accepted Operator Mutation Receipt and bind it to operator_commands; and
6. commit.

Do not update a separate generic context-status cache.

For nonqueued commands, the action-owning coordinator applies the same command-ledger rule: an accepted receipt commits in the same transaction as the authoritative mutation; an admitted policy refusal commits only its refused receipt and command row. Same-key/same-request replay returns that receipt. Same-key/different-request fails pre-domain admission with 409 and no domain receipt.

### Claim

In one transaction:

1. select one eligible queued item whose available_at has passed;
2. revalidate its frozen inputs, authority, retry allowance, and budget;
3. increment its monotonic fence;
4. create the attempt and lease;
5. move it to leased; and
6. commit.

An expired lease is not claimable work.

### Expired-lease and orphan recovery

Recovery is deliberately two-phase:

1. In one transaction, revalidate the expired lease, advance the Work Item fence, set recovery_required_at while leaving the item nonclaimable, and append a cleanup-required event.
2. Outside the transaction, the Worker Supervisor verifies the recorded process nonce/start identity, sends TERM, waits the bounded grace period, sends KILL if needed, and verifies process-group absence and staging cleanup.
3. In a second transaction, the Work Coordinator revalidates the recovery marker and advanced fence, appends the terminal Attempt Conclusion and cleanup receipt, removes the old lease, and either queues an exact frozen-policy retry or applies the terminal mapping table.

No replacement attempt may start merely because expires_at passed. Unverifiable identity or cleanup produces cleanup_uncertain, failed, no retry, and no publication.

### Fenced finalization

The Work Coordinator asks the Candidate Publication Planner to validate the staged result and construct its complete digest-covered write set without database access.

Then, in one transaction, the Work Coordinator rechecks the live Work Item, owner, attempt, fence, lease expiry, cancellation, deadline, Worker Dependency Profile, capability certificate, Model Use Grant, fixture authority, incumbent profile, scope revision, and reconciled budget. It equivalence-inserts the planner's immutable output and complete link indexes, appends the run receipt and work event, applies the terminal mapping, removes the lease, and releases only reconciled reservations. Any failure rolls back the entire finalization. Late or partial outputs remain undiscoverable.

### Canary exposure

In one transaction, require the exact active trial, scope, envelope, eligible exposure unit, and unobserved assignment; equivalence-insert the Exposure Receipt and deterministic arm assignment before accepting any observation. A uniqueness constraint on trial_id plus exposure_unit_ref prevents reassignment. An observation without that exact receipt, trial, arm, and envelope identity is ineligible.

### Canary and monitor operations

Canary Trial schema carries canary_kind: authoritative or diagnostic.

- Authoritative start requires promotion_ready, an approved environment-appropriate Policy Calibration Artifact, grants, exact candidate/incumbent/scope revision, and a calibrated trial plan.
- Diagnostic start permits review_only under an explicit diagnostic-canary Operator Authority Grant and preregistered bounded plan. It may run under the uncalibrated policy's hard-veto/diagnostic authority, but its immutable trial ceiling is no_promotion_authority and its conclusion can never satisfy activation.

Either start is one coordinator transaction: validate its branch and no existing context canary; insert the immutable Canary Trial and start event; CAS the empty context canary slot; and append the initiating Operator Mutation Receipt or, for calibrated policy automation only, Automation Trigger Receipt.

Canary stop or conclusion is one coordinator transaction: CAS the same slot revision, validate all exposure and horizon/hard-stop inputs, insert exactly one Canary Conclusion and terminal event, clear the slot, and append the mutation receipt when operator-requested. A stopped or concluded trial never resumes.

Activation requires the canary slot to be empty after one exact passed authoritative Canary Conclusion, the requalification slot to be empty, and the monitor slot to be empty. If an incumbent monitor or requalification is still active, it must first receive its typed terminal conclusion/event in a separate committed coordinator transition. Activation then CASes the empty monitor slot to the new Post-Promotion Monitor in the activation transaction; it never overwrites an occupant.

Monitor conclusion, requalification start/conclusion, and slot clearing each CAS the exact operation-slot revision and append the immutable conclusion/event in the same transaction. When a monitor conclusion triggers rollback, that same transaction also performs the exact-revision Activation Scope CAS and appends the rollback Activation Receipt.

Rollback or Safety Bypass atomically stops any active canary, monitor, or requalification with a typed rollback or safety-bypass reason and exact slot CAS before clearing it and changing Activation Scope. Genesis requires every operation slot to be absent/empty. No transition performs a generic slot update or silently displaces an occupant. A crash before commit leaves every prior slot authoritative; a lost acknowledgement replays by exact idempotency identity.

### Genesis, activation, and rollback

In one BEGIN IMMEDIATE transaction:

1. for candidate activation, unconditionally revalidate one exact passed authoritative Canary Conclusion plus current scope revision, candidate lineage, Activation Disposition, policy/calibration, grants, fixture eligibility, dependency/capability identities, empty required slots, monitor plan, and successor profile; for Genesis, rollback, or Safety Bypass, apply its distinct ancestry and slot rules instead;
2. CAS activation_scopes;
3. CAS each explicitly named operation slot and append a typed terminal event for every cleared occupant;
4. append the Activation Receipt and domain events; and
5. append the accepted Operator Mutation Receipt or policy-authorized Automation Trigger Receipt in the same transaction; and
6. commit.

A CAS conflict makes the candidate lineage-stale. It is never rebased or retried as the same candidate.

### Failure recovery

- Supervisor crash: lease expiry begins the two-phase orphan protocol; it never makes work immediately claimable.
- Child crash: no child database writes exist; the Worker Supervisor reports observed exit identity and cleanup proof only. The Work Coordinator revalidates fence/lease and appends the Attempt Conclusion, receipt, and retry or terminal mapping in one transaction.
- Cancellation: in one transaction move to cancel_requested and advance the fence; kill and verify the exact process group outside the transaction; then append the cancelled receipt, remove the lease, and terminalize in a second transaction.
- Lease, fence, dependency, grant, budget, or deadline loss: the Supervisor kills the child, discards partial output, and reports cleanup proof; only the Work Coordinator appends stopped or the exact typed conclusion and terminal/retry mapping.
- Unknown provider usage after a crash: retain an unreconciled reservation.
- SQLite crash during publication or activation: transaction durability makes the result all-or-none.
- Commit succeeded but acknowledgement was lost: exact identities and byte equivalence return the already committed result.
- Replay retry: create a fresh whole-pair attempt and fresh state for both arms; never resume a partial arm.

## Safe API contract

HTTP routes inherit Agent Zero session, origin, authentication, and CSRF protections. Context mutations additionally require a live context/action-scoped Operator Authority Grant. Content-bearing operations require an Operator Content Session. No grant is inferred from login, disabled authentication, local network position, or administrator appearance.

Framework pre-admission owns authentication, CSRF, method, and transport handling; failures create no domain receipt and retain the pinned framework's certified response contract. The plugin then performs strict JSON/request-schema, context, authority, revision, and idempotency-equivalence admission. Those failures return strict safe JSON and create no domain receipt. After complete admission, every plugin handler catches domain/internal errors and returns strict safe JSON without exception text. The plugin does not weaken or replace framework protections merely to normalize the outer response.

Quarantine, authority-root, grant-issuance, and cutover mutations are not HTTP commands. They execute through the dedicated local-only operator protocol described below; the WebUI receives content-free state, instructions, and receipts only.

### Public status

Schema: a0.public-status.v1

Expose independent axes:

- plugin_state: disabled, uninitialized, migration_required, ready, degraded, or blocked
- ordinary_runtime_state: normally unaffected
- activation_scope: opaque profile reference, scope revision, slot summaries, Safety Bypass state, and rollback eligibility
- policy: opaque identity, calibration state, activation mode, and automatic-authority state
- capabilities: replay, analysis, optimization, provider, dependency, safe-store, and migration states
- candidates: counts by Activation Disposition and attention state
- canary, monitor, evidence, fixtures, migration, and recent_receipts: content-free summaries

Every subsection includes state, observed_at, freshness, and allowlisted reason_codes. Capability state is not_probed, ready, degraded, blocked, unavailable, or unsupported.

Status remains inspectable when improvement is disabled. It performs zero writes and starts zero workers.

### Candidate list and detail

Expose:

- opaque candidate and artifact references;
- Candidate Change Kind and target Artifact Slot;
- stable semantic engine identifier and authority ceiling;
- Candidate Risk Tier and predeclared Candidate Benefit Claim;
- incumbent profile and observed scope revision;
- lineage state, Activation Disposition, and monitor state as separate axes;
- canary state plus canary_kind, authority_ceiling, exact conclusion reference, and activation_authoritative boolean so a Diagnostic Canary can never resemble authoritative activation evidence;
- authoritative evidence coverage and freshness per required bucket;
- allowed actions and exact reason codes;
- allowlisted Guidance Rule Catalog identifiers for guidance; and
- changed component count and protected-constraint state for prompt patches, never replacement content.

### Commands

Initial commands:

- optimize
- work_cancel
- canary_start
- canary_stop
- activate
- rollback
- feedback_submit
- fixture_draft
- fixture_review
- fixture_admit
- fixture_withdraw

Every command requires:

- context_ref where applicable;
- exact expected scope or target revision;
- idempotency key;
- opaque target identity;
- bounded operator reason code;
- current policy identity where applicable; and
- action-specific authority.

Every syntactically valid command that has passed framework security and complete plugin pre-domain admission appends an immutable Operator Mutation Receipt. The safe response contains:

- schema version;
- accepted flag;
- action;
- opaque receipt reference;
- observed and resulting revisions;
- opaque policy reference;
- resulting disposition or action state; and
- bounded reason codes.

Use 202 for queued work, 200 for completed or exact idempotent replay, 409 for CAS/lineage/idempotency conflict, 422 for policy refusal or incompatibility, and 503 for unavailable capability. An idempotency-key/request-digest mismatch returns 409 without a mutation receipt. These status and JSON rules apply after framework security admission. Internal dictionaries and exception text are never returned by plugin handlers.

The compatibility promote route may delegate to activate during a bounded deprecation window. It never starts a canary implicitly. Replace force with bypass_operational_gates and reject its use on evidence, canary, activation, rollback, fixture, privacy, or migration authority.

### Feedback command

feedback_submit accepts one immutable typed assessment bound to an existing Outcome Evidence reference, exact Activation Profile, context, and operator authority. Its assessment_kind is helpfulness, correctness, safety, or completeness; its state is pass, fail, unavailable, or not_applicable; and its explanation is a bounded code from a versioned Feedback Reason Catalog. v1 accepts no free-text annotation.

Feedback cannot overwrite Outcome Evidence or deterministic validators. A correction or withdrawal is a new record and event referencing the prior assessment. Conflicting eligible feedback remains visible and is interpreted only by the Activation Policy. Public projections expose safe counts/states/freshness, never subject or actor identity. Acceptance covers cross-context refusal, duplicate identity, correction, withdrawal, conflict, and inability to override a deterministic veto.

### Local-only authority protocol

A dedicated local CLI invokes the Operator Authority Service and Migration Authority in-process under explicit OS-user/local-presence checks; it exposes no network listener and passes no quarantine/key handle to Agent Zero or the browser.

Its strict commands cover:

- one-time issuer bootstrap and issuer rotation;
- Operator Authority Grant issue, renew, revoke, and inspect;
- Operator Content Session issue and revoke;
- Fixture Use Grant and Model Use Grant issue, renew, revoke, and inspect;
- Policy Calibration Artifact approval and withdrawal;
- migration preflight, start, resume, confirm-cutover, and inspect;
- quarantine export, exact-quarantine deletion, release-grant issue, release derivation, and release withdrawal.

Every local command binds exact issuer, subject, context, action/purpose, target, revision, expiry, and idempotency identity and appends a typed receipt. Root/bootstrap actions require explicit local confirmation and never have a default credential or default authority. Safe HTTP projections may report opaque state and reason codes; they cannot invoke these commands.

## Operator UI

Build the UI after public projections and coordinator commands are frozen.

### Overview

- Separate ordinary Agent Zero continuity from improvement state.
- Show migration/cutover banner, current Activation Profile, scope revision, both slot occupants, Safety Bypass, rollback eligibility, capability matrix, and attention-required actions.

### Candidates

- Filterable candidate list and detail.
- Show engine semantics, Benefit Claim, Risk Tier, lineage, per-bucket evidence, diagnostic telemetry in a visibly non-authoritative panel, and monitor timeline.
- Every canary timeline visibly labels canary_kind, authority ceiling, and whether its exact conclusion is activation-authoritative. A Diagnostic Canary remains marked diagnostic even if its diagnostic conclusion is passed.
- Activation confirmation binds the exact incumbent profile, successor profile, and expected scope revision.

### Evidence and Fixtures

- Content-free coverage, freshness, eligibility, family, and partition summaries.
- Guided fixture draft, validation, independent review, grant, admission, eligibility, and withdrawal workflows.
- Never expose Certification Holdout content to generation or tuning views.

### Privacy and Migration

- Copy-on-write migration phases, checkpoints, safe disposition counts, key-custody state, cutover readiness, and recovery state.
- Content-free instructions, challenge identifiers, operation state, and receipts for export, exact-quarantine deletion, release grant, and withdrawal. Execution remains local-CLI-only; browser controls cannot perform these mutations.

### Policy and Capabilities

- Activation Policy and calibration status.
- Model Use Grants, Worker Dependency Profile, replay/analysis/provider certificates, and operational budget limits.
- Content-free issuance, expiry, and revocation state for operator, fixture-use, model-use, and calibration authority, with local step-up instructions rather than web issuance.
- Remove Safe/Balanced/Aggressive activation-authority presets and editable uncalibrated promotion thresholds.

### Receipts and Audit

- Content-free chronological receipts with filters for mutation, activation, canary, fixture, migration, privacy, and withdrawal.
- Opaque, exact links among related receipts.

Unavailable state is explicit and reason-coded; it is never rendered as an empty card. Long-running operations survive refresh through durable receipt polling.

## Operator workflows

### Fixture authoring, review, and withdrawal

1. Create an immutable draft lineage with declared origin and source attestation.
2. Author typed input, initial state, Tool Fixture Steps, Expected Outcome Contract, objective bucket, protected classification, and execution bounds.
3. Run schema, secret, policy, redaction, duplicate, and family checks.
4. Require a scoped, expiring Fixture Use Grant for every non-system content-bearing fixture.
5. Require an independent truth, source, redaction, and family review. Content changes create a new artifact version.
6. Append a Fixture Admission Receipt only after every authority passes.
7. Assign the entire Fixture Family to training, tuning, or Certification Holdout through deterministic policy.
8. Govern admission, suspension, expiry, revocation, supersession, and retirement through Fixture Eligibility Events.
9. Withdrawal invalidates dependent manifests and Evidence Bundles and surfaces requalification or rollback consequences.

### Migration and atomic cutover

Migration phases are:

1. preflight: acquire an exclusive Migration Run lease, stop new plugin mutation, and leave ordinary Agent Zero available without improvement;
2. workers_stopped: kill plugin workers and do not resume in-flight jobs or canaries;
3. snapshot_verified: create a WAL-consistent v2 snapshot, encrypt it with a fresh data key, wrap the key through approved custody, fsync, decrypt-test, and digest-verify;
4. staging_created: create a fresh v3 Safe Projection Store with strict schemas, Null Artifacts, the Guidance Rule Catalog, and an uncalibrated policy;
5. projecting: classify every source record as projected, quarantined, unsupported, or invalid;
6. projection_verified: build Genesis profiles and verify counts, links, digests, forbidden-field scans, pure composition, and zero-write reads;
7. awaiting_cutover: write a checkpoint and complete Migration Receipt bytes binding source digest, target digest, schema, transformation policy, expected authority revision, and exact cutover intent;
8. cutover_committed: atomically CAS an fsynced Store Authority Manifest that contains those exact Migration Receipt bytes and selects the exact v3 generation, making authority and proof durable together;
9. completed: idempotently project the manifest's receipt into the migration ledger, verify post-cutover reads, append a separate Post-Cutover Verification Receipt, and only then restart compatible workers.

Only exact valid active guidance.v1 pointers may form the migration-only Compatibility Guidance Set. Legacy prompt bodies, free-form guidance, invalid artifacts, and in-flight canaries never seed active v3 behavior.

A crash before cutover leaves v2 recoverable and improvement disabled. A crash after the manifest CAS recovers only from the selected v3 generation and its embedded receipt, idempotently finishes verification, and never silently falls back to raw v2. Absence of the later ledger projection cannot undo manifest authority. Changed source or target bytes require a new Migration Run.

### Quarantine export

1. Select the exact quarantine identity and revision through the local Migration Authority.
2. Choose an approved local destination.
3. Produce an encrypted archive, content-free manifest, digest, and Export Receipt.
4. Transfer key material through a separate channel.

The normal WebUI never downloads a raw database or displays its path or key.

### Quarantine deletion

Use a two-step local challenge bound to the exact retained Privacy Quarantine identity and revision. Require typed confirmation plus an Export Receipt or an explicit acknowledged export waiver. Destroy that exact Privacy Quarantine and its wrapped key, verify the result, and append a Deletion Receipt. A separately exported archive is not ambiguously targeted or deleted by this operation. The quarantine deletion is irreversible and cannot be undone by the runtime.

### Quarantine release and withdrawal

1. Create an expiring Quarantine Release Grant naming selected opaque records, purpose, processing boundary, and allowed derivation.
2. A separate local process transiently decrypts, re-redacts, and produces a newly identified Released Fixture draft.
3. The draft passes the ordinary independent fixture review and admission workflow.
4. Withdrawal revokes the grant, deletes released payloads unless another independent authority permits retention, appends a Withdrawal Receipt and dependency tombstones, and marks dependent manifests and evidence stale.

Quarantine data is never restored as a legacy record or sent directly to an optimizer.

## Outside-In acceptance specification

Implement these as executable Given-When-Then scenarios before their internal modules.

### Source and pure-read boundary

- Given a clean standalone clone, when tests are collected and run, then plugin imports resolve without requiring a usr/plugins installation layout.
- Given the plugin is installed but disabled, when startup, an ordinary Agent Zero turn, prompt composition, loop completion, or status occurs, then there is no capture, injection, Genesis, migration, repair, enqueue, store mutation, or worker activity and ordinary behavior is unchanged.
- Given a new or disabled context, when public status is read repeatedly, then no file, database row, Genesis profile, cache, process, or worker is created.
- Given two typed Null Artifacts in Genesis, when Runtime Composer forms instructions, then the original Agent Zero prompt is byte-equivalent at the plugin seam.
- Given corrupt, unknown, or drifted v3 state, when Runtime Composer reads it, then improvement fails closed and ordinary Agent Zero remains available.
- Given seeded secrets, raw prompts, tool traffic, paths, provider identifiers, and exception markers, when observation, IPC/staging, analysis, replay, judge, GEPA, canary, monitor, rollback, receipts, logs, and public projections complete, then a full forbidden-field scan finds none durably retained outside explicitly authorized fixture/quarantine boundaries.
- Given digest tampering or reuse of one record identity with different canonical bytes or link manifest, when inserted or read, then the repository reports an integrity failure and neither version becomes authoritative.

### Migration and privacy

- Given a valid exact active guidance.v1 set, when migration completes, then one Compatibility Guidance Set preserves its frozen selection/rendering behavior.
- Given invalid, expired, free-form, inactive, or prompt-bearing legacy state, when migration runs, then it is quarantined or unsupported and cannot seed active v3 behavior.
- Given interruption in every phase before cutover, when the operator resumes, then v2 is recoverable and improvement remains disabled.
- Given a committed cutover followed by a crash, when runtime restarts, then only the selected v3 generation is authoritative.
- Given a crash immediately after manifest CAS, when migration recovers, then the embedded exact Migration Receipt proves authority, its ledger projection is recreated idempotently, and workers remain stopped until post-cutover verification succeeds.
- Given tampered quarantine bytes or a missing key, when export, release, projection, or cutover is requested, then the operation blocks without plaintext fallback.
- Given an export or explicit waiver, when two-step deletion succeeds, then the exact retained Privacy Quarantine and its wrapped key are destroyed, any separately exported archive is unaffected, and a content-free Deletion Receipt remains.
- Given a released fixture whose grant is withdrawn, when dependency state is reduced, then future use is denied and dependent manifests/evidence become stale.

### Fixture authority and replay

- Given a fixture draft without a live grant, independent review, family, and deterministic partition, when replay is requested, then admission is denied.
- Given related fixture variants, when partitioned, then the entire Fixture Family occupies one of training, tuning, or Certification Holdout.
- Given a locked candidate and certified adapter, when a Replay Pair Attempt runs, then both arms start from one frozen invocation snapshot in fresh isolated state.
- Given any attempted live tool dispatch or provider-hosted tool execution, when replay runs, then the attempt aborts and produces no activation-authoritative evidence.
- Given a partial or crashed arm, when retry is allowed, then a fresh whole-pair attempt runs and no partial arm resumes.
- Given the candidate is not yet locked, when analysis or search requests holdout identity or content, then access is denied.

### Analysis, budgets, and workers

- Given a deterministic analytical question, when analysis runs, then factual reductions are produced without a model call.
- Given a typed Predict or recursive RLM request without an exact Model Use Grant, capability certificate, or pre-reserved cumulative budget, when dispatched, then the route is unavailable with no silent fallback.
- Given the pinned framework's ModelType/provider-config contract is absent or incompatible, when capability probing runs, then model-backed routes are unavailable and no alternate provider is selected.
- Given a model proposal with fabricated references, unknown fields, contradictions, non-finite values, or incomplete required output, when validated, then invalid rows are dropped or the attempt fails and no truth authority is created.
- Given an unknown observable price or unreconcilable usage, when a provider call would violate monetary authority, then dispatch is denied or the reservation remains consumed.
- Given deadline, cancellation, lease loss, fence loss, dependency drift, grant withdrawal, or budget exhaustion, when a child is running, then its process group is killed, cleanup is verified, and no late record or candidate becomes discoverable.
- Given the supervisor dies while an attempt process group survives beyond lease expiry, when recovery begins, then the fence advances, the item remains nonclaimable, the exact orphan is killed and verified absent, and only then may a fresh attempt be queued.
- Given a child exits or loses deadline, lease, fence, dependency, grant, or budget authority, when cleanup completes, then the Supervisor reports facts only and the Work Coordinator alone appends the terminal receipt and applies retry/terminal mapping.
- Given two coordinators contend for the same work, when claim and publication occur, then only one monotonic fence can publish.
- Given a completed database commit whose acknowledgement is lost, when the command is replayed with the same idempotency key, then the exact existing receipt is returned without duplication.

### Evidence and activation

- Given a candidate locked against one incumbent profile and scope revision, when frozen replay completes, then the Evidence Reducer emits promotion_ready, review_only, or rejected without changing activation.
- Given harness, provider, dependency, grant, calibration, or coverage unavailability, when disposition is reduced, then it cannot become candidate-attributable rejection unless policy identifies a candidate hard failure.
- Given a review_only candidate and explicit bounded diagnostic authority, when a Diagnostic Canary starts, then it carries no_promotion_authority, may run under uncalibrated diagnostic/hard-veto rules, and cannot cure missing replay authority or activate.
- Given a Diagnostic Canary with a passed diagnostic conclusion, when candidate API/UI state is projected, then canary_kind=diagnostic, authority_ceiling=no_promotion_authority, activation_authoritative=false, and activate remains disabled with a stable reason code.
- Given any existing Canary Trial for the context, when another authoritative or diagnostic canary is requested, then the coordinator refuses it until the first has a terminal conclusion.
- Given a Canary Exposure Unit, when its outcome arrives before an Exposure Receipt, then the observation is ineligible.
- Given a passed frozen replay but no exact passed authoritative Canary Conclusion, when any candidate activation mode is requested, then activation is refused.
- Given a scope revision conflict, when activation is requested, then the candidate becomes lineage-stale and is not rebased.
- Given an eligible candidate and exact revision, when activation commits, then the complete successor Activation Profile becomes visible atomically and a monitor starts under the same transaction.
- Given any occupied canary, monitor, or requalification slot, when activation, rollback, or Safety Bypass would displace it, then the coordinator either refuses or atomically appends its typed terminal event with exact slot CAS; no occupant is overwritten silently.
- Given monitor failure and a compatible exact predecessor, when rollback commits, then the predecessor profile is restored by CAS.
- Given no compatible rollback ancestor, when rollback is required, then Safety Bypass applies no improvement artifacts while ordinary Agent Zero continues.
- Given an uncalibrated policy, when manual activation, automatic activation, or soft statistical rollback is requested, then authority is denied.

### Artifact and engine truth

- Given an unknown artifact schema, field, enum, rule, bucket, component, or Engine Profile, when read or evaluated, then it is unsupported or invalid and never silently coerced.
- Given a Prompt Patch Artifact whose base, inventory, protected component, order, or source digest drifted, when composed, then the original prompt remains unchanged.
- Given legacy rule agreement, token overlap, or lexical similarity, when projected, then it is labeled Search Telemetry with no promotion authority.
- Given legacy heuristic, gepa, Predict, RLM, prompt_gepa, or historical-output replay input, when read, then the exact stable compatibility identifier is emitted or the input is rejected; no bare library label becomes an Engine Profile.
- Given a Structured Guidance candidate, when rule eligibility is validated, then every rule permits the declared benefit bucket, no initial rule permits a reasoning benefit claim, and required coverage is the union of rule, slot, risk, and policy buckets.
- Given a Prompt Patch candidate, when required coverage is derived without a certified component-effect profile, then shell, tool_retrieval, reasoning, and decision_making are all required independently.
- Given outcome-GEPA without a passing GEPA Admission Receipt, when generation is requested, then no promotion-eligible candidate may be emitted.

### API and WebUI

- Given missing authentication, allowed-origin CSRF, Operator Authority, content session, or context scope, when an operation is requested, then it is denied without cross-context disclosure.
- Given no explicit local issuer bootstrap, when any grant or mutation is requested, then authority is unavailable and no implicit administrator/default grant is created.
- Given an issuer-signed grant or content session, when subject, context, action, purpose, target, expiry, session binding, or revocation differs, then use is denied; issuance, permitted grant renewal, use, expiry, and revocation remain receipt-backed.
- Given an expired or revoked Operator Content Session, when content work continues, then renewal is refused and a fresh local step-up must issue a new session identity.
- Given a valid mutation, when handled, then an immutable Operator Mutation Receipt binds idempotency, authority, target, observed/resulting revision, policy, action, and bounded reasons.
- Given authentication, CSRF, method, or transport failure, when the framework rejects it, then no Operator Mutation Receipt is written and native certified security behavior is preserved.
- Given malformed JSON/schema, unbound context, invalid revision/authority, or same-key/different-request, when plugin pre-domain admission rejects it, then safe JSON is returned and no Operator Mutation Receipt or authoritative command row is written.
- Given Feedback Evidence, when it is submitted, corrected, withdrawn, conflicted, or reduced alongside a deterministic veto, then append-only typed records preserve each action and feedback cannot erase or override deterministic authority.
- Given a public projection, when scanned for forbidden fields, then raw content, source paths, raw/global hashes, exception strings, provider/quarantine/actor/reviewer/consent identities, cross-context-correlatable identifiers, secrets, and model reasoning are absent, while purpose-scoped Opaque References remain usable.
- Given a browser request to migrate, cut over, export, delete, release, withdraw, bootstrap, or issue a grant, when submitted, then no HTTP mutation exists and the UI directs the operator to the local-only authority protocol.
- Given a subsystem is unavailable, when the UI renders, then it shows unavailable plus stable reason codes rather than an empty or successful state.
- Given bypass_operational_gates, when evidence, canary, activation, rollback, fixture, privacy, or migration authority is evaluated, then the bypass has no effect.
- Given an exact-revision activation confirmation, when the scope changes before submit, then the UI displays the conflict and offers re-proposal rather than retrying activation.

### Complete closed loop

- Given admitted fixtures, a certified fake provider, Null Genesis, an approved test-only Policy Calibration Artifact, and a deterministic candidate path, when the end-to-end suite runs, then it proves observation → candidate → replay → disposition → canary → activation → monitor → rollback with exact receipts and no worker-owned activation.

## Implementation slices

Each slice ends in a mergeable vertical proof. No activation occurs before an approved calibration artifact scoped to that environment and test purpose.

### Slice 0 — standalone source and CI

- Fix package/test bootstrap so a clean standalone clone collects and runs without being installed under usr/plugins/dspy_rlm.
- Add deterministic dependency installation, framework-signature contract tests, secret scanning, schema linting, and CI.
- Preserve the current failing baseline as evidence: at the planning baseline, pytest collection reaches only three config tests and fails fifteen modules because imports assume the Agent Zero usr/plugins layout.

### Slice 1 — strict records and inert Genesis

- Freeze schema registry, canonicalization, Opaque Reference, public projection, reason-code, command, and receipt contracts.
- Implement immutable records, links, events, equivalence insertion, append-only enforcement, and a pure read-only repository.
- Implement typed Null Artifacts, Activation Profiles, one Activation Scope, Genesis CAS, and pure Runtime Composer.
- Implement local issuer bootstrap, strict authority/grant records and revocation, the command/idempotency ledger, and a minimal content-free authority projection. Issue no default grant.
- Prove zero behavioral change and zero write-on-read.

### Slice 2 — privacy migration

- Implement encrypted copy-on-write quarantine, exact legacy decoders, dispositions, Compatibility Guidance Set, checkpoints, safe-store validation, receipt-bearing authority-manifest CAS, export, and exact-quarantine deletion.
- Prove every interrupted phase and post-cutover recovery.

### Slice 3 — work authority and budgets

- Implement Work Item/lease/fence state machine, command idempotency, attempt receipts, two-phase orphan recovery, process identity, TERM/KILL cleanup, Candidate Publication Planner, coordinator-owned atomic finalization, and cumulative Budget Broker.
- Prove cancellation, deadline, crash, fence loss, unknown usage, and no late publication.

### Slice 4 — fixture governance

- Implement fixture drafts, grants, content sessions, independent review, admission, families, deterministic partitions, eligibility events, manifests, withdrawal, Execution Profiles, Assessment Profiles, and capability identities.
- Add quarantine release-grant, Released Fixture derivation, ordinary admission, and release withdrawal atop the Slice 2 local Migration Authority.

### Slice 5 — certified replay

- Implement transport-specific certified replay adapter, frozen invocation snapshots, fixture tool continuation, paired fresh workers, typed arm outcomes, content-free receipts, exact budgets, and capability probes.

### Slice 6 — deterministic candidate path

- Implement deterministic analysis, Safe Analysis View, rule-catalog projection, strict generation, Candidate Publication Planner, frozen replay, Evidence Bundle, and review-only/promotion-ready/rejected reduction.
- This is the first complete fake-provider vertical candidate proof; it does not activate.

### Slice 7 — calibrated canary, activation, monitor, and rollback

- Implement Policy Calibration Artifact approval/withdrawal, Exposure Receipts, fixed-horizon canary, Canary Conclusion, operator activation, exact-revision CAS, monitor start, requalification, ancestry-safe rollback, and Safety Bypass.
- Use an explicitly approved test-only calibration for fake-provider acceptance. It grants no production or automatic authority.

### Slice 8 — model routes and outcome-GEPA

- Build the hash-complete dspy[deno]==3.3.1 worker environment under Python >=3.12,<3.15.
- Add certified typed Predict, recursive RLM, metering, outcome-aligned metrics, GEPA admission, training/tuning-only search, and holdout isolation.
- Keep legacy surrogate engines diagnostic-only.

### Slice 9 — operator API and WebUI

- Complete receipt-bearing coordinator commands, candidate/fixture/privacy detail projections, and the six operator views.
- Remove split prompt/guidance promotion paths, raw status fields, mixed queue/domain labels, ineffective dashboard bindings, automatic force, and uncalibrated presets.

### Slice 10 — production calibration, automation, and release hardening

- Add production automatic activation or statistically interpreted rollback only after a separately approved production-scoped Policy Calibration Artifact exists.
- Complete migrations, documentation, upgrade/rollback communication, performance bounds, compatibility matrix, release assets, and all evidence gates.

## Delivery and release evidence gates

These gates are independent. Passing a later-looking gate cannot substitute for an earlier one.

### Gate 1 — standalone source

- Clean clone of TerminallyLazy/a0-self-improvement.
- Package/bootstrap install, full test collection, focused and full tests, static/schema checks, and secret scan pass.
- No dependency on an existing Agent Zero usr/plugins checkout.

### Gate 2 — standalone fake-provider behavior

- Exercise deterministic and model-route contracts through standalone framework stubs and the deterministic fake provider.
- Prove Chat Completions and Responses continuation, repair behavior, metering, timeout, cancellation, malformed output, tool isolation, no late publication, and the complete test-calibrated closed loop.
- This does not certify a real Agent Zero checkout.

### Gate 3 — clean pinned Agent Zero compatibility

- Install the exact candidate source into a clean Agent Zero checkout at b22a144bf59f15b1516084c9e7b88133ba92c8a9.
- Use the framework Python 3.12.4 runtime for backend/plugin verification.
- Prove no Agent Zero core changes and certify exact context, ModelType provider resolution, prompt, extension, transport, response, authentication, and CSRF seams.
- Issue a Replay Capability Certificate only after both structural probes and controlled behavioral replay probes pass for that exact Agent Zero build and exact adapter; retain this receipt separately from Gate 2.
- This does not substitute for standalone fake-provider or authorized real-provider evidence.

### Gate 4 — authorized provider interaction

- Use an exact Model Use Grant and approved non-sensitive fixtures.
- Prove typed Predict, RLM, outcome-GEPA, metering, cost reconciliation, cancellation, and no live-tool replay with provider receipts.
- Provider success does not prove live runtime or WebUI acceptance.

### Gate 5 — standalone pull request

- Review source diff, migrations, schemas, docs, security, and CI.
- Merge only after required checks and review.
- Merge does not prove a release artifact.

### Gate 6 — 2.0.0 release candidate

- Cut 2.0.0-rc.N from the reviewed commit.
- Publish tag, release notes, checksums, install artifact, compatibility range, migration preview, quarantine/export/deletion warning, automatic-authority default, known limitations, and rollback instructions.
- Reinstall from the release artifact into a clean target.

### Gate 7 — release-candidate exact named runtime acceptance

- Deploy the exact RC artifact to the explicitly named Dockerized Agent Zero runtime.
- Discover its actual URL and source/runtime mapping rather than assuming a port.
- Prove authenticated WebUI/API, certified outer security responses, disabled and migration states, status zero-write/no-worker behavior, fixture workflow, deterministic closed loop, cancellation, activation CAS, monitor/rollback, Safety Bypass, restart durability, browser console, and network behavior. Any activation uses an explicitly approved calibration bound to this acceptance environment.
- Record the exact source commit, release artifact digest, container/runtime identity, Agent Zero build, plugin version, schema generation, provider profile, and acceptance receipts.

### Gate 8 — final 2.0.0 release

- Promote only the accepted RC commit and artifact inputs.
- Publish final tag, checksums, migration communication, security/privacy notes, compatibility, and rollback instructions.
- Any code change after RC acceptance requires a new RC and Gate 7 rerun.

### Gate 9 — marketplace metadata update

- Update the existing public marketplace entry created through agent0ai/a0-plugins#486 with the intended v3 listing metadata and install contract.
- Treat marketplace validator, CI, review, merge, and public catalog visibility as separate facts.
- Because the index points to the repository rather than pinning a release commit, marketplace success does not prove the installed version or source identity.

### Gate 10 — public install identity

- Install from the public release/marketplace path into a clean environment.
- Require the resolved plugin version, source commit, artifact digest, schema generation, and dependency-lock digest to equal the accepted Gate 8 final-release identities exactly; any stale or post-release-main mismatch fails the gate.
- Record those exact identities, the Plugin Hub/index path, and the clean-install receipt.
- Re-run package identity, safe status, schema, migration preview, and pinned-framework smoke checks.
- A successful public install does not prove the exact named runtime.

### Gate 11 — final public-path exact runtime acceptance

- Deploy the exact artifact proven by Gate 10 to the explicitly named runtime.
- Re-run authenticated browser/API, ordinary-runtime continuity, local-authority handoff, status purity, restart, capability, and safe closed-loop smoke acceptance.
- Record public availability, installed identity, and deployed behavior as separate linked receipts.

## Release communication

The 2.0.0 release is a breaking state-authority migration, not an in-place feature upgrade. Release notes and operator UI must state:

- v2 state is snapshotted into encrypted Privacy Quarantine;
- improvement remains disabled until verified cutover;
- only exact valid active guidance.v1 may seed Compatibility Guidance;
- legacy prompt content and raw/free-form records do not become active v3 artifacts;
- export, deletion, release, and withdrawal are explicit operator workflows;
- all activation is disabled without approved calibrated policy authority, and production automation requires separately production-scoped approval;
- ordinary Agent Zero continues when improvement is unavailable;
- rollback instructions distinguish v3 Activation Profile rollback from reverting the plugin package; and
- pre-cutover recovery, post-cutover recovery, and package downgrade have different safe procedures.

## Definition of implementation-ready

Implementation may begin when:

- ADRs 0001 through 0010 are accepted;
- CONTEXT.md contains the shared terms used here;
- this handoff replaces the stale specification;
- every slice has an executable Outside-In boundary;
- no unresolved threshold, replay, migration, worker, UI, or release assumption is treated as a default;
- automatic authority remains explicitly gated on calibration; and
- source, standalone fake provider, clean compatibility, provider, PR/merge, RC, RC exact runtime, final release, marketplace metadata, public-install identity, and final exact-runtime evidence remain separate.

This handoff intentionally makes no code, release, or runtime claim. Those claims begin only in the implementation and evidence gates above.
