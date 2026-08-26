# A0 Self-Improvement

This context owns the language for proposing, evaluating, activating, monitoring, and rolling back self-improvements in one Agent Zero context.

## Language

**Improvement Artifact**
Immutable, typed content proposed to change Agent Zero behavior. Lifecycle state and evidence do not belong to the artifact.
_Avoid_: Change blob, candidate payload

**Structured Guidance Artifact**
An allowlisted set of behavioral rules proposed as one Improvement Artifact.
_Avoid_: Guidance blob, prompt overlay

**Guidance Rule Catalog**
An immutable, versioned registry of guidance-rule identifiers, parameter and rendering contracts, allowed benefit buckets, required evaluation buckets, and protected constraints.
_Avoid_: Rule allowlist, bucket mapping

**Prompt Patch Artifact**
An indivisible set of replacements for eligible prompt components proposed as one Improvement Artifact.
_Avoid_: Prompt mutation, prompt candidate

**Prompt Component Inventory**
The immutable ordered identity, source digests, protection state, and assembly contract of the prompt components against which a Prompt Patch Artifact is bound.
_Avoid_: Captured prompt, component list

**Improvement Candidate**
A proposal that binds exactly one Improvement Artifact to an exact incumbent Activation Profile and its proposed successor profile.
_Avoid_: Artifact, experiment

**Candidate Change Kind**
The discriminator `replace_structured_guidance` or `replace_prompt_patch` that must agree with an Improvement Candidate's Artifact Slot and Improvement Artifact type.
_Avoid_: Engine kind, optimizer subtype

**Artifact Generation Receipt**
Content-free proof that one exact Engine Profile, admitted inputs, authority, and budget emitted one exact Improvement Artifact.
_Avoid_: Engine metadata, candidate evidence

**Lineage-Stale Candidate**
An Improvement Candidate whose bound incumbent Activation Profile or observed Activation Scope revision has been displaced; its artifact may be proposed again only through a new candidate.
_Avoid_: Failed candidate, stale evidence

**Activation Scope**
The boundary within which self-improvement activation decisions are mutually exclusive for one Agent Zero context.
_Avoid_: Activation namespace, deployment lane

**Artifact Slot**
A named, typed position occupied by an Improvement Artifact in an Activation Profile.
_Avoid_: Field, layer

**Activation Profile**
The immutable, complete set of Artifact Slots selected for an Activation Scope.
_Avoid_: Configuration, deployment manifest

**Incumbent Activation Profile**
The exact Activation Profile selected at an observed Activation Scope revision and used as the deployed comparator for an Improvement Candidate.
_Avoid_: Baseline row, bucket baseline

**Genesis Activation Profile**
The first complete Activation Profile for a context, composed from its actual incumbent artifacts and system-owned Null Artifacts where no improvement exists.
_Avoid_: Baseline v0, empty profile

**Null Artifact**
A permanent, system-owned, typed Artifact Slot occupant that has no behavioral effect and cannot be promoted or expire.
_Avoid_: Missing artifact, magic pointer

**Null Guidance Artifact**
The Null Artifact for a Structured Guidance Artifact slot; it renders no guidance without pretending to be an empty `guidance.v1` artifact.
_Avoid_: Empty guidance, absent guidance

**Null Prompt Patch Artifact**
The Null Artifact for a Prompt Patch Artifact slot; it preserves the assembled prompt unchanged.
_Avoid_: Empty patch, missing prompt artifact

**Compatibility Guidance Set**
A migration-only Structured Guidance Artifact slot occupant that preserves the exact validated active `guidance.v1` set and its frozen selection and rendering semantics without becoming a vNext candidate.
_Avoid_: Upgraded guidance, legacy promotion

**Artifact Read Disposition**
The typed conclusion `decoded`, `unsupported`, `invalid`, or `quarantined` produced by an exact artifact-schema reader.
_Avoid_: Missing artifact, best-effort parse

**Canary Trial**
The bounded comparison of one Improvement Candidate with its incumbent Activation Profile before activation.
_Avoid_: Experiment, canary candidate

**Canary Exposure Unit**
The stable history-bearing conversation or topic episode assigned wholly to one Canary Trial arm before its outcome is observed.
_Avoid_: Turn, observation

**Exposure Receipt**
Content-free proof that an eligible Canary Exposure Unit was assigned to an exact trial arm under the trial's immutable allocation policy before observation.
_Avoid_: Outcome Evidence, routing log

**Canary Conclusion**
The terminal evidentiary result `passed`, `failed`, `inconclusive`, or `stopped` for one Canary Trial.
_Avoid_: Activation Disposition, canary status

**Diagnostic Canary**
An explicitly authorized Canary Trial for a `review_only` candidate that may gather prospective evidence but can neither cure missing frozen replay authority nor authorize activation.
_Avoid_: Operator override, manual promotion

**Evidence Bundle**
A provenance-bound, pre-canary collection of frozen replay, validation, and policy evidence linked to an Improvement Candidate and reduced into one Activation Disposition; later canary authority remains a separate immutable conclusion.
_Avoid_: Metrics blob, test output

**Stale Evidence Bundle**
An Evidence Bundle whose Evaluation Envelope no longer satisfies the current comparison requirements but whose Improvement Candidate remains bound to the incumbent profile.
_Avoid_: Lineage-stale candidate, invalid evidence

**Evaluation Envelope**
The immutable Execution Profile and Assessment Profile shared by the incumbent and candidate arms of one comparison.
_Avoid_: Baseline profile, test configuration

**Execution Profile**
The non-secret identity of behavior-affecting runtime inputs used to execute both comparison arms.
_Avoid_: Model selector, environment

**Assessment Profile**
The versioned coverage, fixture, validator, judge, threshold, and freshness authorities used to interpret both comparison arms.
_Avoid_: Evaluator config, scoring settings

**Replay Case Artifact**
Immutable, typed, reviewed fixture content needed to execute and assess one replay case; admission, eligibility, and consent remain separate records.
_Avoid_: Trace sample, case dictionary

**Fixture Use Grant**
Explicit, scoped, expiring authority to retain and process non-system content for named replay purposes and processing boundaries.
_Avoid_: Content flag, blanket consent

**Fixture Admission Receipt**
Append-only proof that one exact Replay Case Artifact passed source-authority, transformation, safety, truth, review, family, and partition checks.
_Avoid_: Approval flag, fixture status

**Fixture Family**
A stable group of exact duplicates, variants, translations, generated derivatives, or cases sharing source lineage that must remain in one partition.
_Avoid_: Objective bucket, case tag

**Expected Outcome Contract**
Versioned, typed assertions for required schemas, facts, citations, tool behavior, and state transitions without treating historical model output as truth.
_Avoid_: Gold response, score rubric

**Tool Fixture Step**
One ordinal, inert expected tool request, fixture response, and state-transition reference used during replay without live dispatch.
_Avoid_: Mock call, tool log

**Replay Set Manifest**
An immutable ordered selection of exact admitted case versions, family partitions, coverage declarations, selection policy, and Assessment Profile.
_Avoid_: Sample list, dataset snapshot

**Fixture-Isolated Replay**
Provider-backed execution of an admitted Replay Case Artifact under a frozen environment and inert Tool Fixture Steps, with no live tool dispatch or provider-hosted tool execution.
_Avoid_: Live agent run, frozen-output comparison

**Replay Capability Certificate**
Immutable proof that one exact Agent Zero build and replay-adapter version passed the required structural and behavioral compatibility probes.
_Avoid_: Version check, capability flag

**Replay Pair Attempt**
One bounded comparison of an incumbent arm and candidate arm for the same Replay Case Artifact and Evaluation Envelope, with fresh isolated state for each arm.
_Avoid_: Baseline reuse, replay run

**Replay Arm Outcome**
The typed execution conclusion for one arm of a Replay Pair Attempt: completed, deterministic failure, availability failure, cancelled, or harness failure.
_Avoid_: Candidate verdict, replay score

**Replay Execution Budget**
The versioned wall-clock, model-call, turn, fixture-call, token, output-size, and observable-cost limits governing a Replay Pair Attempt.
_Avoid_: Timeout, replay depth

**Replay Invocation Snapshot**
The frozen admitted case, Execution Profile inputs, fixture-backed environment, and incumbent Activation Profile from which both replay-arm prompts are composed.
_Avoid_: Live context, prompt dump

**Replay Execution Receipt**
The content-free durable projection of a Replay Pair Attempt, containing opaque identities, actual execution facts, typed outcomes, cleanup status, and bounded reason codes.
_Avoid_: Replay transcript, model log

**Replay Capability State**
The operator-facing conclusion `not_probed`, `ready`, `degraded`, `blocked`, `unavailable`, or `unsupported` for one exact runtime and replay-adapter combination.
_Avoid_: Healthy flag, installed status

**Certification Holdout**
The family-partitioned replay cases hidden from candidate generation and tuning until the candidate is locked for promotion evaluation.
_Avoid_: Validation set, test samples

**Safe Analysis View**
An immutable, allowlisted aggregate projection and opaque provenance references made available to one analysis without exposing raw prompts, tool arguments or results, secrets, or unrestricted trace content.
_Avoid_: Trace dump, model context

**Analysis Route**
The immutable selection of `deterministic`, `typed_predict`, or `recursive_rlm` for one declared analysis question before semantic output is observed.
_Avoid_: Event-count tier, silent fallback

**Analysis Profile**
The exact routing policy, Safe Analysis View, question and result schema, model or tool identities, Worker Dependency Profile, and Optimization Run Budget governing one analysis.
_Avoid_: Analyzer config, model settings

**Analysis Attempt**
One execution of an Analysis Profile ending as `succeeded`, `partial`, `unavailable`, `budget_exhausted`, `cancelled`, `failed`, or `incompatible`.
_Avoid_: Finding batch, fallback result

**Analysis Proposal**
A typed, provenance-bound candidate-generation hypothesis produced by model-backed analysis; it is neither expected truth, Outcome Evidence, nor a Validation Result.
_Avoid_: Analysis Finding, model verdict

**Worker Dependency Profile**
The immutable identity of an optimizer worker's Python ABI, platform, complete dependency lock, allowed framework bridge, adapter versions, and probed capabilities.
_Avoid_: Installed flag, version marker

**Engine Profile**
The immutable contract binding a stable semantic engine identifier, optimization objective, output artifact type, authority ceiling, and exact implementation and dependency identities.
_Avoid_: Class name, GEPA enabled flag

**Model Use Grant**
Explicit, scoped, expiring authority to call named model and provider identities within an Optimization Run Budget and the applicable processing boundary.
_Avoid_: Model selector, API key

**Optimization Run Budget**
The immutable cumulative ceilings and concurrency reservations for one analysis or candidate-search lineage, including calls, tokens, observable cost, time, cases, variants, outputs, and retries.
_Avoid_: GEPA steps, timeout

**Budget Ledger**
The single-host authority that atomically reserves and records Optimization Run Budget consumption before external work is dispatched.
_Avoid_: Usage telemetry, provider invoice

**Work Item**
A durable, idempotent request for one bounded plugin operation, whose execution state is separate from candidate, evidence, canary, and activation conclusions.
_Avoid_: Candidate, optimization status

**Work Attempt**
One leased and fenced execution of a Work Item under its frozen inputs, retry policy, dependency identity, deadline, and cumulative budget.
_Avoid_: Worker thread, resumed run

**Attempt Conclusion**
The typed terminal operational result of a Work Attempt, such as succeeded, unavailable, budget-exhausted, stopped, failed, or cancelled; it never decides candidate merit.
_Avoid_: Activation Disposition, job status

**Publication Result**
The separate conclusion that a Work Attempt published nothing, locked an artifact, or atomically published a candidate after fence revalidation.
_Avoid_: Attempt Conclusion, promotion result

**Candidate Publication Planner**
The pure authority that validates a staged Work Attempt result and builds the complete immutable artifact, receipt, link-manifest, and candidate write set for Work Coordinator finalization.
_Avoid_: Optimizer worker, Work Item writer

**Optimization Metric Profile**
The versioned search-only projection of typed training and tuning outcomes into a bounded score and fixed feedback; it has no promotion or activation authority.
_Avoid_: Activation Policy, global quality score

**Search Telemetry**
A non-authoritative observation used to steer or diagnose candidate generation, including legacy rule agreement, token similarity, and GEPA search scores.
_Avoid_: Outcome Evidence, Validation Result

**GEPA Admission Receipt**
Immutable proof that one Candidate Search Run may use an exact model, outcome-aligned metric, admitted training and tuning families, capability, grant, risk boundary, and reserved budget.
_Avoid_: Optimizer enabled flag, dependency ready

**Candidate Search Run**
One bounded GEPA search over admitted training and tuning families that may emit at most one locked Improvement Artifact while the Certification Holdout remains inaccessible.
_Avoid_: Candidate evaluation, promotion run

**Optimization Run Receipt**
The content-free terminal record of an Analysis Attempt or Candidate Search Run, including its exact identities, actual bounded usage, cleanup and fence state, and allowlisted reasons.
_Avoid_: Model trace, compile log

**Fixture Eligibility Event**
An append-only admission, suspension, expiry, revocation, supersession, or retirement transition for an admitted Replay Case Artifact.
_Avoid_: Mutable status, deletion flag

**Outcome Evidence**
The immutable, attempt-scoped set of typed Outcome Dimensions and safe provenance references describing an observed result.
_Avoid_: Success flag, score

**Outcome Dimension**
A provenance-bound outcome fact whose state is `pass`, `fail`, `unavailable`, or `not_applicable`.
_Avoid_: Metric, boolean check

**Outcome Projection**
A versioned interpretation of Outcome Evidence as `successful`, `unsuccessful`, or `indeterminate`.
_Avoid_: Outcome Evidence, success flag

**Bucket Validator**
The deterministic task-correctness authority for one declared objective bucket.
_Avoid_: Bucket classifier, semantic judge

**Validation Result**
The provenance-bound conclusion a Bucket Validator produces for one replay execution.
_Avoid_: Outcome Evidence, score

**Feedback Evidence**
A typed human assessment dimension linked to exact existing Outcome Evidence; corrections and withdrawals are append-only and bounded annotations have no deterministic or override authority.
_Avoid_: Deterministic check, free-text review

**Feedback Reason Catalog**
The immutable versioned set of bounded human-assessment kinds and reason codes accepted by Feedback Evidence without admitting free-text authority.
_Avoid_: Comment field, judge rubric

**Efficiency Evidence**
Provenance-bound observations of resource use, such as latency, tokens, cost, turns, and tool calls.
_Avoid_: Quality score, performance verdict

**Activation Disposition**
The candidate-level conclusion of `promotion_ready`, `review_only`, or `rejected` derived from an Evidence Bundle.
_Avoid_: Outcome Projection, candidate status

**Activation Policy**
The immutable, versioned authority for evidence requirements, calibrated decision boundaries, canary and monitoring plans, freshness, overrides, and activation modes within an Activation Scope.
_Avoid_: Threshold config, promotion settings

**Policy Calibration Artifact**
Immutable evidence and approval establishing the numerical boundaries, sampling requirements, uncertainty method, and operating limits of one Activation Policy.
_Avoid_: Default thresholds, settings preset

**Candidate Risk Tier**
The policy-assigned `standard`, `elevated`, or `restricted` automation boundary derived from an Improvement Candidate's Artifact Slot, changed components, required buckets, and protected constraints.
_Avoid_: Quality score, operator preference

**Candidate Benefit Claim**
The predeclared target outcome or efficiency dimension an Improvement Candidate must credibly improve while satisfying every required noninferiority and hard-veto condition.
_Avoid_: Global score gain, post-hoc win

**Judge Calibration Receipt**
Immutable proof that one exact blinded-judge model, rubric, prompt, and version passed the Activation Policy's independent calibration requirements.
_Avoid_: Judge confidence, evaluator enabled flag

**Post-Promotion Monitor**
The bounded observation of an activated Improvement Candidate against its predecessor profile.
_Avoid_: Canary Trial, health check

**Monitor Reference**
The exact compatible predecessor evidence from the passed Canary Trial and frozen replay against which a Post-Promotion Monitor interprets new active-profile observations.
_Avoid_: Historical average, current baseline

**Evidence Requalification Window**
The policy-bounded period in which an active profile with newly stale evidence may obtain replacement authority before rollback or a blocked operator decision is required.
_Avoid_: Candidate TTL, grace period

**Safety Bypass**
The coordinator-owned fail-closed state in which the Runtime Composer applies no improvement artifacts because no compatible rollback target is available.
_Avoid_: Rollback profile, disabled Agent Zero

**Activation Coordinator**
The domain authority that accepts or rejects changes to an Activation Scope.
_Avoid_: Worker, evaluator

**Runtime Composer**
The boundary that forms the effective Agent Zero instructions from an Activation Profile and invariant safety controls.
_Avoid_: Prompt mutator, renderer

**Activation Receipt**
The durable proof that an Activation Coordinator accepted an activation or rollback decision.
_Avoid_: Log entry, deployment event

**Operator Authority Grant**
Explicit, issuer-signed, subject-bound, expiring, revocable, context- and action-scoped authority for one operator to request named mutations without granting fixture-content or quarantine access.
_Avoid_: Login session, administrator flag

**Operator Content Session**
A nonrenewable, short-lived, purpose- and draft-scoped capability issued from a live Operator Authority Grant to author or review named content-bearing fixture records.
_Avoid_: Operator Authority Grant, browser session

**Operator Authority Service**
The local-only trust root that bootstraps issuer identity explicitly and solely owns issuance, session binding, expiry, renewal of renewable grants, revocation, and safe projection of operator, fixture-use, model-use, content-session, and calibration authority.
_Avoid_: Web administrator, login provider

**Authority Issuer Profile**
The immutable public identity, algorithm, key epoch, allowed authority classes, and local custody contract of one issuer trusted by the Operator Authority Service.
_Avoid_: Admin user, signing key

**Operator Mutation Receipt**
Immutable proof that one exact operator command was accepted, refused, or replayed against named authority, target, policy, and observed/resulting revisions.
_Avoid_: API response, audit log

**Automation Trigger Receipt**
Immutable proof that one exact policy authority—calibrated opt-in for activation or soft statistics, or hard-veto authority for emergency rollback—initiated a coordinator transition at an observed scope revision.
_Avoid_: Scheduler event, automatic flag

**Privacy Quarantine**
An encrypted, immutable, recoverable snapshot of pre-v3 plugin state that is inaccessible to normal runtime, learning, replay, and observation paths.
_Avoid_: Backup database, legacy store

**Safe Projection Store**
The only active v3 state authority, containing allowlisted typed projections, validated artifacts, opaque references, and receipts but no quarantined content.
_Avoid_: Migrated database, scrubbed backup

**Safe Status Projection**
A content-free, read-only operator view of independent plugin, activation, evidence, capability, fixture, migration, and receipt states with freshness and allowlisted reasons.
_Avoid_: Runtime state blob, debug dump

**Migration Run**
One operator-initiated, copy-on-write conversion from an exact Privacy Quarantine source digest to an exact target schema and transformation-policy version.
_Avoid_: Schema upgrade, import job

**Migration Checkpoint**
Append-only phase proof that binds a Migration Run to its input checkpoint, output digest, record dispositions, and safe counts.
_Avoid_: Progress flag, migration log

**Migration Receipt**
The exact content-free cutover proof embedded in the Store Authority Manifest CAS and later projected idempotently into the migration ledger.
_Avoid_: Migration Checkpoint, completion log

**Atomic Cutover**
The compare-and-swap transition that makes one verified Safe Projection Store authoritative while preventing the raw v2 source from re-entering learning.
_Avoid_: File replacement, schema commit

**Store Authority Manifest**
The fsynced, compare-and-swap-selected identity of the sole Safe Projection Store generation runtime may read, containing the exact Migration Receipt bytes so authority and cutover proof become durable together.
_Avoid_: Database path, latest-file pointer

**Quarantine Release Grant**
Explicit, expiring operator authority to derive a named safe projection from selected Privacy Quarantine records for one declared purpose.
_Avoid_: Learning opt-in, quarantine access

**Released Fixture**
A newly identified, reviewed, and policy-redacted artifact derived transiently under one Quarantine Release Grant.
_Avoid_: Quarantine record, restored sample

**Quarantine Export**
An encrypted local archive of one exact Privacy Quarantine with a content-free manifest and separately transferred key material.
_Avoid_: Database download, data dump

**Deletion Receipt**
Content-free proof that an exact Privacy Quarantine and its wrapped decryption key were explicitly destroyed after export or an acknowledged export waiver.
_Avoid_: Deletion log, tombstone

**Withdrawal Receipt**
Content-free proof that a Quarantine Release Grant was revoked and its Released Fixtures were made ineligible for future learning or replay.
_Avoid_: Deletion Receipt, consent flag

**Opaque Reference**
A context-, purpose-, and key-epoch-scoped keyed identifier that supports bounded correlation without exposing content or enabling cross-context comparison.
_Avoid_: Content hash, global fingerprint

**Implementation Handoff**
The authoritative ordered contract that binds accepted architecture, service ownership, executable acceptance boundaries, implementation slices, migration, and delivery evidence without claiming implementation.
_Avoid_: Backlog, provisional design

**Delivery Evidence Gate**
One independently proved boundary—source, clean compatibility, provider, review/merge, release, marketplace, public install, or exact runtime—that cannot be inferred from another gate.
_Avoid_: Done status, release checklist item
