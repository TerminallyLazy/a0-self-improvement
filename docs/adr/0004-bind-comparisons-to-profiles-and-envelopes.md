---
status: accepted
---

# Bind comparisons to activation profiles and evaluation envelopes

A0 Self-Improvement will treat the exact context-wide Incumbent Activation Profile at an observed Activation Scope revision as the deployed comparator, not create mutable baselines per bucket, candidate type, or guidance lane. Each baseline/candidate comparison also binds both arms to one immutable Evaluation Envelope composed from an Execution Profile and Assessment Profile. A candidate therefore changes exactly one Artifact Slot while the incumbent, effective runtime, fixtures, and assessment authorities remain explicit. This favors reproducible, fail-closed comparison over simple baseline rows and broad evidence reuse.

## Consequences

- Objective buckets are evidence-coverage dimensions and candidate type identifies the changed Artifact Slot; neither becomes another activation or baseline authority.
- A comparison identity binds the Activation Scope, observed scope revision, incumbent profile identity and digest, target Artifact Slot, Execution Profile digest, and Assessment Profile digest. Its Evidence Bundle separately binds the candidate and successor profile.
- The Execution Profile identifies the resolved model/provider and non-secret inference parameters, provider revision when available, Agent Zero build and capability fingerprint, plugin/Runtime Composer/replay-adapter versions, composed-prompt digest, and behavior-affecting configuration. Operational-only settings do not affect comparison identity.
- The Assessment Profile identifies required bucket coverage, fixture manifest, validators, risk and reduction policy, judge and calibration, thresholds, replay seed, and freshness policy.
- A new context receives a Genesis Activation Profile with permanent, system-owned, typed Null Artifacts for unmodified optimizable slots. The Null Guidance Artifact renders no guidance without using an absent pointer, magic baseline version, or invalid empty `guidance.v1`; a validated migrated active `guidance.v1` may seed the incumbent instead.
- Only the Activation Coordinator may establish Genesis through an idempotent compare-and-swap after the context and required runtime identity exist. Read-only status and observation paths never create it; failure leaves improvement uninitialized or review-only while ordinary Agent Zero remains unchanged.
- Incumbent profile or scope-revision displacement makes the candidate lineage-stale and requires a new candidate against the new incumbent. Execution, assessment, evaluator, or fixture drift makes its Evidence Bundle stale while the candidate may receive fresh evidence if its incumbent binding remains current. Digest conflicts, malformed identity, unsupported schema, and missing required capabilities are incompatible and never reusable.
- When a provider exposes no immutable model revision, only a contemporaneous paired execution under the exact same Execution Profile may authorize comparison. Matching selector text never authorizes cross-run or cross-time automatic reuse.
- Cross-version reuse requires exact Agent Zero build, capability, Runtime Composer, and replay-harness fingerprints unless a later explicit compatibility matrix grants a named equivalence.
- Recalibration creates a new Assessment Profile. A policy-only change may append a new Outcome Projection from complete immutable evidence; stored execution may otherwise be reassessed only when every execution, case, fixture, and harness identity matches and the new freshness policy explicitly permits it. Cross-candidate baseline reuse is denied by default.
- Canary Trial observations are prospective, concurrently assigned, and bound to one incumbent, candidate, Evaluation Envelope, and eligibility contract. Drift ends the trial as inconclusive; observations never resume or mix across trials. Post-Promotion Monitor comparison references the exact predecessor and compatible trial or frozen evidence.
- Rollback creates a new Activation Scope revision and never revives historical promotion evidence. Emergency rollback may select the exact schema- and capability-compatible predecessor without fresh comparative evidence; if no compatible ancestor exists, plugin changes fail closed and ordinary Agent Zero runs unmodified.
- Candidate expiry and evidence freshness are separate versioned policy concepts. No fixed 72-hour default is established by this identity decision.
