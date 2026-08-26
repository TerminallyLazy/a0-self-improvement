---
status: accepted
---

# Unify self-improvement activation under context-wide profiles

A0 Self-Improvement will coordinate prompt-patch and structured-guidance candidates through one immutable Activation Profile, one revisioned Activation Scope, at most one Canary Trial per context, and one Activation Coordinator. Each Improvement Candidate changes exactly one typed Artifact Slot; candidate identity is immutable, evidence and lifecycle decisions are append-only, runtime composition applies the selected profile atomically, and rollback selects the exact predecessor unless an operator explicitly selects a compatible previously active ancestor. This favors coherent, fail-closed behavior over independent prompt and guidance activation lanes, accepting reduced canary concurrency and a temporary compatibility-adapter migration.

## Consequences

- Workers may stage candidates and evidence, but only the Activation Coordinator may change an Activation Scope using its exact expected revision.
- Sibling candidates may evaluate concurrently, but activation makes candidates bound to the displaced baseline stale.
- Replay, Canary Trial, hard-veto, provenance, and audit requirements apply even to manual-only candidates; `review_only` candidates never auto-promote.
- Existing prompt and guidance stores become versioned compatibility inputs rather than independent activation authorities. Valid active `guidance.v1` may seed the incumbent profile; legacy prompt patches, inactive candidates, and in-flight canaries require quarantine or reevaluation.
