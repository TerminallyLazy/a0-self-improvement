---
status: accepted
---

# Use an encrypted privacy quarantine for v3 migration

A0 Self-Improvement will replace its raw-capable v2 state through an operator-initiated, copy-on-write Migration Run rather than an in-place schema upgrade. The run first creates and verifies an encrypted, immutable Privacy Quarantine from a WAL-consistent SQLite snapshot and all legacy compatibility files, then builds a fresh Safe Projection Store from strict typed allowlists. Normal runtime, learning, replay, observation, and worker paths have no access to quarantine. Atomic Cutover occurs only after integrity, privacy, disposition-count, artifact, and safe-projection checks pass; failure leaves v2 recoverable, keeps improvement disabled, and does not interrupt ordinary Agent Zero operation. This favors recoverability and explicit consent over simpler automatic migration, accepting a dedicated local migration authority, key-custody dependency, and additional lifecycle receipts.

## Consequences

- A schema-valid active `guidance.v1` may seed the incumbent Activation Profile. Legacy prompt artifacts, inactive candidates, arbitrary payloads and results, running jobs, and canaries remain quarantined or require reevaluation; compatibility caches and prompt snapshots are regenerated.
- Migration identity binds the source snapshot digest, target schema, and transformation-policy version. Append-only checkpoints make exact retries idempotent; a reused identity with different content is an integrity failure rather than an ignored insert.
- Each source record receives a safe `projected`, `quarantined`, `unsupported`, or `invalid` disposition. Unknown or malformed records never gain active authority through inferred defaults.
- Each Privacy Quarantine uses a random data-encryption key wrapped by an OS-keystore or secret-mounted operator key. Migration blocks when secure key custody is unavailable and never creates a plaintext quarantine.
- Quarantine remains until explicit local export or deletion. Export produces an encrypted archive, manifest, digest, and receipt with separately transferred key material; deletion requires exact identity and revision, confirmation, an export or acknowledged waiver, and a content-free Deletion Receipt.
- Quarantined content defaults to `not_consented`. A scoped, expiring Quarantine Release Grant may authorize a dedicated local process to transiently decrypt, re-redact, and review selected records into newly identified Released Fixtures; optimizers and workers never read quarantine directly.
- Withdrawal blocks future derivation and replay, removes released payloads unless independently authorized, and preserves only content-free provenance and withdrawal receipts.
- v3 uses context-, purpose-, and key-epoch-scoped Opaque References instead of migrating unsalted content hashes as public identities.
- Post-cutover recovery regenerates verified safe projections; it never reactivates raw v2 state for learning. Acceptance covers raw-bearing fixtures, WAL state, interruption at every phase, missing keys, tampering, identity conflicts, forbidden-field scans, retries, and safe public projections.
