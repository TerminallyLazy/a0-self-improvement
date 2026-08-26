---
status: accepted
---

# Use authority-ranked typed outcome evidence

A0 Self-Improvement will represent each attempt as immutable Outcome Evidence composed of provenance-bound Outcome Dimensions whose state is `pass`, `fail`, `unavailable`, or `not_applicable`; it will not store an independent success oracle. A versioned Outcome Projection may derive `successful`, `unsuccessful`, or `indeterminate`, while candidate-level Activation Disposition follows a precedence lattice: any authoritative required failure is `rejected`, otherwise missing or conflicting required evidence is `review_only`, and only complete passing required evidence is `promotion_ready`. This favors explainable, fail-closed evidence over a simpler scalar score and prevents soft signals or strong results in one bucket from hiding deterministic failures elsewhere.

## Consequences

- Cross-cutting identity, provenance, fixture, live-tool, safety, policy, secret, execution, hard-budget, and protected-constraint authorities outrank Bucket Validators; the initial validator namespace is `shell`, `tool_retrieval`, `reasoning`, and `decision_making`.
- Required bucket coverage is derived from the affected Artifact Slot, prompt components, and versioned risk policy. Per-case and per-bucket results remain visible and are never collapsed into a global-average authority.
- A baseline artifact failure may be repaired by a passing candidate, but a shared harness, fixture, provenance, or policy-authority failure makes the comparison `review_only`.
- Feedback Evidence, blinded semantic judgment, and Efficiency Evidence remain distinct. They cannot override deterministic failures; required-but-unavailable evidence yields `review_only`, while optional missing evidence remains `unavailable`.
- Runtime Outcome Evidence may support discovery, canary, and monitoring when bound to an exact Activation Profile, but candidate promotion readiness requires frozen candidate-bound replay evidence.
- Feedback and later analysis are append-only records. Compatibility APIs may derive nullable `success` values, but the stored vector remains authoritative.
- Numerical sample, quality, confidence, and regression thresholds are deliberately deferred to the evaluation and activation policy decision.
