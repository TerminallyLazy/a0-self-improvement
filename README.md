# A0 Self-Improvement

An authority-ranked Agent Zero self-improvement plugin. The v3 design keeps ordinary Agent Zero behavior available while typed observation, candidate search, certified replay, evidence reduction, canary, activation, monitoring, rollback, privacy migration, or operator authority is unavailable.

## What it does

- Stores strict canonical records, links, receipts, lifecycle events, activation scopes, operation slots, work leases, and budget authority in a v3 safe-projection store.
- Records restart-safe, content-free runtime observation facts from the certified message-loop and tool-result seams without retaining prompts, tool traffic, provider data, paths, or error text.
- Composes one atomic Activation Profile containing structured-guidance and prompt-patch slots; Null Genesis is byte-inert at the prompt seam.
- Supports deterministic candidate analysis, certified fixture replay, evidence dispositions, calibrated canaries, exact-revision activation, monitoring, ancestry-safe rollback, and all-null Safety Bypass contracts.
- Routes an occupied canary deterministically through the exact incumbent or successor profile when an explicitly provisioned assignment key matches the frozen plan, then records only content-free exposure facts after the matching loop outcome.
- Presents six context-scoped operator views without raw prompts, tool traffic, fixture content, model reasoning, provider identifiers, filesystem paths, secrets, quarantine identities, or exception strings.
- Isolates DSPy 3.3.1, GEPA, and Deno in a hash-locked worker environment. Model findings remain candidate hypotheses; workers never own activation.

## Install and use

1. Install the repository as `usr/plugins/dspy_rlm` or use Agent Zero's Plugin Hub.
2. Leave the plugin disabled until the local authority and migration state for the target context are ready.
3. Use `python scripts/a0_local_authority.py --help` for explicit issuer, grant, revocation, and Null Genesis operations. The protocol opens no network listener and issues no default authority.
4. Enable the plugin and open its dashboard to inspect the six read-only, content-free operator views for a live context.
5. Submit mutations only through the signed v3 command contract with an exact context, target, revision, idempotency key, browser-session challenge, and unexpired action-scoped grant.

The projection and command APIs retain Agent Zero authentication and CSRF protections. Reads open only the selected existing safe-store generation in SQLite read-only/query-only mode; they never create, repair, migrate, or fall back. The signed command endpoint dispatches optimize, work cancellation, canary start/stop, activation, rollback, Safety Bypass, monitor conclusion, requalification start/conclusion, feedback, and fixture draft/review/admit/withdraw. Fixture commands resolve opaque content-session handles only through an explicitly provisioned private runtime profile, current-owner custody files, the encrypted vault, and the durable repository ledger; missing custody remains a truthful `503`. A rollback-required monitor or requalification conclusion emits a request-only authority record and leaves the Activation Scope unchanged; the separately signed rollback command remains the sole profile-mutating transition. The retired `/optimize`, `/promote`, and `/rollback` routes return safe `410` responses and perform no mutation.

## v3 implementation boundary

This repository contains the standalone v3 schemas, repositories, migration/quarantine lifecycle, work and budget authority, fixture governance, certified replay contracts, deterministic and model-route contracts, outcome-GEPA admission, canary/activation/rollback coordinators, the explicitly injected 11-stage closed-loop runner, operator projections, and signed HTTP seams. Runtime hooks append only neutral v3 observation facts with no promotion authority. The observation bridge requires an exact current-profile policy mapping, window, and evidence authority before it materializes deterministic analysis facts. Canary reduction separately requires exact exposure receipts and one authority-ranked, candidate-attributable, content-free outcome fact per exposure; exposure alone is never outcome authority. Legacy raw loop/tool capture and automatic scheduling remain inert because raw previews and configuration defaults are not v3 observation or work authority.

The fake-provider and coordinator tests prove standalone source contracts. Runtime canary observations have exposure authority only and cannot authorize promotion without separately certified, candidate-attributable Outcome Evidence and a valid conclusion. These tests do not by themselves certify a real provider, a clean pinned Agent Zero checkout, or a named Docker runtime; those are separate acceptance gates in `IMPLEMENTATION_SPEC.md`.

## DSPy/GEPA worker setup

The plugin `install()` and `pre_update()` hooks create a clean isolated environment without host site-package inheritance, bridge only the exact Agent Zero source root, install the hash-locked closure from `requirements-gepa.lock` through `uv`, and smoke-test both the Agent Zero worker imports and `dspy.RLM`/`dspy.GEPA`. `requirements.txt` is intentionally empty so Agent Zero's normal plugin installer cannot install worker dependencies into the framework interpreter. A non-blocking startup extension repairs the environment after Docker container recreation. Native development uses `state/worker-venv`; Docker uses container-local `/opt/dspy-rlm-worker-venv` to avoid synchronizing dependency trees through the host bind mount. `DSPY_RLM_WORKER_VENV` may override either location. Agent Zero's framework interpreter is never modified. The status endpoint reads a lock-digest-bound version marker instead of importing DSPy on every refresh.

The sole worker root is DSPy 3.3.1 with the managed Deno extra; the generated lock resolves GEPA 0.1.4 and the complete transitive closure. Re-run the setup action after changing the lock or rebuilding the Docker container.

Depfix, if evaluated, is experimental and may only act as an isolated-worker adapter over the frozen plugin store. It must use no dynamic requirements, explicitly import dependencies in each subprocess, and must never modify Agent Zero’s interpreter.

## Legacy compatibility settings

The checked-in configuration remains readable for migration and compatibility diagnostics. Its numerical values are not v3 policy calibration, budget, replay, canary, activation, or automatic-work authority. v3 requires those facts as exact typed inputs; it does not infer them from these legacy defaults.

- `optimization.auto_optimize`: retained for legacy configuration parsing; the v2 automatic scheduler hook is inert.
- `optimization.enable_dspy_optimizer`: enables the GEPA path in a ready isolated worker.
- `rlm.enabled`: retained for compatibility; v3 model routes additionally require exact dependency, capability, grant, transport, and budget authority and never silently fall back.
- `rlm.model_ref` / `evaluator.preferred_dspy_model`: optional explicit DSPy model selectors used by RLM, semantic evaluation, and GEPA reflection. When both are blank, the worker checks `DSPY_RLM_MODEL`, then `DSPY_MODEL`, then derives a selector and credentials from Agent Zero's effective utility-model preset.
- `optimization.dry_run_mode`: legacy diagnostic configuration only; it grants no v3 publication or promotion authority.
- `scheduler.max_workers`: desired count of local worker processes on this host.
- `trace_capture`: bounded metadata capture and retention settings.
- `prompt.inject_guidance`: explicit opt-in for applying active guidance.

`DSPY_RLM_CANARY_ASSIGNMENT_KEY` has no default. When an active trial exists, the runtime uses it only if its domain-separated commitment matches the frozen Canary Plan; otherwise the incumbent remains selected and no authoritative exposure receipt is written.

`DSPY_RLM_FIXTURE_RUNTIME_PROFILE` also has no default. Fixture mutations become available only when it names an absolute, canonical runtime profile whose session/vault directories are current-owner `0700` and whose key, partition-secret, signed session-manifest, and content files are current-owner `0600`. Signed commands carry only opaque session and content handles; plaintext is resolved transiently and encrypted before durable fixture admission.

## Safety and state labels

- **heuristic** is the dependency-free local candidate engine. It is not GEPA.
- **GEPA** is shown only for an actual GEPA candidate artifact, not merely because imports are present.
- **candidate** is staged guidance, not active guidance.
- **review_only** means a promotion gate did not authorize automatic promotion.
- **local_multiprocess** means one host with multiple local processes and SQLite coordination.
- Replay labels describe offline prompt-output or tool-fixture replay. They never mean live tool execution.

## Data locations

All runtime data is plugin local. The v3 authority paths are:

- `state/dspy_rlm_v3.sqlite` before cutover, or the exact generation selected by `state/store-authority-manifest.json` after cutover.
- `state/authority/` for explicitly bootstrapped local issuer custody, public profile, and immutable revocations.
- `state/migration/` and `state/safe-generations/` for migration authority, encrypted quarantines/keywraps, and copy-on-write safe-store generations.

Legacy migration inputs and compatibility caches include:

- `state/dspy_rlm_runtime.sqlite` for authoritative candidate, job, and guidance metadata.
- `state/traces.jsonl` for bounded redacted trace projections.
- `state/runtime_state.json` and `state/compiled_guidance.json` as compatibility/read-cache artifacts.

After a valid Store Authority Manifest exists, legacy files are not runtime authority. They may be quarantined or retained for explicit migration recovery; normal v3 readers never consult them.

Disable the plugin to stop capture and guidance injection. Existing local records are not silently deleted. Remove `usr/plugins/dspy_rlm` to uninstall after preserving or deleting plugin-local state according to your retention needs.

## Development and testing

The checkout remains an Agent Zero plugin rooted at this repository; the test harness exposes that root under the runtime import name `usr.plugins.dspy_rlm`. The uv project is configured with `package = false`, installs no runtime dependencies, and does not package or relocate the plugin source.

Use Python 3.12, 3.13, or 3.14 in an isolated development environment:

```bash
uv sync --frozen --extra test
uv run --frozen --extra test python -m pytest
```

The `test` extra contains only pytest, pytest-asyncio, and PyYAML. DSPy, GEPA, model-provider SDKs, and other worker dependencies remain governed by `requirements-gepa.lock` and must stay out of Agent Zero's framework interpreter. CI also parses, but never imports, the exact pinned Agent Zero source contract at `b22a144bf59f15b1516084c9e7b88133ba92c8a9`.

## v3 local authority and Genesis

The v3 safe store is never created by startup, status, prompt composition, or an ordinary Agent Zero turn. Use the local-only protocol explicitly:

```bash
python scripts/a0_local_authority.py --help
```

Bootstrap the issuer and a separate opaque-reference key, issue an exact context/action-scoped grant, then run `genesis --create-store`. Genesis atomically writes the inert two-slot Null Activation Profile, immutable receipts, command ledger entry, event, and revision-zero scope. Grant inspection, revocation, policy-calibration approval/withdrawal/inspection, migration preflight/start/resume/confirm-cutover/inspection, and Privacy Quarantine export/waiver/deletion-challenge/deletion-begin/deletion-resume/inspection are also local-only. Migration start/resume stop at `awaiting_cutover`; only the explicit confirmation command may CAS the Store Authority Manifest. Quarantine deletion begins by atomically consuming the exact challenge and persisting the deletion intent, then resumes by revalidating the grant and durable intent before unlinking the wrapped key ahead of ciphertext. Inspection makes no physical-overwrite claim. All custody and state paths must be absolute; the command opens no network listener and returns only content-free references.

Privacy Quarantine cryptography is pinned separately in `requirements-migration.lock`. It belongs only in the local migration environment; it is intentionally absent from both Agent Zero's framework interpreter and the normal DSPy/GEPA worker environment.
