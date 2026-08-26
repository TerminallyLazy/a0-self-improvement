# A0 Self-Improvement

An authority-ranked Agent Zero self-improvement plugin. The v3 design keeps ordinary Agent Zero behavior available while typed observation, candidate search, certified replay, evidence reduction, canary, activation, monitoring, rollback, privacy migration, or operator authority is unavailable.

## What it does

- Stores strict canonical records, links, receipts, lifecycle events, activation scopes, operation slots, work leases, and budget authority in a v3 safe-projection store.
- Records restart-safe, content-free runtime observation facts from the certified message-loop and tool-result seams without retaining prompts, tool traffic, provider data, paths, or error text.
- Creates a safe, no-effect starting profile for each project chat before any improvement can be considered; internally this is the byte-inert Null Genesis profile.
- Supports deterministic candidate analysis, certified fixture replay, evidence dispositions, calibrated canaries, exact-revision activation, monitoring, ancestry-safe rollback, and all-null Safety Bypass contracts.
- Routes an occupied canary deterministically through the exact incumbent or successor profile when an explicitly provisioned assignment key matches the frozen plan, then records only content-free exposure facts after the matching loop outcome.
- Presents six context-scoped operator views without raw prompts, tool traffic, fixture content, model reasoning, provider identifiers, filesystem paths, secrets, quarantine identities, or exception strings.
- Adds a near-real-time automation board that refreshes while the dashboard is visible and reports project chat coverage, observations, queued work, candidates, receipts, worker health, generation gates, promotion gates, and recent content-free activity.
- Isolates DSPy 3.3.1, GEPA, and Deno in a hash-locked worker environment. Model findings remain candidate hypotheses; workers never own activation.

## Install and use

1. Install the repository as `usr/plugins/dspy_rlm` or use Agent Zero's Plugin Hub.
2. Assign the chat to an Agent Zero project so parallel-agent contexts share one enrollment boundary.
3. Enable the plugin. By default it safely prepares every chat in that project automatically. No command-line setup is required.
4. Open the dashboard, choose a chat from the project-colored context menu, and inspect the six read-only, content-free operator views for that chat.
5. Submit mutations only through the signed v3 command contract with an exact context, target, revision, idempotency key, browser-session challenge, and unexpired action-scoped grant.

The projection and command APIs retain Agent Zero authentication and CSRF protections. Reads open only the selected existing safe-store generation in SQLite read-only/query-only mode; they never create, repair, migrate, or fall back. The signed command endpoint dispatches optimize, work cancellation, canary start/stop, activation, rollback, Safety Bypass, monitor conclusion, requalification start/conclusion, feedback, and fixture draft/review/admit/withdraw. Fixture commands resolve opaque content-session handles only through an explicitly provisioned private runtime profile, current-owner custody files, the encrypted vault, and the durable repository ledger; missing custody remains a truthful `503`. A rollback-required monitor or requalification conclusion emits a request-only authority record and leaves the Activation Scope unchanged; the separately signed rollback command remains the sole profile-mutating transition. The retired `/optimize`, `/promote`, and `/rollback` routes return safe `410` responses and perform no mutation.

## v3 implementation boundary

This repository contains the standalone v3 schemas, repositories, migration/quarantine lifecycle, work and budget authority, fixture governance, certified replay contracts, deterministic and model-route contracts, outcome-GEPA admission, canary/activation/rollback coordinators, the explicitly injected 11-stage closed-loop runner, operator projections, and signed HTTP seams. Runtime hooks append only neutral v3 observation facts with no promotion authority. The observation bridge requires an exact current-profile policy mapping, window, and evidence authority before it materializes deterministic analysis facts. Canary reduction separately requires exact exposure receipts and one authority-ranked, candidate-attributable, content-free outcome fact per exposure; exposure alone is never outcome authority. Automatic scheduling may create compatibility candidate work, but raw previews and configuration defaults remain neither v3 observation authority nor activation authority.

The fake-provider and coordinator tests prove standalone source contracts. Runtime canary observations have exposure authority only and cannot authorize promotion without separately certified, candidate-attributable Outcome Evidence and a valid conclusion. These tests do not by themselves certify a real provider, a clean pinned Agent Zero checkout, or a named Docker runtime; those are separate acceptance gates in `IMPLEMENTATION_SPEC.md`.

## DSPy/GEPA worker setup

The plugin `install()` and `pre_update()` hooks create a clean isolated environment without host site-package inheritance, bridge only the exact Agent Zero source root, install the hash-locked closure from `requirements-gepa.lock` through `uv`, and smoke-test both the Agent Zero worker imports and `dspy.RLM`/`dspy.GEPA`. `requirements.txt` is intentionally empty so Agent Zero's normal plugin installer cannot install worker dependencies into the framework interpreter. A non-blocking startup extension repairs the environment after Docker container recreation. Native development uses `state/worker-venv`; Docker uses container-local `/opt/dspy-rlm-worker-venv` to avoid synchronizing dependency trees through the host bind mount. `DSPY_RLM_WORKER_VENV` may override either location. Agent Zero's framework interpreter is never modified. The status endpoint reads a lock-digest-bound version marker instead of importing DSPy on every refresh.

The sole worker root is DSPy 3.3.1 with the managed Deno extra; the generated lock resolves GEPA 0.1.4 and the complete transitive closure. Re-run the setup action after changing the lock or rebuilding the Docker container.

Depfix, if evaluated, is experimental and may only act as an isolated-worker adapter over the frozen plugin store. It must use no dynamic requirements, explicitly import dependencies in each subprocess, and must never modify Agent Zero’s interpreter.

## Automation modes

The Settings page provides three one-switch modes. **Observe** records content-free runtime facts only. **Review** also schedules RLM/GEPA candidate work for manual review. **Autopilot** schedules the same work and continuously evaluates the certified replay, canary, rollback, calibration, policy, and production-runner gates needed for automatic activation. The public default remains Observe.

Project scope is the default: every persisted chat assigned to the current Agent Zero project, including parallel-agent chats, is considered independently and summarized together on the live dashboard. Current-chat scope is available for narrower experiments. Conversation bodies, tool arguments, tool results, provider content, and error text are excluded from this automation path. Local system-prompt snapshots are captured only when the operator explicitly enables the setting.

Autopilot does not manufacture its own authority. Version 2.0.11 automates safe collection and candidate scheduling, but production automatic canary/activation remains blocked because no production transition runner or production-scoped Policy Calibration Artifact ships with the plugin. The dashboard reports these as explicit blocked gates. That boundary is intentional: workers can propose changes, but they cannot promote themselves.

The dashboard uses bounded two-second polling by default, pauses network reads while the browser tab is hidden, and resumes automatically. It reports the nearest per-chat scheduling threshold as completed loops, required loops, and remaining loops, while cooldown and queued states remain explicit. The interval is configurable from 1 to 30 seconds. Status reads are read-only and do not create stores, start workers, repair state, or initialize projects.

## Legacy compatibility settings

The checked-in configuration remains readable for migration and compatibility diagnostics. Its numerical values are not v3 policy calibration, budget, replay, canary, activation, or automatic-work authority. v3 requires those facts as exact typed inputs; it does not infer them from these legacy defaults.

- `optimization.auto_optimize`: driven by Review and Autopilot to enqueue candidate-generation work only; it grants no v3 publication, canary, activation, or promotion authority.
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

## Automatic project setup and advanced recovery

When the plugin is enabled, automatic project setup defaults to on. Before processing a message, the plugin safely prepares any chats assigned to the same Agent Zero project, including parallel-agent chats. It reads only chat IDs and project identifiers, and the starting state has no effect on prompts or responses. Users do not need to run setup commands.

The dashboard context menu shows the Agent Zero project name and its chosen color, then lists every currently discovered chat in that project, including parallel and child chats. Selecting an entry changes only the plugin's inspection scope; it does not switch the underlying Agent Zero conversation.

The Settings page exposes **Set up project chats automatically** for operators who need to disable this behavior. Disabling it does not remove existing setup. Chats without an Agent Zero project are not prepared automatically.

Internally, this safe starting state is called **Genesis**. The term appears below only because it is part of the advanced recovery command names. Any setup failure disables self-improvement for that chat but never blocks ordinary Agent Zero behavior. Advanced recovery tools remain available:

```bash
python scripts/a0_local_authority.py --help
```

Manual `genesis`, `project-genesis`, and issuer bootstrap are recovery/admin paths. Genesis atomically writes the inert two-slot Null Activation Profile, immutable receipts, command ledger entry, event, and revision-zero scope. Grant inspection, revocation, policy-calibration approval/withdrawal/inspection, migration preflight/start/resume/confirm-cutover/inspection, and Privacy Quarantine export/waiver/deletion-challenge/deletion-begin/deletion-resume/inspection remain local-only. Migration start/resume stop at `awaiting_cutover`; only the explicit confirmation command may CAS the Store Authority Manifest. All custody and state paths must be absolute; the command opens no network listener and returns only content-free references.

Genesis is context-scoped. Creating the store and initializing one chat does not initialize another chat. Verify the exact selected context with the read-only readiness command:

```bash
python scripts/a0_local_authority.py readiness-inspect \
  --store /a0/usr/plugins/dspy_rlm/state/dspy_rlm_v3.sqlite \
  --manifest /a0/usr/plugins/dspy_rlm/state/store-authority-manifest.json \
  --context YOUR_CONTEXT_ID
```

`"state":"ready"` means the command opened the runtime-selected store in read-only/query-only mode, verified any Store Authority Manifest and migration receipt binding, and found a valid Activation Scope and two-slot Activation Profile for that exact context. `safe_store_missing` means automatic setup has not yet run successfully. `activation_scope_missing` means automatic setup is disabled, the chat is not assigned to a project, or automatic enrollment failed; opening a new message loop in that project normally repairs it. Any other command failure is fail-closed; use the manual protocol only if automatic recovery does not succeed.

Parallel agents should be enrolled and checked at the Agent Zero project boundary, not across unrelated chats. Project inspection reads only each chat's context ID and project identifier; it does not read or retain chat content:

```bash
python scripts/a0_local_authority.py project-readiness-inspect \
  --store /a0/usr/plugins/dspy_rlm/state/dspy_rlm_v3.sqlite \
  --manifest /a0/usr/plugins/dspy_rlm/state/store-authority-manifest.json \
  --chats-dir /a0/usr/chats \
  --project YOUR_PROJECT_ID
```

The result is ready only when every currently discovered context in that project has its own valid Activation Scope. Normally, send a message in any chat assigned to the project and automatic enrollment will cover all discovered project chats. For recovery, `project-genesis` can still enroll all missing contexts in one explicit local operation; the grant directory must already exist and remain operator-only:

```bash
python scripts/a0_local_authority.py project-genesis \
  --store /a0/usr/plugins/dspy_rlm/state/dspy_rlm_v3.sqlite \
  --manifest /a0/usr/plugins/dspy_rlm/state/store-authority-manifest.json \
  --chats-dir /a0/usr/chats \
  --project YOUR_PROJECT_ID \
  --secret /a0/usr/plugins/dspy_rlm/state/authority/issuer-root.secret \
  --profile /a0/usr/plugins/dspy_rlm/state/authority/issuer-profile.json \
  --opaque-key /a0/usr/plugins/dspy_rlm/state/authority/opaque-reference.key \
  --opaque-key-epoch YOUR_OPAQUE_KEY_EPOCH \
  --grant-dir /a0/usr/plugins/dspy_rlm/state/authority/project-grants \
  --subject YOUR_OPERATOR_REF \
  --idempotency-prefix YOUR_PROJECT_GENESIS_KEY \
  --session-nonce-prefix YOUR_PROJECT_SESSION_NONCE \
  --authority-expires-at YOUR_ISO_8601_EXPIRY \
  --now YOUR_ISO_8601_NOW \
  --confirm BOOTSTRAP_PROJECT_GENESIS
```

Add `--create-store` only for the first pre-cutover manual initialization. The command skips contexts that already have an Activation Scope, issues and persists one exact grant for every missing context, and returns only context and receipt references. Activation, commands, receipts, and rollback remain context-bound so one parallel agent cannot silently mutate another.

Privacy Quarantine cryptography is pinned separately in `requirements-migration.lock`. It belongs only in the local migration environment; it is intentionally absent from both Agent Zero's framework interpreter and the normal DSPy/GEPA worker environment.
