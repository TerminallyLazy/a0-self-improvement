import { createStore } from "/js/AlpineStore.js";
import { callJsonApi } from "/js/api.js";
import { getContext } from "/index.js";

const API_BASE = "/plugins/dspy_rlm";
const PUBLIC_STATUS_SCHEMA = "a0.public-status.v1";
const SAFE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const SAFE_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

const VIEW_DEFINITIONS = Object.freeze({
  overview: Object.freeze({ label: "Overview", schema: "a0.operator-overview.v1" }),
  candidates: Object.freeze({ label: "Candidates", schema: "a0.operator-candidates.v1" }),
  evidence_fixtures: Object.freeze({ label: "Evidence & Fixtures", schema: "a0.operator-evidence-fixtures.v1" }),
  privacy_migration: Object.freeze({ label: "Privacy & Migration", schema: "a0.operator-privacy-migration.v1" }),
  policy_capabilities: Object.freeze({ label: "Policy & Capabilities", schema: "a0.operator-policy-capabilities.v1" }),
  receipts_audit: Object.freeze({ label: "Receipts & Audit", schema: "a0.operator-receipts-audit.v1" }),
});

const VIEW_IDS = Object.freeze(Object.keys(VIEW_DEFINITIONS));

function safeToken(value, fallback = "unavailable") {
  return typeof value === "string" && SAFE_TOKEN.test(value) ? value : fallback;
}

function optionalToken(value) {
  return value === null || value === undefined ? null : safeToken(value);
}

function safeTimestamp(value) {
  return typeof value === "string" && SAFE_TIMESTAMP.test(value) ? value : null;
}

function safeCount(value) {
  return Number.isInteger(value) && value >= 0 ? value : 0;
}

function safeBoolean(value) {
  return value === true;
}

function safeCodes(values) {
  if (!Array.isArray(values)) return [];
  return values.slice(0, 32).map((value) => safeToken(value)).filter((value) => value !== "unavailable");
}

function safePairs(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key, count]) => SAFE_TOKEN.test(key) && Number.isInteger(count) && count >= 0)
      .map(([key, count]) => [key, count]),
  );
}

function axis(value = {}, reason = "projection_unavailable") {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const reasons = safeCodes(source.reason_codes);
  const state = safeToken(source.state);
  return {
    state,
    observed_at: safeTimestamp(source.observed_at),
    freshness: safeToken(source.freshness, "unavailable"),
    reason_codes: reasons.length ? reasons : (state === "unavailable" ? [reason] : []),
  };
}

function unavailableAxis(reason = "projection_unavailable") {
  return {
    state: "unavailable",
    observed_at: null,
    freshness: "unavailable",
    reason_codes: [reason],
  };
}

function actionSummary(value = {}) {
  return {
    action: safeToken(value.action),
    state: safeToken(value.state),
    reason_codes: safeCodes(value.reason_codes),
  };
}

function capabilitySummary(value = {}) {
  return {
    capability_id: safeToken(value.capability_id),
    semantic_id: safeToken(value.semantic_id),
    state: safeToken(value.state),
    reason_codes: safeCodes(value.reason_codes),
  };
}

function bucketSummary(value = {}) {
  return {
    ...axis(value),
    bucket_id: safeToken(value.bucket_id),
    required_count: safeCount(value.required_count),
    eligible_count: safeCount(value.eligible_count),
    outcome_state: safeToken(value.outcome_state),
  };
}

function baseProjection(raw, viewId, contextId) {
  const definition = VIEW_DEFINITIONS[viewId];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (raw.schema !== definition.schema || raw.view !== viewId) return null;
  const projectedContext = safeToken(raw.context_ref, "");
  const requestedContext = safeToken(contextId, "");
  if (!projectedContext || !requestedContext || projectedContext !== requestedContext) return null;
  return raw;
}

function unavailableOverview() {
  return {
    ordinary_runtime: unavailableAxis(),
    improvement: unavailableAxis(),
    migration_cutover: unavailableAxis(),
    activation: {
      ...unavailableAxis(),
      profile_ref: null,
      scope_revision: null,
      safety_bypass_state: "unavailable",
      rollback_eligibility: "unavailable",
      slots: [],
    },
    capabilities: { ...unavailableAxis(), items: [] },
    attention_actions: [],
  };
}

function normalizeOverview(raw, contextId) {
  const value = baseProjection(raw, "overview", contextId);
  if (!value) return unavailableOverview();
  const activation = value.activation && typeof value.activation === "object" ? value.activation : {};
  const capabilities = value.capabilities && typeof value.capabilities === "object" ? value.capabilities : {};
  return {
    ordinary_runtime: axis(value.ordinary_runtime),
    improvement: axis(value.improvement),
    migration_cutover: axis(value.migration_cutover),
    activation: {
      ...axis(activation),
      profile_ref: optionalToken(activation.profile_ref),
      scope_revision: activation.scope_revision === null ? null : safeCount(activation.scope_revision),
      safety_bypass_state: safeToken(activation.safety_bypass_state),
      rollback_eligibility: safeToken(activation.rollback_eligibility),
      slots: Array.isArray(activation.slots) ? activation.slots.map((item) => ({
        slot_kind: safeToken(item?.slot_kind),
        state: safeToken(item?.state),
        occupant_ref: optionalToken(item?.occupant_ref),
      })) : [],
    },
    capabilities: {
      ...axis(capabilities),
      items: Array.isArray(capabilities.items) ? capabilities.items.map(capabilitySummary) : [],
    },
    attention_actions: Array.isArray(value.attention_actions) ? value.attention_actions.map(actionSummary) : [],
  };
}

function normalizeCanary(value = {}) {
  const kind = safeToken(value.canary_kind, "none");
  const authorityCeiling = safeToken(value.authority_ceiling, "none");
  const activationAuthoritative = safeBoolean(value.activation_authoritative);
  const diagnosticConflict = kind === "diagnostic" && (
    authorityCeiling !== "no_promotion_authority" || activationAuthoritative
  );
  if (diagnosticConflict) {
    return {
      ...unavailableAxis("diagnostic_authority_conflict"),
      canary_kind: "diagnostic",
      authority_ceiling: "no_promotion_authority",
      conclusion_ref: null,
      activation_authoritative: false,
    };
  }
  return {
    ...axis(value),
    canary_kind: kind,
    authority_ceiling: authorityCeiling,
    conclusion_ref: optionalToken(value.conclusion_ref),
    activation_authoritative: activationAuthoritative,
  };
}

function normalizeCandidate(value = {}) {
  const disposition = value.disposition && typeof value.disposition === "object" ? value.disposition : {};
  const monitor = value.monitor && typeof value.monitor === "object" ? value.monitor : {};
  const diagnostic = value.diagnostic && typeof value.diagnostic === "object" ? value.diagnostic : {};
  return {
    ...axis(value),
    candidate_ref: safeToken(value.candidate_ref),
    artifact_ref: safeToken(value.artifact_ref),
    change_kind: safeToken(value.change_kind),
    target_slot: safeToken(value.target_slot),
    engine_semantic_id: safeToken(value.engine_semantic_id),
    authority_ceiling: safeToken(value.authority_ceiling),
    benefit_claim: safeToken(value.benefit_claim),
    benefit_state: safeToken(value.benefit_state),
    risk_tier: safeToken(value.risk_tier),
    incumbent_profile_ref: safeToken(value.incumbent_profile_ref),
    successor_profile_ref: optionalToken(value.successor_profile_ref),
    observed_scope_revision: safeCount(value.observed_scope_revision),
    lineage: axis(value.lineage),
    disposition: { ...axis(disposition), value: safeToken(disposition.value, "none") },
    monitor: {
      ...axis(monitor),
      receipt_refs: Array.isArray(monitor.receipt_refs) ? monitor.receipt_refs.map((item) => safeToken(item)) : [],
    },
    changed_component_count: safeCount(value.changed_component_count),
    protected_constraint_state: safeToken(value.protected_constraint_state),
    rule_catalog_ids: Array.isArray(value.rule_catalog_ids) ? value.rule_catalog_ids.map((item) => safeToken(item)) : [],
    evidence_buckets: Array.isArray(value.evidence_buckets) ? value.evidence_buckets.map(bucketSummary) : [],
    canary: normalizeCanary(value.canary),
    diagnostic: {
      authority_ceiling: safeToken(diagnostic.authority_ceiling, "no_promotion_authority"),
      labels: safeCodes(diagnostic.labels),
      reason_codes: safeCodes(diagnostic.reason_codes),
    },
    allowed_actions: Array.isArray(value.allowed_actions) ? value.allowed_actions.map(actionSummary) : [],
  };
}

function unavailableCandidates() {
  return { axis: unavailableAxis(), disposition_counts: {}, attention_count: 0, items: [] };
}

function normalizeCandidates(raw, contextId) {
  const value = baseProjection(raw, "candidates", contextId);
  if (!value) return unavailableCandidates();
  return {
    axis: axis(value.axis),
    disposition_counts: safePairs(value.disposition_counts),
    attention_count: safeCount(value.attention_count),
    items: Array.isArray(value.items) ? value.items.map(normalizeCandidate) : [],
  };
}

function unavailableEvidenceFixtures() {
  return {
    evidence: { ...unavailableAxis(), buckets: [] },
    fixtures: { ...unavailableAxis(), workflow_counts: {}, families: [] },
  };
}

function normalizeEvidenceFixtures(raw, contextId) {
  const value = baseProjection(raw, "evidence_fixtures", contextId);
  if (!value) return unavailableEvidenceFixtures();
  const evidence = value.evidence && typeof value.evidence === "object" ? value.evidence : {};
  const fixtures = value.fixtures && typeof value.fixtures === "object" ? value.fixtures : {};
  return {
    evidence: {
      ...axis(evidence),
      buckets: Array.isArray(evidence.buckets) ? evidence.buckets.map(bucketSummary) : [],
    },
    fixtures: {
      ...axis(fixtures),
      workflow_counts: safePairs(fixtures.workflow_counts),
      families: Array.isArray(fixtures.families) ? fixtures.families.map((item) => ({
        ...axis(item),
        family_ref: safeToken(item?.family_ref),
        eligibility_state: safeToken(item?.eligibility_state),
        partition_counts: safePairs(item?.partition_counts),
        grant_state: safeToken(item?.grant_state),
      })) : [],
    },
  };
}

function unavailablePrivacyMigration() {
  return {
    privacy: unavailableAxis(),
    migration: {
      ...unavailableAxis(),
      migration_ref: null,
      phase: "unavailable",
      checkpoint_count: 0,
      disposition_counts: {},
      key_custody_state: "unavailable",
      cutover_readiness: "unavailable",
      recovery_state: "unavailable",
    },
    operations: [],
  };
}

function normalizePrivacyMigration(raw, contextId) {
  const value = baseProjection(raw, "privacy_migration", contextId);
  if (!value) return unavailablePrivacyMigration();
  const migration = value.migration && typeof value.migration === "object" ? value.migration : {};
  return {
    privacy: axis(value.privacy),
    migration: {
      ...axis(migration),
      migration_ref: optionalToken(migration.migration_ref),
      phase: safeToken(migration.phase),
      checkpoint_count: safeCount(migration.checkpoint_count),
      disposition_counts: safePairs(migration.disposition_counts),
      key_custody_state: safeToken(migration.key_custody_state),
      cutover_readiness: safeToken(migration.cutover_readiness),
      recovery_state: safeToken(migration.recovery_state),
    },
    operations: Array.isArray(value.operations) ? value.operations.map((item) => ({
      ...axis(item),
      operation_ref: safeToken(item?.operation_ref),
      operation_kind: safeToken(item?.operation_kind),
      challenge_ref: optionalToken(item?.challenge_ref),
      receipt_refs: Array.isArray(item?.receipt_refs) ? item.receipt_refs.map((ref) => safeToken(ref)) : [],
      instruction_code: safeToken(item?.instruction_code),
      execution_surface: item?.execution_surface === "local_cli_only" ? "local_cli_only" : "unavailable",
    })) : [],
  };
}

function unavailablePolicyCapabilities() {
  return {
    policy: {
      ...unavailableAxis(),
      policy_ref: null,
      calibration_state: "unavailable",
      activation_mode: "unavailable",
      automatic_authority_state: "unavailable",
    },
    capabilities: { ...unavailableAxis(), items: [], dependency_profile_ref: null, dependency_state: "unavailable" },
    grants: { ...unavailableAxis(), items: [] },
    budgets: { ...unavailableAxis(), items: [] },
    local_step_up_instruction_code: "local_authority_unavailable",
  };
}

function normalizePolicyCapabilities(raw, contextId) {
  const value = baseProjection(raw, "policy_capabilities", contextId);
  if (!value) return unavailablePolicyCapabilities();
  const policy = value.policy && typeof value.policy === "object" ? value.policy : {};
  const capabilities = value.capabilities && typeof value.capabilities === "object" ? value.capabilities : {};
  const grants = value.grants && typeof value.grants === "object" ? value.grants : {};
  const budgets = value.budgets && typeof value.budgets === "object" ? value.budgets : {};
  return {
    policy: {
      ...axis(policy),
      policy_ref: optionalToken(policy.policy_ref),
      calibration_state: safeToken(policy.calibration_state),
      activation_mode: safeToken(policy.activation_mode),
      automatic_authority_state: safeToken(policy.automatic_authority_state),
    },
    capabilities: {
      ...axis(capabilities),
      items: Array.isArray(capabilities.items) ? capabilities.items.map(capabilitySummary) : [],
      dependency_profile_ref: optionalToken(capabilities.dependency_profile_ref),
      dependency_state: safeToken(capabilities.dependency_state),
    },
    grants: {
      ...axis(grants),
      items: Array.isArray(grants.items) ? grants.items.map((item) => ({
        grant_ref: safeToken(item?.grant_ref),
        grant_kind: safeToken(item?.grant_kind),
        state: safeToken(item?.state),
        authority_ceiling: safeToken(item?.authority_ceiling),
        expiry_state: safeToken(item?.expiry_state),
      })) : [],
    },
    budgets: {
      ...axis(budgets),
      items: Array.isArray(budgets.items) ? budgets.items.map((item) => ({
        budget_id: safeToken(item?.budget_id),
        state: safeToken(item?.state),
        limit_units: safeCount(item?.limit_units),
        reserved_units: safeCount(item?.reserved_units),
        consumed_units: safeCount(item?.consumed_units),
      })) : [],
    },
    local_step_up_instruction_code: safeToken(value.local_step_up_instruction_code),
  };
}

function unavailableReceiptsAudit() {
  return { receipts: unavailableAxis(), category_counts: {}, items: [] };
}

function normalizeReceiptsAudit(raw, contextId) {
  const value = baseProjection(raw, "receipts_audit", contextId);
  if (!value) return unavailableReceiptsAudit();
  return {
    receipts: axis(value.receipts),
    category_counts: safePairs(value.category_counts),
    items: Array.isArray(value.items) ? value.items.map((item) => ({
      sequence: safeCount(item?.sequence),
      receipt_ref: safeToken(item?.receipt_ref),
      category: safeToken(item?.category),
      action: safeToken(item?.action),
      state: safeToken(item?.state),
      observed_at: safeTimestamp(item?.observed_at),
      related_receipt_refs: Array.isArray(item?.related_receipt_refs)
        ? item.related_receipt_refs.map((ref) => safeToken(ref))
        : [],
    })) : [],
  };
}

const NORMALIZERS = Object.freeze({
  overview: normalizeOverview,
  candidates: normalizeCandidates,
  evidence_fixtures: normalizeEvidenceFixtures,
  privacy_migration: normalizePrivacyMigration,
  policy_capabilities: normalizePolicyCapabilities,
  receipts_audit: normalizeReceiptsAudit,
});

const UNAVAILABLE_PROJECTIONS = Object.freeze({
  overview: unavailableOverview,
  candidates: unavailableCandidates,
  evidence_fixtures: unavailableEvidenceFixtures,
  privacy_migration: unavailablePrivacyMigration,
  policy_capabilities: unavailablePolicyCapabilities,
  receipts_audit: unavailableReceiptsAudit,
});

function detectContextId() {
  const query = new URLSearchParams(window.location.search || "").get("ctxid");
  let current = "";
  try {
    current = typeof getContext === "function" ? getContext() : "";
  } catch (_) {
    current = "";
  }
  return String(query || current || "").trim();
}

export const store = createStore("dspyRlm", {
  activeView: "overview",
  contextId: "",
  initialized: false,
  loading: false,
  loaded: false,
  lastErrorCode: "",
  candidateFilter: "all",
  receiptFilter: "all",
  selectedCandidateRef: null,
  pendingAction: null,
  projections: {
    overview: unavailableOverview(),
    candidates: unavailableCandidates(),
    evidence_fixtures: unavailableEvidenceFixtures(),
    privacy_migration: unavailablePrivacyMigration(),
    policy_capabilities: unavailablePolicyCapabilities(),
    receipts_audit: unavailableReceiptsAudit(),
  },

  get viewTabs() {
    return VIEW_IDS.map((id) => ({ id, label: VIEW_DEFINITIONS[id].label }));
  },

  get overview() { return this.projections.overview; },
  get candidates() { return this.projections.candidates; },
  get evidenceFixtures() { return this.projections.evidence_fixtures; },
  get privacyMigration() { return this.projections.privacy_migration; },
  get policyCapabilities() { return this.projections.policy_capabilities; },
  get receiptsAudit() { return this.projections.receipts_audit; },

  get filteredCandidates() {
    const items = this.candidates.items;
    return this.candidateFilter === "all"
      ? items
      : items.filter((item) => item.disposition.value === this.candidateFilter);
  },

  get selectedCandidate() {
    const candidates = this.filteredCandidates;
    return candidates.find((item) => item.candidate_ref === this.selectedCandidateRef) || candidates[0] || null;
  },

  get receiptCategories() {
    return ["all", ...Object.keys(this.receiptsAudit.category_counts)];
  },

  get filteredReceipts() {
    return this.receiptFilter === "all"
      ? this.receiptsAudit.items
      : this.receiptsAudit.items.filter((item) => item.category === this.receiptFilter);
  },

  async initRuntime() {
    if (this.initialized) return;
    this.initialized = true;
    this.contextId = detectContextId();
    await this.refreshAll();
  },

  setActiveView(viewId) {
    if (VIEW_DEFINITIONS[viewId]) this.activeView = viewId;
  },

  setContextId(value) {
    const next = String(value?.target ? value.target.value : value || "").trim();
    if (!next) {
      this.lastErrorCode = "context_required";
      return;
    }
    this.contextId = next;
    this.selectedCandidateRef = null;
    this.pendingAction = null;
    void this.refreshAll();
  },

  async refreshAll() {
    if (this.loading) return;
    if (!this.contextId) {
      this.lastErrorCode = "context_required";
      this.loaded = true;
      return;
    }
    this.loading = true;
    this.lastErrorCode = "";
    let publicStatus;
    try {
      publicStatus = await callJsonApi(`${API_BASE}/status`, {
        context_id: this.contextId,
      });
    } catch (_) {
      this.lastErrorCode = "status_unavailable";
      this.loaded = true;
      this.loading = false;
      return;
    }
    const projectedContext = safeToken(publicStatus?.context_ref, "");
    const pluginState = safeToken(publicStatus?.plugin_state, "unavailable");
    if (publicStatus?.schema !== PUBLIC_STATUS_SCHEMA || projectedContext !== this.contextId) {
      this.lastErrorCode = "status_invalid";
      this.loaded = true;
      this.loading = false;
      return;
    }
    if (pluginState !== "ready") {
      const reasons = safeCodes(publicStatus?.activation_scope?.reason_codes);
      this.lastErrorCode = reasons[0] || `plugin_${pluginState}`;
      this.projections = Object.fromEntries(
        VIEW_IDS.map((viewId) => [viewId, UNAVAILABLE_PROJECTIONS[viewId]()]),
      );
      this.loaded = true;
      this.loading = false;
      return;
    }
    const results = await Promise.allSettled(VIEW_IDS.map(async (viewId) => {
      const payload = await callJsonApi(`${API_BASE}/operator_projection`, {
        context_id: this.contextId,
        view: viewId,
      });
      return [viewId, NORMALIZERS[viewId](payload, this.contextId)];
    }));
    let unavailableCount = 0;
    results.forEach((result, index) => {
      const viewId = VIEW_IDS[index];
      if (result.status === "fulfilled") {
        const [, projection] = result.value;
        this.projections[viewId] = projection;
      } else {
        unavailableCount += 1;
        this.projections[viewId] = UNAVAILABLE_PROJECTIONS[viewId]();
      }
    });
    if (unavailableCount) this.lastErrorCode = "operator_projection_unavailable";
    if (unavailableCount === VIEW_IDS.length) {
      this.projections = Object.fromEntries(
        VIEW_IDS.map((viewId) => [viewId, UNAVAILABLE_PROJECTIONS[viewId]()]),
      );
    }
    this.loaded = true;
    this.loading = false;
  },

  actionFor(candidate, actionName) {
    if (!candidate || !Array.isArray(candidate.allowed_actions)) return null;
    return candidate.allowed_actions.find((action) => action.action === actionName) || null;
  },

  actionAllowed(candidate, actionName) {
    const action = this.actionFor(candidate, actionName);
    return Boolean(action && action.state === "eligible");
  },

  actionReasonCodes(candidate, actionName) {
    return this.actionFor(candidate, actionName)?.reason_codes || ["action_not_authorized"];
  },

  stageCandidateAction(candidate, actionName) {
    if (!this.actionAllowed(candidate, actionName)) return;
    this.pendingAction = {
      action: actionName,
      candidate_ref: candidate.candidate_ref,
      incumbent_profile_ref: candidate.incumbent_profile_ref,
      successor_profile_ref: candidate.successor_profile_ref,
      expected_scope_revision: candidate.observed_scope_revision,
    };
  },

  clearPendingAction() {
    this.pendingAction = null;
  },

  axisClass(value) {
    const state = safeToken(value?.state);
    if (["active", "completed", "current", "eligible", "passed", "promotion_ready", "ready"].includes(state)) return "is-ok";
    if (["blocked", "corrupt", "failed", "ineligible", "rejected", "revoked"].includes(state)) return "is-danger";
    return "is-warn";
  },

  observedLabel(value) {
    return safeTimestamp(value) || "not_observed";
  },

  reasonLabel(values) {
    const codes = safeCodes(values);
    return codes.length ? codes.join(" · ") : "no_reason_code";
  },
});
