from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "webui" / "main.html").read_text(encoding="utf-8")
STORE = (ROOT / "webui" / "dspy-rlm-store.js").read_text(encoding="utf-8")


def test_operator_shell_exposes_exactly_the_six_public_views() -> None:
    expected = (
        "Overview",
        "Candidates",
        "Evidence & Fixtures",
        "Privacy & Migration",
        "Policy & Capabilities",
        "Receipts & Audit",
    )

    for label in expected:
        assert f">{label}<" in MAIN

    assert "viewTabs" in MAIN
    assert 'x-for="tab in $store.dspyRlm.viewTabs"' in MAIN
    assert "$store.dspyRlm.activeView === tab.id" in MAIN
    for view_id in (
        "overview",
        "candidates",
        "evidence_fixtures",
        "privacy_migration",
        "policy_capabilities",
        "receipts_audit",
    ):
        assert f"$store.dspyRlm.activeView === '{view_id}'" in MAIN


def test_store_consumes_only_exact_operator_projection_schemas() -> None:
    for schema in (
        "a0.operator-overview.v1",
        "a0.operator-candidates.v1",
        "a0.operator-evidence-fixtures.v1",
        "a0.operator-privacy-migration.v1",
        "a0.operator-policy-capabilities.v1",
        "a0.operator-receipts-audit.v1",
    ):
        assert schema in STORE

    assert '`${API_BASE}/operator_projection`' in STORE
    assert "context_id:" in STORE
    assert "view: viewId" in STORE
    assert "schema !== definition.schema" in STORE
    assert "legacy" not in STORE.lower()
    for forbidden in (
        "/optimize",
        "/promote",
        "/rollback",
        "runOptimize",
        "lastGuidance",
        "optimizationResult",
        "latestToolRows",
        ".payload",
        ".error",
        "force:",
    ):
        assert forbidden not in STORE


def test_store_preflights_public_status_before_requesting_operator_views() -> None:
    status_call = STORE.index('`${API_BASE}/status`')
    projection_call = STORE.index('`${API_BASE}/operator_projection`')

    assert status_call < projection_call
    assert 'const PUBLIC_STATUS_SCHEMA = "a0.public-status.v1";' in STORE
    assert 'if (pluginState !== "ready")' in STORE
    assert "publicStatus?.activation_scope?.reason_codes" in STORE


def test_store_explains_project_setup_without_internal_jargon_or_paths() -> None:
    assert 'title: "Project setup needed"' in STORE
    assert "prepared for safe self-improvement" in STORE
    assert "Genesis required" not in STORE
    assert "Activation Scope yet" not in STORE
    assert "Store Authority Manifest failed verification." in STORE
    assert 'x-text="$store.dspyRlm.errorCopy.message"' in MAIN


def test_mutation_and_diagnostic_authority_stay_fail_closed() -> None:
    assert 'action.state === "eligible"' in STORE
    assert "diagnostic_canary_no_activation_authority" in MAIN
    assert "no_promotion_authority" in MAIN
    assert "activation_authoritative" in MAIN
    assert "local_cli_only" in MAIN
    assert "stageCandidateAction" in MAIN
    assert "callJsonApi" not in STORE[STORE.index("stageCandidateAction"):]
    assert "stageSafetyBypass" not in MAIN
    assert ">Apply Safety Bypass<" not in MAIN
    assert "force" not in MAIN.lower()


def test_operator_styles_are_isolated_from_agent_zero_host_css() -> None:
    assert '<main id="a0si-operator" class="operator-shell"' in MAIN
    assert "#a0si-operator .panel {" in MAIN
    assert "display:block;" in MAIN
    assert "height:auto;" in MAIN
    assert "overflow:visible;" in MAIN
    assert ":root { --ink" not in MAIN
    assert "\n      body {" not in MAIN
    assert "\n      * { box-sizing" not in MAIN


def test_context_picker_groups_agent_zero_chats_by_project() -> None:
    assert 'from "/components/sidebar/chats/chats-store.js"' in STORE
    assert "context?.project?.name" in STORE
    assert "projectChats" in STORE
    assert "projectColor" in STORE
    assert "selectedChatLabel" in STORE
    assert 'x-for="chat in $store.dspyRlm.projectChats"' in MAIN
    assert "backgroundColor: $store.dspyRlm.projectColor" in MAIN
    assert "$store.dspyRlm.selectProjectChat(chat.id)" in MAIN
    assert 'placeholder="Select a context"' not in MAIN

    init_runtime = STORE[STORE.index("async initRuntime()") : STORE.index("setActiveView(viewId)")]
    assert init_runtime.index("const detectedContext = detectContextId();") < init_runtime.index("if (this.initialized)")
    assert "detectedContext !== this.contextId" in init_runtime


def test_overview_axis_cards_contain_long_projection_reasons() -> None:
    assert ".axis-card > * { min-width:0; max-width:100%; }" in MAIN
    assert "overflow:hidden; }" in MAIN
    assert "overflow-wrap:anywhere; word-break:break-word;" in MAIN
    assert ".metric-grid span { display:block; min-width:0; min-height:2.5em;" in MAIN


def test_overview_exposes_live_autopilot_observability() -> None:
    assert "Closed-loop automation" in MAIN
    assert "Next optimization" in MAIN
    assert "nextOptimizationLabel" in STORE
    assert "Automatic promotion" in MAIN
    assert "Recent activity" in MAIN
    assert "autopilot_status" in STORE
    assert "startLiveUpdates" in STORE
    assert "document.hidden" in STORE
