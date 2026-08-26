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
