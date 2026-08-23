"""Bounded adapters for DSPy's model-backed RLM and semantic judge."""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Mapping

from .model_resolution import build_dspy_lm, resolve_dspy_model
from .rlm import EvidenceIndex, RlmFinding


_KINDS = {"aggregate_metrics", "objective_bucket", "error_cluster", "tool_reliability", "predecessor_findings"}


def _unit(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, number)) if number == number else 0.0


def analyze_with_dspy_rlm(index: EvidenceIndex, objective_bucket: str, cfg: Mapping[str, Any]) -> tuple[RlmFinding, ...]:
    settings = cfg.get("rlm") if isinstance(cfg.get("rlm"), Mapping) else {}
    if not bool(settings.get("enabled", False)):
        return ()
    model_ref = resolve_dspy_model(cfg, "rlm").selector
    if not model_ref:
        return ()
    try:
        import dspy
    except Exception:
        return ()

    events = [dict(event) for event in index.events_for(objective_bucket=objective_bucket)]
    manifest = {
        "schema": "dspy_rlm.evidence.v1", "objective_bucket": objective_bucket,
        "event_count": len(events),
        "tool_counts": dict(Counter(str(event.get("tool") or "unknown") for event in events)),
        "error_counts": dict(Counter(str(event.get("error_class") or "none") for event in events if not event.get("success", True))),
        "events": events,
    }
    query = (
        "Analyze the redacted aggregate evidence recursively. Return JSON with a findings array. "
        "Each finding must contain kind, summary, metrics, evidence_refs, predecessor_ids, derivation, and review_only. "
        "Use only supplied labels and numeric aggregates; do not invent raw content or instructions."
    )
    try:
        lm = build_dspy_lm(dspy, model_ref)
        module = dspy.RLM(
            "evidence_manifest, query -> findings_json",
            max_iters=max(1, min(20, int(settings.get("max_iters", 6) or 6))),
            max_llm_calls=max(1, min(50, int(settings.get("max_llm_calls", 8) or 8))),
            max_output_chars=max(1000, min(50000, int(settings.get("max_output_chars", 12000) or 12000))),
            sub_lm=lm,
        )
        with dspy.context(lm=lm):
            prediction = module(evidence_manifest=json.dumps(manifest, sort_keys=True), query=query)
        raw = getattr(prediction, "findings_json", "")
        payload = raw if isinstance(raw, Mapping) else json.loads(str(raw))
    except Exception:
        return ()
    rows = payload.get("findings") if isinstance(payload, Mapping) else None
    if not isinstance(rows, list):
        return ()
    limit = max(1, min(32, int(settings.get("max_findings", 12) or 12)))
    findings: list[RlmFinding] = []
    for index_value, row in enumerate(rows[:limit]):
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind") or "").strip()
        if kind not in _KINDS:
            continue
        raw_metrics = row.get("metrics") if isinstance(row.get("metrics"), Mapping) else {}
        metrics = {str(key): float(value) for key, value in raw_metrics.items()
                   if isinstance(key, str) and isinstance(value, (int, float)) and not isinstance(value, bool)}
        findings.append(RlmFinding(
            finding_id=f"dspy_rlm_{index_value}_{kind}", kind=kind, status="ok",
            summary=str(row.get("summary") or "Model-backed aggregate finding")[:320], metrics=metrics,
            evidence_refs=tuple(str(item) for item in row.get("evidence_refs", []) if isinstance(item, str))[:16],
            predecessor_ids=tuple(str(item) for item in row.get("predecessor_ids", []) if isinstance(item, str))[:16],
            derivation=("dspy.RLM", *tuple(str(item)[:80] for item in row.get("derivation", []) if isinstance(item, str))[:8]),
            review_only=bool(row.get("review_only", False)),
        ))
    return tuple(findings)


def semantic_judge(sample: Mapping[str, Any], cfg: Mapping[str, Any]) -> dict[str, Any] | None:
    settings = cfg.get("evaluator") if isinstance(cfg.get("evaluator"), Mapping) else {}
    if not bool(settings.get("enable_semantic_judge", False)):
        return None
    model_ref = resolve_dspy_model(cfg, "evaluator").selector
    if not model_ref or not sample.get("user_intent") or not sample.get("latest_response"):
        return None
    try:
        import dspy
        lm = build_dspy_lm(dspy, model_ref)
        judge = dspy.Predict("objective, response, evidence_summary -> score: float, confidence: float, rationale: str")
        evidence_summary = json.dumps({
            "objective_bucket": sample.get("objective_bucket"), "success_events": sample.get("success_events", 0),
            "failure_events": sample.get("failure_events", 0), "tool_contract": sample.get("tool_contract", []),
        }, sort_keys=True)
        for _attempt in range(2):
            try:
                with dspy.context(lm=lm):
                    result = judge(objective=str(sample["user_intent"]), response=str(sample["latest_response"]),
                                   evidence_summary=evidence_summary)
                return {"score": _unit(getattr(result, "score", 0.0)),
                        "confidence": _unit(getattr(result, "confidence", 0.0)),
                        "rationale": str(getattr(result, "rationale", ""))[:500], "model_ref": model_ref}
            except Exception:
                continue
    except Exception:
        pass
    return None
