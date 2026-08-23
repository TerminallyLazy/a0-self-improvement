"""DSPy GEPA adapter for versioned Agent Zero prompt components."""
from __future__ import annotations

from hashlib import sha256
import json
import time
from typing import Any, Mapping, Sequence

from ..model_resolution import build_dspy_lm
from ..prompt_artifacts import PromptArtifact
from . import EngineBudget


def _tokens(value: Any) -> set[str]:
    return {token.lower() for token in str(value or "").split() if len(token) > 2}


def _score(expected: Any, observed: Any) -> float:
    left, right = _tokens(expected), _tokens(observed)
    if not left:
        return 0.0
    return len(left & right) / max(1, len(left | right))


def _instructions(program: Any) -> str:
    signature = getattr(program, "signature", None)
    value = getattr(signature, "instructions", None)
    if isinstance(value, str) and value.strip():
        return value.strip()
    predictors = getattr(program, "predictors", None)
    if callable(predictors):
        for predictor in predictors():
            value = getattr(getattr(predictor, "signature", None), "instructions", None)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


class PromptGepaEngine:
    kind = "gepa_prompt_components"
    version = "gepa.prompt.v1"

    def compile(
        self, *, context_id: str, snapshot: Mapping[str, Any], objective_rows: Sequence[Mapping[str, Any]],
        model_config_ref: str, target_mode: str, activation_mode: str, selected_components: Sequence[str],
        budget: EngineBudget, max_components: int = 4,
    ) -> tuple[PromptArtifact | None, dict[str, Any]]:
        eligible_examples = [
            dict(row) for row in objective_rows
            if bool(row.get("objective_content_approved")) and str(row.get("user_intent") or "").strip()
            and str(row.get("latest_response") or "").strip()
        ][: budget.max_examples]
        reproducibility: dict[str, Any] = {
            "engine": self.kind, "engine_version": self.version, "target_mode": target_mode,
            "activation_mode": activation_mode, "example_count": len(eligible_examples),
            "base_snapshot_id": str(snapshot.get("snapshot_id") or ""), "base_digest": str(snapshot.get("base_digest") or ""),
            "budget": budget.to_mapping(),
        }
        if len(eligible_examples) < 3:
            return None, {**reproducibility, "status": "review_only", "error": "approved_prompt_training_examples_required"}
        components = [dict(item) for item in snapshot.get("components", ()) if isinstance(item, Mapping) and not bool(item.get("protected"))]
        if target_mode == "selected_components":
            selected = set(str(item) for item in selected_components)
            components = [item for item in components if str(item.get("component_id")) in selected]
        components = components[: max(1, min(12, int(max_components)))]
        if not components:
            return None, {**reproducibility, "status": "review_only", "error": "no_eligible_prompt_components"}
        if not model_config_ref:
            return None, {**reproducibility, "status": "failed", "error": "model_config_ref_required"}
        try:
            import dspy
            lm = build_dspy_lm(dspy, model_config_ref)
            examples = []
            for row in eligible_examples:
                example = dspy.Example(
                    user_intent=str(row.get("user_intent") or ""),
                    evidence_summary=json.dumps({
                        "objective_bucket": row.get("objective_bucket"), "tool_contract": row.get("tool_contract", []),
                        "success_events": row.get("success_events", 0), "failure_events": row.get("failure_events", 0),
                    }, sort_keys=True),
                    expected_response=str(row.get("latest_response") or ""),
                ).with_inputs("user_intent", "evidence_summary")
                examples.append(example)
            split = max(1, len(examples) - max(1, len(examples) // 4))
            trainset, valset = examples[:split], examples[split:] or examples[-1:]

            def metric(example: Any, prediction: Any, trace: Any = None, **_kwargs: Any) -> Any:
                observed = str(getattr(prediction, "response", "") or "")
                score = _score(getattr(example, "expected_response", ""), observed)
                feedback = "Preserve the successful response behavior, follow the supplied tool contract, and avoid unsupported claims."
                return dspy.Prediction(score=score, feedback=feedback)

            replacements: list[dict[str, str]] = []
            scores: list[float] = []
            started = time.monotonic()
            for component in components:
                source = str(component.get("body") or "")[:20_000]
                signature = dspy.Signature("user_intent, evidence_summary -> response", instructions=source)
                student = dspy.Predict(signature)
                compiler = dspy.GEPA(
                    metric=metric, reflection_lm=lm, num_threads=budget.num_threads,
                    max_metric_calls=max(8, budget.max_steps * max(2, len(examples)) * 2),
                    component_selector="round_robin",
                )
                with dspy.context(lm=lm):
                    compiled = compiler.compile(student=student, trainset=trainset, valset=valset)
                optimized = _instructions(compiled)
                if not optimized or optimized == source or len(optimized) > 30_000:
                    continue
                component_scores = []
                for example in valset:
                    with dspy.context(lm=lm):
                        prediction = compiled(user_intent=example.user_intent, evidence_summary=example.evidence_summary)
                    component_scores.append(_score(example.expected_response, getattr(prediction, "response", "")))
                scores.extend(component_scores)
                replacements.append({
                    "component_id": str(component["component_id"]),
                    "source_digest": str(component["source_digest"]),
                    "text": optimized,
                })
                if time.monotonic() - started > budget.max_compile_seconds:
                    return None, {**reproducibility, "status": "failed", "error": "compile_runtime_budget_exceeded"}
            if not replacements:
                return None, {**reproducibility, "status": "review_only", "error": "gepa_produced_no_changed_components"}
            validation_score = sum(scores) / len(scores) if scores else 0.0
            baseline_failures = sum(int(row.get("failure_events", 0) or 0) for row in eligible_examples)
            baseline_events = sum(int(row.get("failure_events", 0) or 0) + int(row.get("success_events", 0) or 0) for row in eligible_examples)
            validation = {
                "passed": validation_score >= 0.20,
                "validation_score": validation_score,
                "validation_examples": len(valset),
                "baseline_failure_rate": baseline_failures / max(1, baseline_events),
            }
            identity = json.dumps({"snapshot": snapshot.get("snapshot_id"), "replacements": replacements, "mode": target_mode}, sort_keys=True)
            artifact_id = "prompt-artifact-" + sha256(identity.encode("utf-8")).hexdigest()[:24]
            artifact = PromptArtifact(
                artifact_id=artifact_id, context_id=context_id, target_mode=target_mode, activation_mode=activation_mode,
                base_snapshot_id=str(snapshot.get("snapshot_id") or ""), base_digest=str(snapshot.get("base_digest") or ""),
                replacements=tuple(replacements), validation=validation,
                provenance={**reproducibility, "dspy_version": str(getattr(dspy, "__version__", "unknown")), "model_config_ref": model_config_ref},
            )
            return artifact, {**reproducibility, "status": "succeeded", "validation": validation, "replacement_count": len(replacements)}
        except Exception as error:
            return None, {**reproducibility, "status": "failed", "error": f"prompt GEPA compile failed: {error}"}


__all__ = ["PromptGepaEngine"]
