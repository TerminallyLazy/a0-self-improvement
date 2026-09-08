"""Pure outcome telemetry: absence of a structured result is not success."""
from __future__ import annotations
from typing import Any, Iterable, Mapping


def explicit_outcome(value: object) -> bool | None:
    return value if type(value) is bool else None


def outcome_counts(events: Iterable[Mapping[str, Any]]) -> dict[str, int | float]:
    outcomes = [explicit_outcome(event.get("success", True)) for event in events]
    successes = sum(value is True for value in outcomes)
    failures = sum(value is False for value in outcomes)
    known = successes + failures
    return {
        "success_count": successes, "failure_count": failures,
        "unknown_count": len(outcomes) - known, "known_outcome_count": known,
        "outcome_coverage": round(known / len(outcomes), 6) if outcomes else 0.0,
        "success_rate": round(successes / known, 6) if known else 0.0,
    }
