"""Read-only, content-free opportunities from structured runtime outcomes."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
import sqlite3
from typing import Any, Mapping, Sequence

from . import paths
from .learning_health import _object, _reader
from .objective import infer_bucket
from .outcomes import outcome_counts

BUCKETS = ("shell", "tool_retrieval", "decision_making", "reasoning", "unknown")
MAX_EVENTS = 2000


def summarize_opportunities(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list] = defaultdict(list)
    unverified = 0
    for event in events:
        if event.get("event_type") != "tool" or event.get("redacted") is not True:
            continue
        # Older automatic traces always said success. Do not present those
        # historical booleans as newly measured tool reliability.
        if type(event.get("outcome_source")) is not str or event.get("outcome_source") not in {"structured_tool_result", "unknown"}:
            unverified += 1
            continue
        bucket = event.get("objective_bucket")
        if bucket not in BUCKETS or bucket == "unknown":
            tool = event.get("tool")
            bucket = infer_bucket("", [tool]) if type(tool) is str and tool not in {"none", "unknown"} else "unknown"
        groups[bucket].append(event)
    opportunities = []
    for bucket, rows in groups.items():
        counts = outcome_counts(rows)
        failures = counts["failure_count"]
        known = counts["known_outcome_count"]
        opportunities.append({"bucket": bucket, **counts,
            "state": "recurring_failures" if failures >= 2 else "failure_observed" if failures else "collecting_outcomes" if not known else "observing",
        })
    opportunities.sort(key=lambda row: (-row["failure_count"], -row["known_outcome_count"], row["bucket"]))
    totals = outcome_counts([row for rows in groups.values() for row in rows])
    return {"state": "ready" if groups else "empty", "window": MAX_EVENTS,
            "unverified_older_events": unverified, "totals": totals, "opportunities": opportunities}


def read_learning_insights(context_ref: str, config: Mapping[str, Any]) -> dict[str, Any]:
    empty = summarize_opportunities([])
    if not paths.STORE_FILE.is_file():
        return empty
    capture = config.get("trace_capture", {})
    ttl = max(60, int(capture.get("event_ttl_seconds", 604800)))
    try:
        with _reader() as db:
            rows = db.execute(
                "SELECT CASE WHEN length(event_json)<=32768 THEN event_json END FROM evidence_events "
                "WHERE context_id=? AND event_type='tool' AND created_at>=? "
                "ORDER BY created_at DESC,event_id DESC LIMIT ?",
                (context_ref, datetime.now(timezone.utc).timestamp()-ttl, MAX_EVENTS),
            ).fetchall()
        return summarize_opportunities([_object(row[0]) for row in rows])
    except (OSError, sqlite3.Error, ValueError):
        return {**empty, "state": "unavailable"}


def select_learning_target(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Prefer observed failures over incidental recency; grant no activation authority."""
    groups: dict[str, list] = defaultdict(list)
    for row in rows:
        groups[str(row.get("objective_bucket") or "reasoning")].append(row)
    if not groups:
        return {"bucket": "reasoning", "signature": "", "reason": "no_objectives"}
    def counts(bucket):
        items = groups[bucket]
        failures = sum(max(0, int(item.get("failure_events", 0) or 0)) for item in items)
        known = failures + sum(max(0, int(item.get("success_events", 0) or 0)) for item in items)
        return failures, known
    # Stable sorting preserves the newest objective bucket when counts tie.
    bucket = max(groups, key=counts)
    failures, known = counts(bucket)
    return {"bucket": bucket, "signature": str(groups[bucket][0].get("objective_signature") or ""),
            "reason": "observed_failures" if failures else "known_outcomes" if known else "latest_objective"}
