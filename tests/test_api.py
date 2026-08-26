"""Task 10 API contract tests; all collaborators are local stubs."""
from __future__ import annotations

import sys
import types

# ``helpers.api`` imports helpers.network, whose optional HTTP client is absent
# in this development interpreter. These tests exercise handlers directly and
# never make a request, so provide only the import-time protocol surface.
if "requests" not in sys.modules:
    requests_stub = types.ModuleType("requests")
    requests_stub.RequestException = Exception
    requests_stub.Session = object
    sys.modules["requests"] = requests_stub

if "agent" not in sys.modules:
    agent_stub = types.ModuleType("agent")

    class AgentContext:  # pragma: no cover - direct handler tests replace lookup.
        @staticmethod
        def get(_context_id):
            return None

    agent_stub.AgentContext = AgentContext
    sys.modules["agent"] = agent_stub

from usr.plugins.dspy_rlm.api import status


def test_trace_summary_has_fixed_allowlisted_ui_rows() -> None:
    result = status.public_trace_summary(
        {
            "event_count": "12",
            "loop_count": 2,
            "tool_count": 9,
            "success_rate": "nan",
            "top_tools": [
                {"tool": "shell", "count": "4"},
                {"tool": "shell", "count": 2},
                {"tool": "secret_tool_name", "count": 99},
                {"tool": "search", "count": -2},
                "not-a-row",
            ],
            "latest_ts": "2026-08-19T00:00:00Z",
        }
    )

    assert result == {
        "event_count": 12,
        "loop_count": 2,
        "tool_count": 9,
        "success_rate": 0.0,
        "top_tools": [{"tool": "shell", "count": 6}],
        "latest_ts": "2026-08-19T00:00:00Z",
    }
    assert "latest_objective" not in result
    assert "latest_response" not in result


def test_scheduler_public_contract_calls_sqlite_workers_local_multiprocess() -> None:
    result = status.public_scheduler(
        {
            "mode": "distributed",
            "target_workers": 2,
            "running_workers": 1,
            "jobs": {"running": "1", "leak": 4},
            "samples": {"reasoning": "2", "other": 100},
        }
    )

    assert result["mode"] == "local_multiprocess"
    assert result["jobs"] == {"running": 1}
    assert result["samples"] == {"reasoning": 2}
