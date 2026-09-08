"""Run with unittest in the Agent Zero framework runtime; no model calls."""
import unittest
from unittest.mock import patch

from usr.plugins.dspy_rlm.helpers import dspy_runtime, optimizer
from usr.plugins.dspy_rlm.helpers.evidence import sanitize_event
from usr.plugins.dspy_rlm.helpers.rlm import EvidenceIndex
from usr.plugins.dspy_rlm.helpers.scheduler import worker


class TokenAuditRegressions(unittest.TestCase):
    def event(self, **changes):
        return dict(redacted=True, event_type="tool", tool="code_execution_tool",
                    objective_bucket="unknown", success=False, **changes)

    def test_existing_unknown_tool_bucket_is_searchable(self):
        index = EvidenceIndex([self.event()])
        self.assertEqual(len(index.events_for(objective_bucket="shell")), 1)
        self.assertFalse(index.events_for(objective_bucket="shell")[0]["success"])

    def test_explicit_bucket_is_preserved(self):
        event = self.event()
        event["objective_bucket"] = "decision_making"
        index = EvidenceIndex([event])
        self.assertEqual(len(index.events_for(objective_bucket="decision_making")), 1)
        self.assertEqual(index.events_for(objective_bucket="shell"), ())

    def test_missing_tool_label_stays_unknown(self):
        event = self.event()
        event["tool"] = "unknown"
        self.assertEqual(len(EvidenceIndex([event]).events_for(objective_bucket="unknown")), 1)

    def test_raw_fields_still_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceIndex([self.event(response="private response")])

    def test_unredacted_events_still_rejected(self):
        event = self.event()
        event["redacted"] = False
        with self.assertRaises(ValueError):
            EvidenceIndex([event])

    def test_empty_partition_never_resolves_or_calls_model(self):
        with patch.object(dspy_runtime, "resolve_dspy_model") as resolve:
            self.assertEqual(dspy_runtime.analyze_with_dspy_rlm(
                EvidenceIndex([self.event()]), "tool_retrieval", {"rlm": {"enabled": True}}
            ), ())
            resolve.assert_not_called()

    def test_metadata_capture_reaches_candidate_generation_without_model(self):
        event = sanitize_event({"context_id": "audit-chat", "event_type": "tool",
                                "tool": "code_execution_tool", "objective_bucket": "unknown",
                                "success": True, "loop_iteration": 0})
        with patch.object(optimizer.trace, "read_context_events", return_value=[event]):
            result, gepa = optimizer._candidate_engine_result(
                "audit-chat", "shell",
                {"rlm": {"enabled": False}, "optimization": {"enable_dspy_optimizer": False}},
            )
        self.assertTrue(result.succeeded)
        self.assertIsNone(gepa)
        self.assertEqual(result.artifact.engine_kind, "heuristic")

    def test_leased_worker_does_not_self_block_on_queued_context(self):
        with patch.object(optimizer, "run_optimization_sync", return_value={"status": "candidate"}) as run:
            worker._run_without_promotion("audit-chat", {}, False)
        run.assert_called_once_with("audit-chat", {}, force=False, manage_context_state=False)


if __name__ == "__main__":
    unittest.main()
