from __future__ import annotations

import json

import pytest

from usr.plugins.dspy_rlm.api.candidates_list import CandidatesList
from usr.plugins.dspy_rlm.api.optimize import Optimize
from usr.plugins.dspy_rlm.api.prompt_optimization_meta import PromptOptimizationMeta
from usr.plugins.dspy_rlm.api.promote import Promote
from usr.plugins.dspy_rlm.api.rollback import Rollback


@pytest.mark.asyncio
async def test_legacy_mutation_routes_are_safe_retired_surfaces() -> None:
    routes = (
        (Optimize, "optimize", "optimize"),
        (Promote, "promote", "activate"),
        (Rollback, "rollback", "rollback"),
    )
    hostile = {
        "context_id": "other.context",
        "prompt_artifact_id": "/private/target",
        "guidance_version": "secret-version",
        "force": True,
    }

    for handler_type, legacy_route, operator_action in routes:
        handler = object.__new__(handler_type)
        result = await handler.process(hostile, None)
        body = json.loads(result.response)

        assert result.status == 410
        assert result.mimetype == "application/json"
        assert body == {
            "schema": "a0.legacy-mutation-retired.v1",
            "accepted": False,
            "legacy_route": legacy_route,
            "state": "retired",
            "reason_codes": ["signed_v3_operator_command_required"],
            "operator_command": {
                "route": "/plugins/dspy_rlm/operator_command",
                "action": operator_action,
            },
        }
        assert "/private/target" not in result.response
        assert handler.requires_auth() is True
        assert handler.requires_csrf() is True


@pytest.mark.asyncio
async def test_legacy_read_routes_direct_to_authoritative_v3_projections() -> None:
    routes = (
        (CandidatesList, "candidates_list", "candidates"),
        (PromptOptimizationMeta, "prompt_optimization_meta", "policy_capabilities"),
    )
    hostile = {
        "context_id": "other.context",
        "objective_bucket": "/private/target",
        "limit": 999999,
    }

    for handler_type, legacy_route, projection_view in routes:
        handler = object.__new__(handler_type)
        result = await handler.process(hostile, None)
        body = json.loads(result.response)

        assert result.status == 410
        assert result.mimetype == "application/json"
        assert body == {
            "schema": "a0.legacy-read-retired.v1",
            "available": False,
            "legacy_route": legacy_route,
            "state": "retired",
            "reason_codes": ["v3_operator_projection_required"],
            "operator_projection": {
                "route": "/plugins/dspy_rlm/operator_projection",
                "view": projection_view,
            },
        }
        assert "/private/target" not in result.response
        assert handler.requires_auth() is True
        assert handler.requires_csrf() is True
