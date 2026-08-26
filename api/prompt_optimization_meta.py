"""Fail-closed compatibility response for retired v2 prompt metadata."""
from __future__ import annotations

import json

from helpers.api import ApiHandler, Request, Response


_SCHEMA = "a0.legacy-read-retired.v1"


class PromptOptimizationMeta(ApiHandler):
    """Direct callers to the authoritative v3 policy/capability projection."""

    async def process(self, input: dict, request: Request) -> Response:
        body = {
            "schema": _SCHEMA,
            "available": False,
            "legacy_route": "prompt_optimization_meta",
            "state": "retired",
            "reason_codes": ["v3_operator_projection_required"],
            "operator_projection": {
                "route": "/plugins/dspy_rlm/operator_projection",
                "view": "policy_capabilities",
            },
        }
        return Response(
            json.dumps(body, allow_nan=False, sort_keys=True, separators=(",", ":")),
            status=410,
            mimetype="application/json",
        )
