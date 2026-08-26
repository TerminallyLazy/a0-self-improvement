"""Fail-closed compatibility response for the retired v2 candidate reader."""
from __future__ import annotations

import json

from helpers.api import ApiHandler, Request, Response


_SCHEMA = "a0.legacy-read-retired.v1"


class CandidatesList(ApiHandler):
    """Direct callers to the authoritative content-free v3 candidate view."""

    async def process(self, input: dict, request: Request) -> Response:
        body = {
            "schema": _SCHEMA,
            "available": False,
            "legacy_route": "candidates_list",
            "state": "retired",
            "reason_codes": ["v3_operator_projection_required"],
            "operator_projection": {
                "route": "/plugins/dspy_rlm/operator_projection",
                "view": "candidates",
            },
        }
        return Response(
            json.dumps(body, allow_nan=False, sort_keys=True, separators=(",", ":")),
            status=410,
            mimetype="application/json",
        )
