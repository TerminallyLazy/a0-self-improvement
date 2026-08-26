"""Fail-closed compatibility response for the retired v2 rollback route."""
from __future__ import annotations

import json

from helpers.api import ApiHandler, Request, Response


_SCHEMA = "a0.legacy-mutation-retired.v1"


class Rollback(ApiHandler):
    """Preserve framework auth/CSRF while refusing unsigned v2 rollback."""

    async def process(self, input: dict, request: Request) -> Response:
        body = {
            "schema": _SCHEMA,
            "accepted": False,
            "legacy_route": "rollback",
            "state": "retired",
            "reason_codes": ["signed_v3_operator_command_required"],
            "operator_command": {
                "route": "/plugins/dspy_rlm/operator_command",
                "action": "rollback",
            },
        }
        return Response(
            json.dumps(body, allow_nan=False, sort_keys=True, separators=(",", ":")),
            status=410,
            mimetype="application/json",
        )
