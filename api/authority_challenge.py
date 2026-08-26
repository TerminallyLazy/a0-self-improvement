"""Rotate the browser-session binding used by local operator authority grants.

Agent Zero performs authentication, CSRF, method, and transport admission before
calling this handler.  A challenge is not a grant and carries no mutation
authority; it only gives the local step-up protocol a fresh context-bound nonce.
"""
from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable, MutableMapping
from typing import Any

from agent import AgentContext
from flask import session
from helpers.api import ApiHandler, Request, Response


CHALLENGE_SCHEMA = "a0.operator-authority-challenge.v1"
CHALLENGE_SESSION_KEY = "dspy_rlm.operator_authority_challenge"

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _safe_ref(value: object) -> str | None:
    return value if type(value) is str and _SAFE_REF.fullmatch(value) else None


def _response(status: int, body: dict[str, object]) -> Response | dict[str, object]:
    if status == 200:
        return body
    return Response(
        json.dumps(body, allow_nan=False, sort_keys=True, separators=(",", ":")),
        status=status,
        mimetype="application/json",
    )


def unavailable_challenge(reason_code: str, *, status: int) -> Response:
    return _response(
        status,
        {
            "schema": CHALLENGE_SCHEMA,
            "context_ref": None,
            "session_nonce": None,
            "authority_state": "unavailable",
            "reason_codes": [reason_code],
        },
    )  # type: ignore[return-value]


def rotate_session_challenge(
    session_state: MutableMapping[str, Any],
    *,
    context_ref: str,
    nonce_factory: Callable[[], str] | None = None,
) -> dict[str, object]:
    """Replace the current challenge and bind it to exactly one live context."""

    admitted_context = _safe_ref(context_ref)
    if admitted_context is None:
        raise ValueError("context_ref is not an opaque reference")
    nonce = (nonce_factory or (lambda: secrets.token_urlsafe(32)))()
    if type(nonce) is not str or _SAFE_REF.fullmatch(nonce) is None or len(nonce) < 32:
        raise ValueError("nonce factory returned an invalid challenge")
    session_state[CHALLENGE_SESSION_KEY] = {
        "context_ref": admitted_context,
        "session_nonce": nonce,
    }
    if hasattr(session_state, "modified"):
        session_state.modified = True  # type: ignore[attr-defined]
    return {
        "schema": CHALLENGE_SCHEMA,
        "context_ref": admitted_context,
        "session_nonce": nonce,
        "authority_state": "challenge_ready",
        "reason_codes": [],
    }


class AuthorityChallenge(ApiHandler):
    """Create a nonce after Agent Zero's normal auth and CSRF admission."""

    async def process(self, input: dict, request: Request) -> dict | Response:
        try:
            if type(input) is not dict or set(input) != {"context_id"}:
                return unavailable_challenge("schema_invalid", status=400)
            context_ref = _safe_ref(input.get("context_id"))
            if context_ref is None:
                return unavailable_challenge("schema_invalid", status=400)
            context = AgentContext.get(context_ref)
            if context is None or str(getattr(context, "id", "")) != context_ref:
                return unavailable_challenge("context_unavailable", status=404)
            return rotate_session_challenge(session, context_ref=context_ref)
        except Exception:
            return unavailable_challenge("authority_challenge_unavailable", status=503)


__all__ = [
    "AuthorityChallenge",
    "CHALLENGE_SCHEMA",
    "CHALLENGE_SESSION_KEY",
    "rotate_session_challenge",
]
