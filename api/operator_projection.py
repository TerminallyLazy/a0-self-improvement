"""Read-only HTTP dispatch for the six content-free operator projections."""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from agent import AgentContext
from helpers.api import ApiHandler, Request, Response
from helpers.print_style import PrintStyle

from usr.plugins.dspy_rlm.helpers import paths as plugin_paths
from usr.plugins.dspy_rlm.helpers.v3.operator_projection import (
    OperatorProjectionError,
    project_candidates,
    project_evidence_fixtures,
    project_overview,
    project_policy_capabilities,
    project_privacy_migration,
    project_receipts_audit,
)
from usr.plugins.dspy_rlm.helpers.v3.operator_repository import (
    OperatorRepositoryAdapter,
    SafeStoreOperatorReader,
)
from usr.plugins.dspy_rlm.helpers.v3.repository import StoreNotFoundError
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_reader


UNAVAILABLE_SCHEMA = "a0.operator-projection-unavailable.v1"

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PROJECTIONS: dict[str, Callable[[Any, str], dict[str, object]]] = {
    "overview": project_overview,
    "candidates": project_candidates,
    "evidence_fixtures": project_evidence_fixtures,
    "privacy_migration": project_privacy_migration,
    "policy_capabilities": project_policy_capabilities,
    "receipts_audit": project_receipts_audit,
}


def _safe_ref(value: object) -> str | None:
    return value if type(value) is str and _SAFE_REF.fullmatch(value) else None


def _json_response(status: int, body: dict[str, object]) -> Response | dict[str, object]:
    if status == 200:
        return body
    return Response(
        json.dumps(body, allow_nan=False, sort_keys=True, separators=(",", ":")),
        status=status,
        mimetype="application/json",
    )


def unavailable_projection(
    *,
    status: int,
    view: str | None,
    context_ref: str | None,
    reason_code: str,
) -> Response:
    return _json_response(
        status,
        {
            "schema": UNAVAILABLE_SCHEMA,
            "view": view,
            "context_ref": context_ref,
            "state": "unavailable",
            "reason_codes": [reason_code],
        },
    )  # type: ignore[return-value]


def project_selected_view(*, view: str, context_ref: str) -> dict[str, object]:
    """Open only the selected read-only generation and project one exact view."""

    projection = _PROJECTIONS.get(view)
    if projection is None:
        raise ValueError("view is not admitted")
    with open_runtime_reader(
        pre_cutover_path=plugin_paths.SAFE_STORE_FILE,
        manifest_path=plugin_paths.STORE_AUTHORITY_MANIFEST_FILE,
    ) as reader:
        facts = SafeStoreOperatorReader(reader)
        adapter = OperatorRepositoryAdapter(facts)
        return projection(adapter, context_ref)


class OperatorProjection(ApiHandler):
    """Serve one projection after Agent Zero's normal auth and CSRF admission."""

    async def process(self, input: dict, request: Request) -> dict | Response:
        context_ref: str | None = None
        view: str | None = None
        try:
            if type(input) is not dict or set(input) != {"context_id", "view"}:
                return unavailable_projection(
                    status=400,
                    view=None,
                    context_ref=None,
                    reason_code="schema_invalid",
                )
            context_ref = _safe_ref(input.get("context_id"))
            raw_view = input.get("view")
            view = raw_view if type(raw_view) is str and raw_view in _PROJECTIONS else None
            if context_ref is None or view is None:
                return unavailable_projection(
                    status=400,
                    view=view,
                    context_ref=context_ref,
                    reason_code="schema_invalid",
                )
            context = AgentContext.get(context_ref)
            if context is None or str(getattr(context, "id", "")) != context_ref:
                return unavailable_projection(
                    status=404,
                    view=view,
                    context_ref=context_ref,
                    reason_code="context_unavailable",
                )
            return project_selected_view(view=view, context_ref=context_ref)
        except (StoreNotFoundError, OperatorProjectionError):
            return unavailable_projection(
                status=503,
                view=view,
                context_ref=context_ref,
                reason_code="operator_projection_unavailable",
            )
        except Exception:
            PrintStyle.error("dspy_rlm operator projection: safe store is unreadable")
            return unavailable_projection(
                status=503,
                view=view,
                context_ref=context_ref,
                reason_code="operator_projection_unavailable",
            )


__all__ = [
    "OperatorProjection",
    "UNAVAILABLE_SCHEMA",
    "project_selected_view",
    "unavailable_projection",
]
