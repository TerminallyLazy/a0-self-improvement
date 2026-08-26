"""Purpose- and context-scoped opaque references for v3 public identities."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Any, Mapping

from .schemas import canonical_json


OPAQUE_REFERENCE_SCHEMA = "a0.opaque-reference.v1"
_OPAQUE_REFERENCE = re.compile(r"^a0r1_[a-z2-7]{52}$")


class OpaqueReferenceError(ValueError):
    pass


def opaque_reference(
    key: bytes,
    *,
    key_epoch: str,
    purpose: str,
    context_ref: str | None,
    identity: Mapping[str, Any],
) -> str:
    """Derive an unlinkable public identifier from an exact canonical identity."""

    if type(key) is not bytes or len(key) < 32:
        raise OpaqueReferenceError("opaque-reference key must contain at least 32 bytes")
    for label, value in (("key_epoch", key_epoch), ("purpose", purpose)):
        if type(value) is not str or not value or len(value) > 128:
            raise OpaqueReferenceError(f"{label} must be a bounded non-empty string")
    if context_ref is not None and (
        type(context_ref) is not str or not context_ref or len(context_ref) > 256
    ):
        raise OpaqueReferenceError("context_ref must be null or a bounded non-empty string")
    if type(identity) is not dict or not identity:
        raise OpaqueReferenceError("identity must be a non-empty plain mapping")
    framed = canonical_json(
        {
            "schema": OPAQUE_REFERENCE_SCHEMA,
            "key_epoch": key_epoch,
            "purpose": purpose,
            "context_ref": context_ref,
            "identity": dict(identity),
        }
    )
    digest = hmac.new(
        key,
        b"a0.self-improvement.opaque-reference.v1\x00" + framed,
        hashlib.sha256,
    ).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    return "a0r1_" + encoded


def validate_opaque_reference(value: Any, path: str = "reference") -> str:
    if type(value) is not str or _OPAQUE_REFERENCE.fullmatch(value) is None:
        raise OpaqueReferenceError(f"{path} is not an a0 opaque reference")
    return value
