from __future__ import annotations

import pytest

from usr.plugins.dspy_rlm.helpers.v3.opaque import (
    OpaqueReferenceError,
    opaque_reference,
    validate_opaque_reference,
)


_KEY = bytes(range(32))


def _reference(**overrides: object) -> str:
    values = {
        "key_epoch": "epoch-1",
        "purpose": "activation-profile",
        "context_ref": "context-secret-value",
        "identity": {"revision": 0, "source": "genesis"},
    }
    values.update(overrides)
    return opaque_reference(_KEY, **values)


def test_reference_is_deterministic_opaque_and_validated() -> None:
    first = _reference()

    assert first == _reference()
    assert validate_opaque_reference(first) == first
    assert "context-secret-value" not in first
    assert "genesis" not in first


def test_reference_is_domain_separated_by_purpose_context_and_epoch() -> None:
    baseline = _reference()

    assert _reference(purpose="activation-receipt") != baseline
    assert _reference(context_ref="other-context") != baseline
    assert _reference(key_epoch="epoch-2") != baseline
    assert _reference(identity={"revision": 1, "source": "genesis"}) != baseline


@pytest.mark.parametrize("key", [b"", b"short", "not-bytes"])
def test_reference_rejects_weak_or_nonbyte_keys(key: object) -> None:
    with pytest.raises(OpaqueReferenceError):
        opaque_reference(
            key,
            key_epoch="epoch-1",
            purpose="profile",
            context_ref="ctx",
            identity={"revision": 0},
        )


def test_reference_rejects_nonplain_or_empty_identity() -> None:
    with pytest.raises(OpaqueReferenceError):
        _reference(identity={})
    with pytest.raises(OpaqueReferenceError):
        _reference(identity=[("revision", 0)])


def test_validator_rejects_free_form_or_uppercase_values() -> None:
    with pytest.raises(OpaqueReferenceError):
        validate_opaque_reference("context-1")
    with pytest.raises(OpaqueReferenceError):
        validate_opaque_reference(_reference().upper())
