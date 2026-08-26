"""Strict schemas and canonical identities for the v3 safe projection store.

The module deliberately has no Agent Zero imports.  It is safe to use from the
runtime composer, coordinators, migration tooling, and read-only projections.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
import re
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence


class V3SchemaError(ValueError):
    """Base class for a closed-schema or canonicalization failure."""


class CanonicalJSONError(V3SchemaError):
    """Raised when a value is not losslessly representable as canonical JSON."""


class SchemaValidationError(V3SchemaError):
    """Raised when a payload does not exactly match its registered schema."""


class UnknownSchemaError(SchemaValidationError):
    """Raised when a schema identifier is not in the closed registry."""


class UnknownRecordKindError(SchemaValidationError):
    """Raised when a record kind is not in the closed registry."""


Validator = Callable[[Any, str], Any]
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _type_name(value: Any) -> str:
    return type(value).__name__


def strict_string(*, minimum: int = 1, maximum: int = 512) -> Validator:
    def validate(value: Any, path: str) -> str:
        if type(value) is not str:
            raise SchemaValidationError(f"{path} must be a string, got {_type_name(value)}")
        if not minimum <= len(value) <= maximum:
            raise SchemaValidationError(
                f"{path} length must be between {minimum} and {maximum}"
            )
        return value

    return validate


def strict_integer(*, minimum: int | None = None, maximum: int | None = None) -> Validator:
    def validate(value: Any, path: str) -> int:
        if type(value) is not int:
            raise SchemaValidationError(f"{path} must be an integer, got {_type_name(value)}")
        if minimum is not None and value < minimum:
            raise SchemaValidationError(f"{path} must be at least {minimum}")
        if maximum is not None and value > maximum:
            raise SchemaValidationError(f"{path} must be at most {maximum}")
        return value

    return validate


def strict_boolean() -> Validator:
    def validate(value: Any, path: str) -> bool:
        if type(value) is not bool:
            raise SchemaValidationError(f"{path} must be a boolean, got {_type_name(value)}")
        return value

    return validate


def strict_literal(expected: Any) -> Validator:
    expected_type = type(expected)

    def validate(value: Any, path: str) -> Any:
        if type(value) is not expected_type or value != expected:
            raise SchemaValidationError(f"{path} must be exactly {expected!r}")
        return value

    return validate


def strict_enum(values: Iterable[str]) -> Validator:
    admitted = frozenset(values)
    if not admitted:
        raise ValueError("an enum must admit at least one value")

    def validate(value: Any, path: str) -> str:
        if type(value) is not str or value not in admitted:
            raise SchemaValidationError(f"{path} is not an admitted enum value")
        return value

    return validate


def strict_nullable(validator: Validator) -> Validator:
    def validate(value: Any, path: str) -> Any:
        return None if value is None else validator(value, path)

    return validate


def strict_list(
    item_validator: Validator,
    *,
    minimum: int = 0,
    maximum: int = 10_000,
) -> Validator:
    def validate(value: Any, path: str) -> list[Any]:
        if type(value) is not list:
            raise SchemaValidationError(f"{path} must be a list, got {_type_name(value)}")
        if not minimum <= len(value) <= maximum:
            raise SchemaValidationError(
                f"{path} item count must be between {minimum} and {maximum}"
            )
        return [item_validator(item, f"{path}[{index}]") for index, item in enumerate(value)]

    return validate


def strict_object(
    required: Mapping[str, Validator],
    *,
    optional: Mapping[str, Validator] | None = None,
) -> Validator:
    required_fields = dict(required)
    optional_fields = dict(optional or {})
    overlap = required_fields.keys() & optional_fields.keys()
    if overlap:
        raise ValueError(f"fields cannot be both required and optional: {sorted(overlap)}")
    admitted = required_fields.keys() | optional_fields.keys()

    def validate(value: Any, path: str) -> dict[str, Any]:
        if type(value) is not dict:
            raise SchemaValidationError(f"{path} must be an object, got {_type_name(value)}")
        unknown = value.keys() - admitted
        missing = required_fields.keys() - value.keys()
        if unknown:
            raise SchemaValidationError(f"{path} has unknown fields: {sorted(unknown)}")
        if missing:
            raise SchemaValidationError(f"{path} is missing fields: {sorted(missing)}")
        result: dict[str, Any] = {}
        for key, validator in required_fields.items():
            result[key] = validator(value[key], f"{path}.{key}")
        for key, validator in optional_fields.items():
            if key in value:
                result[key] = validator(value[key], f"{path}.{key}")
        return result

    return validate


def _validate_json_value(value: Any, path: str = "$") -> None:
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise CanonicalJSONError(f"{path} contains a non-finite number")
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise CanonicalJSONError(f"{path} contains a non-string object key")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise CanonicalJSONError(f"{path} contains unsupported type {_type_name(value)}")


def canonical_json(value: Any) -> bytes:
    """Return the one admitted UTF-8 JSON representation for ``value``."""

    _validate_json_value(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:  # defensive; validation owns the contract
        raise CanonicalJSONError("value cannot be encoded as canonical JSON") from exc
    return encoded.encode("utf-8")


def canonical_loads(encoded: bytes | str) -> Any:
    """Decode canonical JSON and reject duplicate keys and non-canonical bytes."""

    raw = encoded.encode("utf-8") if type(encoded) is str else encoded
    if type(raw) is not bytes:
        raise CanonicalJSONError("canonical input must be bytes or a string")

    def object_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CanonicalJSONError(f"duplicate object key {key!r}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise CanonicalJSONError(f"non-finite JSON constant {value!r}")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs, parse_constant=invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalJSONError("invalid UTF-8 JSON") from exc
    _validate_json_value(value)
    if canonical_json(value) != raw:
        raise CanonicalJSONError("JSON bytes are not in canonical form")
    return value


def schema_digest(domain: str, schema_id: str, canonical_bytes: bytes) -> str:
    """Hash canonical bytes under explicit purpose and schema domains."""

    for label, value in (("domain", domain), ("schema_id", schema_id)):
        if type(value) is not str or not value:
            raise ValueError(f"{label} must be a non-empty string")
    framed = b"a0-self-improvement:v3\0" + domain.encode("utf-8")
    framed += b"\0" + schema_id.encode("utf-8") + b"\0" + canonical_bytes
    return sha256(framed).hexdigest()


def validate_digest(value: Any, path: str) -> str:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        raise SchemaValidationError(f"{path} must be a lowercase SHA-256 digest")
    return value


LINK_VALIDATOR = strict_object(
    {
        "role": strict_string(maximum=128),
        "ordinal": strict_integer(minimum=0),
        "target_id": strict_string(maximum=512),
        "target_digest": validate_digest,
    }
)


def validate_links(value: Any, path: str) -> list[dict[str, Any]]:
    links = strict_list(LINK_VALIDATOR, maximum=1_000)(value, path)
    identities: set[tuple[str, int]] = set()
    for link in links:
        identity = (link["role"], link["ordinal"])
        if identity in identities:
            raise SchemaValidationError(f"{path} repeats link identity {identity!r}")
        identities.add(identity)
    return links


@dataclass(frozen=True, slots=True)
class RecordSchema:
    schema_id: str
    record_kind: str
    payload_validator: Validator
    context_required: bool = True

    def validate(self, payload: Any) -> dict[str, Any]:
        result = self.payload_validator(payload, "payload")
        if type(result) is not dict:
            raise TypeError("a record schema must validate to an object")
        if "links" not in result:
            raise SchemaValidationError("payload must contain its complete links manifest")
        return result


class SchemaRegistry:
    """A closed mapping from exact schema identifiers to exact record kinds."""

    def __init__(self, schemas: Iterable[RecordSchema]) -> None:
        by_id: dict[str, RecordSchema] = {}
        kinds: set[str] = set()
        for schema in schemas:
            if schema.schema_id in by_id:
                raise ValueError(f"duplicate schema identifier {schema.schema_id!r}")
            by_id[schema.schema_id] = schema
            kinds.add(schema.record_kind)
        if not by_id:
            raise ValueError("a schema registry cannot be empty")
        self._schemas = MappingProxyType(by_id)
        self._record_kinds = frozenset(kinds)

    @property
    def schemas(self) -> Mapping[str, RecordSchema]:
        return self._schemas

    @property
    def record_kinds(self) -> frozenset[str]:
        return self._record_kinds

    def schema(self, schema_id: str, record_kind: str | None = None) -> RecordSchema:
        try:
            schema = self._schemas[schema_id]
        except KeyError as exc:
            raise UnknownSchemaError(f"unknown schema {schema_id!r}") from exc
        if record_kind is not None:
            if record_kind not in self._record_kinds:
                raise UnknownRecordKindError(f"unknown record kind {record_kind!r}")
            if schema.record_kind != record_kind:
                raise SchemaValidationError(
                    f"schema {schema_id!r} belongs to {schema.record_kind!r}, not {record_kind!r}"
                )
        return schema


def merge_schema_registries(*registries: SchemaRegistry) -> SchemaRegistry:
    """Compose closed registries while rejecting ambiguous schema authority."""

    if not registries or any(not isinstance(item, SchemaRegistry) for item in registries):
        raise ValueError("at least one SchemaRegistry is required")
    schemas: dict[str, RecordSchema] = {}
    for registry in registries:
        for schema_id, schema in registry.schemas.items():
            existing = schemas.get(schema_id)
            if existing is not None and existing is not schema:
                raise ValueError(f"schema authority collision for {schema_id!r}")
            schemas[schema_id] = schema
    return SchemaRegistry(schemas.values())


@dataclass(frozen=True, slots=True)
class RecordLink:
    role: str
    ordinal: int
    target_id: str
    target_digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RecordLink":
        return cls(
            role=value["role"],
            ordinal=value["ordinal"],
            target_id=value["target_id"],
            target_digest=value["target_digest"],
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "ordinal": self.ordinal,
            "target_id": self.target_id,
            "target_digest": self.target_digest,
        }


@dataclass(frozen=True, slots=True)
class TypedRecord:
    record_id: str
    context_ref: str | None
    record_kind: str
    schema_id: str
    canonical_bytes: bytes
    content_digest: str
    link_manifest_digest: str
    key_epoch: str
    links: tuple[RecordLink, ...]

    @property
    def payload(self) -> dict[str, Any]:
        value = canonical_loads(self.canonical_bytes)
        if type(value) is not dict:  # schema validation gives a clearer invariant
            raise SchemaValidationError("record payload is not an object")
        return value

    def verify(self, registry: SchemaRegistry) -> None:
        schema = registry.schema(self.schema_id, self.record_kind)
        if type(self.record_id) is not str or not self.record_id:
            raise SchemaValidationError("record_id must be a non-empty string")
        if self.context_ref is not None and (type(self.context_ref) is not str or not self.context_ref):
            raise SchemaValidationError("context_ref must be null or a non-empty string")
        if schema.context_required and self.context_ref is None:
            raise SchemaValidationError(f"schema {self.schema_id!r} requires a context_ref")
        if type(self.key_epoch) is not str or not self.key_epoch:
            raise SchemaValidationError("key_epoch must be a non-empty string")
        payload = schema.validate(canonical_loads(self.canonical_bytes))
        admitted_bytes = canonical_json(payload)
        if admitted_bytes != self.canonical_bytes:
            raise CanonicalJSONError("schema normalization changed canonical bytes")
        expected_content = schema_digest("record-content", self.schema_id, admitted_bytes)
        if self.content_digest != expected_content:
            raise SchemaValidationError("record content digest does not match canonical bytes")
        links = tuple(RecordLink.from_mapping(item) for item in payload["links"])
        if links != self.links:
            raise SchemaValidationError("record links do not match the complete payload manifest")
        expected_manifest = schema_digest(
            "record-link-manifest", self.schema_id, canonical_json(payload["links"])
        )
        if self.link_manifest_digest != expected_manifest:
            raise SchemaValidationError("record link-manifest digest does not match canonical bytes")


def build_typed_record(
    *,
    record_id: str,
    context_ref: str | None,
    record_kind: str,
    schema_id: str,
    payload: Mapping[str, Any],
    key_epoch: str,
    registry: SchemaRegistry,
) -> TypedRecord:
    schema = registry.schema(schema_id, record_kind)
    if schema.context_required and context_ref is None:
        raise SchemaValidationError(f"schema {schema_id!r} requires a context_ref")
    validated = schema.validate(dict(payload))
    encoded = canonical_json(validated)
    links = tuple(RecordLink.from_mapping(item) for item in validated["links"])
    record = TypedRecord(
        record_id=record_id,
        context_ref=context_ref,
        record_kind=record_kind,
        schema_id=schema_id,
        canonical_bytes=encoded,
        content_digest=schema_digest("record-content", schema_id, encoded),
        link_manifest_digest=schema_digest(
            "record-link-manifest", schema_id, canonical_json(validated["links"])
        ),
        key_epoch=key_epoch,
        links=links,
    )
    record.verify(registry)
    return record
