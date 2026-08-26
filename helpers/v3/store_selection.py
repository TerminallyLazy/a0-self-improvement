"""Pure selection of the one runtime-authoritative v3 store generation."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .repository import V3Reader, V3Repository
from .schemas import SchemaRegistry, canonical_loads
from .store_authority import (
    StoreAuthorityCorrupt,
    StoreAuthorityManifest,
    StoreAuthorityManifestStore,
)


@dataclass(frozen=True, slots=True)
class StoreSelection:
    path: Path
    source: str
    manifest: StoreAuthorityManifest | None


def resolve_runtime_store(
    *, pre_cutover_path: Path, manifest_path: Path
) -> StoreSelection:
    """Resolve authority without creating, repairing, or silently falling back.

    The fixed path is admitted only while no Store Authority Manifest exists.
    Once a manifest exists, any corrupt manifest or selected generation raises
    and the caller must block improvement rather than consult the fixed path.
    """

    if not isinstance(pre_cutover_path, Path) or not pre_cutover_path.is_absolute():
        raise ValueError("pre_cutover_path must be an absolute Path")
    authority = StoreAuthorityManifestStore(manifest_path)
    manifest = authority.read()
    if manifest is None:
        return StoreSelection(pre_cutover_path, "pre_cutover", None)
    return StoreSelection(Path(manifest.generation_path_identity), "manifest", manifest)


def open_runtime_reader(
    *,
    pre_cutover_path: Path,
    manifest_path: Path,
    registry: SchemaRegistry | None = None,
) -> V3Reader:
    selection = resolve_runtime_store(
        pre_cutover_path=pre_cutover_path,
        manifest_path=manifest_path,
    )
    selected_registry = registry
    if selected_registry is None:
        # Import lazily so resolving a path remains pure and does not create a
        # store, run migration work, or initialize model dependencies.
        from .registry import V3_REGISTRY

        selected_registry = V3_REGISTRY
    reader = V3Reader.open(selection.path, registry=selected_registry)
    try:
        _verify_selected_generation(reader, selection.manifest)
    except Exception as exc:
        reader.close()
        if isinstance(exc, StoreAuthorityCorrupt):
            raise
        raise StoreAuthorityCorrupt(
            "selected generation migration receipt cannot be verified"
        ) from exc
    return reader


def open_runtime_repository(
    *,
    pre_cutover_path: Path,
    manifest_path: Path,
    registry: SchemaRegistry | None = None,
) -> V3Repository:
    """Open the selected generation for an explicit coordinator mutation.

    Selection and its embedded receipt are checked before returning.  A
    manifest change during the open is rejected; migration coordination still
    owns stopping workers and command admission around cutover.
    """

    selection = resolve_runtime_store(
        pre_cutover_path=pre_cutover_path,
        manifest_path=manifest_path,
    )
    if registry is None:
        from .registry import V3_REGISTRY

        registry = V3_REGISTRY
    repository = V3Repository.open(selection.path, registry=registry)
    try:
        _verify_selected_generation(repository, selection.manifest)
        current = StoreAuthorityManifestStore(manifest_path).read()
        if current != selection.manifest:
            raise StoreAuthorityCorrupt("store authority changed while opening coordinator state")
    except Exception:
        repository.close()
        raise
    return repository


def _verify_selected_generation(
    reader: V3Reader | V3Repository,
    manifest: StoreAuthorityManifest | None,
) -> None:
    if manifest is None:
        return
    try:
        receipt = canonical_loads(manifest.migration_receipt)
        if type(receipt) is not dict or type(receipt.get("run_id")) is not str:
            raise StoreAuthorityCorrupt("manifest migration receipt identity is invalid")
        stored = reader.get_record(f"migration:{receipt['run_id']}:receipt")
        if stored is None or stored.canonical_bytes != manifest.migration_receipt:
            raise StoreAuthorityCorrupt(
                "selected generation does not contain the manifest migration receipt"
            )
    except Exception as exc:
        if isinstance(exc, StoreAuthorityCorrupt):
            raise
        raise StoreAuthorityCorrupt(
            "selected generation migration receipt cannot be verified"
        ) from exc
