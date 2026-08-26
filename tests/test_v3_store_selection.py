from __future__ import annotations

from pathlib import Path

import pytest

from usr.plugins.dspy_rlm.helpers.v3.store_authority import (
    StoreAuthorityCorrupt,
    StoreAuthorityManifestStore,
)
from usr.plugins.dspy_rlm.helpers.v3.store_selection import resolve_runtime_store
from usr.plugins.dspy_rlm.helpers.v3.store_selection import open_runtime_repository
from usr.plugins.dspy_rlm.helpers.v3.repository import V3Repository


def test_fixed_path_is_admitted_only_before_cutover(tmp_path: Path) -> None:
    fixed = (tmp_path / "fixed.sqlite").resolve()
    manifest = (tmp_path / "authority.json").resolve()
    before = set(tmp_path.iterdir())

    selection = resolve_runtime_store(
        pre_cutover_path=fixed, manifest_path=manifest
    )

    assert selection.path == fixed
    assert selection.source == "pre_cutover"
    assert set(tmp_path.iterdir()) == before


def test_manifest_selects_exact_generation(tmp_path: Path) -> None:
    fixed = (tmp_path / "fixed.sqlite").resolve()
    fixed.write_bytes(b"legacy fixed path must not win")
    generation = (tmp_path / "generation.sqlite").resolve()
    generation.write_bytes(b"selected generation")
    authority = StoreAuthorityManifestStore((tmp_path / "authority.json").resolve())
    authority.compare_and_swap(
        expected_revision=0,
        generation_ref="generation-1",
        generation_path=generation,
        migration_receipt=b"receipt",
    )

    selection = resolve_runtime_store(
        pre_cutover_path=fixed, manifest_path=authority.path
    )

    assert selection.path == generation
    assert selection.source == "manifest"


def test_corrupt_manifest_blocks_without_fixed_path_fallback(tmp_path: Path) -> None:
    fixed = (tmp_path / "fixed.sqlite").resolve()
    fixed.write_bytes(b"valid-looking fixed store")
    manifest = (tmp_path / "authority.json").resolve()
    manifest.write_bytes(b"corrupt authority")
    manifest.chmod(0o600)

    with pytest.raises(StoreAuthorityCorrupt):
        resolve_runtime_store(pre_cutover_path=fixed, manifest_path=manifest)


def test_coordinator_writer_opens_only_the_selected_pre_cutover_store(tmp_path: Path) -> None:
    fixed = (tmp_path / "fixed.sqlite").resolve()
    manifest = (tmp_path / "authority.json").resolve()
    V3Repository.create(fixed).close()

    with open_runtime_repository(pre_cutover_path=fixed, manifest_path=manifest) as repository:
        assert repository.path == fixed
