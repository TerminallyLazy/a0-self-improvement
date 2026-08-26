from __future__ import annotations

import os
import hashlib
from pathlib import Path
import stat

import pytest

from usr.plugins.dspy_rlm.helpers.v3.store_authority import (
    StaleStoreAuthorityRevision,
    StoreAuthorityCorrupt,
    StoreAuthorityManifestStore,
)


def _generation(tmp_path: Path, name: str = "safe-store-generation-01.sqlite") -> Path:
    path = tmp_path / name
    path.write_bytes(b"verified safe projection bytes")
    return path.resolve()


def _commit(
    store: StoreAuthorityManifestStore,
    generation_path: Path,
    *,
    expected_revision: int = 0,
    receipt=b"receipt-1",
):
    return store.compare_and_swap(
        expected_revision=expected_revision,
        generation_ref="generation_01",
        generation_path=generation_path,
        migration_receipt=receipt,
    )


def test_manifest_round_trip_embeds_exact_receipt_and_is_0600(tmp_path: Path) -> None:
    store = StoreAuthorityManifestStore(tmp_path / "authority.json")
    generation = _generation(tmp_path)
    committed = _commit(store, generation)
    read = store.read()

    assert committed.recovered_lost_ack is False
    assert read == committed.manifest
    assert read.migration_receipt == b"receipt-1"
    assert read.generation_path_identity == str(generation)
    assert read.initial_digest == hashlib.sha256(generation.read_bytes()).hexdigest()
    assert store.resolve_selected_generation() == generation
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_stale_compare_and_swap_cannot_replace_authority(tmp_path: Path) -> None:
    store = StoreAuthorityManifestStore(tmp_path / "authority.json")
    generation = _generation(tmp_path)
    first = _commit(store, generation)
    other_generation = _generation(tmp_path, "safe-store-generation-02.sqlite")

    with pytest.raises(StaleStoreAuthorityRevision, match="observed 1"):
        store.compare_and_swap(
            expected_revision=0,
            generation_ref="generation_02",
            generation_path=other_generation,
            migration_receipt=b"different-receipt",
        )

    assert store.read() == first.manifest


def test_identical_retry_recovers_lost_ack_without_replacing_bytes(tmp_path: Path) -> None:
    store = StoreAuthorityManifestStore(tmp_path / "authority.json")
    generation = _generation(tmp_path)
    first = _commit(store, generation)
    inode = store.path.stat().st_ino
    generation.write_bytes(b"legitimate write after cutover")
    second = _commit(store, generation)

    assert second.recovered_lost_ack is True
    assert second.manifest == first.manifest
    assert store.path.stat().st_ino == inode


def test_post_cutover_writes_resolve_but_missing_or_unsafe_custody_blocks(tmp_path: Path) -> None:
    store = StoreAuthorityManifestStore(tmp_path / "authority.json")
    generation = _generation(tmp_path)
    _commit(store, generation)
    generation.write_bytes(b"changed after selection")

    assert store.resolve_selected_generation() == generation

    generation.unlink()
    with pytest.raises(StoreAuthorityCorrupt, match="missing"):
        store.read()

    generation.write_bytes(b"valid later SQLite state")
    os.chmod(generation, 0o666)
    with pytest.raises(StoreAuthorityCorrupt, match="custody"):
        store.read()
