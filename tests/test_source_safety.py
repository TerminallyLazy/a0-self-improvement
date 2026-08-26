from __future__ import annotations

from pathlib import Path

from scripts.scan_source_secrets import scan


def test_secret_scanner_rejects_high_confidence_token(tmp_path: Path) -> None:
    source = tmp_path / "leak.txt"
    source.write_text("token=ghp_abcdefghijklmnopqrstuvwxyz012345", encoding="utf-8")

    assert scan(tmp_path, [source]) == [("leak.txt", "github_token")]


def test_secret_scanner_rejects_environment_files(tmp_path: Path) -> None:
    source = tmp_path / ".env.production"
    source.write_text("PLACEHOLDER=true", encoding="utf-8")

    assert scan(tmp_path, [source]) == [(".env.production", "environment_file")]


def test_secret_scanner_ignores_binary_files(tmp_path: Path) -> None:
    source = tmp_path / "image.bin"
    source.write_bytes(b"\0ghp_abcdefghijklmnopqrstuvwxyz012345")

    assert scan(tmp_path, [source]) == []
