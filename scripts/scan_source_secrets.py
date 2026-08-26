#!/usr/bin/env python3
"""Fail CI on high-confidence secret material in the standalone source tree."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable, Sequence


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("openai_token", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)
_ALLOWED_PATTERN_DEFINITIONS = frozenset(
    {
        "helpers/guidance.py",
        "helpers/redaction.py",
        "scripts/scan_source_secrets.py",
        "tests/test_redaction.py",
        "tests/test_source_safety.py",
    }
)


class SecretScanError(RuntimeError):
    pass


def tracked_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SecretScanError("unable to enumerate repository source files") from exc
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def scan(root: Path, paths: Iterable[Path] | None = None) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for path in paths if paths is not None else tracked_files(root):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        if relative in _ALLOWED_PATTERN_DEFINITIONS or not path.is_file():
            continue
        if path.name == ".env" or path.name.startswith(".env."):
            findings.append((relative, "environment_file"))
            continue
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise SecretScanError(f"unable to read source path {relative}") from exc
        if b"\0" in content[:8192]:
            continue
        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(content):
                findings.append((relative, label))
    return sorted(findings)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    findings = scan(args.root.resolve())
    if findings:
        for path, label in findings:
            print(f"secret scan failed: {path}: {label}", file=sys.stderr)
        return 1
    print("secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
