#!/usr/bin/env python3
"""Sync release version metadata from pyproject.toml.

This script treats pyproject.toml as the canonical source of truth and keeps
the duplicated version fields in sync.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
VERSION_PY_PATH = REPO_ROOT / "socket_basics" / "version.py"
INIT_PY_PATH = REPO_ROOT / "socket_basics" / "__init__.py"
ACTION_YML_PATH = REPO_ROOT / "action.yml"


def read_canonical_version() -> str:
    data = tomllib.loads(PYPROJECT_PATH.read_text())
    return data["project"]["version"]


def replace_first(pattern: str, replacement: str, content: str, path: Path) -> str:
    updated, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"Could not update expected version field in {path}")
    return updated


def build_expected_files(version: str) -> dict[Path, str]:
    expected: dict[Path, str] = {}

    version_py = VERSION_PY_PATH.read_text()
    expected[VERSION_PY_PATH] = replace_first(
        r'^__version__ = "[^"]+"$',
        f'__version__ = "{version}"',
        version_py,
        VERSION_PY_PATH,
    )

    init_py = INIT_PY_PATH.read_text()
    expected[INIT_PY_PATH] = replace_first(
        r'^__version__ = "[^"]+"$',
        f'__version__ = "{version}"',
        init_py,
        INIT_PY_PATH,
    )

    action_yml = ACTION_YML_PATH.read_text()
    expected[ACTION_YML_PATH] = replace_first(
        r'^(  image: "docker://ghcr\.io/socketdev/socket-basics:)[^"]+(")$',
        rf'\g<1>{version}\2',
        action_yml,
        ACTION_YML_PATH,
    )

    return expected


def check_files(expected: dict[Path, str]) -> list[str]:
    mismatches: list[str] = []
    for path, rendered in expected.items():
        current = path.read_text()
        if current != rendered:
            mismatches.append(str(path.relative_to(REPO_ROOT)))
    return mismatches


def write_files(expected: dict[Path, str]) -> None:
    for path, rendered in expected.items():
        path.write_text(rendered)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync socket-basics version metadata from pyproject.toml"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check",
        action="store_true",
        help="Fail if any derived version files differ from pyproject.toml",
    )
    group.add_argument(
        "--write",
        action="store_true",
        help="Rewrite derived version files to match pyproject.toml",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    version = read_canonical_version()
    expected = build_expected_files(version)

    if args.write:
        write_files(expected)
        print(f"Synchronized release version metadata to {version}")
        return 0

    mismatches = check_files(expected)
    if mismatches:
        print(f"Release version metadata is out of sync with pyproject.toml ({version}):")
        for mismatch in mismatches:
            print(f" - {mismatch}")
        print("Run: python3 scripts/sync_release_version.py --write")
        return 1

    print(f"Release version metadata is in sync: {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
