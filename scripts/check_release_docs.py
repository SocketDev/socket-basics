#!/usr/bin/env python3
"""Check or update current Socket Basics release references in documentation."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
DOC_PATHS = (REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").rglob("*.md")))
SEMVER = r"\d+\.\d+\.\d+"

# Match only references that describe the current Socket Basics release. Other
# versions in these guides (scanner versions, vulnerable Trivy versions, pinned
# third-party Actions, and so on) must remain independent.
REFERENCE_PATTERNS = (
    re.compile(rf"SocketDev/socket-basics@v?(?P<version>{SEMVER})"),
    re.compile(rf"SocketDev/socket-basics@<sha>\s+# v(?P<version>{SEMVER})"),
    re.compile(
        rf"(?:(?:ghcr\.io|docker\.io)/socketdev/|socketdev/)?"
        rf"socket-basics:(?P<version>{SEMVER})"
    ),
    re.compile(rf"github\.com/SocketDev/socket-basics refs/tags/v(?P<version>{SEMVER})"),
    re.compile(rf"specific version tag \(e\.g\. `@v(?P<version>{SEMVER})`\)"),
    re.compile(rf"Version tags\*\* \(`@v(?P<version>{SEMVER})`\)"),
    re.compile(rf"\| `@v(?P<version>{SEMVER})` \+ Dependabot"),
    re.compile(rf"keeping the `# v(?P<version>{SEMVER})` comment"),
    re.compile(rf"exact version such as `(?P<version>{SEMVER})`"),
    re.compile(rf'org\.opencontainers\.image\.version": "(?P<version>{SEMVER})"'),
    re.compile(rf"pin to `(?P<version>{SEMVER})` and upgrade"),
)


@dataclass(frozen=True)
class Reference:
    start: int
    end: int
    version: str


def read_canonical_version() -> str:
    return tomllib.loads(PYPROJECT_PATH.read_text())["project"]["version"]


def find_references(content: str) -> list[Reference]:
    references: set[Reference] = set()
    for pattern in REFERENCE_PATTERNS:
        for match in pattern.finditer(content):
            references.add(
                Reference(
                    start=match.start("version"),
                    end=match.end("version"),
                    version=match.group("version"),
                )
            )
    return sorted(references, key=lambda reference: reference.start)


def render_content(content: str, version: str) -> tuple[str, int]:
    references = find_references(content)
    updated = content
    changed = 0
    for reference in reversed(references):
        if reference.version == version:
            continue
        updated = updated[: reference.start] + version + updated[reference.end :]
        changed += 1
    return updated, changed


def check_docs(version: str) -> list[str]:
    mismatches: list[str] = []
    for path in DOC_PATHS:
        content = path.read_text()
        for reference in find_references(content):
            if reference.version == version:
                continue
            line = content.count("\n", 0, reference.start) + 1
            mismatches.append(
                f"{path.relative_to(REPO_ROOT)}:{line} references "
                f"{reference.version}; expected {version}"
            )
    return mismatches


def write_docs(version: str, dry_run: bool) -> int:
    total = 0
    for path in DOC_PATHS:
        content = path.read_text()
        updated, changed = render_content(content, version)
        total += changed
        if changed and not dry_run:
            path.write_text(updated)
        if changed:
            print(f"{path.relative_to(REPO_ROOT)}: {changed} reference(s) updated")
    return total


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Keep current Socket Basics release references aligned with pyproject.toml"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail on stale references")
    mode.add_argument("--write", action="store_true", help="update stale references")
    parser.add_argument(
        "--version",
        help="target version (defaults to the canonical pyproject.toml version)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show updates without writing (only valid with --write)",
    )
    args = parser.parse_args()
    if args.dry_run and not args.write:
        parser.error("--dry-run requires --write")
    if args.version and not re.fullmatch(SEMVER, args.version):
        parser.error("--version must be X.Y.Z")
    return args


def main() -> int:
    args = parse_args()
    version = args.version or read_canonical_version()
    if args.write:
        changed = write_docs(version, args.dry_run)
        action = "Would update" if args.dry_run else "Updated"
        print(f"{action} {changed} current-release reference(s) to {version}")
        return 0

    mismatches = check_docs(version)
    if mismatches:
        print(f"Current-release documentation is out of sync with {version}:")
        for mismatch in mismatches:
            print(f" - {mismatch}")
        print("Run: python3 scripts/check_release_docs.py --write")
        return 1

    print(f"Current-release documentation is in sync: {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
