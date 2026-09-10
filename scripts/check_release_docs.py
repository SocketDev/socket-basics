#!/usr/bin/env python3
"""Check or update version references in documentation.

Two kinds of reference are kept in sync:

* the current Socket Basics release (``@v3.1.0``, ``socket-basics:3.1.0`` ...),
  compared against the canonical ``pyproject.toml`` version, and
* the bundled scanner versions the guides quote (TruffleHog, OpenGrep, Trivy),
  compared against the ``ARG`` pins in the ``Dockerfile`` so "match the version
  bundled in the image" advice stays true.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
DOCKERFILE_PATH = REPO_ROOT / "Dockerfile"
DOC_PATHS = (REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").rglob("*.md")))
SEMVER = r"\d+\.\d+\.\d+"

# Match only references that describe the current Socket Basics release. Other
# versions in these guides (vulnerable Trivy versions, pinned third-party
# Actions, and so on) must remain independent. Bundled scanner versions are
# checked separately against the Dockerfile pins via TOOL_REFERENCE_PATTERNS.
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
    # The action never publishes a floating major tag, so a `@v2`-style
    # reference is stale by definition and is rewritten to the exact release.
    re.compile(r"SocketDev/socket-basics@v(?P<version>\d+)(?![\d.])"),
)

# Bundled scanner pins: Dockerfile ARG name per tool, and the doc patterns that
# quote that tool's version. Values are compared without any leading "v".
TOOL_PINS = {
    "trufflehog": "TRUFFLEHOG_VERSION",
    "opengrep": "OPENGREP_VERSION",
    "trivy": "TRIVY_VERSION",
}
TOOL_REFERENCE_PATTERNS = {
    "trufflehog": (
        re.compile(rf"trufflesecurity/trufflehog:v?(?P<version>{SEMVER})"),
        re.compile(rf"trufflehog/releases/download/v(?P<version>{SEMVER})/"),
        re.compile(rf"trufflehog_(?P<version>{SEMVER})_"),
        re.compile(rf'com\.socket\.trufflehog-version": "(?P<version>{SEMVER})"'),
        re.compile(rf"TRUFFLEHOG_VERSION=(?P<version>{SEMVER})"),
    ),
    "opengrep": (
        re.compile(rf'com\.socket\.opengrep-version": "v(?P<version>{SEMVER})"'),
        re.compile(rf"OPENGREP_VERSION=v(?P<version>{SEMVER})"),
    ),
    "trivy": (
        re.compile(rf"aquasec/trivy:(?P<version>{SEMVER})"),
        re.compile(rf'com\.socket\.trivy-version": "(?P<version>{SEMVER})"'),
        re.compile(rf"TRIVY_VERSION=(?P<version>{SEMVER})"),
    ),
}


@dataclass(frozen=True)
class Reference:
    start: int
    end: int
    version: str


def read_canonical_version() -> str:
    return tomllib.loads(PYPROJECT_PATH.read_text())["project"]["version"]


def read_tool_pins() -> dict[str, str]:
    """Return {tool: version} from the Dockerfile ARG pins, without any "v"."""
    content = DOCKERFILE_PATH.read_text()
    pins: dict[str, str] = {}
    for tool, arg in TOOL_PINS.items():
        match = re.search(rf"^ARG {arg}=v?(?P<version>{SEMVER})\b", content, re.MULTILINE)
        if not match:
            raise ValueError(f"Dockerfile has no 'ARG {arg}=<version>' pin")
        pins[tool] = match.group("version")
    return pins


def _targets(version: str) -> list[tuple[str, str, tuple[re.Pattern[str], ...]]]:
    """Every (label, expected version, patterns) the docs must agree with."""
    targets = [("socket-basics", version, REFERENCE_PATTERNS)]
    for tool, pinned in read_tool_pins().items():
        targets.append((tool, pinned, TOOL_REFERENCE_PATTERNS[tool]))
    return targets


def find_references(
    content: str, patterns: tuple[re.Pattern[str], ...] = REFERENCE_PATTERNS
) -> list[Reference]:
    references: set[Reference] = set()
    for pattern in patterns:
        for match in pattern.finditer(content):
            references.add(
                Reference(
                    start=match.start("version"),
                    end=match.end("version"),
                    version=match.group("version"),
                )
            )
    return sorted(references, key=lambda reference: reference.start)


def render_content(
    content: str, version: str, patterns: tuple[re.Pattern[str], ...] = REFERENCE_PATTERNS
) -> tuple[str, int]:
    references = find_references(content, patterns)
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
    targets = _targets(version)
    for path in DOC_PATHS:
        content = path.read_text()
        for label, expected, patterns in targets:
            for reference in find_references(content, patterns):
                if reference.version == expected:
                    continue
                line = content.count("\n", 0, reference.start) + 1
                mismatches.append(
                    f"{path.relative_to(REPO_ROOT)}:{line} references "
                    f"{label} {reference.version}; expected {expected}"
                )
    return mismatches


def write_docs(version: str, dry_run: bool) -> int:
    total = 0
    targets = _targets(version)
    for path in DOC_PATHS:
        original = path.read_text()
        updated = original
        changed = 0
        for _label, expected, patterns in targets:
            updated, count = render_content(updated, expected, patterns)
            changed += count
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
        print(f"{action} {changed} version reference(s) (release {version} + Dockerfile tool pins)")
        return 0

    mismatches = check_docs(version)
    if mismatches:
        print(f"Documentation version references are out of sync (release {version}, Dockerfile tool pins):")
        for mismatch in mismatches:
            print(f" - {mismatch}")
        print("Run: python3 scripts/check_release_docs.py --write")
        return 1

    print(f"Documentation version references are in sync: release {version}, tool pins {read_tool_pins()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
