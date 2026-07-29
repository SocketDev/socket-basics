#!/usr/bin/env python3
"""
prep_release.py — Prepare the final release-prep PR for a new version.

Feature PRs never touch version files; they only add CHANGELOG entries under
[Unreleased]. When a release batch is complete, run this once on a fresh
branch: it bumps every version-bearing file and stamps the [Unreleased]
changelog section, so the release PR is a mechanical five-file diff. Tag the
release PR's merge commit and the publish workflow's version gate passes by
construction.

Files updated:
    pyproject.toml             [project] version (canonical source)
    socket_basics/version.py   derived via sync_release_version.py
    socket_basics/__init__.py  derived via sync_release_version.py
    action.yml                 derived via sync_release_version.py
    uv.lock                    project entry (via `uv lock`)
    CHANGELOG.md               [Unreleased] -> [X.Y.Z] - YYYY-MM-DD

Usage:
    python scripts/prep_release.py --version 2.2.0
    python scripts/prep_release.py --version 2.2.0 --date 2026-07-29
    python scripts/prep_release.py --version 2.2.0 --dry-run
"""
from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# pyproject.toml is the canonical version source; version.py, __init__.py, and
# action.yml are derived from it by scripts/sync_release_version.py.
PYPROJECT_PATTERN = re.compile(r'^version = "(\d+\.\d+\.\d+)"$', re.M)


def _bump_file(path: Path, pattern: re.Pattern[str], replacement: str, version: str) -> tuple[str, str]:
    """Return (old_version, new_content) without writing."""
    content = path.read_text()
    match = pattern.search(content)
    if not match:
        sys.exit(f"error: no version pattern found in {path.relative_to(ROOT)}")
    old = match.group(match.lastindex or 0) if match.lastindex else match.group(1)
    new_content, count = pattern.subn(replacement.format(v=version), content, count=1)
    if count != 1:
        sys.exit(f"error: expected exactly one version in {path.relative_to(ROOT)}, replaced {count}")
    return old, new_content


def _stamp_changelog(version: str, date: str) -> str:
    """Return the stamped CHANGELOG content without writing."""
    content = CHANGELOG.read_text()

    if f"## [{version}]" in content:
        sys.exit(f"error: CHANGELOG.md already has a [{version}] section")

    match = re.search(r"^## \[Unreleased\]\n(.*?)(?=^## \[)", content, re.M | re.S)
    if not match:
        sys.exit("error: could not find an [Unreleased] section followed by a release section")

    body = match.group(1).strip("\n")
    if not body.strip():
        sys.exit("error: [Unreleased] is empty — nothing to release. "
                 "Feature PRs should add their entries there before release prep.")

    stamped = f"## [Unreleased]\n\n## [{version}] - {date}\n\n{body}\n\n"
    return content[:match.start()] + stamped + content[match.end():]


def _refresh_lock(dry_run: bool) -> None:
    if dry_run:
        print("dry-run: skipping `uv lock`")
        return
    try:
        subprocess.run(["uv", "lock"], cwd=ROOT, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("error: `uv` not found — install uv or run `uv lock` manually before committing")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"error: `uv lock` failed:\n{exc.stderr}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare version bumps and changelog for a release PR.")
    parser.add_argument("--version", required=True, help="Release version without v prefix, e.g. 2.2.0")
    parser.add_argument("--date", default=datetime.date.today().isoformat(),
                        help="Release date for the changelog section (default: today)")
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing")
    args = parser.parse_args()

    if not SEMVER_RE.match(args.version):
        sys.exit(f"error: version must be X.Y.Z (got {args.version!r})")

    tags = subprocess.run(["git", "tag", "--list", f"v{args.version}", args.version],
                          cwd=ROOT, capture_output=True, text=True).stdout.split()
    if tags:
        sys.exit(f"error: tag for {args.version} already exists: {', '.join(tags)}")

    # Validate and render every change first; only write once all succeed,
    # so a failure never leaves a half-modified tree.
    old, pyproject_content = _bump_file(PYPROJECT, PYPROJECT_PATTERN, 'version = "{v}"', args.version)
    changelog_content = _stamp_changelog(args.version, args.date)

    if not args.dry_run:
        PYPROJECT.write_text(pyproject_content)
    print(f"pyproject.toml: {old} -> {args.version}")

    if args.dry_run:
        print("dry-run: skipping sync_release_version.py --write")
    else:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "sync_release_version.py"), "--write"],
                       cwd=ROOT, check=True)

    if not args.dry_run:
        CHANGELOG.write_text(changelog_content)
    print(f"CHANGELOG.md: [Unreleased] -> [{args.version}] - {args.date}")

    _refresh_lock(args.dry_run)
    if not args.dry_run:
        print("uv.lock: refreshed")

    print("\nNext steps: commit these changes on a release branch, open the release PR,")
    print(f"merge it last, then tag the merge commit as v{args.version} to trigger publish.")


if __name__ == "__main__":
    main()
