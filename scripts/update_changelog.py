#!/usr/bin/env python3
"""
update_changelog.py — Prepend a new release section to CHANGELOG.md.

Called automatically by the publish-docker workflow after a GitHub Release
is created. Reads the generated release notes, inserts a new version section
immediately after [Unreleased], and updates the comparison links at the bottom.

Usage:
    # Notes from a file:
    python scripts/update_changelog.py --version 2.0.1 --date 2024-06-01 --notes-file notes.txt

    # Notes from stdin:
    echo "release notes" | python scripts/update_changelog.py --version 2.0.1 --date 2024-06-01

    # Dry run (print result without writing):
    python scripts/update_changelog.py --version 2.0.1 --date 2024-06-01 --dry-run
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = "SocketDev/socket-basics"
CHANGELOG = Path(__file__).parent.parent / "CHANGELOG.md"

# Tags from v2.0.0 onward use a v prefix; older tags don't.
# The script always adds the v prefix for new releases.
def _tag(version: str) -> str:
    """Return the git tag string for a version (adds v prefix)."""
    return f"v{version}"


def _compare_url(from_tag: str, to_tag: str) -> str:
    return f"https://github.com/{REPO}/compare/{from_tag}...{to_tag}"


def _commits_url(tag: str) -> str:
    return f"https://github.com/{REPO}/commits/{tag}"


def _find_previous_release_tag(content: str) -> str | None:
    """
    Find the tag used in the current [Unreleased] comparison link,
    which is the tag of the most recently published release.
    """
    match = re.search(
        r"^\[Unreleased\]:\s+https://github\.com/[^/]+/[^/]+/compare/([^.]+\.[^.]+\.[^.]+)\.\.\.",
        content,
        re.MULTILINE,
    )
    return match.group(1) if match else None


def _insert_release_section(content: str, version: str, date: str, notes: str) -> str:
    """
    Replace [Unreleased] content with a new ## [version] section.

    Clears any manually-maintained [Unreleased] notes (they're superseded by the
    GitHub-generated release notes) and inserts the new versioned section.
    The [Unreleased] heading is preserved but left empty, ready for the next cycle.
    """
    new_section = f"\n## [{version}] - {date}\n\n{notes.strip()}\n"

    # Match the [Unreleased] heading through to (but not including) the next ## heading
    unreleased_pattern = re.compile(
        r"(## \[Unreleased\][^\n]*\n)"  # the heading line
        r"(.*?)"                          # any existing [Unreleased] content
        r"(?=## \[)",                     # stop before the next ## [ section
        re.IGNORECASE | re.DOTALL,
    )
    match = unreleased_pattern.search(content)
    if not match:
        raise ValueError("Could not find '## [Unreleased]' section in CHANGELOG.md")

    # Replace the heading + its content with heading (empty) + new versioned section
    return content[: match.start()] + match.group(1) + new_section + content[match.end() :]


def _update_links(content: str, version: str, prev_tag: str) -> str:
    """
    Update the comparison links block at the bottom of the changelog.

    Before:
        [Unreleased]: .../compare/1.1.3...HEAD

    After publishing v2.0.1:
        [Unreleased]: .../compare/v2.0.1...HEAD
        [2.0.1]:      .../compare/v2.0.0...v2.0.1
    """
    new_tag = _tag(version)

    # Update the [Unreleased] link to point to the new tag
    content = re.sub(
        r"^\[Unreleased\]:.*$",
        f"[Unreleased]: {_compare_url(new_tag, 'HEAD')}",
        content,
        flags=re.MULTILINE,
    )

    # Insert the new version link immediately after [Unreleased]
    new_link = f"[{version}]:      {_compare_url(prev_tag, new_tag)}"
    content = re.sub(
        r"(\[Unreleased\]:.*\n)",
        rf"\1{new_link}\n",
        content,
        flags=re.MULTILINE,
    )

    return content


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, help="New version without v prefix, e.g. 2.0.1")
    parser.add_argument("--date", required=True, help="Release date in YYYY-MM-DD format")
    parser.add_argument("--notes-file", help="Path to file containing release notes (default: read stdin)")
    parser.add_argument("--dry-run", action="store_true", help="Print result without writing to disk")
    args = parser.parse_args()

    # Read release notes
    if args.notes_file:
        notes = Path(args.notes_file).read_text()
    elif not sys.stdin.isatty():
        notes = sys.stdin.read()
    else:
        parser.error("Provide release notes via --notes-file or stdin")

    content = CHANGELOG.read_text()

    prev_tag = _find_previous_release_tag(content)
    if not prev_tag:
        raise RuntimeError(
            "Could not determine previous release tag from [Unreleased] link in CHANGELOG.md. "
            "Ensure the link block at the bottom is up to date."
        )

    content = _insert_release_section(content, args.version, args.date, notes)
    content = _update_links(content, args.version, prev_tag)

    if args.dry_run:
        print(content)
    else:
        CHANGELOG.write_text(content)
        print(f"CHANGELOG.md updated for {args.version} (previous tag: {prev_tag})")


if __name__ == "__main__":
    main()
