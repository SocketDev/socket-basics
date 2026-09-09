"""Regression tests for the bundled Java opengrep rules.

Each fixture under ``tests/fixtures/opengrep/java`` annotates the line that
follows it with either ``// ruleid: <rule>`` (the rule must report that line) or
``// ok: <rule>`` (the rule must not report it). These are cheap guards against
the regex and taint regressions that are easy to reintroduce when editing
``java.yml``; they do not need the OWASP Benchmark corpus.

Skipped when ``opengrep`` is not on PATH, so they are a no-op for contributors
who only touch Python.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES = REPO_ROOT / "socket_basics" / "rules" / "java.yml"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "opengrep" / "java"

ANNOTATION = re.compile(r"//\s*(ruleid|ok):\s*([\w-]+)\s*$")

pytestmark = pytest.mark.skipif(
    shutil.which("opengrep") is None,
    reason="opengrep is not installed; Java rule regression tests skipped",
)


def _expectations() -> tuple[set[tuple[str, str, int]], set[tuple[str, str, int]]]:
    """Return (must_report, must_not_report) as {(file, rule, line)} sets."""
    expected: set[tuple[str, str, int]] = set()
    forbidden: set[tuple[str, str, int]] = set()
    for path in sorted(FIXTURES.glob("*.java")):
        lines = path.read_text().splitlines()
        for idx, line in enumerate(lines):
            match = ANNOTATION.search(line)
            if not match:
                continue
            kind, rule = match.group(1), match.group(2)
            # The annotation refers to the next non-comment line.
            target = idx + 1
            while target < len(lines) and lines[target].strip().startswith("//"):
                target += 1
            if target >= len(lines):
                continue
            entry = (path.name, rule, target + 1)  # 1-indexed
            (expected if kind == "ruleid" else forbidden).add(entry)
    return expected, forbidden


def _scan() -> set[tuple[str, str, int]]:
    """Run opengrep over the fixtures and return {(file, rule, line)}."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        out = Path(handle.name)
    # Pass explicit file paths. opengrep's default ignore list skips any
    # directory named tests/, so handing it FIXTURES scans nothing.
    targets = [str(path) for path in sorted(FIXTURES.glob("*.java"))]
    try:
        subprocess.run(
            [
                "opengrep", "--json", "--quiet", "-a", "--no-git-ignore",
                "--config", str(RULES), "--output", str(out), *targets,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        data = json.loads(out.read_text() or "{}")
    finally:
        out.unlink(missing_ok=True)

    found: set[tuple[str, str, int]] = set()
    for result in data.get("results", []):
        rule = result.get("check_id", "").split(".")[-1]
        name = Path(result.get("path", "")).name
        start = result.get("start", {}).get("line")
        end = result.get("end", {}).get("line", start)
        # A match can span several lines; credit every line it covers so an
        # annotation on the first line of a multi-line statement still matches.
        for line in range(start, (end or start) + 1):
            found.add((name, rule, line))
    return found


@pytest.fixture(scope="module")
def scan_results() -> set[tuple[str, str, int]]:
    return _scan()


def test_fixtures_have_annotations() -> None:
    expected, forbidden = _expectations()
    assert expected, "no positive fixture annotations were collected"
    assert forbidden, "no negative fixture annotations were collected"


def test_expected_findings_are_reported(scan_results) -> None:
    expected, _ = _expectations()
    missing = sorted(entry for entry in expected if entry not in scan_results)
    assert not missing, "rules failed to report annotated true positives: " + ", ".join(
        f"{name}:{line} {rule}" for name, rule, line in missing
    )


def test_forbidden_findings_are_not_reported(scan_results) -> None:
    _, forbidden = _expectations()
    reported = sorted(entry for entry in forbidden if entry in scan_results)
    assert not reported, "rules reported annotated false positives: " + ", ".join(
        f"{name}:{line} {rule}" for name, rule, line in reported
    )


def test_rules_config_is_valid() -> None:
    result = subprocess.run(
        ["opengrep", "--validate", "--config", str(RULES)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_every_annotated_rule_exists() -> None:
    import yaml

    ids = {rule["id"] for rule in yaml.safe_load(RULES.read_text())["rules"]}
    expected, forbidden = _expectations()
    referenced = {rule for _, rule, _ in expected | forbidden}
    unknown = sorted(referenced - ids)
    assert not unknown, f"fixtures reference rules that do not exist: {unknown}"


def _group(entries):
    grouped = defaultdict(list)
    for name, rule, line in entries:
        grouped[name].append((rule, line))
    return grouped
