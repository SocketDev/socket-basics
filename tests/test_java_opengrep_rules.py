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
import os
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

# CI sets this so a missing opengrep fails the job instead of silently
# skipping every test in this module.
REQUIRE_OPENGREP_ENV = "SOCKET_BASICS_REQUIRE_OPENGREP"

_HAVE_OPENGREP = shutil.which("opengrep") is not None
if not _HAVE_OPENGREP and os.environ.get(REQUIRE_OPENGREP_ENV):
    pytest.fail(
        f"{REQUIRE_OPENGREP_ENV} is set but opengrep is not on PATH", pytrace=False
    )

pytestmark = pytest.mark.skipif(
    not _HAVE_OPENGREP,
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
    """Run opengrep over a copy of the fixtures and return {(file, rule, line)}."""
    fixtures = sorted(FIXTURES.glob("*.java"))
    # Scan a copy outside the repository. opengrep's default ignore list skips
    # any path with a tests/ directory in it, and on some versions (1.19.0)
    # that applies even to explicitly listed files, so scanning in place
    # silently scanned nothing and every positive annotation "failed".
    with tempfile.TemporaryDirectory(prefix="opengrep-java-fixtures-") as tmp:
        for path in fixtures:
            shutil.copy(path, tmp)
        out = Path(tmp) / "results.json"
        proc = subprocess.run(
            [
                "opengrep", "--json", "--quiet", "--no-git-ignore",
                "--config", str(RULES), "--output", str(out), tmp,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert out.exists(), (
            f"opengrep wrote no output (exit {proc.returncode}): {proc.stderr[-2000:]}"
        )
        data = json.loads(out.read_text() or "{}")

    errors = [e.get("message", str(e))[:200] for e in data.get("errors", [])]
    assert not errors, f"opengrep reported errors while scanning the fixtures: {errors}"
    scanned = {Path(p).name for p in data.get("paths", {}).get("scanned", [])}
    expected = {p.name for p in fixtures}
    assert scanned == expected, (
        f"opengrep scanned {sorted(scanned)} but the fixtures are {sorted(expected)}"
    )

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


def test_no_unannotated_findings(scan_results) -> None:
    """Every finding must land on an annotated line.

    Without this, an annotation can be satisfied by an unrelated finding that
    happens to cover the same line, and the fixture silently stops guarding
    the behaviour it was written for.
    """
    expected, forbidden = _expectations()
    annotated = {(name, rule, line) for name, rule, line in expected | forbidden}
    stray = sorted(entry for entry in scan_results if entry not in annotated)
    # A multi-line match credits every line it spans, so only report a finding
    # when none of its lines carry an annotation for that rule.
    by_rule_file = defaultdict(set)
    for name, rule, line in annotated:
        by_rule_file[(name, rule)].add(line)
    unexplained = [
        (name, rule, line)
        for name, rule, line in stray
        if line not in by_rule_file.get((name, rule), set())
    ]
    assert not unexplained, "findings on unannotated lines: " + ", ".join(
        f"{name}:{line} {rule}" for name, rule, line in unexplained
    )
