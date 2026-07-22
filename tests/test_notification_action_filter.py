"""Suppressed findings must be excluded from notifications.

A rule disabled via *_disabled_rules (or matched by a local SAST ignore
override) is forced to action 'ignore' and tagged with an ``actionReason`` by
the normalizer. The dashboard honors that, but notification generation
previously keyed off severity alone, so suppressed critical/high findings still
posted to the PR comment, Slack, etc.

generate_notifications() now drops suppressed alerts before building any notifier
output. It gates on the explicit ``actionReason`` rather than
``action == 'ignore'``, because 'ignore' is also the default action the
normalizer derives for low-severity findings -- those must still notify when a
user opts in to low severities. Suppressed alerts still ship in the uploaded
facts; only notifications are gated.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.preview_pr_comments import make_mock_config

from socket_basics.core.connector.normalizer import _normalize_alert
from socket_basics.core.connector.opengrep import OpenGrepScanner


def _make_scanner(config, allowed_severities=("critical", "high")):
    # generate_notifications() only needs .config and .allowed_severities;
    # bypass __init__, which shells out to build the opengrep rule set.
    scanner = OpenGrepScanner.__new__(OpenGrepScanner)
    scanner.config = config
    scanner.allowed_severities = set(allowed_severities)
    return scanner


def _alert(rule_id, severity, snippet, line):
    # A raw alert as the connector emits it, before normalization. No action or
    # actionReason -- the normalizer derives those from config + severity.
    return {
        "title": rule_id,
        "severity": severity,
        "subType": "sast-generic",
        "location": {"path": "slik/domain/GetActionablePlanStatusesUseCase.kt"},
        "props": {
            "ruleId": rule_id,
            "filePath": "slik/domain/GetActionablePlanStatusesUseCase.kt",
            "startLine": line,
            "endLine": line,
            "codeSnippet": snippet,
        },
    }


def _normalize(scanner, components):
    # Run every alert through the real normalizer with the scanner's config, so
    # actionReason and default actions are set exactly as in the pipeline.
    for c in components:
        c["alerts"] = [_normalize_alert(a, connector=scanner) for a in c["alerts"]]
    return components


@pytest.fixture
def config():
    cfg = make_mock_config()
    # Suppress a SAST rule the way org/repo config lands in config: the dashboard
    # API's kotlinDisabledRules maps to kotlin_disabled_rules, as does a repo-level
    # *_disabled_rules action input.
    cfg["kotlin_disabled_rules"] = "kotlin-sql-injection"
    return cfg


def test_suppressed_alert_excluded_from_pr_notifications(config):
    scanner = _make_scanner(config)
    components = _normalize(scanner, [
        {
            "id": "GetActionablePlanStatusesUseCase.kt",
            "name": "GetActionablePlanStatusesUseCase.kt",
            "type": "generic",
            "alerts": [
                _alert("kotlin-sql-injection", "critical", "SUPPRESSED_SNIPPET_XYZ", 66),
                _alert("kotlin-weak-hash", "critical", "ACTIVE_SNIPPET_ABC", 70),
            ],
        }
    ])

    # The normalizer flagged only the disabled rule as suppressed.
    alerts = components[0]["alerts"]
    assert alerts[0]["actionReason"] == "disabled_rule"
    assert "actionReason" not in alerts[1]

    result = scanner.generate_notifications(components)
    content = "\n".join(item["content"] for item in result.get("github_pr", []))

    # The active finding survives.
    assert "kotlin-weak-hash" in content
    assert "ACTIVE_SNIPPET_ABC" in content

    # The suppressed finding is gone, even though it is critical.
    assert "kotlin-sql-injection" not in content
    assert "SUPPRESSED_SNIPPET_XYZ" not in content

    # Summary counts only the non-suppressed critical.
    assert "Critical: 1" in content
    assert "Critical: 2" not in content


def test_all_suppressed_yields_no_notifications(config):
    scanner = _make_scanner(config)
    components = _normalize(scanner, [
        {
            "id": "f.kt",
            "name": "f.kt",
            "type": "generic",
            "alerts": [_alert("kotlin-sql-injection", "critical", "X", 66)],
        }
    ])

    # Every alert suppressed -> no groups -> empty per-notifier mapping.
    assert scanner.generate_notifications(components) == {}


def test_low_severity_not_suppressed_still_notifies(config):
    # The normalizer maps low severity to the default action 'ignore'. That must
    # NOT be treated as suppression: a user who opts in to low severities should
    # still see those findings in the PR comment. Regression guard against gating
    # notifications on action == 'ignore' instead of the explicit actionReason.
    scanner = _make_scanner(config, allowed_severities=("critical", "high", "low"))
    components = _normalize(scanner, [
        {
            "id": "f.kt",
            "name": "f.kt",
            "type": "generic",
            "alerts": [_alert("kotlin-style-nit", "low", "LOW_SNIPPET_LMN", 12)],
        }
    ])

    # Low maps to action 'ignore' but carries no actionReason (not suppressed).
    low = components[0]["alerts"][0]
    assert low["action"] == "ignore"
    assert "actionReason" not in low

    result = scanner.generate_notifications(components)
    content = "\n".join(item["content"] for item in result.get("github_pr", []))

    # The opted-in low-severity finding still notifies.
    assert "kotlin-style-nit" in content
    assert "LOW_SNIPPET_LMN" in content
