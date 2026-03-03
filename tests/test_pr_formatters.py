"""Unit tests for PR comment formatter output structure.

Verifies that each scanner's format_notifications() produces well-formed
markdown with the expected structural elements (section markers, logo,
severity badges, links, collapsible sections, etc.).

These tests do NOT hit any network — they use the same mock config and
fixture data as scripts/preview_pr_comments.py.
"""

import pytest
import re

# Re-use the shared mock config and fixtures from the preview script
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.preview_pr_comments import (
    make_mock_config,
    OPENGREP_FIXTURES,
    TRUFFLEHOG_FIXTURES,
    TIER1_FIXTURES,
    _trivy_image_fixture,
    _trivy_dockerfile_fixture,
)


@pytest.fixture
def config():
    return make_mock_config()


@pytest.fixture
def config_no_links():
    return make_mock_config(repo="", commit="")


# ---------------------------------------------------------------------------
# Shared assertions
# ---------------------------------------------------------------------------

def assert_section_markers(content: str, section_id: str):
    """Every formatter output must have matching start/end HTML comment markers."""
    assert f"<!-- {section_id} start -->" in content
    assert f"<!-- {section_id} end -->" in content


def assert_has_logo(content: str):
    """Logo image tag must be present in the H2 header."""
    assert '<img src="' in content
    assert 'socket-logo.png' in content
    assert 'width="24"' in content


def assert_has_scan_link(content: str):
    """Full scan report link must be present when configured."""
    assert "View Full Socket Scan Report" in content
    assert "socket.dev/dashboard" in content


def assert_severity_emojis(content: str, expected_severities: list):
    """Check that expected severity emojis appear."""
    emoji_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
    for sev in expected_severities:
        assert emoji_map[sev] in content, f"Missing emoji for {sev}"


# ---------------------------------------------------------------------------
# OpenGrep SAST
# ---------------------------------------------------------------------------

class TestOpenGrepFormatter:
    def test_returns_one_result_per_subtype(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config)
        assert len(results) == 2  # sast-javascript + sast-python
        assert all("title" in r and "content" in r for r in results)

    def test_section_markers(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config)
        for result in results:
            content = result["content"]
            # Section ID is the subtype key
            assert re.search(r"<!-- sast-\w+ start -->", content)
            assert re.search(r"<!-- sast-\w+ end -->", content)

    def test_logo_and_scan_link(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config)
        for result in results:
            assert_has_logo(result["content"])
            assert_has_scan_link(result["content"])

    def test_summary_section(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config)
        js_content = next(r["content"] for r in results if "JavaScript" in r["title"])
        assert "### Summary" in js_content
        assert "Critical: 1" in js_content
        assert "High: 1" in js_content

    def test_collapsible_sections(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config)
        js_content = next(r["content"] for r in results if "JavaScript" in r["title"])
        assert "<details" in js_content
        assert "</details>" in js_content
        # Critical file should be auto-expanded
        assert "<details open>" in js_content

    def test_clickable_file_links(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config)
        js_content = next(r["content"] for r in results if "JavaScript" in r["title"])
        assert "https://github.com/SocketDev/example-app/blob/" in js_content
        # Line anchors
        assert "#L42-L45" in js_content
        assert "#L78-L80" in js_content

    def test_code_fencing_with_language(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config)
        js_content = next(r["content"] for r in results if "JavaScript" in r["title"])
        # .ts files -> typescript fencing
        assert "```typescript" in js_content

    def test_no_links_when_repo_empty(self, config_no_links):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config_no_links)
        js_content = next(r["content"] for r in results if "JavaScript" in r["title"])
        assert "https://github.com" not in js_content

    def test_clean_filepath_no_workspace_prefix(self, config):
        """Display paths must not contain /github/workspace/ prefixes."""
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        # Inject a workspace-prefixed path
        fixture = {
            "sast-javascript": [
                {
                    "component": {"id": "c"},
                    "alert": {
                        "severity": "high",
                        "title": "test-rule",
                        "location": {},
                        "props": {
                            "filePath": "/github/workspace/src/app.js",
                            "ruleId": "test-rule",
                            "startLine": 1,
                            "endLine": 1,
                            "codeSnippet": "x()",
                        },
                    },
                }
            ]
        }
        results = format_notifications(fixture, config=config)
        content = results[0]["content"]
        assert "/github/workspace/" not in content


# ---------------------------------------------------------------------------
# Trivy (image / vuln)
# ---------------------------------------------------------------------------

class TestTrivyImageFormatter:
    def test_returns_single_result(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications(_trivy_image_fixture(), scan_type="image", config=config)
        assert len(results) == 1
        assert results[0]["title"] == "Socket Container Scan"

    def test_section_markers(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications(_trivy_image_fixture(), scan_type="image", config=config)
        assert_section_markers(results[0]["content"], "trivy-container")

    def test_logo_and_scan_link(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications(_trivy_image_fixture(), scan_type="image", config=config)
        assert_has_logo(results[0]["content"])
        assert_has_scan_link(results[0]["content"])

    def test_cve_links_use_html_in_summary(self, config):
        """CVE links inside <summary> must use HTML <a> tags, not markdown."""
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications(_trivy_image_fixture(), scan_type="image", config=config)
        content = results[0]["content"]
        assert '<a href="https://nvd.nist.gov/vuln/detail/CVE-2021-23337">CVE-2021-23337</a>' in content
        # Should NOT have markdown link syntax inside <summary>
        assert "[CVE-2021-23337](https://nvd.nist.gov" not in content

    def test_cvss_scores(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications(_trivy_image_fixture(), scan_type="image", config=config)
        content = results[0]["content"]
        assert "CVSS 7.2" in content

    def test_expandable_panels(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications(_trivy_image_fixture(), scan_type="image", config=config)
        content = results[0]["content"]
        assert "<details>" in content
        assert "</details>" in content
        assert "**Package:**" in content
        assert "**Fixed Version:**" in content


# ---------------------------------------------------------------------------
# Trivy Dockerfile
# ---------------------------------------------------------------------------

class TestTrivyDockerfileFormatter:
    def test_returns_single_result(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications(_trivy_dockerfile_fixture(), scan_type="dockerfile", config=config)
        assert len(results) == 1
        assert results[0]["title"] == "Socket Dockerfile Scan"

    def test_table_format(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications(_trivy_dockerfile_fixture(), scan_type="dockerfile", config=config)
        content = results[0]["content"]
        # Dockerfile scan uses a markdown table
        assert "| Rule ID |" in content
        assert "| Severity |" in content
        assert "**DS002**" in content


# ---------------------------------------------------------------------------
# TruffleHog
# ---------------------------------------------------------------------------

class TestTruffleHogFormatter:
    def test_returns_single_result(self, config):
        from socket_basics.core.connector.trufflehog.github_pr import format_notifications
        results = format_notifications(TRUFFLEHOG_FIXTURES, config=config)
        assert len(results) == 1
        assert results[0]["title"] == "Socket Secret Scanning"

    def test_section_markers(self, config):
        from socket_basics.core.connector.trufflehog.github_pr import format_notifications
        results = format_notifications(TRUFFLEHOG_FIXTURES, config=config)
        assert_section_markers(results[0]["content"], "trufflehog-secrets")

    def test_table_with_expected_columns(self, config):
        from socket_basics.core.connector.trufflehog.github_pr import format_notifications
        results = format_notifications(TRUFFLEHOG_FIXTURES, config=config)
        content = results[0]["content"]
        assert "| Detector |" in content
        assert "| Severity |" in content
        assert "| Status |" in content
        assert "| Location |" in content
        assert "| Secret |" in content

    def test_verified_status(self, config):
        from socket_basics.core.connector.trufflehog.github_pr import format_notifications
        results = format_notifications(TRUFFLEHOG_FIXTURES, config=config)
        content = results[0]["content"]
        assert "✅ **VERIFIED**" in content
        assert "⚠️ *Unverified*" in content

    def test_clickable_file_links(self, config):
        from socket_basics.core.connector.trufflehog.github_pr import format_notifications
        results = format_notifications(TRUFFLEHOG_FIXTURES, config=config)
        content = results[0]["content"]
        assert "config/deploy.env:12" in content
        assert "#L12" in content

    def test_redacted_secrets(self, config):
        from socket_basics.core.connector.trufflehog.github_pr import format_notifications
        results = format_notifications(TRUFFLEHOG_FIXTURES, config=config)
        content = results[0]["content"]
        assert "`AKIA****EXAMPLE`" in content


# ---------------------------------------------------------------------------
# Socket Tier 1
# ---------------------------------------------------------------------------

class TestTier1Formatter:
    def test_returns_single_result(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        results = format_notifications(TIER1_FIXTURES, config=config)
        assert len(results) == 1
        assert results[0]["title"] == "Socket Security Tier 1"

    def test_section_markers(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        results = format_notifications(TIER1_FIXTURES, config=config)
        assert_section_markers(results[0]["content"], "socket-tier1")

    def test_severity_summary(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        results = format_notifications(TIER1_FIXTURES, config=config)
        content = results[0]["content"]
        assert "### Summary" in content
        assert "Critical: 1" in content
        assert "High: 2" in content

    def test_reachability_grouping(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        results = format_notifications(TIER1_FIXTURES, config=config)
        content = results[0]["content"]
        assert "**Reachable**" in content
        assert "**Unknown**" in content
        assert "**Unreachable**" in content

    def test_cve_links(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        results = format_notifications(TIER1_FIXTURES, config=config)
        content = results[0]["content"]
        assert "[CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337)" in content

    def test_trace_with_links(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        results = format_notifications(TIER1_FIXTURES, config=config)
        content = results[0]["content"]
        # Trace should contain file links
        assert "template.js" in content
        assert "server.js" in content

    def test_collapsible_purl_sections(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        results = format_notifications(TIER1_FIXTURES, config=config)
        content = results[0]["content"]
        assert "<details" in content
        assert "pkg:npm/lodash@4.17.15" in content


# ---------------------------------------------------------------------------
# Cross-cutting: empty input handling
# ---------------------------------------------------------------------------

class TestEmptyInputs:
    def test_opengrep_empty_groups(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications({}, config=config)
        assert results == []

    def test_trivy_empty_mapping(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        results = format_notifications({}, scan_type="image", config=config)
        assert len(results) == 1
        assert "No vulnerabilities found" in results[0]["content"]

    def test_trufflehog_empty_mapping(self, config):
        from socket_basics.core.connector.trufflehog.github_pr import format_notifications
        results = format_notifications({}, config=config)
        assert len(results) == 1
        assert "No secrets detected" in results[0]["content"]

    def test_tier1_empty_list(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        results = format_notifications([], config=config)
        assert len(results) == 1
        assert "No reachability issues found" in results[0]["content"]
