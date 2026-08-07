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


# ---------------------------------------------------------------------------
# pr_comment_collapse_all: close the collapsible sections, critical included
# ---------------------------------------------------------------------------

@pytest.fixture
def config_collapse_all():
    return make_mock_config(collapse_all=True)


class TestCollapseAll:
    """`pr_comment_collapse_all` is the only way to collapse critical findings.

    `pr_comment_collapse_non_critical` deliberately leaves critical sections
    expanded, so before this flag existed a critical finding always forced the
    comment open.
    """

    def test_opengrep_critical_section_is_expanded_by_default(self, config):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config)
        js_content = next(r["content"] for r in results if "JavaScript" in r["title"])
        assert "<details open>" in js_content

    def test_opengrep_collapses_critical_section_when_enabled(self, config_collapse_all):
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config_collapse_all)
        js_content = next(r["content"] for r in results if "JavaScript" in r["title"])
        assert "<details open>" not in js_content
        # Sections are still present, just closed.
        assert "<details>" in js_content

    def test_tier1_critical_section_is_expanded_by_default(self, config):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        content = format_notifications(TIER1_FIXTURES, config=config)[0]["content"]
        assert "<details open>" in content

    def test_tier1_collapses_critical_section_when_enabled(self, config_collapse_all):
        from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
        content = format_notifications(TIER1_FIXTURES, config=config_collapse_all)[0]["content"]
        assert "<details open>" not in content
        assert "<details>" in content


class TestCollapseAllScope:
    """The flag only reaches sections that are built from collapsible panels.

    Those are the SAST sections and the Socket Tier 1 section. Secret findings
    and Dockerfile findings are plain markdown tables, so the flag has nothing
    to close there, and a closed SAST section still shows one summary row per
    file. The comment never comes down to a single line, and these tests are
    what keep the documented contract that narrow.
    """

    def _trufflehog(self, config):
        from socket_basics.core.connector.trufflehog.github_pr import format_notifications
        return format_notifications(TRUFFLEHOG_FIXTURES, config=config)

    def _trivy_dockerfile(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        return format_notifications(_trivy_dockerfile_fixture(),
                                    item_name="Dockerfile", scan_type="dockerfile", config=config)

    def _trivy_image(self, config):
        from socket_basics.core.connector.trivy.github_pr import format_notifications
        return format_notifications(_trivy_image_fixture(),
                                    item_name="example-app:latest", scan_type="image", config=config)

    def test_trufflehog_output_is_byte_identical(self, config, config_collapse_all):
        default = [r["content"] for r in self._trufflehog(config)]
        collapsed = [r["content"] for r in self._trufflehog(config_collapse_all)]
        assert collapsed == default

    def test_trufflehog_secrets_stay_fully_visible(self, config_collapse_all):
        content = self._trufflehog(config_collapse_all)[0]["content"]
        assert "<details" not in content
        assert "AWS" in content

    def test_trivy_dockerfile_output_is_byte_identical(self, config, config_collapse_all):
        default = [r["content"] for r in self._trivy_dockerfile(config)]
        collapsed = [r["content"] for r in self._trivy_dockerfile(config_collapse_all)]
        assert collapsed == default

    def test_trivy_dockerfile_findings_stay_fully_visible(self, config_collapse_all):
        content = self._trivy_dockerfile(config_collapse_all)[0]["content"]
        assert "<details" not in content

    def test_trivy_image_output_is_byte_identical(self, config, config_collapse_all):
        default = [r["content"] for r in self._trivy_image(config)]
        collapsed = [r["content"] for r in self._trivy_image(config_collapse_all)]
        assert collapsed == default

    def test_sast_keeps_one_visible_summary_row_per_file(self, config_collapse_all):
        """A closed section is still a row on screen, not nothing."""
        from socket_basics.core.connector.opengrep.github_pr import format_notifications
        results = format_notifications(OPENGREP_FIXTURES, config=config_collapse_all)
        js_content = next(r["content"] for r in results if "JavaScript" in r["title"])
        assert js_content.count("<summary>") == 2
        assert "src/server/app.ts" in js_content
        assert "src/utils/config-loader.js" in js_content


class TestFeatureFlagCoercion:
    """Dashboard-sourced config can deliver flags as strings, not booleans."""

    def test_string_true_enables_collapse_all(self):
        from socket_basics.core.notification.github_pr_helpers import get_feature_flags
        flags = get_feature_flags(make_mock_config(collapse_all="true"))
        assert flags["collapse_all"] is True

    def test_string_false_does_not_enable_collapse_all(self):
        from socket_basics.core.notification.github_pr_helpers import get_feature_flags
        flags = get_feature_flags(make_mock_config(collapse_all="false"))
        assert flags["collapse_all"] is False

    def test_string_false_disables_links(self):
        from socket_basics.core.notification.github_pr_helpers import get_feature_flags
        config = make_mock_config()
        config["pr_comment_links_enabled"] = "false"
        assert get_feature_flags(config)["enable_links"] is False

    def test_missing_config_keeps_documented_defaults(self):
        from socket_basics.core.notification.github_pr_helpers import get_feature_flags
        flags = get_feature_flags(None)
        assert flags["collapse_all"] is False
        assert flags["collapse_non_critical"] is True


class TestActionInputCoercion:
    """GitHub Action inputs are always strings, and blank means "unset".

    An input forwarded from an unset workflow variable arrives as an empty
    string. Reading that as "off" would silently suppress the PR comment for a
    workflow that never asked to suppress it, so a value that says nothing has
    to fall back to the documented default.
    """

    def _load(self, monkeypatch, **env):
        from socket_basics.core.config import load_config_from_env
        for name in (
            "INPUT_PR_COMMENT_ENABLED",
            "INPUT_PR_COMMENT_COLLAPSE_ALL",
            "INPUT_PR_LABELS_ENABLED",
        ):
            monkeypatch.delenv(name, raising=False)
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        return load_config_from_env()

    def test_comment_stays_enabled_when_the_input_is_unset(self, monkeypatch):
        assert self._load(monkeypatch).get("pr_comment_enabled") is True

    def test_comment_stays_enabled_for_a_blank_input(self, monkeypatch):
        config = self._load(monkeypatch, INPUT_PR_COMMENT_ENABLED="")
        assert config.get("pr_comment_enabled") is True

    def test_comment_stays_enabled_for_a_whitespace_input(self, monkeypatch):
        config = self._load(monkeypatch, INPUT_PR_COMMENT_ENABLED="   ")
        assert config.get("pr_comment_enabled") is True

    def test_comment_stays_enabled_for_an_unrecognized_input(self, monkeypatch):
        config = self._load(monkeypatch, INPUT_PR_COMMENT_ENABLED="maybe")
        assert config.get("pr_comment_enabled") is True

    @pytest.mark.parametrize("value", ["false", "False", "FALSE", "0", "no", "off"])
    def test_comment_is_disabled_by_every_false_spelling(self, monkeypatch, value):
        config = self._load(monkeypatch, INPUT_PR_COMMENT_ENABLED=value)
        assert config.get("pr_comment_enabled") is False

    @pytest.mark.parametrize("value", ["true", "True", "TRUE", "1", "yes", "on"])
    def test_comment_is_enabled_by_every_true_spelling(self, monkeypatch, value):
        config = self._load(monkeypatch, INPUT_PR_COMMENT_ENABLED=value)
        assert config.get("pr_comment_enabled") is True

    def test_collapse_all_stays_off_for_a_blank_input(self, monkeypatch):
        """A blank input falls back to the default, which here is off."""
        config = self._load(monkeypatch, INPUT_PR_COMMENT_COLLAPSE_ALL="")
        assert config.get("pr_comment_collapse_all") is False

    def test_collapse_all_is_enabled_by_a_string_true(self, monkeypatch):
        config = self._load(monkeypatch, INPUT_PR_COMMENT_COLLAPSE_ALL="true")
        assert config.get("pr_comment_collapse_all") is True

    def test_labels_stay_enabled_for_a_blank_input(self, monkeypatch):
        config = self._load(monkeypatch, INPUT_PR_LABELS_ENABLED="")
        assert config.get("pr_labels_enabled") is True


class TestNotifierCliArgsReachTheConfig:
    """A notifier flag has to survive the whole trip from argv to the config.

    The PR comment flags are declared in notifications.yaml, and the CLI parser
    registers an option for each one. Parsing that option is only half the job:
    the value also has to be copied into the effective config, or the scan reads
    the default and the flag does nothing.
    """

    def _config(self, monkeypatch, tmp_path, *cli_args, **env):
        from socket_basics.core.config import parse_cli_args, create_config_from_args

        # A stale INPUT_* variable would decide the outcome instead of the flag.
        for name in (
            "INPUT_PR_COMMENT_ENABLED",
            "INPUT_PR_COMMENT_COLLAPSE_ALL",
            "INPUT_PR_COMMENT_LINKS_ENABLED",
        ):
            monkeypatch.delenv(name, raising=False)
        for name, value in env.items():
            monkeypatch.setenv(name, value)

        # tmp_path is not a git repo, so --repo and --branch are required and no
        # git command can reach the network.
        argv = ["--workspace", str(tmp_path), "--repo", "acme/widget",
                "--branch", "feature-x", *cli_args]
        return create_config_from_args(parse_cli_args().parse_args(argv))

    def test_collapse_all_flag_lands_in_the_effective_config(self, monkeypatch, tmp_path):
        config = self._config(monkeypatch, tmp_path, "--pr-comment-collapse-all")
        assert config.get("pr_comment_collapse_all") is True

    def test_collapse_all_stays_off_without_the_flag(self, monkeypatch, tmp_path):
        config = self._config(monkeypatch, tmp_path)
        assert config.get("pr_comment_collapse_all") is False

    def test_negative_flag_disables_the_pr_comment(self, monkeypatch, tmp_path):
        """`pr_comment_enabled` defaults to true, so it needs a `--no-` form."""
        config = self._config(monkeypatch, tmp_path, "--no-pr-comment")
        assert config.get("pr_comment_enabled") is False

    def test_positive_flag_keeps_the_pr_comment_enabled(self, monkeypatch, tmp_path):
        config = self._config(monkeypatch, tmp_path, "--pr-comment")
        assert config.get("pr_comment_enabled") is True

    def test_pr_comment_stays_enabled_without_any_flag(self, monkeypatch, tmp_path):
        config = self._config(monkeypatch, tmp_path)
        assert config.get("pr_comment_enabled") is True

    def test_an_unused_flag_does_not_overwrite_the_environment(self, monkeypatch, tmp_path):
        """An option nobody passed must read as "unset", not as false.

        The workflow turned links off through the environment. Copying the
        parser's value for every flag regardless would put that back to on.
        """
        config = self._config(monkeypatch, tmp_path, "--pr-comment-collapse-all",
                              INPUT_PR_COMMENT_LINKS_ENABLED="false")
        assert config.get("pr_comment_links_enabled") is False
        assert config.get("pr_comment_collapse_all") is True
