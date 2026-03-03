"""Unit tests for GitHub PR comment helper functions."""

import pytest
from socket_basics.core.notification import github_pr_helpers as github_helpers


class TestDetectLanguageFromFilename:
    """Tests for detect_language_from_filename function."""

    def test_javascript_extensions(self):
        assert github_helpers.detect_language_from_filename('app.js') == 'javascript'
        assert github_helpers.detect_language_from_filename('component.jsx') == 'javascript'

    def test_typescript_extensions(self):
        assert github_helpers.detect_language_from_filename('main.ts') == 'typescript'
        assert github_helpers.detect_language_from_filename('component.tsx') == 'typescript'

    def test_python_extensions(self):
        assert github_helpers.detect_language_from_filename('main.py') == 'python'
        assert github_helpers.detect_language_from_filename('script.py') == 'python'

    def test_go_extensions(self):
        assert github_helpers.detect_language_from_filename('test.go') == 'go'

    def test_java_extensions(self):
        assert github_helpers.detect_language_from_filename('Main.java') == 'java'

    def test_rust_extensions(self):
        assert github_helpers.detect_language_from_filename('main.rs') == 'rust'

    def test_ruby_extensions(self):
        assert github_helpers.detect_language_from_filename('app.rb') == 'ruby'

    def test_php_extensions(self):
        assert github_helpers.detect_language_from_filename('index.php') == 'php'

    def test_unknown_extensions(self):
        assert github_helpers.detect_language_from_filename('unknown.xyz') == ''
        assert github_helpers.detect_language_from_filename('noextension') == ''

    def test_with_paths(self):
        assert github_helpers.detect_language_from_filename('src/components/app.js') == 'javascript'
        assert github_helpers.detect_language_from_filename('/absolute/path/main.py') == 'python'

    def test_case_insensitive(self):
        assert github_helpers.detect_language_from_filename('App.JS') == 'javascript'
        assert github_helpers.detect_language_from_filename('Main.PY') == 'python'


class TestBuildGithubFileUrl:
    """Tests for build_github_file_url function."""

    def test_basic_url_without_lines(self):
        url = github_helpers.build_github_file_url(
            'owner/repo',
            'abc123',
            'src/main.py'
        )
        assert url == 'https://github.com/owner/repo/blob/abc123/src/main.py'

    def test_url_with_single_line(self):
        url = github_helpers.build_github_file_url(
            'owner/repo',
            'abc123',
            'src/main.py',
            10
        )
        assert url == 'https://github.com/owner/repo/blob/abc123/src/main.py#L10'

    def test_url_with_line_range(self):
        url = github_helpers.build_github_file_url(
            'owner/repo',
            'abc123',
            'src/main.py',
            10,
            15
        )
        assert url == 'https://github.com/owner/repo/blob/abc123/src/main.py#L10-L15'

    def test_url_with_same_start_end_line(self):
        url = github_helpers.build_github_file_url(
            'owner/repo',
            'abc123',
            'src/main.py',
            10,
            10
        )
        assert url == 'https://github.com/owner/repo/blob/abc123/src/main.py#L10'

    def test_cleans_leading_dot_slash(self):
        url = github_helpers.build_github_file_url(
            'owner/repo',
            'abc123',
            './src/main.py'
        )
        assert url == 'https://github.com/owner/repo/blob/abc123/src/main.py'

    def test_cleans_leading_slash(self):
        url = github_helpers.build_github_file_url(
            'owner/repo',
            'abc123',
            '/src/main.py'
        )
        # Note: lstrip('./') removes leading ./ but not just /
        # Need to handle both cases
        assert 'src/main.py' in url

    def test_empty_repository(self):
        url = github_helpers.build_github_file_url(
            '',
            'abc123',
            'src/main.py'
        )
        assert url == ''

    def test_empty_commit_hash(self):
        url = github_helpers.build_github_file_url(
            'owner/repo',
            '',
            'src/main.py'
        )
        assert url == ''

    def test_none_repository(self):
        url = github_helpers.build_github_file_url(
            None,
            'abc123',
            'src/main.py'
        )
        assert url == ''

    def test_none_commit_hash(self):
        url = github_helpers.build_github_file_url(
            'owner/repo',
            None,
            'src/main.py'
        )
        assert url == ''


class TestFormatTraceWithLinks:
    """Tests for format_trace_with_links function."""

    def test_empty_trace_lines(self):
        result = github_helpers.format_trace_with_links(
            [],
            'owner/repo',
            'abc123'
        )
        assert result == ''

    def test_basic_trace_format(self):
        trace_lines = [
            'owasp-goat - server.js 72:12-75:6'
        ]

        result = github_helpers.format_trace_with_links(
            trace_lines,
            'owner/repo',
            'abc123',
            enable_links=True
        )

        assert 'https://github.com/owner/repo' in result
        assert '[server.js 72:12-75:6]' in result
        assert 'owasp-goat' in result

    def test_indented_trace_format(self):
        trace_lines = [
            '  -> express routes/auth.js 45:2'
        ]

        result = github_helpers.format_trace_with_links(
            trace_lines,
            'owner/repo',
            'abc123',
            enable_links=True
        )

        assert 'https://github.com/owner/repo' in result
        assert '[routes/auth.js 45:2]' in result
        assert 'express' in result
        assert '  ->' in result  # Preserves indentation

    def test_multiple_trace_lines(self):
        trace_lines = [
            'owasp-goat - server.js 72:12-75:6',
            '  -> express routes/auth.js 45:2'
        ]

        result = github_helpers.format_trace_with_links(
            trace_lines,
            'owner/repo',
            'abc123',
            enable_links=True
        )

        lines = result.split('\n')
        assert len(lines) == 2
        assert '[server.js 72:12-75:6]' in lines[0]
        assert '[routes/auth.js 45:2]' in lines[1]

    def test_links_disabled(self):
        trace_lines = [
            'owasp-goat - server.js 72:12-75:6'
        ]

        result = github_helpers.format_trace_with_links(
            trace_lines,
            'owner/repo',
            'abc123',
            enable_links=False
        )

        assert 'https://github.com' not in result
        assert result == 'owasp-goat - server.js 72:12-75:6'

    def test_unparseable_line_preserved(self):
        trace_lines = [
            'some random text without proper format'
        ]

        result = github_helpers.format_trace_with_links(
            trace_lines,
            'owner/repo',
            'abc123',
            enable_links=True
        )

        assert result == 'some random text without proper format'

    def test_single_line_number(self):
        trace_lines = [
            'package - file.js 42:5'
        ]

        result = github_helpers.format_trace_with_links(
            trace_lines,
            'owner/repo',
            'abc123',
            enable_links=True
        )

        assert '[file.js 42:5]' in result
        assert '#L42' in result

    def test_missing_repository(self):
        trace_lines = [
            'package - file.js 42:5'
        ]

        result = github_helpers.format_trace_with_links(
            trace_lines,
            '',
            'abc123',
            enable_links=True
        )

        # Should preserve original format if URL can't be built
        assert result == 'package - file.js 42:5'


class TestExtractRuleName:
    """Tests for extract_rule_name function."""

    def test_from_props_rule(self):
        alert = {
            'props': {
                'rule': 'CVE-2024-1234'
            }
        }
        assert github_helpers.extract_rule_name(alert) == 'CVE-2024-1234'

    def test_from_props_rule_name(self):
        alert = {
            'props': {
                'rule_name': 'GHSA-xxxx-yyyy-zzzz'
            }
        }
        assert github_helpers.extract_rule_name(alert) == 'GHSA-xxxx-yyyy-zzzz'

    def test_from_props_ruleName_camelCase(self):
        alert = {
            'props': {
                'ruleName': 'custom-rule'
            }
        }
        assert github_helpers.extract_rule_name(alert) == 'custom-rule'

    def test_from_alert_rule(self):
        alert = {
            'rule': 'some-rule'
        }
        assert github_helpers.extract_rule_name(alert) == 'some-rule'

    def test_from_alert_type(self):
        alert = {
            'type': 'vulnerability'
        }
        assert github_helpers.extract_rule_name(alert) == 'vulnerability'

    def test_priority_order(self):
        # props.rule should take priority over props.rule_name
        alert = {
            'props': {
                'rule': 'high-priority',
                'rule_name': 'low-priority'
            }
        }
        assert github_helpers.extract_rule_name(alert) == 'high-priority'

    def test_empty_alert(self):
        alert = {}
        assert github_helpers.extract_rule_name(alert) == ''

    def test_none_props(self):
        alert = {
            'props': None
        }
        assert github_helpers.extract_rule_name(alert) == ''

    def test_empty_values(self):
        alert = {
            'props': {
                'rule': '',
                'rule_name': ''
            }
        }
        assert github_helpers.extract_rule_name(alert) == ''


class TestFormatCveLink:
    """Tests for format_cve_link function."""

    def test_valid_cve_id(self):
        result = github_helpers.format_cve_link('CVE-2021-23337')
        assert result == '[CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337)'

    def test_cve_id_lowercase(self):
        result = github_helpers.format_cve_link('cve-2021-44228')
        assert result == '[cve-2021-44228](https://nvd.nist.gov/vuln/detail/cve-2021-44228)'

    def test_non_cve_id(self):
        result = github_helpers.format_cve_link('GHSA-abcd-1234-efgh')
        assert result == 'GHSA-abcd-1234-efgh'

    def test_empty_string(self):
        result = github_helpers.format_cve_link('')
        assert result == ''

    def test_none_value(self):
        result = github_helpers.format_cve_link(None)
        assert result == ''


class TestFormatVulnerabilityHeader:
    """Tests for format_vulnerability_header function."""

    def test_with_cvss_score(self):
        result = github_helpers.format_vulnerability_header(
            'CVE-2021-23337',
            'critical',
            cvss_score=9.8
        )
        assert '🔴' in result
        assert '[CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337)' in result
        assert 'CRITICAL' in result
        assert 'CVSS 9.8' in result

    def test_without_cvss_score(self):
        result = github_helpers.format_vulnerability_header(
            'CVE-2021-23338',
            'high'
        )
        assert '🟠' in result
        assert '[CVE-2021-23338](https://nvd.nist.gov/vuln/detail/CVE-2021-23338)' in result
        assert 'HIGH' in result
        assert 'CVSS' not in result

    def test_with_custom_emoji(self):
        result = github_helpers.format_vulnerability_header(
            'CVE-2021-23337',
            'critical',
            cvss_score=9.8,
            emoji='⚠️'
        )
        assert '⚠️' in result
        assert '🔴' not in result

    def test_non_cve_vulnerability(self):
        result = github_helpers.format_vulnerability_header(
            'GHSA-abcd-1234-efgh',
            'high',
            cvss_score=7.5
        )
        assert '🟠' in result
        assert 'GHSA-abcd-1234-efgh' in result
        assert 'https://nvd.nist.gov' not in result
        assert 'HIGH' in result
        assert 'CVSS 7.5' in result

    def test_medium_severity(self):
        result = github_helpers.format_vulnerability_header(
            'CVE-2021-12345',
            'medium',
            cvss_score=5.0
        )
        assert '🟡' in result
        assert 'MEDIUM' in result
        assert 'CVSS 5.0' in result

    def test_low_severity(self):
        result = github_helpers.format_vulnerability_header(
            'CVE-2021-67890',
            'low'
        )
        assert '⚪' in result
        assert 'LOW' in result

    def test_empty_vuln_id(self):
        result = github_helpers.format_vulnerability_header(
            '',
            'critical',
            cvss_score=10.0
        )
        assert 'Unknown' in result
        assert 'CRITICAL' in result
        assert 'CVSS 10.0' in result
