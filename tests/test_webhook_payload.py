"""Tests for each connector's webhook formatter returning structured findings."""

from socket_basics.core.connector.trivy.webhook import format_notifications as trivy_format
from socket_basics.core.connector.socket_tier1.webhook import format_notifications as tier1_format
from socket_basics.core.connector.opengrep.webhook import format_notifications as opengrep_format
from socket_basics.core.connector.trufflehog.webhook import format_notifications as trufflehog_format


# --- Trivy ---

class TestTrivyWebhookFindings:
    def _make_vuln_mapping(self):
        return {
            'comp1': {
                'name': 'bson',
                'version': '1.0.9',
                'qualifiers': {'ecosystem': 'npm'},
                'alerts': [{
                    'severity': 'critical',
                    'props': {'vulnerabilityId': 'CVE-2020-7610'},
                }],
            }
        }

    def _make_dockerfile_mapping(self):
        return {
            'comp1': {
                'alerts': [{
                    'severity': 'high',
                    'title': 'DS001',
                    'description': 'Use COPY instead of ADD',
                    'props': {'ruleId': 'DS001', 'resolution': 'Replace ADD with COPY'},
                }],
            }
        }

    def test_vuln_findings_key_present(self):
        result = trivy_format(self._make_vuln_mapping(), 'test', 'vuln')
        assert 'findings' in result[0]

    def test_vuln_findings_structure(self):
        result = trivy_format(self._make_vuln_mapping(), 'test', 'vuln')
        f = result[0]['findings'][0]
        assert f['package'] == 'bson'
        assert f['version'] == '1.0.9'
        assert f['ecosystem'] == 'npm'
        assert f['purl'] == 'pkg:npm/bson@1.0.9'
        assert f['cves'] == ['CVE-2020-7610']
        assert f['severity'] == 'critical'
        assert f['scanner'] == 'trivy'

    def test_vuln_no_pkg_unknown(self):
        result = trivy_format(self._make_vuln_mapping(), 'test', 'vuln')
        f = result[0]['findings'][0]
        assert 'pkg:unknown/' not in f['purl']

    def test_dockerfile_findings_structure(self):
        result = trivy_format(self._make_dockerfile_mapping(), 'test', 'dockerfile')
        f = result[0]['findings'][0]
        assert f['rule'] == 'DS001'
        assert f['severity'] == 'high'
        assert f['message'] == 'Use COPY instead of ADD'
        assert f['resolution'] == 'Replace ADD with COPY'
        assert f['scanner'] == 'trivy'

    def test_content_still_present(self):
        result = trivy_format(self._make_vuln_mapping(), 'test', 'vuln')
        assert 'content' in result[0]
        assert 'title' in result[0]

    def test_empty_mapping_returns_empty_findings(self):
        result = trivy_format({}, 'test', 'vuln')
        assert result[0]['findings'] == []


# --- Socket Tier1 ---

class TestTier1WebhookFindings:
    def _make_components(self):
        return [{
            'name': 'lodash',
            'type': 'npm',
            'version': '4.17.20',
            'alerts': [{
                'severity': 'high',
                'props': {
                    'ghsaId': 'GHSA-xxxx-yyyy',
                    'cveId': 'CVE-2021-23337',
                    'reachability': 'reachable',
                    'purl': 'pkg:npm/lodash@4.17.20',
                },
            }],
        }]

    def test_findings_key_present(self):
        result = tier1_format(self._make_components())
        assert 'findings' in result[0]

    def test_findings_structure(self):
        result = tier1_format(self._make_components())
        f = result[0]['findings'][0]
        assert f['package'] == 'lodash'
        assert f['version'] == '4.17.20'
        assert f['purl'] == 'pkg:npm/lodash@4.17.20'
        assert f['cves'] == ['GHSA-xxxx-yyyy']
        assert f['severity'] == 'high'
        assert f['reachability'] == 'reachable'
        assert f['scanner'] == 'socket-tier1'

    def test_empty_returns_empty_findings(self):
        result = tier1_format([])
        assert result[0]['findings'] == []


# --- OpenGrep ---

class TestOpenGrepWebhookFindings:
    def _make_groups(self):
        return {
            'sast-python': [{
                'component': {'name': 'app.py'},
                'alert': {
                    'severity': 'medium',
                    'title': 'python.flask.security.injection',
                    'props': {
                        'ruleId': 'python.flask.security.injection',
                        'filePath': '/src/app.py',
                        'startLine': '10',
                        'endLine': '12',
                    },
                },
            }]
        }

    def test_findings_key_present(self):
        result = opengrep_format(self._make_groups())
        assert 'findings' in result[0]

    def test_findings_structure(self):
        result = opengrep_format(self._make_groups())
        f = result[0]['findings'][0]
        assert f['rule'] == 'python.flask.security.injection'
        assert f['severity'] == 'medium'
        assert f['file'] == 'app.py'
        assert f['path'] == '/src/app.py'
        assert f['lines'] == '10-12'
        assert f['language'] == 'sast-python'
        assert f['scanner'] == 'opengrep'

    def test_empty_groups_returns_empty(self):
        result = opengrep_format({})
        assert result == []

    def test_empty_items_skipped(self):
        result = opengrep_format({'sast-python': []})
        assert result == []


# --- TruffleHog ---

class TestTruffleHogWebhookFindings:
    def _make_mapping(self):
        return {
            'comp1': {
                'alerts': [{
                    'severity': 'high',
                    'title': 'AWS',
                    'props': {
                        'detectorName': 'AWS',
                        'filePath': '.env',
                        'lineNumber': '5',
                        'redactedValue': 'AKIA****XXXX',
                        'verified': True,
                        'secretType': 'aws_access_key',
                    },
                }],
            }
        }

    def test_findings_key_present(self):
        result = trufflehog_format(self._make_mapping())
        assert 'findings' in result[0]

    def test_findings_structure(self):
        result = trufflehog_format(self._make_mapping())
        f = result[0]['findings'][0]
        assert f['detector'] == 'AWS'
        assert f['severity'] == 'high'
        assert f['file'] == '.env'
        assert f['line'] == '5'
        assert f['verified'] is True
        assert f['scanner'] == 'trufflehog'

    def test_findings_omit_redacted_value(self):
        result = trufflehog_format(self._make_mapping())
        f = result[0]['findings'][0]
        assert 'redacted_value' not in f
        assert 'redactedValue' not in f

    def test_markdown_still_has_redacted(self):
        """The markdown content (for human reading) should still include redacted values."""
        result = trufflehog_format(self._make_mapping())
        assert 'AKIA****XXXX' in result[0]['content']

    def test_empty_mapping_returns_empty_findings(self):
        result = trufflehog_format({})
        assert result[0]['findings'] == []
