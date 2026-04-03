from socket_basics.core.config import (
    Config,
    normalize_repo_relative_path,
    parse_sast_ignore_overrides,
)
from socket_basics.core.connector.normalizer import _normalize_alert
from socket_basics.core.connector.opengrep import OpenGrepScanner
from socket_basics.socket_basics import count_blocking_alerts


class _DummyConnector:
    def __init__(self, config: Config):
        self.config = config


def _build_alert(path: str = 'index.js') -> dict:
    return {
        'title': 'js-sql-injection',
        'severity': 'critical',
        'props': {
            'ruleId': 'js-sql-injection',
            'filePath': path,
            'startLine': 14,
            'endLine': 14,
        },
        'location': {
            'path': path,
            'start': 14,
            'end': 14,
        },
    }


def test_parse_sast_ignore_overrides_supports_rule_and_exact_path():
    parsed = parse_sast_ignore_overrides(
        'js-sql-injection, js-sql-injection:./src/db/query.js'
    )

    assert parsed == [
        {'rule_id': 'js-sql-injection', 'path': None},
        {'rule_id': 'js-sql-injection', 'path': 'src/db/query.js'},
    ]


def test_parse_sast_ignore_overrides_skips_glob_paths(caplog):
    parsed = parse_sast_ignore_overrides('js-sql-injection:src/**/*.js')

    assert parsed == []
    assert 'glob syntax' in caplog.text


def test_normalize_alert_ignores_rule_only_override():
    connector = _DummyConnector(Config({'workspace': '.', 'sast_ignore_overrides': 'js-sql-injection'}))

    alert = _normalize_alert(_build_alert(), connector=connector)

    assert alert['action'] == 'ignore'
    assert alert['actionReason'] == 'sast_ignore_override'


def test_normalize_alert_ignores_matching_rule_and_path_override():
    connector = _DummyConnector(
        Config({'workspace': '.', 'sast_ignore_overrides': 'js-sql-injection:index.js'})
    )

    alert = _normalize_alert(_build_alert(), connector=connector)

    assert alert['action'] == 'ignore'
    assert alert['actionReason'] == 'sast_ignore_override'


def test_normalize_alert_accepts_windows_style_override_paths():
    connector = _DummyConnector(
        Config({'workspace': '.', 'sast_ignore_overrides': r'js-sql-injection:src\unsafe\demo.js'})
    )

    alert = _normalize_alert(_build_alert('src/unsafe/demo.js'), connector=connector)

    assert alert['action'] == 'ignore'
    assert alert['actionReason'] == 'sast_ignore_override'


def test_get_sast_ignore_overrides_warns_when_path_does_not_exist(tmp_path, caplog):
    config = Config(
        {
            'workspace': str(tmp_path),
            'sast_ignore_overrides': 'js-sql-injection:src/services/credential_sync/api.ts',
        }
    )

    parsed = config.get_sast_ignore_overrides()

    assert parsed == [{'rule_id': 'js-sql-injection', 'path': 'src/services/credential_sync/api.ts'}]
    assert 'does not exist under workspace' in caplog.text
    assert 'will not fall back to rule-only matching' in caplog.text


def test_normalize_repo_relative_path_strips_github_actions_workspace_prefix(monkeypatch):
    monkeypatch.setenv('GITHUB_WORKSPACE', '/github/workspace')

    assert normalize_repo_relative_path('github/workspace/index.js') == 'index.js'


def test_normalize_repo_relative_path_strips_gitlab_workspace_prefix(monkeypatch):
    monkeypatch.setenv('CI_PROJECT_DIR', '/builds/acme/sample-repo')

    assert normalize_repo_relative_path('/builds/acme/sample-repo/src/index.js') == 'src/index.js'


def test_normalize_repo_relative_path_strips_bitbucket_workspace_prefix(monkeypatch):
    monkeypatch.setenv('BITBUCKET_CLONE_DIR', '/opt/atlassian/pipelines/agent/build')

    assert normalize_repo_relative_path('/opt/atlassian/pipelines/agent/build/index.js') == 'index.js'


def test_normalize_repo_relative_path_strips_buildkite_workspace_prefix(monkeypatch):
    monkeypatch.setenv('BUILDKITE_BUILD_CHECKOUT_PATH', '/var/lib/buildkite-agent/builds/agent-1/org/repo')

    assert normalize_repo_relative_path(
        '/var/lib/buildkite-agent/builds/agent-1/org/repo/app/index.js'
    ) == 'app/index.js'


def test_normalize_alert_strips_github_actions_workspace_prefix(monkeypatch):
    monkeypatch.setenv('GITHUB_WORKSPACE', '/github/workspace')

    connector = _DummyConnector(
        Config({'workspace': '.', 'sast_ignore_overrides': 'js-sql-injection:index.js'})
    )

    alert = _normalize_alert(
        _build_alert('github/workspace/index.js'),
        connector=connector,
    )

    assert alert['action'] == 'ignore'


def test_normalize_alert_does_not_ignore_non_matching_path_override():
    connector = _DummyConnector(
        Config({'workspace': '.', 'sast_ignore_overrides': 'js-sql-injection:src/index.js'})
    )

    alert = _normalize_alert(_build_alert(), connector=connector)

    assert alert['action'] == 'error'
    assert 'actionReason' not in alert


def test_normalize_alert_marks_disabled_rule_ignores():
    connector = _DummyConnector(
        Config({'workspace': '.', 'javascript_disabled_rules': 'js-sql-injection'})
    )

    alert = _normalize_alert(_build_alert('src/services/credential_sync/api.ts'), connector=connector)

    assert alert['action'] == 'ignore'
    assert alert['actionReason'] == 'disabled_rule'


def test_count_blocking_alerts_skips_ignored_findings():
    results = {
        'components': [
            {'id': 'ignored.js', 'alerts': [{**_build_alert('ignored.js'), 'action': 'ignore'}]},
            {'id': 'active.js', 'alerts': [{**_build_alert('active.js'), 'action': 'error'}]},
        ]
    }

    assert count_blocking_alerts(results) == 1


def test_opengrep_notifications_skip_ignored_findings():
    scanner = OpenGrepScanner(Config({'workspace': '.'}))
    component = {
        'id': 'index.js',
        'qualifiers': {'scanner': 'opengrep', 'type': 'javascript'},
        'alerts': [{**_build_alert(), 'action': 'ignore', 'subType': 'sast-javascript'}],
    }

    notifications = scanner.generate_notifications([component])

    assert notifications == {}
