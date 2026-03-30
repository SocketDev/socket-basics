from socket_basics.core.config import (
    Config,
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


def test_normalize_alert_ignores_matching_rule_and_path_override():
    connector = _DummyConnector(
        Config({'workspace': '.', 'sast_ignore_overrides': 'js-sql-injection:index.js'})
    )

    alert = _normalize_alert(_build_alert(), connector=connector)

    assert alert['action'] == 'ignore'


def test_normalize_alert_accepts_windows_style_override_paths():
    connector = _DummyConnector(
        Config({'workspace': '.', 'sast_ignore_overrides': r'js-sql-injection:src\unsafe\demo.js'})
    )

    alert = _normalize_alert(_build_alert('src/unsafe/demo.js'), connector=connector)

    assert alert['action'] == 'ignore'


def test_normalize_alert_does_not_ignore_non_matching_path_override():
    connector = _DummyConnector(
        Config({'workspace': '.', 'sast_ignore_overrides': 'js-sql-injection:src/index.js'})
    )

    alert = _normalize_alert(_build_alert(), connector=connector)

    assert alert['action'] == 'error'


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
