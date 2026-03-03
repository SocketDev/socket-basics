import os
from unittest.mock import patch, MagicMock

from socket_basics.core.notification.webhook_notifier import WebhookNotifier, _compute_summary
from socket_basics.core.notification.manager import NotificationManager


def _base_cfg():
    return {
        "notifiers": {
            "webhook": {
                "module_path": "socket_basics.core.notification.webhook_notifier",
                "class": "WebhookNotifier",
                "parameters": [
                    {"name": "webhook_url", "env_variable": "INPUT_WEBHOOK_URL", "type": "str"},
                ],
            }
        }
    }


def test_webhook_notifier_reads_url_from_params():
    """webhook_url param from dashboard config should populate self.url"""
    n = WebhookNotifier({"webhook_url": "https://hooks.example.com/endpoint"})
    assert n.url == "https://hooks.example.com/endpoint"


def test_webhook_notifier_url_is_none_without_config(monkeypatch):
    """Without any config or env var, url should be falsy"""
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.delenv("INPUT_WEBHOOK_URL", raising=False)
    n = WebhookNotifier({})
    assert not n.url


def test_webhook_notifier_falls_back_to_env_var(monkeypatch):
    """INPUT_WEBHOOK_URL env var should work as fallback when params empty"""
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.setenv("INPUT_WEBHOOK_URL", "https://env.example.com/hook")
    n = WebhookNotifier({})
    assert n.url == "https://env.example.com/hook"


def test_webhook_notifier_params_take_precedence_over_env(monkeypatch):
    """Dashboard config (params) should take precedence over env var"""
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.setenv("INPUT_WEBHOOK_URL", "https://env.example.com/hook")
    n = WebhookNotifier({"webhook_url": "https://dashboard.example.com/hook"})
    assert n.url == "https://dashboard.example.com/hook"


def test_webhook_enabled_via_app_config(monkeypatch):
    """Webhook notifier should load when webhook_url is in app_config (dashboard)"""
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.delenv("INPUT_WEBHOOK_URL", raising=False)

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={"webhook_url": "https://app.example.com/hook"})
    nm.load_from_config()

    webhook = next(n for n in nm.notifiers if getattr(n, "name", "") == "webhook")
    assert webhook.url == "https://app.example.com/hook"


def test_webhook_enabled_via_env_var(monkeypatch):
    """Webhook notifier should load when INPUT_WEBHOOK_URL env var is set"""
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.setenv("INPUT_WEBHOOK_URL", "https://env.example.com/hook")

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={})
    nm.load_from_config()

    webhook = next(n for n in nm.notifiers if getattr(n, "name", "") == "webhook")
    assert webhook.url == "https://env.example.com/hook"


def test_webhook_app_config_precedence_over_env(monkeypatch):
    """app_config webhook_url should take precedence over env var in manager flow"""
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.setenv("INPUT_WEBHOOK_URL", "https://env.example.com/hook")

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={"webhook_url": "https://dashboard.example.com/hook"})
    nm.load_from_config()

    webhook = next(n for n in nm.notifiers if getattr(n, "name", "") == "webhook")
    assert webhook.url == "https://dashboard.example.com/hook"


# --- Structured payload tests ---

def _make_notifier():
    return WebhookNotifier({"webhook_url": "https://example.com/hook"})


def _make_facts(notifications):
    return {'notifications': notifications}


def test_compute_summary_empty():
    assert _compute_summary([]) == {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}


def test_compute_summary_counts():
    findings = [
        {'severity': 'critical'},
        {'severity': 'critical'},
        {'severity': 'high'},
        {'severity': 'medium'},
        {'severity': 'low'},
        {'severity': 'low'},
    ]
    result = _compute_summary(findings)
    assert result == {'total': 6, 'critical': 2, 'high': 1, 'medium': 1, 'low': 2}


def test_compute_summary_unknown_severity_in_total():
    findings = [{'severity': 'info'}, {'severity': 'critical'}]
    result = _compute_summary(findings)
    assert result['total'] == 2
    assert result['critical'] == 1


@patch('socket_basics.core.notification.webhook_notifier.requests')
def test_payload_has_timestamp(mock_requests):
    mock_requests.post.return_value = MagicMock(status_code=200)
    n = _make_notifier()
    findings = [{'severity': 'high', 'package': 'foo', 'scanner': 'trivy'}]
    n.notify(_make_facts([{'title': 'Test', 'content': 'table', 'findings': findings}]))

    payload = mock_requests.post.call_args[1]['json']
    assert payload['timestamp'] is not None
    assert 'T' in payload['timestamp']
    assert payload['timestamp'].endswith('Z')


@patch('socket_basics.core.notification.webhook_notifier.requests')
def test_payload_has_summary(mock_requests):
    mock_requests.post.return_value = MagicMock(status_code=200)
    n = _make_notifier()
    findings = [
        {'severity': 'critical', 'package': 'a'},
        {'severity': 'high', 'package': 'b'},
        {'severity': 'high', 'package': 'c'},
    ]
    n.notify(_make_facts([{'title': 'Test', 'content': 'md', 'findings': findings}]))

    payload = mock_requests.post.call_args[1]['json']
    assert payload['summary']['total'] == 3
    assert payload['summary']['critical'] == 1
    assert payload['summary']['high'] == 2


@patch('socket_basics.core.notification.webhook_notifier.requests')
def test_payload_has_findings_array(mock_requests):
    mock_requests.post.return_value = MagicMock(status_code=200)
    n = _make_notifier()
    findings = [{'severity': 'low', 'package': 'x', 'scanner': 'trivy'}]
    n.notify(_make_facts([{'title': 'T', 'content': 'c', 'findings': findings}]))

    payload = mock_requests.post.call_args[1]['json']
    assert isinstance(payload['findings'], list)
    assert len(payload['findings']) == 1
    assert payload['findings'][0]['package'] == 'x'


@patch('socket_basics.core.notification.webhook_notifier.requests')
def test_backward_compat_notification_field(mock_requests):
    mock_requests.post.return_value = MagicMock(status_code=200)
    n = _make_notifier()
    n.notify(_make_facts([{'title': 'Title', 'content': 'markdown table'}]))

    payload = mock_requests.post.call_args[1]['json']
    assert payload['notification']['title'] == 'Title'
    assert payload['notification']['content'] == 'markdown table'


@patch('socket_basics.core.notification.webhook_notifier.requests')
def test_missing_findings_defaults_empty(mock_requests):
    """Connectors that haven't been updated yet still work (no findings key)."""
    mock_requests.post.return_value = MagicMock(status_code=200)
    n = _make_notifier()
    n.notify(_make_facts([{'title': 'T', 'content': 'c'}]))

    payload = mock_requests.post.call_args[1]['json']
    assert payload['findings'] == []
    assert payload['summary']['total'] == 0


@patch('socket_basics.core.notification.webhook_notifier.requests')
def test_scan_type_set_from_title(mock_requests):
    mock_requests.post.return_value = MagicMock(status_code=200)
    n = _make_notifier()
    n.notify(_make_facts([{'title': 'Socket CVE Scanning Results: Dockerfile', 'content': 'c'}]))

    payload = mock_requests.post.call_args[1]['json']
    assert payload['scan_type'] == 'Socket CVE Scanning Results: Dockerfile'
