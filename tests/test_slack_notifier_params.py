import os

from socket_basics.core.notification.slack_notifier import SlackNotifier
from socket_basics.core.notification.manager import NotificationManager


def _base_cfg():
    return {
        "notifiers": {
            "slack": {
                "module_path": "socket_basics.core.notification.slack_notifier",
                "class": "SlackNotifier",
                "parameters": [
                    {"name": "slack_webhook_url", "env_variable": "INPUT_SLACK_WEBHOOK_URL", "type": "str"},
                ],
            }
        }
    }


def test_slack_notifier_reads_url_from_params():
    """slack_webhook_url param from dashboard config should populate self.webhook_url"""
    n = SlackNotifier({"slack_webhook_url": "https://hooks.slack.com/services/T00/B00/xxx"})
    assert n.webhook_url == "https://hooks.slack.com/services/T00/B00/xxx"


def test_slack_notifier_url_is_none_without_config(monkeypatch):
    """Without any config or env var, webhook_url should be falsy"""
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("INPUT_SLACK_WEBHOOK_URL", raising=False)
    n = SlackNotifier({})
    assert not n.webhook_url


def test_slack_notifier_falls_back_to_env_var(monkeypatch):
    """INPUT_SLACK_WEBHOOK_URL env var should work as fallback when params empty"""
    monkeypatch.setenv("INPUT_SLACK_WEBHOOK_URL", "https://hooks.slack.com/env")
    n = SlackNotifier({})
    assert n.webhook_url == "https://hooks.slack.com/env"


def test_slack_notifier_params_take_precedence_over_env(monkeypatch):
    """Dashboard config (params) should take precedence over env var"""
    monkeypatch.setenv("INPUT_SLACK_WEBHOOK_URL", "https://hooks.slack.com/env")
    n = SlackNotifier({"slack_webhook_url": "https://hooks.slack.com/dashboard"})
    assert n.webhook_url == "https://hooks.slack.com/dashboard"


def test_slack_enabled_via_app_config(monkeypatch):
    """Slack notifier should load and receive URL when slack_webhook_url is in app_config"""
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("INPUT_SLACK_WEBHOOK_URL", raising=False)

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={"slack_webhook_url": "https://hooks.slack.com/dashboard"})
    nm.load_from_config()

    slack = next(n for n in nm.notifiers if getattr(n, "name", "") == "slack")
    assert slack.webhook_url == "https://hooks.slack.com/dashboard"


def test_slack_enabled_via_env_var(monkeypatch):
    """Slack notifier should load when INPUT_SLACK_WEBHOOK_URL env var is set"""
    monkeypatch.setenv("INPUT_SLACK_WEBHOOK_URL", "https://hooks.slack.com/env")

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={})
    nm.load_from_config()

    slack = next(n for n in nm.notifiers if getattr(n, "name", "") == "slack")
    assert slack.webhook_url == "https://hooks.slack.com/env"


def test_slack_app_config_precedence_over_env(monkeypatch):
    """app_config slack_webhook_url should take precedence over env var in manager flow"""
    monkeypatch.setenv("INPUT_SLACK_WEBHOOK_URL", "https://hooks.slack.com/env")

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={"slack_webhook_url": "https://hooks.slack.com/dashboard"})
    nm.load_from_config()

    slack = next(n for n in nm.notifiers if getattr(n, "name", "") == "slack")
    assert slack.webhook_url == "https://hooks.slack.com/dashboard"
