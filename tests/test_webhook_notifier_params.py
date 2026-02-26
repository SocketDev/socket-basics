import os

from socket_basics.core.notification.webhook_notifier import WebhookNotifier
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
