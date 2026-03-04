import os

from socket_basics.core.notification.ms_teams_notifier import MSTeamsNotifier
from socket_basics.core.notification.manager import NotificationManager


def _base_cfg():
    return {
        "notifiers": {
            "msteams": {
                "module_path": "socket_basics.core.notification.ms_teams_notifier",
                "class": "MSTeamsNotifier",
                "parameters": [
                    {"name": "msteams_webhook_url", "env_variable": "INPUT_MSTEAMS_WEBHOOK_URL", "type": "str"},
                ],
            }
        }
    }


def test_msteams_notifier_reads_url_from_params():
    """msteams_webhook_url param from dashboard config should populate self.webhook_url"""
    n = MSTeamsNotifier({"msteams_webhook_url": "https://outlook.office.com/webhook/xxx"})
    assert n.webhook_url == "https://outlook.office.com/webhook/xxx"


def test_msteams_notifier_url_is_none_without_config(monkeypatch):
    """Without any config or env var, webhook_url should be falsy"""
    monkeypatch.delenv("MSTEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("INPUT_MSTEAMS_WEBHOOK_URL", raising=False)
    n = MSTeamsNotifier({})
    assert not n.webhook_url


def test_msteams_notifier_falls_back_to_env_var(monkeypatch):
    """INPUT_MSTEAMS_WEBHOOK_URL env var should work as fallback when params empty"""
    monkeypatch.setenv("INPUT_MSTEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/env")
    n = MSTeamsNotifier({})
    assert n.webhook_url == "https://outlook.office.com/webhook/env"


def test_msteams_notifier_params_take_precedence_over_env(monkeypatch):
    """Dashboard config (params) should take precedence over env var"""
    monkeypatch.setenv("INPUT_MSTEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/env")
    n = MSTeamsNotifier({"msteams_webhook_url": "https://outlook.office.com/webhook/dashboard"})
    assert n.webhook_url == "https://outlook.office.com/webhook/dashboard"


def test_msteams_enabled_via_app_config(monkeypatch):
    """MS Teams notifier should load and receive URL when msteams_webhook_url is in app_config"""
    monkeypatch.delenv("MSTEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("INPUT_MSTEAMS_WEBHOOK_URL", raising=False)

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={"msteams_webhook_url": "https://outlook.office.com/webhook/dashboard"})
    nm.load_from_config()

    msteams = next(n for n in nm.notifiers if getattr(n, "name", "") == "msteams")
    assert msteams.webhook_url == "https://outlook.office.com/webhook/dashboard"


def test_msteams_enabled_via_env_var(monkeypatch):
    """MS Teams notifier should load when INPUT_MSTEAMS_WEBHOOK_URL env var is set"""
    monkeypatch.setenv("INPUT_MSTEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/env")

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={})
    nm.load_from_config()

    msteams = next(n for n in nm.notifiers if getattr(n, "name", "") == "msteams")
    assert msteams.webhook_url == "https://outlook.office.com/webhook/env"


def test_msteams_app_config_precedence_over_env(monkeypatch):
    """app_config msteams_webhook_url should take precedence over env var in manager flow"""
    monkeypatch.setenv("INPUT_MSTEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/env")

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={"msteams_webhook_url": "https://outlook.office.com/webhook/dashboard"})
    nm.load_from_config()

    msteams = next(n for n in nm.notifiers if getattr(n, "name", "") == "msteams")
    assert msteams.webhook_url == "https://outlook.office.com/webhook/dashboard"
