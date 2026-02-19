import os

from socket_basics.core.notification.manager import NotificationManager


def _base_cfg():
    return {
        "notifiers": {
            "jira": {
                "module_path": "socket_basics.core.notification.jira_notifier",
                "class": "JiraNotifier",
                "parameters": [
                    {"name": "jira_url", "env_variable": "INPUT_JIRA_URL", "type": "str"},
                    {"name": "jira_project", "env_variable": "INPUT_JIRA_PROJECT", "type": "str"},
                    {"name": "jira_email", "env_variable": "INPUT_JIRA_EMAIL", "type": "str"},
                    {"name": "jira_api_token", "env_variable": "INPUT_JIRA_API_TOKEN", "type": "str"},
                ],
            }
        }
    }


def test_param_precedence_app_config_over_env_and_default(monkeypatch):
    cfg = _base_cfg()
    # default should be overridden by env, then app_config should win
    cfg["notifiers"]["jira"]["parameters"][0]["default"] = "https://default.example"
    monkeypatch.setenv("INPUT_JIRA_URL", "https://env.example")

    nm = NotificationManager(cfg, app_config={"jira_url": "https://app.example"})
    nm.load_from_config()

    jira = next(n for n in nm.notifiers if getattr(n, "name", "") == "jira")
    assert jira.server == "https://app.example"


def test_param_precedence_env_over_default(monkeypatch):
    cfg = _base_cfg()
    cfg["notifiers"]["jira"]["parameters"][0]["default"] = "https://default.example"
    monkeypatch.setenv("INPUT_JIRA_URL", "https://env.example")

    nm = NotificationManager(cfg, app_config={})
    nm.load_from_config()

    jira = next(n for n in nm.notifiers if getattr(n, "name", "") == "jira")
    assert jira.server == "https://env.example"


def test_param_precedence_default_used_when_no_env_or_app_config(monkeypatch):
    cfg = _base_cfg()
    # Use default for jira_project while enabling via app_config jira_url
    cfg["notifiers"]["jira"]["parameters"][1]["default"] = "DEFAULTPROJ"
    monkeypatch.delenv("INPUT_JIRA_PROJECT", raising=False)

    nm = NotificationManager(cfg, app_config={"jira_url": "https://app.example"})
    nm.load_from_config()

    jira = next(n for n in nm.notifiers if getattr(n, "name", "") == "jira")
    assert jira.project == "DEFAULTPROJ"


def test_jira_enabled_via_app_config(monkeypatch):
    cfg = _base_cfg()
    monkeypatch.delenv("INPUT_JIRA_URL", raising=False)

    nm = NotificationManager(cfg, app_config={"jira_url": "https://app.example"})
    nm.load_from_config()

    jira = next(n for n in nm.notifiers if getattr(n, "name", "") == "jira")
    assert jira.server == "https://app.example"
