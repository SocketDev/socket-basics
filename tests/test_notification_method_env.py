"""OpenGrep and TruffleHog notify inputs must not share a config key.

GitHub Actions always exports every ``runs.env`` entry, so an unset
``trufflehog_notification_method`` arrives as ``INPUT_TRUFFLEHOG_NOTIFICATION_METHOD=""``.
That empty string must not wipe a real OpenGrep notify setting.
"""

from socket_basics.core.config import load_config_from_env
from socket_basics.core.notification.manager import NotificationManager

NOTIFY_ENV_VARS = (
    "INPUT_OPENGREP_NOTIFICATION_METHOD",
    "INPUT_TRUFFLEHOG_NOTIFICATION_METHOD",
    "INPUT_TRIVY_NOTIFICATION_METHOD",
)


def test_empty_trufflehog_action_input_does_not_wipe_opengrep_notify(monkeypatch):
    for name in NOTIFY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("INPUT_OPENGREP_NOTIFICATION_METHOD", "slack")
    # Unset Action inputs are forwarded as empty strings, not omitted.
    monkeypatch.setenv("INPUT_TRUFFLEHOG_NOTIFICATION_METHOD", "")

    config = load_config_from_env()

    assert config.get("opengrep_notification_method") == "slack"
    assert not config.get("trufflehog_notification_method")

    nm = NotificationManager(
        {
            "notifiers": {
                "slack": {
                    "module_path": "socket_basics.core.notification.slack_notifier",
                    "class": "SlackNotifier",
                    "parameters": [],
                }
            }
        },
        app_config=config,
    )
    nm.load_from_config()
    assert any(getattr(n, "name", "") == "slack" for n in nm.notifiers)
