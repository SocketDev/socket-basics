import pytest

from socket_basics.core.notification.manager import NotificationManager
from socket_basics.core.notification.sumologic_notifier import SumoLogicNotifier

SUMO_ENV_VARS = (
    "SUMOLOGIC_ENDPOINT",
    "INPUT_SUMOLOGIC_ENDPOINT",
    "SUMO_LOGIC_HTTP_SOURCE_URL",
    "INPUT_SUMO_LOGIC_HTTP_SOURCE_URL",
)


@pytest.fixture
def clean_env(monkeypatch):
    for name in SUMO_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _base_cfg():
    return {
        "notifiers": {
            "sumologic": {
                "module_path": "socket_basics.core.notification.sumologic_notifier",
                "class": "SumoLogicNotifier",
                "parameters": [
                    {"name": "sumologic_endpoint", "env_variable": "INPUT_SUMOLOGIC_ENDPOINT", "type": "str"},
                ],
            }
        }
    }


def test_sumologic_reads_notifications_yaml_param_name(clean_env):
    """--sumologic-endpoint and the sumologic_endpoint action input deliver this name."""
    n = SumoLogicNotifier({"sumologic_endpoint": "https://endpoint.sumologic.com/receiver/v1/http/abc"})
    assert n.http_source_url == "https://endpoint.sumologic.com/receiver/v1/http/abc"


def test_sumologic_falls_back_to_either_env_name(clean_env):
    clean_env.setenv("SUMOLOGIC_ENDPOINT", "https://endpoint.sumologic.com/env")
    assert SumoLogicNotifier({}).http_source_url == "https://endpoint.sumologic.com/env"

    clean_env.delenv("SUMOLOGIC_ENDPOINT")
    clean_env.setenv("SUMO_LOGIC_HTTP_SOURCE_URL", "https://endpoint.sumologic.com/legacy")
    assert SumoLogicNotifier({}).http_source_url == "https://endpoint.sumologic.com/legacy"


def test_sumologic_enabled_via_action_env_var(clean_env):
    clean_env.setenv("INPUT_SUMOLOGIC_ENDPOINT", "https://endpoint.sumologic.com/action")

    nm = NotificationManager(_base_cfg(), app_config={})
    nm.load_from_config()

    sumo = next(n for n in nm.notifiers if getattr(n, "name", "") == "sumologic")
    assert sumo.http_source_url == "https://endpoint.sumologic.com/action"


def test_sumologic_enabled_via_app_config(clean_env):
    nm = NotificationManager(_base_cfg(), app_config={"sumologic_endpoint": "https://endpoint.sumologic.com/cli"})
    nm.load_from_config()

    sumo = next(n for n in nm.notifiers if getattr(n, "name", "") == "sumologic")
    assert sumo.http_source_url == "https://endpoint.sumologic.com/cli"
