import pytest

from socket_basics.core.notification.manager import NotificationManager
from socket_basics.core.notification.ms_sentinel_notifier import MSSentinelNotifier

SENTINEL_ENV_VARS = (
    "MS_SENTINEL_WORKSPACE_ID",
    "INPUT_MS_SENTINEL_WORKSPACE_ID",
    "MS_SENTINEL_SHARED_KEY",
    "INPUT_MS_SENTINEL_SHARED_KEY",
    "INPUT_MS_SENTINEL_KEY",
)


@pytest.fixture
def clean_env(monkeypatch):
    for name in SENTINEL_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _base_cfg():
    return {
        "notifiers": {
            "ms_sentinel": {
                "module_path": "socket_basics.core.notification.ms_sentinel_notifier",
                "class": "MSSentinelNotifier",
                "parameters": [
                    {"name": "ms_sentinel_workspace_id", "env_variable": "INPUT_MS_SENTINEL_WORKSPACE_ID", "type": "str"},
                    {"name": "ms_sentinel_key", "env_variable": "INPUT_MS_SENTINEL_KEY", "type": "str"},
                ],
            }
        }
    }


def test_sentinel_reads_notifications_yaml_param_names(clean_env):
    """--ms-sentinel-workspace-id / --ms-sentinel-key and the action inputs deliver these names."""
    n = MSSentinelNotifier({"ms_sentinel_workspace_id": "ws-123", "ms_sentinel_key": "shared"})
    assert n.workspace_id == "ws-123"
    assert n.shared_key == "shared"


def test_sentinel_accepts_shared_key_alias(clean_env):
    n = MSSentinelNotifier({"ms_sentinel_workspace_id": "ws-123", "ms_sentinel_shared_key": "shared"})
    assert n.shared_key == "shared"


def test_sentinel_falls_back_to_env(clean_env):
    clean_env.setenv("MS_SENTINEL_WORKSPACE_ID", "ws-env")
    clean_env.setenv("INPUT_MS_SENTINEL_SHARED_KEY", "key-env")
    n = MSSentinelNotifier({})
    assert n.workspace_id == "ws-env"
    assert n.shared_key == "key-env"


def test_sentinel_enabled_via_action_env_vars(clean_env):
    """The action maps ms_sentinel_workspace_id / ms_sentinel_key to these INPUT_ vars."""
    clean_env.setenv("INPUT_MS_SENTINEL_WORKSPACE_ID", "ws-action")
    clean_env.setenv("INPUT_MS_SENTINEL_KEY", "key-action")

    nm = NotificationManager(_base_cfg(), app_config={})
    nm.load_from_config()

    sentinel = next(n for n in nm.notifiers if getattr(n, "name", "") == "ms_sentinel")
    assert sentinel.workspace_id == "ws-action"
    assert sentinel.shared_key == "key-action"


def test_sentinel_enabled_via_app_config(clean_env):
    nm = NotificationManager(
        _base_cfg(),
        app_config={"ms_sentinel_workspace_id": "ws-cli", "ms_sentinel_key": "key-cli"},
    )
    nm.load_from_config()

    sentinel = next(n for n in nm.notifiers if getattr(n, "name", "") == "ms_sentinel")
    assert sentinel.workspace_id == "ws-cli"
    assert sentinel.shared_key == "key-cli"
