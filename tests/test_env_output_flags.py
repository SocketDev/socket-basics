"""INPUT_VERBOSE / INPUT_CONSOLE_*_ENABLED and --version.

The GitHub Action inputs ``verbose``, ``console_tabular_enabled`` and
``console_json_enabled`` arrive as ``INPUT_*`` environment variables and must
behave like the matching CLI flags.
"""

import pytest

from socket_basics.core.config import load_config_from_env, load_explicit_env_config, parse_cli_args
from socket_basics.version import __version__

OUTPUT_ENV_VARS = ("INPUT_VERBOSE", "INPUT_CONSOLE_TABULAR_ENABLED", "INPUT_CONSOLE_JSON_ENABLED")


@pytest.fixture
def clean_env(monkeypatch):
    for name in OUTPUT_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_output_flags_default_off(clean_env):
    config = load_config_from_env()
    assert config["verbose"] is False
    assert config["console_tabular_enabled"] is False
    assert config["console_json_enabled"] is False

    explicit = load_explicit_env_config()
    assert not any(key in explicit for key in ("verbose", "console_tabular_enabled", "console_json_enabled"))


def test_output_flags_read_from_input_env(clean_env):
    clean_env.setenv("INPUT_VERBOSE", "true")
    clean_env.setenv("INPUT_CONSOLE_TABULAR_ENABLED", "True")
    clean_env.setenv("INPUT_CONSOLE_JSON_ENABLED", "false")

    config = load_config_from_env()
    assert config["verbose"] is True
    assert config["console_tabular_enabled"] is True
    assert config["console_json_enabled"] is False

    explicit = load_explicit_env_config()
    assert explicit["verbose"] is True
    assert explicit["console_tabular_enabled"] is True
    assert explicit["console_json_enabled"] is False


def test_empty_action_input_does_not_turn_flags_on(clean_env):
    """An unset workflow input is forwarded as an empty string, not as off."""
    for name in OUTPUT_ENV_VARS:
        clean_env.setenv(name, "")
    config = load_config_from_env()
    assert config["verbose"] is False
    assert config["console_tabular_enabled"] is False
    assert config["console_json_enabled"] is False


def test_version_flag_prints_version_and_exits(capsys):
    with pytest.raises(SystemExit) as exc:
        parse_cli_args().parse_args(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"socket-basics {__version__}"
