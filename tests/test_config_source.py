import logging

from socket_basics.core.config import Config, load_explicit_env_config


def test_config_logs_default_environment_source(caplog, tmp_path):
    caplog.set_level(logging.INFO, logger="socket_basics.core.config")

    Config({"workspace": str(tmp_path)})

    assert "Configuration loaded from: environment variables" in caplog.text


def test_config_logs_named_source(caplog, tmp_path):
    caplog.set_level(logging.INFO, logger="socket_basics.core.config")

    Config({"workspace": str(tmp_path), "_config_source": "api"})

    assert "Configuration loaded from: Socket dashboard (API)" in caplog.text


def test_api_key_source_log_names_variables_not_values(caplog, monkeypatch):
    """The debug line reports which variables are set, never what is in them."""
    caplog.set_level(logging.DEBUG, logger="socket_basics.core.config")
    monkeypatch.setenv("SOCKET_SECURITY_API_KEY", "first-value-not-for-logs")
    monkeypatch.setenv("INPUT_SOCKET_SECURITY_API_KEY", "second-value-not-for-logs")
    monkeypatch.delenv("SOCKET_SECURITY_API_TOKEN", raising=False)

    load_explicit_env_config()

    assert "SOCKET_SECURITY_API_KEY" in caplog.text
    assert "INPUT_SOCKET_SECURITY_API_KEY" in caplog.text
    assert "first-value-not-for-logs" not in caplog.text
    assert "second-value-not-for-logs" not in caplog.text


def test_an_empty_api_key_variable_is_not_reported_as_a_source(caplog, monkeypatch):
    # An exported-but-empty variable is not a configured key, so it must not
    # show up as one.
    caplog.set_level(logging.DEBUG, logger="socket_basics.core.config")
    monkeypatch.setenv("SOCKET_SECURITY_API_KEY", "")
    monkeypatch.setenv("SOCKET_SECURITY_API_TOKEN", "a-real-looking-token")
    monkeypatch.delenv("INPUT_SOCKET_SECURITY_API_KEY", raising=False)

    load_explicit_env_config()

    assert "API key sources detected: SOCKET_SECURITY_API_TOKEN" in caplog.text
