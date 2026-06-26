import logging

from socket_basics.core.config import Config


def test_config_logs_default_environment_source(caplog, tmp_path):
    caplog.set_level(logging.INFO, logger="socket_basics.core.config")

    Config({"workspace": str(tmp_path)})

    assert "Configuration loaded from: environment variables" in caplog.text


def test_config_logs_named_source(caplog, tmp_path):
    caplog.set_level(logging.INFO, logger="socket_basics.core.config")

    Config({"workspace": str(tmp_path), "_config_source": "api"})

    assert "Configuration loaded from: Socket dashboard (API)" in caplog.text
