from pathlib import Path

from socket_basics.core import config as config_mod
from socket_basics.core.connector.trivy.trivy import TrivyScanner


class _DummyConfig:
    def __init__(self, values, workspace):
        self._config = values
        self.workspace = workspace

    def get(self, key, default=None):
        return self._config.get(key, default)


def test_api_empty_dockerfiles_does_not_override_env(monkeypatch):
    monkeypatch.setattr(config_mod, "load_config_from_env", lambda: {"dockerfiles": "Dockerfile"})
    monkeypatch.setattr(config_mod, "load_socket_basics_config", lambda: {"dockerfiles": ""})

    merged = config_mod.merge_json_and_env_config()

    assert merged["dockerfiles"] == "Dockerfile"


def test_api_non_empty_dockerfiles_still_overrides_env(monkeypatch):
    monkeypatch.setattr(config_mod, "load_config_from_env", lambda: {"dockerfiles": "Dockerfile"})
    monkeypatch.setattr(config_mod, "load_socket_basics_config", lambda: {"dockerfiles": "infra/Dockerfile"})

    merged = config_mod.merge_json_and_env_config()

    assert merged["dockerfiles"] == "infra/Dockerfile"


def test_trivy_string_false_disables_vuln_scan(tmp_path):
    cfg = _DummyConfig({"trivy_vuln_enabled": "false"}, Path(tmp_path))
    scanner = TrivyScanner(cfg)

    assert scanner.is_enabled() is False
    assert scanner.scan_vulnerabilities() == {}


def test_trivy_string_true_enables_vuln_scan_flag(tmp_path):
    cfg = _DummyConfig({"trivy_vuln_enabled": "true"}, Path(tmp_path))
    scanner = TrivyScanner(cfg)

    assert scanner.is_enabled() is True
