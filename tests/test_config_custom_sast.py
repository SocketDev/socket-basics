from socket_basics.core import config as config_module
from socket_basics.core.config import (
    create_config_from_args,
    merge_json_and_env_config,
    normalize_api_config,
    parse_cli_args,
)


def test_normalize_api_config_maps_custom_sast_keys():
    normalized = normalize_api_config(
        {
            "useCustomSastRules": True,
            "customSastRulePath": ".socket/rules",
        }
    )

    assert normalized["use_custom_sast_rules"] is True
    assert normalized["custom_sast_rule_path"] == ".socket/rules"


def test_normalize_api_config_maps_custom_sast_plural_path_alias():
    normalized = normalize_api_config({"customSastRulesPath": "custom_rules"})
    assert normalized["custom_sast_rule_path"] == "custom_rules"


def test_merge_json_and_env_config_api_overrides_env_custom_sast(monkeypatch):
    monkeypatch.setenv("INPUT_USE_CUSTOM_SAST_RULES", "true")
    monkeypatch.setenv("INPUT_CUSTOM_SAST_RULE_PATH", ".socket/rules")

    monkeypatch.setattr(
        config_module,
        "load_socket_basics_config",
        lambda: {"useCustomSastRules": False, "customSastRulePath": "dashboard/rules"},
    )

    merged = merge_json_and_env_config()
    assert merged["use_custom_sast_rules"] is False
    assert merged["custom_sast_rule_path"] == "dashboard/rules"


def test_merge_json_and_env_config_json_overrides_env_custom_sast(monkeypatch):
    monkeypatch.setenv("INPUT_USE_CUSTOM_SAST_RULES", "false")
    monkeypatch.setenv("INPUT_CUSTOM_SAST_RULE_PATH", "custom_rules")

    merged = merge_json_and_env_config(
        {"useCustomSastRules": True, "customSastRulePath": ".socket/rules"}
    )
    assert merged["use_custom_sast_rules"] is True
    assert merged["custom_sast_rule_path"] == ".socket/rules"


def test_create_config_from_args_does_not_override_env_custom_path(monkeypatch):
    monkeypatch.setenv("INPUT_USE_CUSTOM_SAST_RULES", "true")
    monkeypatch.setenv("INPUT_CUSTOM_SAST_RULE_PATH", ".socket/rules")

    monkeypatch.setattr(config_module, "_discover_repository", lambda *args, **kwargs: "repo")
    monkeypatch.setattr(config_module, "_discover_branch", lambda *args, **kwargs: "branch")
    monkeypatch.setattr(config_module, "_discover_commit_hash", lambda *args, **kwargs: "commit")
    monkeypatch.setattr(config_module, "_discover_is_default_branch", lambda *args, **kwargs: False)
    monkeypatch.setattr(config_module, "_discover_pull_request", lambda *args, **kwargs: 0)
    monkeypatch.setattr(config_module, "_discover_committers", lambda *args, **kwargs: [])

    parser = parse_cli_args()
    args = parser.parse_args([])
    config = create_config_from_args(args)

    assert config.get("use_custom_sast_rules") is True
    assert config.get("custom_sast_rule_path") == ".socket/rules"
