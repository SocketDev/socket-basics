"""action.yml, connectors.yaml and notifications.yaml must describe one interface.

Every parameter that the scanners or notifiers read from an ``INPUT_*``
environment variable has to be produced by the action's ``runs.env`` block, and
every ``inputs.<name>`` the env block references has to be a declared input.
Otherwise a documented action input silently does nothing.
"""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _action() -> dict:
    return yaml.safe_load((ROOT / "action.yml").read_text())


def _parameter_env_vars() -> set[str]:
    env_vars: set[str] = set()
    for filename, top_key in (("connectors.yaml", "connectors"), ("notifications.yaml", "notifiers")):
        data = yaml.safe_load((ROOT / "socket_basics" / filename).read_text())
        for cfg in (data.get(top_key) or {}).values():
            for param in cfg.get("parameters") or []:
                if param.get("env_variable"):
                    env_vars.add(param["env_variable"])
    return env_vars


def test_every_parameter_env_var_is_set_by_the_action() -> None:
    action_env = set(_action()["runs"]["env"])
    missing = _parameter_env_vars() - action_env
    # GITHUB_API_URL is a runner-provided default variable; action.yml cannot
    # override it (runner env wins), so it is intentionally not mapped.
    missing.discard("GITHUB_API_URL")
    assert missing == set(), f"parameters with no action env mapping: {sorted(missing)}"


def test_every_env_mapping_references_a_declared_input() -> None:
    action = _action()
    inputs = set(action["inputs"])
    undeclared = [
        (env_key, name)
        for env_key, expr in action["runs"]["env"].items()
        for name in re.findall(r"inputs\.([A-Za-z0-9_]+)", str(expr))
        if name not in inputs
    ]
    assert undeclared == []


def test_input_names_used_in_the_docs_are_declared() -> None:
    """Names the guides tell users to put under ``with:``."""
    inputs = set(_action()["inputs"])
    documented = {
        "verbose",
        "console_tabular_enabled",
        "console_json_enabled",
        "jira_url",
        "jira_project",
        "ms_sentinel_shared_key",
        "opengrep_notification_method",
        "trufflehog_notification_method",
        "changed_files",
        "scan_all",
        "scan_files",
    }
    assert documented <= inputs, f"undeclared: {sorted(documented - inputs)}"


def _bundled_rule_ids() -> set[str]:
    ids: set[str] = set()
    for path in (ROOT / "socket_basics" / "rules").glob("*.yml"):
        for rule in (yaml.safe_load(path.read_text()) or {}).get("rules") or []:
            ids.add(rule["id"])
    return ids


def test_default_rule_lists_name_only_existing_rules() -> None:
    """A renamed rule must not leave a dead ID in a default allowlist."""
    known = _bundled_rule_ids()
    defaults = {
        f"action.yml:{name}": spec.get("default") or ""
        for name, spec in _action()["inputs"].items()
        if name.endswith(("_enabled_rules", "_disabled_rules"))
    }
    connectors = yaml.safe_load((ROOT / "socket_basics" / "connectors.yaml").read_text())
    for cfg in connectors["connectors"].values():
        for param in cfg.get("parameters") or []:
            if param["name"].endswith(("_enabled_rules", "_disabled_rules")):
                defaults[f"connectors.yaml:{param['name']}"] = param.get("default") or ""
    unknown = {
        where: sorted({i.strip() for i in value.split(",") if i.strip()} - known)
        for where, value in defaults.items()
    }
    assert {k: v for k, v in unknown.items() if v} == {}
