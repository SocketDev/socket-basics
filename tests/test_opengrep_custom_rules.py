import json
from pathlib import Path
from types import SimpleNamespace

from socket_basics.core.config import Config
from socket_basics.core.connector.opengrep import OpenGrepScanner


def _write_rule_file(path: Path, rule_ids: list[str]) -> None:
    rules = [{"id": rid, "languages": ["javascript"], "pattern": "eval(...)"} for rid in rule_ids]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"rules": rules}), encoding="utf-8")


def _write_custom_rules_file(path: Path, rule_ids: list[str]) -> None:
    lines = ["rules:"]
    for rid in rule_ids:
        lines.extend(
            [
                f"  - id: {rid}",
                "    pattern: eval(...)",
                "    languages: [javascript, typescript]",
                f'    message: Rule {rid}',
                "    severity: ERROR",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _mock_subprocess_run(monkeypatch, captured_cmd: list[str]):
    def _runner(cmd, capture_output, text):
        captured_cmd.extend(cmd)
        out_file = cmd[cmd.index("--output") + 1]
        Path(out_file).write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr("socket_basics.core.connector.opengrep.subprocess.run", _runner)


def test_scan_uses_custom_rule_file_when_available(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    custom_rules_dir = workspace / ".socket" / "rules"
    # Custom file can be any yaml name; builder groups by languages.
    custom_rules_file = custom_rules_dir / "org-rules.yml"
    _write_custom_rules_file(custom_rules_file, ["org.no-eval"])

    bundled_rules_dir = tmp_path / "bundled-rules"
    _write_rule_file(bundled_rules_dir / "javascript_typescript.yml", ["js-default-rule"])

    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "javascript_sast_enabled": True,
            "use_custom_sast_rules": True,
            "custom_sast_rule_path": ".socket/rules",
            "opengrep_rules_dir": str(bundled_rules_dir),
            "all_languages_enabled": False,
            "all_rules_enabled": False,
            "verbose": False,
        }
    )
    scanner = OpenGrepScanner(config)
    scanner._convert_to_socket_facts = lambda _: {"components": []}
    scanner.generate_notifications = lambda _: {}

    captured_cmd: list[str] = []
    _mock_subprocess_run(monkeypatch, captured_cmd)
    scanner.scan()

    cmd_str = " ".join(captured_cmd)
    assert "socket_custom_rules_" in cmd_str
    assert str(bundled_rules_dir / "javascript_typescript.yml") not in cmd_str


def test_scan_falls_back_to_bundled_file_when_custom_missing(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    bundled_rules_dir = tmp_path / "bundled-rules"
    bundled_file = bundled_rules_dir / "javascript_typescript.yml"
    _write_rule_file(bundled_file, ["js-default-rule"])

    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "javascript_sast_enabled": True,
            "use_custom_sast_rules": True,
            "custom_sast_rule_path": ".socket/missing-rules",
            "opengrep_rules_dir": str(bundled_rules_dir),
            "all_languages_enabled": False,
            "all_rules_enabled": False,
            "verbose": False,
        }
    )
    scanner = OpenGrepScanner(config)
    scanner._convert_to_socket_facts = lambda _: {"components": []}
    scanner.generate_notifications = lambda _: {}

    captured_cmd: list[str] = []
    _mock_subprocess_run(monkeypatch, captured_cmd)
    scanner.scan()

    assert str(bundled_file) in " ".join(captured_cmd)


def test_custom_rules_ignore_nonmatching_bundled_allowlist_ids(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    custom_rules_file = workspace / ".socket" / "rules" / "org-rules.yml"
    _write_custom_rules_file(custom_rules_file, ["org.no-eval", "org.no-innerhtml"])

    bundled_rules_dir = tmp_path / "bundled-rules"
    _write_rule_file(bundled_rules_dir / "javascript_typescript.yml", ["js-default-rule"])

    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "javascript_sast_enabled": True,
            "javascript_enabled_rules": "js-default-rule",
            "use_custom_sast_rules": True,
            "custom_sast_rule_path": ".socket/rules",
            "opengrep_rules_dir": str(bundled_rules_dir),
            "all_languages_enabled": False,
            "all_rules_enabled": False,
            "verbose": False,
        }
    )
    scanner = OpenGrepScanner(config)
    scanner._convert_to_socket_facts = lambda _: {"components": []}
    scanner.generate_notifications = lambda _: {}

    captured_cmd: list[str] = []
    _mock_subprocess_run(monkeypatch, captured_cmd)
    scanner.scan()

    cmd_str = " ".join(captured_cmd)
    assert "socket_custom_rules_" in cmd_str
    assert "--exclude-rule org.no-eval" not in cmd_str
    assert "--exclude-rule org.no-innerhtml" not in cmd_str


def test_custom_rules_apply_allowlist_when_custom_ids_match(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    custom_rules_file = workspace / ".socket" / "rules" / "org-rules.yml"
    _write_custom_rules_file(custom_rules_file, ["org.no-eval", "org.no-innerhtml"])

    bundled_rules_dir = tmp_path / "bundled-rules"
    _write_rule_file(bundled_rules_dir / "javascript_typescript.yml", ["js-default-rule"])

    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "javascript_sast_enabled": True,
            "javascript_enabled_rules": "org.no-eval",
            "use_custom_sast_rules": True,
            "custom_sast_rule_path": ".socket/rules",
            "opengrep_rules_dir": str(bundled_rules_dir),
            "all_languages_enabled": False,
            "all_rules_enabled": False,
            "verbose": False,
        }
    )
    scanner = OpenGrepScanner(config)
    scanner._convert_to_socket_facts = lambda _: {"components": []}
    scanner.generate_notifications = lambda _: {}

    captured_cmd: list[str] = []
    _mock_subprocess_run(monkeypatch, captured_cmd)
    scanner.scan()

    cmd_str = " ".join(captured_cmd)
    assert "--exclude-rule org.no-innerhtml" in cmd_str
    assert "--exclude-rule org.no-eval" not in cmd_str
