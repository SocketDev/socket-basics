import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

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


def _mock_subprocess_run(monkeypatch, captured_cmd: list[str], configs: dict | None = None):
    """Record the command. When ``configs`` is given, also record the rule IDs
    in each ``--config`` file, keyed by path, while the files still exist."""

    def _runner(cmd, capture_output, text):
        captured_cmd.extend(cmd)
        if configs is not None:
            for i, arg in enumerate(cmd):
                if arg == "--config":
                    path = Path(cmd[i + 1])
                    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                    configs[str(path)] = [r["id"] for r in data.get("rules") or []]
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


def test_all_languages_custom_rules_without_individual_language_flags(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    custom_rules_file = workspace / ".socket" / "rules" / "org-rules.yml"
    _write_custom_rules_file(custom_rules_file, ["org.no-eval"])

    bundled_rules_dir = tmp_path / "bundled-rules"
    bundled_js_file = bundled_rules_dir / "javascript_typescript.yml"
    bundled_python_file = bundled_rules_dir / "python.yml"
    _write_rule_file(bundled_js_file, ["js-default-rule"])
    _write_rule_file(bundled_python_file, ["py-default-rule"])

    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "all_languages_enabled": True,
            "use_custom_sast_rules": True,
            "custom_sast_rule_path": ".socket/rules",
            "opengrep_rules_dir": str(bundled_rules_dir),
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
    assert str(bundled_js_file) not in cmd_str
    assert str(bundled_python_file) in cmd_str


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
    configs: dict = {}
    _mock_subprocess_run(monkeypatch, captured_cmd, configs)
    scanner.scan()

    # No allowlist ID names a custom rule, so every custom rule runs.
    assert "--exclude-rule" not in captured_cmd
    [(path, ids)] = configs.items()
    assert "socket_custom_rules_" in path
    assert sorted(ids) == ["org.no-eval", "org.no-innerhtml"]


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
    configs: dict = {}
    _mock_subprocess_run(monkeypatch, captured_cmd, configs)
    scanner.scan()

    assert "--exclude-rule" not in captured_cmd
    [(path, ids)] = configs.items()
    # The filtered copy sits next to the custom rules file it was made from.
    assert "socket_custom_rules_" in path
    assert Path(path).name.startswith(".socket-filtered-")
    assert ids == ["org.no-eval"]


def _bundled_js_scanner(tmp_path, rule_ids: list[str], enabled: str) -> tuple[OpenGrepScanner, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    bundled_rules_dir = tmp_path / "bundled-rules"
    bundled_file = bundled_rules_dir / "javascript_typescript.yml"
    _write_rule_file(bundled_file, rule_ids)
    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "javascript_sast_enabled": True,
            "javascript_enabled_rules": enabled,
            "opengrep_rules_dir": str(bundled_rules_dir),
            "all_languages_enabled": False,
            "all_rules_enabled": False,
            "verbose": False,
        }
    )
    scanner = OpenGrepScanner(config)
    scanner._convert_to_socket_facts = lambda _: {"components": []}
    scanner.generate_notifications = lambda _: {}
    return scanner, bundled_file


def test_bundled_allowlist_passes_only_enabled_rules(tmp_path, monkeypatch):
    scanner, bundled_file = _bundled_js_scanner(tmp_path, ["js-a", "js-b", "js-c"], "js-a,js-c")

    captured_cmd: list[str] = []
    configs: dict = {}
    _mock_subprocess_run(monkeypatch, captured_cmd, configs)
    scanner.scan()

    assert "--exclude-rule" not in captured_cmd
    assert str(bundled_file) not in captured_cmd
    [(path, ids)] = configs.items()
    assert ids == ["js-a", "js-c"]
    # The copy sits next to the original, so OpenGrep gives its rules the same
    # ID prefix, and is removed once OpenGrep has run.
    assert Path(path).parent == bundled_file.parent
    assert Path(path).name.startswith(".socket-filtered-") and path.endswith(".yaml")
    assert [p.name for p in bundled_file.parent.iterdir()] == [bundled_file.name]


def test_bundled_allowlist_warns_about_unknown_ids(tmp_path, monkeypatch, caplog):
    scanner, _ = _bundled_js_scanner(tmp_path, ["js-a", "js-b"], "js-a,js-renamed-long-ago")

    configs: dict = {}
    _mock_subprocess_run(monkeypatch, [], configs)
    with caplog.at_level("WARNING"):
        scanner.scan()

    [ids] = configs.values()
    assert ids == ["js-a"]
    assert "js-renamed-long-ago" in caplog.text


def test_bundled_allowlist_matching_nothing_runs_every_rule(tmp_path, monkeypatch, caplog):
    scanner, bundled_file = _bundled_js_scanner(tmp_path, ["js-a", "js-b"], "js-typo")

    captured_cmd: list[str] = []
    configs: dict = {}
    _mock_subprocess_run(monkeypatch, captured_cmd, configs)
    with caplog.at_level("WARNING"):
        scanner.scan()

    assert list(configs) == [str(bundled_file)]
    assert "js-typo" in caplog.text


def test_all_rules_enabled_ignores_allowlist(tmp_path, monkeypatch):
    scanner, bundled_file = _bundled_js_scanner(tmp_path, ["js-a", "js-b"], "js-a")
    scanner.config.set("all_rules_enabled", True)

    configs: dict = {}
    _mock_subprocess_run(monkeypatch, [], configs)
    scanner.scan()

    assert configs == {str(bundled_file): ["js-a", "js-b"]}


def test_custom_rule_files_are_removed_after_the_scan(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    _write_custom_rules_file(workspace / ".socket" / "rules" / "org-rules.yml", ["org.no-eval"])
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

    configs: dict = {}
    _mock_subprocess_run(monkeypatch, [], configs)
    scanner.scan()

    [path] = configs
    assert "socket_custom_rules_" in path
    assert not Path(path).parent.exists()


def test_all_languages_scan_skips_rule_files_opengrep_cannot_load(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    bundled_rules_dir = tmp_path / "bundled-rules"
    for name in ("python.yml", "erlang.yml", "objective-c.yml"):
        _write_rule_file(bundled_rules_dir / name, [f"{name}-rule"])

    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "opengrep_rules_dir": str(bundled_rules_dir),
            "all_languages_enabled": True,
            "all_rules_enabled": False,
            "verbose": False,
        }
    )
    scanner = OpenGrepScanner(config)
    scanner._convert_to_socket_facts = lambda _: {"components": []}
    scanner.generate_notifications = lambda _: {}

    configs: dict = {}
    _mock_subprocess_run(monkeypatch, [], configs)
    scanner.scan()

    assert [Path(p).name for p in configs] == ["python.yml"]


def test_all_rules_and_languages_skip_rule_files_opengrep_cannot_load():
    rule_files = Config({"all_rules_enabled": True, "all_languages_enabled": True}).build_opengrep_rules()
    assert "python.yml" in rule_files
    assert not {"erlang.yml", "objective-c.yml"} & set(rule_files)


def _record_temp_paths(monkeypatch) -> list[Path]:
    """Record every directory and file ``tempfile`` creates during the test."""
    created: list[Path] = []
    real_mkdtemp, real_mkstemp = tempfile.mkdtemp, tempfile.mkstemp

    def _mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created.append(Path(path))
        return path

    def _mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        created.append(Path(path))
        return fd, path

    monkeypatch.setattr(tempfile, "mkdtemp", _mkdtemp)
    monkeypatch.setattr(tempfile, "mkstemp", _mkstemp)
    return created


def _custom_and_filtered_scanner(tmp_path) -> tuple[OpenGrepScanner, Path]:
    """Scanner that writes a custom-rule directory, a filtered copy inside it
    (JavaScript) and a filtered copy next to a bundled rules file (Python)."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    _write_custom_rules_file(workspace / ".socket" / "rules" / "org-rules.yml", ["org.no-eval", "org.no-innerhtml"])
    bundled_rules_dir = tmp_path / "bundled-rules"
    _write_rule_file(bundled_rules_dir / "javascript_typescript.yml", ["js-default-rule"])
    _write_rule_file(bundled_rules_dir / "python.yml", ["py-a", "py-b"])
    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "javascript_sast_enabled": True,
            "javascript_enabled_rules": "org.no-eval",
            "python_sast_enabled": True,
            "python_enabled_rules": "py-a",
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
    return scanner, bundled_rules_dir


def _assert_all_removed(created: list[Path], bundled_rules_dir: Path) -> None:
    assert created
    assert not any(p.exists() for p in created)
    assert sorted(p.name for p in bundled_rules_dir.iterdir()) == ["javascript_typescript.yml", "python.yml"]


def test_temp_rule_paths_are_removed_when_opengrep_is_missing(tmp_path, monkeypatch):
    created = _record_temp_paths(monkeypatch)
    scanner, bundled_rules_dir = _custom_and_filtered_scanner(tmp_path)

    def _missing(cmd, capture_output, text):
        raise FileNotFoundError("opengrep")

    monkeypatch.setattr("socket_basics.core.connector.opengrep.subprocess.run", _missing)
    assert scanner.scan() == {}

    # The custom-rule directory, plus one filtered copy inside it and one
    # next to the bundled python.yml.
    assert sum(p.name.startswith("socket_custom_rules_") for p in created) == 1
    assert sorted(p.parent == bundled_rules_dir for p in created if p.name.startswith(".socket-filtered-")) == [False, True]
    _assert_all_removed(created, bundled_rules_dir)


def test_temp_rule_paths_are_removed_when_the_scan_raises(tmp_path, monkeypatch):
    created = _record_temp_paths(monkeypatch)
    scanner, bundled_rules_dir = _custom_and_filtered_scanner(tmp_path)

    def _crash(cmd, capture_output, text):
        raise RuntimeError("opengrep crashed")

    monkeypatch.setattr("socket_basics.core.connector.opengrep.subprocess.run", _crash)
    with pytest.raises(RuntimeError, match="opengrep crashed"):
        scanner.scan()

    _assert_all_removed(created, bundled_rules_dir)


def test_custom_rule_dir_is_removed_when_building_custom_rules_fails(tmp_path, monkeypatch):
    created = _record_temp_paths(monkeypatch)
    scanner, bundled_rules_dir = _custom_and_filtered_scanner(tmp_path)

    def _fail(self, rules_by_file):
        raise OSError("disk full")

    monkeypatch.setattr(
        "socket_basics.core.connector.opengrep.custom_rules.CustomRulesBuilder._write_rule_files", _fail
    )
    _mock_subprocess_run(monkeypatch, [])
    scanner.scan()

    assert any(p.name.startswith("socket_custom_rules_") for p in created)
    _assert_all_removed(created, bundled_rules_dir)


def test_filtered_copy_falls_back_to_a_temp_dir_when_rules_dir_is_read_only(tmp_path, monkeypatch, caplog):
    scanner, bundled_file = _bundled_js_scanner(tmp_path, ["js-a", "js-b"], "js-a")
    created = _record_temp_paths(monkeypatch)
    record_mkstemp = tempfile.mkstemp

    def _mkstemp(*args, **kwargs):
        if Path(kwargs.get("dir", "")) == bundled_file.parent:
            raise PermissionError("read-only")
        return record_mkstemp(*args, **kwargs)

    monkeypatch.setattr(tempfile, "mkstemp", _mkstemp)
    configs: dict = {}
    _mock_subprocess_run(monkeypatch, [], configs)
    with caplog.at_level("WARNING"):
        scanner.scan()

    [(path, ids)] = configs.items()
    assert ids == ["js-a"]
    assert "socket_filtered_rules_" in path
    assert "fingerprints" in caplog.text
    assert created and not any(p.exists() for p in created)


@pytest.mark.parametrize(
    ("first", "second", "rule_file"),
    [("c", "cpp", "c_cpp.yml"), ("csharp", "dotnet", "dotnet.yml")],
)
def test_shared_rule_file_stays_unfiltered_when_one_language_has_no_list(first, second, rule_file):
    config = Config(
        {
            f"{first}_sast_enabled": True,
            f"{second}_sast_enabled": True,
            f"{first}_enabled_rules": "rule-x",
            f"{second}_enabled_rules": " ",
        }
    )
    assert rule_file not in config.build_filtered_opengrep_rules()


@pytest.mark.parametrize(
    ("first", "second", "rule_file"),
    [("c", "cpp", "c_cpp.yml"), ("csharp", "dotnet", "dotnet.yml")],
)
def test_shared_rule_file_combines_both_lists(first, second, rule_file):
    config = Config(
        {
            f"{first}_sast_enabled": True,
            f"{second}_sast_enabled": True,
            f"{first}_enabled_rules": "rule-x",
            f"{second}_enabled_rules": "rule-y,rule-x",
        }
    )
    assert sorted(config.build_filtered_opengrep_rules()[rule_file]) == ["rule-x", "rule-y"]


def test_shared_rule_file_ignores_a_disabled_languages_empty_list():
    config = Config({"c_sast_enabled": True, "c_enabled_rules": "rule-x", "cpp_enabled_rules": ""})
    assert config.build_filtered_opengrep_rules() == {"c_cpp.yml": ["rule-x"]}
