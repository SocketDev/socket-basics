from pathlib import Path
import hashlib
import logging
import re
from types import SimpleNamespace

from socket_basics.core.connector.trufflehog import TruffleHogScanner


def _scanner(tmp_path, exclude_dirs):
    config = SimpleNamespace(
        workspace=tmp_path,
        trufflehog_exclude_dir=exclude_dirs,
    )
    config.get = lambda key, default=None: {
        "trufflehog_exclude_dir": exclude_dirs,
        "trufflehog_show_unverified": False,
    }.get(key, default)
    config.get_action_for_severity = lambda severity: "error"
    config.get_scan_targets = lambda: []
    scanner = TruffleHogScanner.__new__(TruffleHogScanner)
    scanner.config = config
    return scanner


def test_build_exclude_patterns_are_anchored_to_workspace(tmp_path):
    scanner = _scanner(tmp_path, "")

    patterns = scanner._build_exclude_patterns("node_modules,.git,tmp")

    assert len(patterns) == 3
    workspace_regex = scanner._path_regex(str(tmp_path))
    assert all(workspace_regex in pattern for pattern in patterns)
    assert any(r"\.git" in pattern for pattern in patterns)
    assert all(".github" not in pattern for pattern in patterns)
    assert all(not pattern.startswith(r"(?:^|[/\\])") for pattern in patterns)

    def matches(path):
        return any(re.search(pattern, path) for pattern in patterns)

    assert matches(str(tmp_path / "src" / "node_modules" / "package.json"))
    assert not matches(str(tmp_path / ".github" / "workflows" / "scan.yml"))
    assert not re.search(patterns[2], str(tmp_path / "app.py"))


def test_build_exclude_patterns_skip_empty_entries(tmp_path):
    scanner = _scanner(tmp_path, "")

    patterns = scanner._build_exclude_patterns(" node_modules, ,dist, ")

    assert len(patterns) == 2
    assert all("node_modules" in pattern or "dist" in pattern for pattern in patterns)


def test_build_exclude_patterns_translate_globs_at_any_depth(tmp_path):
    scanner = _scanner(tmp_path, "")

    pattern = scanner._build_exclude_patterns("**/appsettings.*.json")[0]

    assert re.search(pattern, str(tmp_path / "appsettings.Production.json"))
    assert re.search(pattern, str(tmp_path / "config" / "appsettings.Staging.json"))
    assert not re.search(pattern, str(tmp_path / "config" / "appsettings.json"))
    assert not re.search(pattern, str(tmp_path / "config" / "appsettings.Staging.json.bak"))


def test_build_exclude_patterns_keep_slash_globs_root_relative(tmp_path):
    scanner = _scanner(tmp_path, "")

    pattern = scanner._build_exclude_patterns("config/*.json")[0]

    assert re.search(pattern, str(tmp_path / "config" / "secrets.json"))
    assert not re.search(pattern, str(tmp_path / "src" / "config" / "secrets.json"))


def test_build_exclude_patterns_keep_literal_entries_segment_anchored(tmp_path):
    scanner = _scanner(tmp_path, "")

    pattern = scanner._build_exclude_patterns("node_modules")[0]

    assert re.search(pattern, str(tmp_path / "src" / "node_modules" / "package.json"))
    assert not re.search(pattern, str(tmp_path / "src" / "node_modules_backup" / "package.json"))


def test_build_exclude_patterns_keep_slash_literals_root_relative(tmp_path):
    scanner = _scanner(tmp_path, "")

    pattern = scanner._build_exclude_patterns("config/secrets")[0]

    assert re.search(pattern, str(tmp_path / "config" / "secrets" / "token.txt"))
    assert not re.search(pattern, str(tmp_path / "src" / "config" / "secrets" / "token.txt"))


def test_build_exclude_patterns_handle_filesystem_root_workspace(tmp_path):
    scanner = _scanner(tmp_path, "")
    scanner._workspace_root = lambda: "/"

    pattern = scanner._build_exclude_patterns("tmp")[0]

    assert re.search(pattern, "/tmp/secret.txt")
    assert re.search(pattern, "/var/tmp/secret.txt")
    assert not re.search(pattern, "/template/secret.txt")


def test_write_exclude_file_contains_one_pattern_per_line(tmp_path):
    scanner = _scanner(tmp_path, "")

    exclude_file = scanner._write_exclude_file("node_modules,.git")
    try:
        contents = Path(exclude_file).read_text(encoding="utf-8").splitlines()
    finally:
        Path(exclude_file).unlink()

    assert len(contents) == 2
    workspace_regex = scanner._path_regex(str(tmp_path))
    assert all(workspace_regex in pattern for pattern in contents)


def test_scan_passes_one_exclude_paths_flag_and_cleans_up(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path, "node_modules,.yarn,dist")
    scanner.is_enabled = lambda: True
    scanner.config.get = lambda key, default=None: {
        "trufflehog_exclude_dir": scanner.config.trufflehog_exclude_dir,
        "trufflehog_show_unverified": False,
    }.get(key, default)
    scanner.config.get_scan_targets = lambda: [str(tmp_path)]
    scanner._process_results = lambda findings: {}

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        exclude_path = Path(command[command.index("--exclude-paths") + 1])
        captured["contents"] = exclude_path.read_text(encoding="utf-8").splitlines()
        captured["exists_during_run"] = exclude_path.exists()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        fake_run,
    )

    scanner.scan()

    command = captured["command"]
    assert command.count("--exclude-paths") == 1
    assert captured["exists_during_run"] is True
    assert len(captured["contents"]) == 3
    assert not Path(command[command.index("--exclude-paths") + 1]).exists()


def test_scan_uses_absolute_targets_for_relative_workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scanner = _scanner(Path("."), "node_modules")
    scanner.is_enabled = lambda: True
    scanner.config.get = lambda key, default=None: {
        "trufflehog_exclude_dir": scanner.config.trufflehog_exclude_dir,
        "trufflehog_show_unverified": False,
    }.get(key, default)
    scanner.config.get_scan_targets = lambda: ["."]
    scanner._process_results = lambda findings: {}

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        fake_run,
    )

    scanner.scan()

    command = captured["command"]
    assert command[-1] == str(tmp_path)


def test_process_results_strips_absolute_workspace_from_output_and_id(tmp_path):
    scanner = _scanner(tmp_path, "")
    scanner.generate_notifications = lambda components: {}

    file_path = tmp_path / "app" / "creds.txt"
    finding = {
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIA1234567890EXAMPLE",
        "SourceMetadata": {"Data": {"Filesystem": {"file": str(file_path), "line": 7}}},
    }

    result = scanner._process_results([finding])
    component = result["components"][0]
    alert = component["alerts"][0]

    assert component["name"] == "app/creds.txt"
    assert component["subpath"] == "app/creds.txt"
    assert component["manifestFiles"] == [{"file": "app/creds.txt"}]
    assert alert["props"]["filePath"] == "app/creds.txt"
    assert component["id"] == hashlib.sha256(b"app/creds.txt").hexdigest()


def test_process_results_strips_relative_workspace_from_output(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    workspace = Path("ws")
    scanner = _scanner(workspace, "")
    scanner.generate_notifications = lambda components: {}

    finding = {
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIA1234567890EXAMPLE",
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": str((tmp_path / "ws" / "app" / "creds.txt").resolve()),
                    "line": 7,
                }
            }
        },
    }

    result = scanner._process_results([finding])

    assert result["components"][0]["name"] == "app/creds.txt"
    assert result["components"][0]["alerts"][0]["props"]["filePath"] == "app/creds.txt"


def test_process_results_hashes_windows_paths_as_posix(tmp_path):
    scanner = _scanner(tmp_path, "")
    scanner.generate_notifications = lambda components: {}

    finding = {
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIA1234567890EXAMPLE",
        "SourceMetadata": {"Data": {"Filesystem": {"file": r"app\creds.txt", "line": 7}}},
    }

    result = scanner._process_results([finding])

    assert result["components"][0]["id"] == hashlib.sha256(b"app/creds.txt").hexdigest()


def test_scan_filters_excluded_changed_files(tmp_path, monkeypatch, caplog):
    scanner = _scanner(tmp_path, "node_modules")
    scanner.is_enabled = lambda: True
    scanner.config._config = {}
    scanner.config.get = lambda key, default=None: {
        "changed_files": ["node_modules/staged.txt", "app/staged.txt"],
        "trufflehog_exclude_dir": "node_modules",
        "trufflehog_show_unverified": False,
    }.get(key, default)
    scanner._process_results = lambda findings: {}

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        fake_run,
    )

    with caplog.at_level(logging.DEBUG):
        scanner.scan()

    command = captured["command"]
    assert str(tmp_path / "app" / "staged.txt") in command
    assert str(tmp_path / "node_modules" / "staged.txt") not in command
    assert "TruffleHog exclude patterns:" in caplog.text
    assert "Skipping excluded changed file:" in caplog.text


def test_scan_filters_changed_files_with_glob_excludes(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path, "**/appsettings.*.json")
    scanner.is_enabled = lambda: True
    scanner.config._config = {}
    scanner.config.get = lambda key, default=None: {
        "changed_files": [
            "config/appsettings.Staging.json",
            "config/appsettings.json",
        ],
        "trufflehog_exclude_dir": "**/appsettings.*.json",
        "trufflehog_show_unverified": False,
    }.get(key, default)
    scanner._process_results = lambda findings: {}
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        fake_run,
    )

    scanner.scan()

    assert str(tmp_path / "config" / "appsettings.Staging.json") not in captured["command"]
    assert str(tmp_path / "config" / "appsettings.json") in captured["command"]


def test_scan_filters_excluded_explicit_scan_targets(tmp_path, monkeypatch, caplog):
    scanner = _scanner(tmp_path, "excluded")
    scanner.is_enabled = lambda: True
    scanner.config.get_scan_targets = lambda: [
        str(tmp_path / "excluded" / "secret.txt"),
        str(tmp_path / "app" / "secret.txt"),
    ]
    scanner._process_results = lambda findings: {}
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        fake_run,
    )

    with caplog.at_level(logging.INFO):
        scanner.scan()

    assert str(tmp_path / "excluded" / "secret.txt") not in captured["command"]
    assert str(tmp_path / "app" / "secret.txt") in captured["command"]
    assert "Skipping excluded scan target:" in caplog.text


def test_scan_cleans_filter_when_all_explicit_targets_are_excluded(tmp_path, monkeypatch, caplog):
    scanner = _scanner(tmp_path, "excluded")
    scanner.is_enabled = lambda: True
    scanner.config.get_scan_targets = lambda: [
        str(tmp_path / "excluded" / "secret.txt"),
    ]
    captured = {}
    write_patterns = scanner._write_exclude_patterns

    def capture_filter_path(patterns):
        filter_path = write_patterns(patterns)
        captured["filter_path"] = Path(filter_path)
        return filter_path

    def unexpected_run(command, **kwargs):
        raise AssertionError("TruffleHog should not run when all targets are excluded")

    monkeypatch.setattr(scanner, "_write_exclude_patterns", capture_filter_path)
    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        unexpected_run,
    )

    with caplog.at_level(logging.INFO):
        result = scanner.scan()

    assert result == {}
    assert "All scan targets were excluded from TruffleHog scanning" in caplog.text
    assert not captured["filter_path"].exists()


def test_scan_skips_when_no_targets_are_available(tmp_path, monkeypatch, caplog):
    scanner = _scanner(tmp_path, "")
    scanner.is_enabled = lambda: True
    scanner.config.get_scan_targets = lambda: []

    def unexpected_run(command, **kwargs):
        raise AssertionError("TruffleHog should not run without scan targets")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        unexpected_run,
    )

    with caplog.at_level(logging.INFO):
        result = scanner.scan()

    assert result == {}
    assert "No TruffleHog scan targets found; skipping" in caplog.text


def test_scan_warns_for_target_outside_workspace(tmp_path, monkeypatch, caplog):
    scanner = _scanner(tmp_path, "node_modules")
    scanner.is_enabled = lambda: True
    outside_target = tmp_path.parent / "outside-repo"
    scanner.config.get_scan_targets = lambda: [str(outside_target)]
    scanner._process_results = lambda findings: {}

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    with caplog.at_level(logging.WARNING):
        scanner.scan()

    assert "is outside workspace" in caplog.text


def test_scan_cleans_exclude_file_when_trufflehog_fails(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path, "node_modules")
    scanner.is_enabled = lambda: True
    scanner.config.get_scan_targets = lambda: [str(tmp_path)]
    scanner._process_results = lambda findings: {}
    captured = {}

    def fake_run(command, **kwargs):
        exclude_path = Path(command[command.index("--exclude-paths") + 1])
        captured["exclude_path"] = exclude_path
        return SimpleNamespace(returncode=1, stdout="", stderr="failed")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        fake_run,
    )

    scanner.scan()

    assert not captured["exclude_path"].exists()
