from pathlib import Path
import re
from types import SimpleNamespace

from socket_basics.core.connector.trufflehog import TruffleHogScanner


def _scanner(tmp_path, exclude_dirs):
    config = SimpleNamespace(
        workspace=tmp_path,
        trufflehog_exclude_dir=exclude_dirs,
    )
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
