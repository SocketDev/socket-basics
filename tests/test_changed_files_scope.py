"""Tests for diff-only (changed-files) scan scoping.

SAST/OpenGrep (and the other connectors that call ``get_scan_targets``) must
honor ``changed_files`` so PRs report only on what the PR changed, instead of
re-scanning the whole repository.
"""

import os
import subprocess
from argparse import Namespace

import pytest

from socket_basics.core.config import (
    Config,
    _detect_git_changed_files,
    _discover_repository,
    _git_env,
    create_config_from_args,
)


def _make_config(workspace, **overrides):
    cfg = {"workspace": str(workspace)}
    cfg.update(overrides)
    return Config(cfg)


class TestGetScanTargets:
    """Precedence and scoping behaviour of Config.get_scan_targets()."""

    def test_default_scans_whole_workspace(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        assert _make_config(tmp_path).get_scan_targets() == [str(tmp_path)]

    def test_scan_all_returns_workspace(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        cfg = _make_config(tmp_path, scan_all=True, changed_files=["a.py"])
        # scan_all is an explicit override and wins over changed_files
        assert cfg.get_scan_targets() == [str(tmp_path)]

    def test_changed_files_scopes_to_existing_files(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        (tmp_path / "b.py").write_text("y = 2")
        cfg = _make_config(tmp_path, changed_files=["a.py"])
        assert cfg.get_scan_targets() == [str(tmp_path / "a.py")]

    def test_changed_files_skips_missing_paths(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        cfg = _make_config(tmp_path, changed_files=["a.py", "gone.py"])
        assert cfg.get_scan_targets() == [str(tmp_path / "a.py")]

    def test_delete_only_pr_returns_empty(self, tmp_path):
        # All changed paths were deleted -> nothing to scan. Must NOT fall back
        # to scanning the whole workspace/cwd (the footgun this fixes).
        cfg = _make_config(tmp_path, changed_files=["gone.py"])
        assert cfg.get_scan_targets() == []

    def test_changed_files_takes_precedence_over_scan_files(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        (tmp_path / "b.py").write_text("y = 2")
        cfg = _make_config(tmp_path, scan_files="a.py", changed_files=["b.py"])
        assert cfg.get_scan_targets() == [str(tmp_path / "b.py")]

    def test_scan_files_used_when_no_changed_files(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        cfg = _make_config(tmp_path, scan_files="a.py")
        assert cfg.get_scan_targets() == [str(tmp_path / "a.py")]

    def test_absolute_changed_file_path_preserved(self, tmp_path):
        abs_path = tmp_path / "a.py"
        abs_path.write_text("x = 1")
        cfg = _make_config(tmp_path, changed_files=[str(abs_path)])
        assert cfg.get_scan_targets() == [str(abs_path)]


def _git(repo, *args):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=env
    )


def _config_args(workspace, changed_files):
    return Namespace(
        config=None,
        workspace=str(workspace),
        scan_files=None,
        console_tabular_enabled=False,
        output_console_enabled=False,
        console_json_enabled=False,
        output_json_enabled=False,
        verbose=False,
        repo="test/repo",
        branch="feature",
        default_branch=False,
        commit_message=None,
        pull_request=None,
        committers=None,
        enable_s3_upload=False,
        output=".socket.facts.json",
        changed_files=changed_files,
    )


@pytest.fixture
def pr_repo(tmp_path, monkeypatch):
    """A git repo with a 'main' base and a 'feature' branch ahead of it."""
    # _detect_git_changed_files prefers GITHUB_WORKSPACE; clear it so the
    # explicit workspace path is used.
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)

    _git(tmp_path, "init", "-b", "main")
    (tmp_path / "base.py").write_text("base = 1")
    (tmp_path / "old.py").write_text("old = 1")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")

    _git(tmp_path, "checkout", "-b", "feature")
    (tmp_path / "feat.py").write_text("feat = 1")
    (tmp_path / "base.py").write_text("base = 2")  # modify
    (tmp_path / "old.py").unlink()  # delete
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "feature")
    return tmp_path


class TestDetectGitChangedFiles:

    def test_pr_mode_lists_added_and_modified(self, pr_repo):
        files = _detect_git_changed_files(str(pr_repo), mode="pr", base_ref="main")
        assert sorted(files) == ["base.py", "feat.py"]

    def test_pr_mode_excludes_deletions(self, pr_repo):
        files = _detect_git_changed_files(str(pr_repo), mode="pr", base_ref="main")
        assert "old.py" not in files

    def test_auto_uses_base_ref_env(self, pr_repo, monkeypatch):
        monkeypatch.setenv("GITHUB_BASE_REF", "main")
        files = _detect_git_changed_files(str(pr_repo), mode="auto")
        assert sorted(files) == ["base.py", "feat.py"]

    def test_auto_falls_back_to_staged_without_base_ref(self, pr_repo):
        # No GITHUB_BASE_REF and no base_ref -> staged changes (none staged here)
        (pr_repo / "staged.py").write_text("s = 1")
        _git(pr_repo, "add", "staged.py")
        files = _detect_git_changed_files(str(pr_repo), mode="auto")
        assert files == ["staged.py"]

    def test_non_git_dir_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
        assert _detect_git_changed_files(str(tmp_path), mode="pr", base_ref="main") == []

    def test_delete_only_pr_config_creation_keeps_empty_scope(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
        monkeypatch.setenv("GITHUB_BASE_REF", "main")

        _git(tmp_path, "init", "-b", "main")
        (tmp_path / "old.py").write_text("old = 1")
        _git(tmp_path, "add", ".")
        _git(tmp_path, "commit", "-m", "base")

        _git(tmp_path, "checkout", "-b", "feature")
        (tmp_path / "old.py").unlink()
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-m", "delete old")

        cfg = create_config_from_args(_config_args(tmp_path, "pr"))

        assert cfg.get("changed_files") == []
        assert cfg.get_scan_targets() == []


def _git_refuses_repo(repo):
    """True when git, told to assume a different owner, refuses to read `repo`.

    ``GIT_TEST_ASSUME_DIFFERENT_OWNER`` is git's own test knob for the
    ownership check behind ``safe.directory``; it makes every repository look
    like it belongs to another user, which is exactly what a checkout looks
    like from inside the container action. Used as a control so these tests
    skip (instead of passing vacuously) on a git build without the knob.
    """
    probe = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"},
    )
    return probe.returncode != 0


class TestDubiousOwnership:
    """Git subprocesses must survive the container-action ownership mismatch.

    The pre-built Docker action runs as root while the checkout is owned by
    the runner user; without ``safe.directory`` git refuses the repo, the diff
    resolves to zero files, and the scanners silently skip.
    """

    def test_pr_diff_survives_dubious_ownership(self, pr_repo, monkeypatch):
        for i in range(3):
            monkeypatch.delenv(f"GIT_CONFIG_KEY_{i}", raising=False)
            monkeypatch.delenv(f"GIT_CONFIG_VALUE_{i}", raising=False)
        monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)

        if not _git_refuses_repo(pr_repo):
            pytest.skip("this git build does not honor GIT_TEST_ASSUME_DIFFERENT_OWNER")

        monkeypatch.setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
        files = _detect_git_changed_files(str(pr_repo), mode="pr", base_ref="main")
        assert sorted(files) == ["base.py", "feat.py"]

    def test_repo_discovery_survives_dubious_ownership(self, pr_repo, monkeypatch):
        _git(pr_repo, "remote", "add", "origin", "https://github.com/acme/demo.git")

        if not _git_refuses_repo(pr_repo):
            pytest.skip("this git build does not honor GIT_TEST_ASSUME_DIFFERENT_OWNER")

        monkeypatch.chdir(pr_repo)
        monkeypatch.setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
        assert _discover_repository(None, "", "") == "acme/demo"


class TestGitEnv:
    """_git_env injects safe.directory without clobbering caller config."""

    def test_injects_safe_directory_for_workspace(self, monkeypatch):
        monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
        env = _git_env("/scan/me")
        assert env["GIT_CONFIG_COUNT"] == "1"
        assert env["GIT_CONFIG_KEY_0"] == "safe.directory"
        assert env["GIT_CONFIG_VALUE_0"] == "/scan/me"

    def test_appends_after_caller_provided_entries(self, monkeypatch):
        # A user already deploying the documented env-var workaround must not
        # have their entry clobbered.
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "user.name")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "runner")
        env = _git_env("/scan/me")
        assert env["GIT_CONFIG_COUNT"] == "2"
        assert env["GIT_CONFIG_KEY_0"] == "user.name"
        assert env["GIT_CONFIG_VALUE_0"] == "runner"
        assert env["GIT_CONFIG_KEY_1"] == "safe.directory"
        assert env["GIT_CONFIG_VALUE_1"] == "/scan/me"

    def test_garbage_count_treated_as_zero(self, monkeypatch):
        monkeypatch.setenv("GIT_CONFIG_COUNT", "not-a-number")
        env = _git_env("/scan/me")
        assert env["GIT_CONFIG_COUNT"] == "1"
        assert env["GIT_CONFIG_KEY_0"] == "safe.directory"

    def test_defaults_to_github_workspace(self, monkeypatch):
        monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
        monkeypatch.setenv("GITHUB_WORKSPACE", "/github/workspace")
        env = _git_env()
        assert env["GIT_CONFIG_VALUE_0"] == "/github/workspace"
