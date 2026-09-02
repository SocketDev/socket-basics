"""Tests for diff-only (changed-files) scan scoping.

SAST/OpenGrep (and the other connectors that call ``get_scan_targets``) must
honor ``changed_files`` so PRs report only on what the PR changed, instead of
re-scanning the whole repository.
"""

import json
import logging
import os
import subprocess
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

from socket_basics.core.config import (
    Config,
    _detect_git_changed_files,
    _discover_repository,
    _git_env,
    create_config_from_args,
    resolve_changed_files_request,
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

    def test_resolved_changed_files_outrank_scan_all_fallback(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        cfg = _make_config(tmp_path, scan_all=True, changed_files=["a.py"])
        assert cfg.get_scan_targets() == [str(tmp_path / "a.py")]

    def test_empty_resolved_scope_outranks_scan_all_fallback(self, tmp_path):
        cfg = _make_config(
            tmp_path,
            scan_all=True,
            changed_files=[],
            changed_files_scope_requested=True,
        )
        assert cfg.get_scan_targets() == []

    def test_scan_all_without_a_successful_scope_returns_workspace(self, tmp_path):
        assert _make_config(tmp_path, scan_all=True).get_scan_targets() == [str(tmp_path)]

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
    # Clear ambient GitHub metadata so a developer's local/CI environment does
    # not supply a real PR base to tests that are exercising a synthetic one.
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

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

    def test_non_git_dir_returns_failure(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
        assert _detect_git_changed_files(str(tmp_path), mode="pr", base_ref="main") is None

    def test_delete_only_pr_config_creation_keeps_empty_scope(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
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


# ===========================================================================
# The scope request must reach the file walk from every entry point, and a
# scope it cannot honor must say so in the log.
# ===========================================================================


@pytest.fixture
def cloned_pr_repo(tmp_path, monkeypatch):
    """An 'upstream' repo plus a CI-style checkout with an ``origin`` remote.

    ``pr_repo`` has no remote, so ``origin/main`` never exists there and the
    bare ``main`` fallback always saves it. Real CI checkouts only have the
    remote-tracking ref, and only when the fetch was deep enough.
    """
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

    upstream = tmp_path / "upstream"
    upstream.mkdir()
    _git(upstream, "init", "-b", "main")
    (upstream / "base.py").write_text("base = 1")
    (upstream / "untouched.py").write_text("untouched = 1")
    _git(upstream, "add", ".")
    _git(upstream, "commit", "-m", "base")
    _git(upstream, "checkout", "-b", "feature")
    (upstream / "feat.py").write_text("feat = 1")
    _git(upstream, "add", "-A")
    _git(upstream, "commit", "-m", "feature")
    _git(upstream, "checkout", "main")

    def checkout(name, depth):
        ws = tmp_path / name
        ws.mkdir()
        _git(ws, "init")
        _git(ws, "remote", "add", "origin", str(upstream))
        if depth:
            _git(ws, "fetch", "--no-tags", f"--depth={depth}", "origin",
                 "+refs/heads/feature:refs/remotes/origin/feature")
        else:
            _git(ws, "fetch", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*")
        _git(ws, "checkout", "--force", "origin/feature")
        return ws

    return {
        "upstream": upstream,
        "deep": checkout("deep", 0),      # actions/checkout with fetch-depth: 0
        "shallow": checkout("shallow", 1),  # actions/checkout default
    }


def _write_event(tmp_path, monkeypatch, payload):
    """Point GITHUB_EVENT_PATH at a pull_request event payload."""
    import json
    event = tmp_path / "event.json"
    event.write_text(json.dumps(payload))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    return event


class TestScopeRequestReachesEveryConfigPath:
    """`changed_files` used to be resolved only in create_config_from_args().

    A Config built any other way -- the env loader, a --config JSON file, a
    Socket dashboard config -- either ignored the request and scanned the whole
    repository, or kept the raw string and iterated it character by character.
    """

    def test_env_only_config_honors_input_changed_files(self, pr_repo, monkeypatch):
        from socket_basics.core.config import load_config_from_env

        monkeypatch.setenv("GITHUB_WORKSPACE", str(pr_repo))
        monkeypatch.setenv("GITHUB_BASE_REF", "main")
        monkeypatch.setenv("INPUT_CHANGED_FILES", "auto")

        cfg = Config(load_config_from_env())

        assert sorted(cfg.get("changed_files")) == ["base.py", "feat.py"]
        assert cfg.get_scan_targets() == [str(pr_repo / "base.py"), str(pr_repo / "feat.py")]

    def test_env_only_config_without_request_scans_workspace(self, pr_repo, monkeypatch):
        from socket_basics.core.config import load_config_from_env

        monkeypatch.setenv("GITHUB_WORKSPACE", str(pr_repo))
        monkeypatch.delenv("INPUT_CHANGED_FILES", raising=False)

        cfg = Config(load_config_from_env())

        assert cfg.get_scan_targets() == [str(pr_repo)]

    def test_env_only_config_fails_closed_when_scope_cannot_resolve(
        self, pr_repo, monkeypatch
    ):
        from socket_basics.core.config import load_config_from_env

        monkeypatch.setenv("GITHUB_WORKSPACE", str(pr_repo))
        monkeypatch.setenv("INPUT_CHANGED_FILES", "pr")
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

        with pytest.raises(SystemExit, match="could not be resolved"):
            Config(load_config_from_env())

    def test_env_only_scan_all_opts_into_full_fallback(self, pr_repo, monkeypatch):
        from socket_basics.core.config import load_config_from_env

        monkeypatch.setenv("GITHUB_WORKSPACE", str(pr_repo))
        monkeypatch.setenv("INPUT_CHANGED_FILES", "pr")
        monkeypatch.setenv("INPUT_SCAN_ALL", "true")
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

        cfg = Config(load_config_from_env())

        assert cfg.get("changed_files") == []
        assert cfg.get("changed_files_scope_requested") is False
        assert cfg.get("scan_all") is True
        assert cfg.get_scan_targets() == [str(pr_repo)]

    def test_string_false_does_not_enable_scan_all_fallback(self, pr_repo, monkeypatch):
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

        with pytest.raises(SystemExit, match="could not be resolved"):
            _make_config(pr_repo, changed_files="pr", scan_all="false")

    def test_raw_auto_string_is_resolved_not_iterated(self, pr_repo, monkeypatch):
        """A JSON/dashboard config value of 'auto' must hit git.

        Before, `_resolve_file_targets("auto")` walked the string and looked
        for files named 'a', 'u', 't', 'o'.
        """
        monkeypatch.setenv("GITHUB_BASE_REF", "main")

        cfg = _make_config(pr_repo, changed_files="auto")

        assert sorted(cfg.get("changed_files")) == ["base.py", "feat.py"]
        assert cfg.get_scan_targets() == [str(pr_repo / "base.py"), str(pr_repo / "feat.py")]

    def test_raw_comma_list_string_is_split(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        (tmp_path / "b.py").write_text("y = 2")
        (tmp_path / "c.py").write_text("z = 3")

        cfg = _make_config(tmp_path, changed_files="a.py,b.py")

        assert cfg.get("changed_files") == ["a.py", "b.py"]
        assert cfg.get_scan_targets() == [str(tmp_path / "a.py"), str(tmp_path / "b.py")]

    def test_already_resolved_list_is_not_re_resolved(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        cfg = _make_config(tmp_path, changed_files=["a.py"])
        assert cfg.get("changed_files") == ["a.py"]

    def test_empty_request_normalizes_to_empty_list(self, tmp_path):
        cfg = _make_config(tmp_path, changed_files="")
        assert cfg.get("changed_files") == []
        assert cfg.get_scan_targets() == [str(tmp_path)]

    def test_cli_value_overrides_env_value(self, pr_repo, monkeypatch):
        monkeypatch.setenv("GITHUB_WORKSPACE", str(pr_repo))
        monkeypatch.setenv("INPUT_CHANGED_FILES", "auto")

        cfg = create_config_from_args(_config_args(pr_repo, "base.py"))

        assert cfg.get("changed_files") == ["base.py"]

    def test_env_value_is_used_when_no_cli_value(self, pr_repo, monkeypatch):
        monkeypatch.setenv("GITHUB_WORKSPACE", str(pr_repo))
        monkeypatch.setenv("GITHUB_BASE_REF", "main")
        monkeypatch.setenv("INPUT_CHANGED_FILES", "pr")

        cfg = create_config_from_args(_config_args(pr_repo, ""))

        assert sorted(cfg.get("changed_files")) == ["base.py", "feat.py"]


class TestPrBaseResolution:
    """`auto`/`pr` used to consult GITHUB_BASE_REF and nothing else."""

    def test_uses_base_sha_from_event_payload(self, pr_repo, tmp_path, monkeypatch):
        """GITHUB_BASE_REF is only set on pull_request triggers.

        On a pull_request_review or pull_request_review_comment run the PR base
        is only in the event payload, where base.sha is an exact commit that
        does not need a remote-tracking branch to resolve.
        """
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        base_sha = _git(pr_repo, "rev-parse", "main").stdout.strip()
        _write_event(tmp_path, monkeypatch, {"pull_request": {"base": {"sha": base_sha}}})

        files = _detect_git_changed_files(str(pr_repo), mode="pr")

        assert sorted(files) == ["base.py", "feat.py"]

    def test_uses_base_ref_from_event_payload(self, pr_repo, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        _write_event(tmp_path, monkeypatch, {"pull_request": {"base": {"ref": "main"}}})

        files = _detect_git_changed_files(str(pr_repo), mode="pr")

        assert sorted(files) == ["base.py", "feat.py"]

    def test_tries_event_candidates_after_an_unresolvable_environment_ref(
        self, pr_repo, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("GITHUB_BASE_REF", "not-present")
        _write_event(
            tmp_path,
            monkeypatch,
            {
                "pull_request": {
                    "base": {
                        "sha": "0123456789012345678901234567890123456789",
                        "ref": "main",
                    }
                }
            },
        )

        files = _detect_git_changed_files(str(pr_repo), mode="pr")

        assert sorted(files) == ["base.py", "feat.py"]

    def test_explicit_workspace_wins_over_ambient_github_workspace(
        self, pr_repo, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path / "wrong-workspace"))

        files = _detect_git_changed_files(
            str(pr_repo),
            mode="pr",
            base_ref="main",
        )

        assert sorted(files) == ["base.py", "feat.py"]

    def test_ignores_event_payload_without_a_pull_request(self, pr_repo, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        _write_event(tmp_path, monkeypatch, {"ref": "refs/heads/feature"})

        assert _detect_git_changed_files(str(pr_repo), mode="pr") is None

    def test_survives_an_unreadable_event_payload(self, pr_repo, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_BASE_REF", "main")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(tmp_path / "does-not-exist.json"))

        files = _detect_git_changed_files(str(pr_repo), mode="pr")

        assert sorted(files) == ["base.py", "feat.py"]

    def test_deep_checkout_resolves_remote_tracking_base(self, cloned_pr_repo, monkeypatch):
        monkeypatch.setenv("GITHUB_BASE_REF", "main")
        files = _detect_git_changed_files(str(cloned_pr_repo["deep"]), mode="pr")
        assert files == ["feat.py"]

    def test_issue_comment_payload_yields_no_base_and_says_why(
        self, pr_repo, tmp_path, monkeypatch, caplog
    ):
        """issue_comment is the one PR trigger the payload fallback cannot serve.

        Its payload has no top-level pull_request. It has issue.pull_request,
        which is a set of URLs with no base ref or sha in it, so there is
        nothing to diff against without a GitHub API call. The run must say
        that rather than resolve to nothing and look like an empty diff.
        """
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        _write_event(
            tmp_path,
            monkeypatch,
            {
                "action": "created",
                "issue": {
                    "number": 98,
                    "pull_request": {
                        "url": "https://api.github.com/repos/o/r/pulls/98",
                        "html_url": "https://github.com/o/r/pull/98",
                    },
                },
            },
        )

        with caplog.at_level(logging.WARNING, logger="socket_basics.core.config"):
            files = _detect_git_changed_files(str(pr_repo), mode="pr")

        assert files is None
        assert "issue_comment" in caplog.text
        assert "GITHUB_BASE_REF" in caplog.text

    def test_plain_issue_comment_gets_the_generic_warning(
        self, pr_repo, tmp_path, monkeypatch, caplog
    ):
        """A comment on a real issue is not a pull request at all.

        issue_comment fires for both, and only issue.pull_request tells them
        apart, so the PR-specific advice must not be given for an issue.
        """
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        _write_event(
            tmp_path, monkeypatch, {"action": "created", "issue": {"number": 12}}
        )

        with caplog.at_level(logging.WARNING, logger="socket_basics.core.config"):
            files = _detect_git_changed_files(str(pr_repo), mode="pr")

        assert files is None
        assert "no pull request base was found" in caplog.text
        assert "issue_comment" not in caplog.text


class TestScopeResolutionPolicy:
    """Failures fail closed; successful empty diffs remain empty scopes."""

    def test_shallow_checkout_fails_and_names_fetch_depth(self, cloned_pr_repo, monkeypatch):
        monkeypatch.setenv("GITHUB_BASE_REF", "main")

        with pytest.raises(SystemExit, match="fetch-depth: 0") as error:
            _detect_git_changed_files(str(cloned_pr_repo["shallow"]), mode="pr")

        assert "shallow" in str(error.value).lower()

    def test_missing_pr_base_warns(self, pr_repo, monkeypatch, caplog):
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

        with caplog.at_level(logging.WARNING, logger="socket_basics.core.config"):
            files = _detect_git_changed_files(str(pr_repo), mode="pr")

        assert files is None
        assert "no pull request base was found" in caplog.text

    def test_non_git_workspace_warns(self, tmp_path, monkeypatch, caplog):
        monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)

        with caplog.at_level(logging.WARNING, logger="socket_basics.core.config"):
            files = _detect_git_changed_files(str(tmp_path), mode="pr", base_ref="main")

        assert files is None
        assert "not a git repository" in caplog.text

    def test_failed_resolution_is_not_an_empty_list(self, pr_repo, monkeypatch, caplog):
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

        with caplog.at_level(logging.WARNING, logger="socket_basics.core.config"):
            files = resolve_changed_files_request("pr", str(pr_repo))

        assert files is None
        assert "could not be resolved" in caplog.text

    def test_config_fails_closed_when_scope_cannot_be_resolved(self, pr_repo, monkeypatch):
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

        with pytest.raises(SystemExit, match="could not be resolved"):
            _make_config(pr_repo, changed_files="pr")

    def test_scan_all_opts_into_full_scan_on_resolution_failure(
        self, pr_repo, monkeypatch, caplog
    ):
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

        with caplog.at_level(logging.WARNING, logger="socket_basics.core.config"):
            cfg = _make_config(pr_repo, changed_files="pr", scan_all=True)

        assert cfg.get("changed_files") == []
        assert cfg.get("changed_files_scope_requested") is False
        assert cfg.get_scan_targets() == [str(pr_repo)]
        assert "falling back to a full-repo scan" in caplog.text

    def test_unreadable_repository_returns_failure(self, pr_repo):
        (pr_repo / ".git" / "HEAD").write_text("garbage")
        assert _detect_git_changed_files(
            str(pr_repo), mode="pr", base_ref="main"
        ) is None

    def test_auto_does_not_fall_back_to_staged_when_pr_base_is_unresolvable(
        self, pr_repo, monkeypatch
    ):
        monkeypatch.setenv("GITHUB_BASE_REF", "no-such-branch")
        (pr_repo / "staged.py").write_text("staged = True\n")
        _git(pr_repo, "add", "staged.py")

        assert _detect_git_changed_files(str(pr_repo), mode="auto") is None

    def test_shallow_no_merge_base_fails_fast(self, pr_repo):
        _git(pr_repo, "checkout", "--orphan", "disconnected")
        _git(pr_repo, "add", "-A")
        _git(pr_repo, "commit", "-m", "orphan")
        (pr_repo / ".git" / "shallow").touch()

        with pytest.raises(SystemExit, match="fetch-depth: 0"):
            _detect_git_changed_files(str(pr_repo), mode="pr", base_ref="main")

    def test_scan_all_skips_shallow_no_merge_base_fail_fast(self, pr_repo):
        _git(pr_repo, "checkout", "--orphan", "disconnected")
        _git(pr_repo, "add", "-A")
        _git(pr_repo, "commit", "-m", "orphan")
        (pr_repo / ".git" / "shallow").touch()

        assert _detect_git_changed_files(
            str(pr_repo),
            mode="pr",
            base_ref="main",
            fail_open=True,
        ) is None

    def test_successful_resolution_does_not_warn(self, pr_repo, monkeypatch, caplog):
        monkeypatch.setenv("GITHUB_BASE_REF", "main")

        with caplog.at_level(logging.WARNING, logger="socket_basics.core.config"):
            files = resolve_changed_files_request("auto", str(pr_repo))

        assert sorted(files) == ["base.py", "feat.py"]
        assert caplog.text == ""


def _git_refuses_repo(repo):
    probe = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"},
    )
    return probe.returncode != 0


class TestContainerOwnershipMismatch:
    """The scan runs as root in a container over a runner-owned workspace.

    git refuses that with "detected dubious ownership", which fails every diff
    and looks exactly like a PR that changed nothing. Nothing in the workflow
    can fix it -- `git config --global --add safe.directory` before the scan
    step writes the runner's git config, not the container's -- so the git
    calls have to trust the workspace themselves.

    `GIT_TEST_ASSUME_DIFFERENT_OWNER` is git's own switch for that state, so
    these run against real repositories and the real git binary.
    """

    @pytest.fixture
    def refusing_git(self, pr_repo, monkeypatch):
        """``pr_repo`` with git refusing to read it on ownership grounds.

        Skips rather than passing vacuously where the switch has no effect, so
        a git that ignores it shows up in the run instead of hiding.
        """
        if not _git_refuses_repo(pr_repo):
            pytest.skip("this git ignores GIT_TEST_ASSUME_DIFFERENT_OWNER")
        monkeypatch.setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
        return pr_repo

    def test_pr_diff_survives_an_ownership_mismatch(self, refusing_git):
        files = _detect_git_changed_files(str(refusing_git), mode="pr", base_ref="main")

        assert sorted(files) == ["base.py", "feat.py"]

    def test_auto_scope_survives_an_ownership_mismatch(self, refusing_git, monkeypatch):
        monkeypatch.setenv("GITHUB_BASE_REF", "main")

        cfg = _make_config(refusing_git, changed_files="auto")

        assert sorted(cfg.get("changed_files")) == ["base.py", "feat.py"]
        assert cfg.get_scan_targets() == [
            str(refusing_git / "base.py"),
            str(refusing_git / "feat.py"),
        ]

    def test_current_commit_survives_an_ownership_mismatch(self, refusing_git):
        files = _detect_git_changed_files(str(refusing_git), mode="current-commit")

        assert "feat.py" in files

    def test_ownership_mismatch_no_longer_warns_about_safe_directory(
        self, refusing_git, monkeypatch, caplog
    ):
        monkeypatch.setenv("GITHUB_BASE_REF", "main")

        with caplog.at_level(logging.WARNING, logger="socket_basics.core.config"):
            files = _detect_git_changed_files(str(refusing_git), mode="pr")

        assert sorted(files) == ["base.py", "feat.py"]
        assert caplog.text == ""

    def test_relative_workspace_survives_an_ownership_mismatch(
        self, refusing_git, monkeypatch
    ):
        monkeypatch.chdir(refusing_git.parent)
        files = _detect_git_changed_files(
            refusing_git.name,
            mode="pr",
            base_ref="main",
        )
        assert sorted(files) == ["base.py", "feat.py"]

    def test_repository_discovery_survives_an_ownership_mismatch(
        self, refusing_git, monkeypatch
    ):
        setup = subprocess.run(
            [
                "git",
                "-C",
                str(refusing_git),
                "remote",
                "add",
                "origin",
                "https://github.com/acme/demo.git",
            ],
            capture_output=True,
            text=True,
            env=_git_env(refusing_git),
        )
        assert setup.returncode == 0, setup.stderr
        monkeypatch.chdir(refusing_git)

        assert _discover_repository(None, "", "") == "acme/demo"


class TestGitEnv:
    """Command-scoped safe.directory config preserves caller entries."""

    def test_injects_only_the_absolute_workspace(self, monkeypatch, tmp_path):
        monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
        monkeypatch.chdir(tmp_path)

        env = _git_env("relative/workspace")

        assert env["GIT_CONFIG_COUNT"] == "1"
        assert env["GIT_CONFIG_KEY_0"] == "safe.directory"
        assert Path(env["GIT_CONFIG_VALUE_0"]).is_absolute()
        assert env["GIT_CONFIG_VALUE_0"].endswith("relative/workspace")
        assert env["GIT_CONFIG_VALUE_0"] != "*"

    def test_appends_after_caller_provided_entries(self, monkeypatch):
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "user.name")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "runner")

        env = _git_env("/scan/me")

        assert env["GIT_CONFIG_COUNT"] == "2"
        assert env["GIT_CONFIG_KEY_0"] == "user.name"
        assert env["GIT_CONFIG_VALUE_0"] == "runner"
        assert env["GIT_CONFIG_KEY_1"] == "safe.directory"
        assert env["GIT_CONFIG_VALUE_1"] == "/scan/me"

    def test_garbage_count_is_treated_as_zero(self, monkeypatch):
        monkeypatch.setenv("GIT_CONFIG_COUNT", "not-a-number")
        env = _git_env("/scan/me")
        assert env["GIT_CONFIG_COUNT"] == "1"
        assert env["GIT_CONFIG_KEY_0"] == "safe.directory"


class TestResolveChangedFilesRequest:
    """The single resolver every config path now goes through."""

    def test_commit_hash_request(self, pr_repo):
        head = _git(pr_repo, "rev-parse", "HEAD").stdout.strip()
        files = resolve_changed_files_request(head, str(pr_repo))
        # commit/current-commit list every path in the commit, deletions
        # included; the deleted path is dropped when targets are resolved.
        assert sorted(files) == ["base.py", "feat.py", "old.py"]

    def test_current_commit_request(self, pr_repo):
        files = resolve_changed_files_request("current-commit", str(pr_repo))
        assert sorted(files) == ["base.py", "feat.py", "old.py"]

    def test_current_commit_drops_deleted_paths_from_targets(self, pr_repo):
        cfg = _make_config(pr_repo, changed_files="current-commit")
        targets = [os.path.basename(t) for t in cfg.get_scan_targets()]
        assert sorted(targets) == ["base.py", "feat.py"]

    def test_explicit_list_request_does_not_touch_git(self, tmp_path):
        assert resolve_changed_files_request("a.py, b.py ", str(tmp_path)) == ["a.py", "b.py"]

    def test_blank_request_returns_empty(self, tmp_path):
        assert resolve_changed_files_request("   ", str(tmp_path)) == []


class TestConnectorsHonorTheResolvedScope:
    """Connectors derive their own changed-file list when the config has none.

    That fallback must not fire when the user explicitly asked for a scope and
    it resolved to nothing. Substituting "whatever is staged" for "what the PR
    changed" scans a different set of files than the one that was requested.
    """

    def _scanner(self, tmp_path, changed_files, scope_requested, scan_all=False):
        from socket_basics.core.connector.trufflehog import TruffleHogScanner

        values = {
            "changed_files": changed_files,
            "changed_files_scope_requested": scope_requested,
            "scan_all": scan_all,
            "trufflehog_exclude_dir": "",
            "trufflehog_show_unverified": False,
        }
        config = SimpleNamespace(workspace=tmp_path, _config=values)
        config.get = lambda key, default=None: values.get(key, default)
        config.get_scan_targets = lambda: []
        scanner = TruffleHogScanner.__new__(TruffleHogScanner)
        scanner.config = config
        scanner.is_enabled = lambda: True
        return scanner

    def test_scope_resolved_to_nothing_is_not_replaced_by_staged(self, pr_repo, monkeypatch):
        (pr_repo / "staged_secret.py").write_text("token = 'abc'")
        _git(pr_repo, "add", "staged_secret.py")

        called = []
        monkeypatch.setattr(
            "socket_basics.core.config._detect_git_changed_files",
            lambda *a, **k: called.append(k.get("mode")) or ["staged_secret.py"],
        )

        scanner = self._scanner(pr_repo, changed_files=[], scope_requested=True)
        assert scanner.scan() == {}
        assert called == []

    def test_empty_scope_with_scan_all_does_not_widen_to_the_workspace(
        self, pr_repo, monkeypatch
    ):
        """scan_all must not override an empty scope for TruffleHog.

        A successfully resolved scope remains authoritative when scan_all is
        configured as the failure fallback, so an empty scope must skip rather
        than falling through to the workspace target.
        """
        from socket_basics.core.connector.trufflehog import TruffleHogScanner

        cfg = _make_config(
            pr_repo,
            changed_files=[],
            changed_files_scope_requested=True,
            scan_all=True,
            secret_scanning_enabled=True,
            trufflehog_exclude_dir="",
            trufflehog_show_unverified=False,
        )
        invocations = []

        def record_run(cmd, *args, **kwargs):
            invocations.append(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "socket_basics.core.connector.trufflehog.subprocess.run", record_run
        )

        assert TruffleHogScanner(cfg).scan() == {}
        assert invocations == []

    def test_scan_all_without_a_scope_still_scans_the_workspace(
        self, pr_repo, monkeypatch
    ):
        """The empty-scope guard must not disable an ordinary scan_all run."""
        from socket_basics.core.connector.trufflehog import TruffleHogScanner

        cfg = _make_config(
            pr_repo,
            scan_all=True,
            secret_scanning_enabled=True,
            trufflehog_exclude_dir="",
            trufflehog_show_unverified=False,
        )
        staged_calls = []
        monkeypatch.setattr(
            "socket_basics.core.config._detect_git_changed_files",
            lambda *a, **k: staged_calls.append(k.get("mode")) or ["staged_secret.py"],
        )
        invocations = []

        def record_run(cmd, *args, **kwargs):
            invocations.append(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "socket_basics.core.connector.trufflehog.subprocess.run", record_run
        )

        TruffleHogScanner(cfg).scan()
        assert staged_calls == []
        assert invocations == [
            [
                "trufflehog",
                "filesystem",
                "--json",
                "--no-verification",
                str(pr_repo),
            ]
        ]

    def test_staged_fallback_still_runs_when_no_scope_was_requested(self, pr_repo, monkeypatch):
        called = []
        monkeypatch.setattr(
            "socket_basics.core.config._detect_git_changed_files",
            lambda *a, **k: called.append(k.get("mode")) or [],
        )

        scanner = self._scanner(pr_repo, changed_files=[], scope_requested=False)
        scanner.scan()
        assert called == ["staged"]

    def test_changed_paths_that_are_all_gone_never_reach_trufflehog(
        self, pr_repo, monkeypatch
    ):
        """Nothing runs when every path in the scope is gone.

        A changed-file list names deleted paths all the time, and TruffleHog
        exits non-zero on a path it cannot open, so handing it one loses the
        run instead of skipping it. The invocations are recorded rather than
        raised on, because ``scan()`` catches every exception a fake run
        raises and would swallow the failure.
        """
        invocations = []

        def record_run(cmd, *args, **kwargs):
            invocations.append(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "socket_basics.core.connector.trufflehog.subprocess.run", record_run
        )

        scanner = self._scanner(
            pr_repo, changed_files=["gone.py"], scope_requested=True
        )

        assert scanner.scan() == {}
        assert invocations == []

    def test_a_changed_path_that_survives_is_still_scanned(self, pr_repo, monkeypatch):
        """Dropping the missing paths must not drop the ones that are there."""
        (pr_repo / "kept.py").write_text("token = 'abc'")

        captured = {}

        def fake_run(cmd, *args, **kwargs):
            captured["cmd"] = cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "socket_basics.core.connector.trufflehog.subprocess.run", fake_run
        )

        scanner = self._scanner(
            pr_repo, changed_files=["gone.py", "kept.py"], scope_requested=True
        )
        scanner.scan()

        assert captured["cmd"][-1] == str(pr_repo / "kept.py")
        assert str(pr_repo / "gone.py") not in captured["cmd"]


def _record_trivy_paths(monkeypatch):
    """Capture the path argument of every trivy invocation."""
    scanned = []

    def fake_run(cmd, *args, **kwargs):
        scanned.append(cmd[-1])
        # Write the JSON Trivy would have written to --output.
        out_index = cmd.index('--output') + 1
        with open(cmd[out_index], 'w') as fh:
            json.dump({"Results": []}, fh)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "socket_basics.core.connector.trivy.trivy.subprocess.run", fake_run
    )
    return scanned


class TestTrivyVulnScanHonorsTheResolvedScope:
    """Trivy's filesystem vulnerability scan never calls get_scan_targets().

    Every other connector inherits the empty-scope behaviour from
    ``Config.get_scan_targets()``. This one builds its own path list from
    ``changed_files`` and falls back to the whole workspace when that list is
    empty, so declining the staged-file substitution is not enough on its own:
    the workspace fallback has to be declined too, or a successfully resolved
    empty scope still turns into a full-repository scan.
    """

    def _scanner(self, tmp_path, changed_files, scope_requested, scan_all=False):
        from socket_basics.core.connector.trivy.trivy import TrivyScanner

        values = {
            "trivy_vuln_enabled": True,
            "changed_files": changed_files,
            "changed_files_scope_requested": scope_requested,
            "scan_all": scan_all,
        }
        config = SimpleNamespace(workspace=tmp_path, _config=values)
        config.get = lambda key, default=None: values.get(key, default)
        scanner = TrivyScanner.__new__(TrivyScanner)
        scanner.config = config
        return scanner

    def test_successful_empty_scope_does_not_widen_to_the_whole_workspace(
        self, tmp_path, monkeypatch
    ):
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(tmp_path, changed_files=[], scope_requested=True)

        assert scanner.scan_vulnerabilities() == {}
        assert scanned == []

    def test_scope_whose_paths_all_vanished_does_not_widen_either(
        self, tmp_path, monkeypatch
    ):
        # A delete-only PR: the scope resolved to files, but none of them exist
        # in the checkout any more, so no directory survives resolution.
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(
            tmp_path, changed_files=["gone/removed.py"], scope_requested=True
        )

        assert scanner.scan_vulnerabilities() == {}
        assert scanned == []

    def test_resolved_scope_still_scans_only_the_changed_directories(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "requirements.txt").write_text("requests==2.0.0\n")
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(
            tmp_path, changed_files=["pkg/requirements.txt"], scope_requested=True
        )

        scanner.scan_vulnerabilities()
        assert scanned == [str(tmp_path / "pkg")]

    def test_whole_workspace_is_still_scanned_when_no_scope_was_requested(
        self, tmp_path, monkeypatch
    ):
        scanned = _record_trivy_paths(monkeypatch)
        monkeypatch.setattr(
            "socket_basics.core.config._detect_git_changed_files", lambda *a, **k: []
        )
        scanner = self._scanner(tmp_path, changed_files=[], scope_requested=False)

        scanner.scan_vulnerabilities()
        assert scanned == [str(tmp_path)]

    def test_successful_empty_scope_still_wins_when_scan_all_is_set(
        self, tmp_path, monkeypatch
    ):
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(
            tmp_path, changed_files=[], scope_requested=True, scan_all=True
        )

        assert scanner.scan_vulnerabilities() == {}
        assert scanned == []

    def test_scan_all_after_failed_resolution_scans_the_workspace(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "staged").mkdir()
        (tmp_path / "staged" / "requirements.txt").write_text("requests==2.0.0\n")
        staged_calls = []
        monkeypatch.setattr(
            "socket_basics.core.config._detect_git_changed_files",
            lambda *a, **k: staged_calls.append(k.get("mode"))
            or ["staged/requirements.txt"],
        )
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(
            tmp_path, changed_files=[], scope_requested=False, scan_all=True
        )

        scanner.scan_vulnerabilities()
        assert staged_calls == []
        assert scanned == [str(tmp_path)]


class TestTrivyDockerfileScanHonorsTheResolvedScope:
    """Trivy's Dockerfile scan builds its own file list too.

    Declining the staged-file substitution is not enough on its own here
    either. A scope that resolves to real files but names no Dockerfile leaves
    the configured ``dockerfiles`` list exactly as it was, and every one of
    those files is scanned even though the change never touched them.
    """

    def _scanner(
        self,
        tmp_path,
        changed_files,
        scope_requested,
        dockerfiles='Dockerfile',
        scan_all=False,
    ):
        from socket_basics.core.connector.trivy.trivy import TrivyScanner

        values = {
            "dockerfile_scanning_enabled": True,
            "dockerfiles": dockerfiles,
            "changed_files": changed_files,
            "changed_files_scope_requested": scope_requested,
            "scan_all": scan_all,
        }
        config = SimpleNamespace(workspace=tmp_path, _config=values)
        config.get = lambda key, default=None: values.get(key, default)
        scanner = TrivyScanner.__new__(TrivyScanner)
        scanner.config = config
        return scanner

    def test_scope_without_a_dockerfile_leaves_the_configured_ones_unscanned(
        self, tmp_path, monkeypatch
    ):
        # The connector resolves a configured Dockerfile against the working
        # directory before the workspace, and this repository has a Dockerfile
        # of its own, so run from the workspace to keep the paths unambiguous.
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Dockerfile").write_text("FROM alpine\n")
        (tmp_path / "app.py").write_text("x = 1\n")
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(tmp_path, changed_files=["app.py"], scope_requested=True)

        assert scanner.scan_dockerfiles() == {}
        assert scanned == []

    def test_scope_still_narrows_to_the_changed_dockerfile(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Dockerfile").write_text("FROM alpine\n")
        (tmp_path / "web.Dockerfile").write_text("FROM nginx\n")
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(
            tmp_path,
            changed_files=["web.Dockerfile"],
            scope_requested=True,
            dockerfiles="Dockerfile,web.Dockerfile",
        )

        scanner.scan_dockerfiles()
        assert scanned == ["web.Dockerfile"]

    def test_successful_scope_still_wins_when_scan_all_is_set(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Dockerfile").write_text("FROM alpine\n")
        (tmp_path / "app.py").write_text("x = 1\n")
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(
            tmp_path, changed_files=["app.py"], scope_requested=True, scan_all=True
        )

        assert scanner.scan_dockerfiles() == {}
        assert scanned == []

    def test_scan_all_after_failed_resolution_scans_configured_dockerfiles(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Dockerfile").write_text("FROM alpine\n")
        (tmp_path / "staged.Dockerfile").write_text("FROM busybox\n")
        staged_calls = []
        monkeypatch.setattr(
            "socket_basics.core.config._detect_git_changed_files",
            lambda *a, **k: staged_calls.append(k.get("mode"))
            or ["staged.Dockerfile"],
        )
        scanned = _record_trivy_paths(monkeypatch)
        scanner = self._scanner(
            tmp_path,
            changed_files=[],
            scope_requested=False,
            scan_all=True,
        )

        scanner.scan_dockerfiles()
        assert staged_calls == []
        assert scanned == ["Dockerfile"]

    def test_staged_fallback_without_a_dockerfile_keeps_the_configured_ones(
        self, tmp_path, monkeypatch
    ):
        """Nobody asked for a scope on this run, so nothing may be taken away.

        The staged-file list is a convenience the connector reaches for on its
        own. A staged file that happens not to be a Dockerfile is not a request
        to leave the configured Dockerfile unscanned.
        """
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Dockerfile").write_text("FROM alpine\n")
        scanned = _record_trivy_paths(monkeypatch)
        monkeypatch.setattr(
            "socket_basics.core.config._detect_git_changed_files",
            lambda *a, **k: ["app.py"],
        )
        scanner = self._scanner(tmp_path, changed_files=[], scope_requested=False)

        scanner.scan_dockerfiles()
        assert scanned == ["Dockerfile"]
