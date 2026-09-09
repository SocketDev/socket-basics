import tomllib

from scripts import check_release_docs, prep_release


def test_current_release_references_match_canonical_version() -> None:
    version = check_release_docs.read_canonical_version()
    covered_paths = set()

    for path in check_release_docs.DOC_PATHS:
        references = check_release_docs.find_references(path.read_text())
        if not references:
            continue
        covered_paths.add(path.relative_to(check_release_docs.REPO_ROOT).as_posix())
        assert {reference.version for reference in references} == {version}

    assert {
        "README.md",
        "docs/github-action.md",
        "docs/local-install-docker.md",
        "docs/pre-commit-hook.md",
    } <= covered_paths


def test_render_content_updates_only_socket_basics_release_references() -> None:
    content = """\
uses: SocketDev/socket-basics@v2.0.3
image: ghcr.io/socketdev/socket-basics:2.0.3
uses: actions/checkout@abc123 # v6.0.2
uses: aquasecurity/trivy-action@v0.35.0
TRIVY_VERSION=0.73.0
"""

    rendered, changed = check_release_docs.render_content(content, "3.0.0")

    assert changed == 2
    assert "SocketDev/socket-basics@v3.0.0" in rendered
    assert "ghcr.io/socketdev/socket-basics:3.0.0" in rendered
    assert "actions/checkout@abc123 # v6.0.2" in rendered
    assert "aquasecurity/trivy-action@v0.35.0" in rendered
    assert "TRIVY_VERSION=0.73.0" in rendered


def test_floating_major_tag_is_treated_as_stale() -> None:
    """The action publishes no `@v2`-style tag, so such references must be rewritten."""
    content = "- uses: SocketDev/socket-basics@v2\n  # prose about `@v2` floating tags stays\n"

    rendered, changed = check_release_docs.render_content(content, "3.1.0")

    assert changed == 1
    assert "uses: SocketDev/socket-basics@v3.1.0" in rendered
    assert "prose about `@v2` floating tags stays" in rendered
    # an exact release is matched once, not also as a floating major
    assert len(check_release_docs.find_references("SocketDev/socket-basics@v3.1.0")) == 1


def test_tool_pins_come_from_dockerfile_and_docs_match() -> None:
    pins = check_release_docs.read_tool_pins()

    assert set(pins) == {"trufflehog", "opengrep", "trivy"}
    assert all(not v.startswith("v") for v in pins.values())
    assert check_release_docs.check_docs(check_release_docs.read_canonical_version()) == []


def test_render_tool_references_only_touches_that_tool() -> None:
    content = """\
docker pull trufflesecurity/trufflehog:3.93.8
wget .../trufflehog/releases/download/v3.93.8/trufflehog_3.93.8_linux_amd64.tar.gz
"com.socket.opengrep-version": "v1.16.5"
uses: SocketDev/socket-basics@v3.1.0
"""

    rendered, changed = check_release_docs.render_content(
        content, "3.96.0", check_release_docs.TOOL_REFERENCE_PATTERNS["trufflehog"]
    )

    assert changed == 3
    assert "trufflesecurity/trufflehog:3.96.0" in rendered
    assert "download/v3.96.0/trufflehog_3.96.0_linux_amd64" in rendered
    assert '"com.socket.opengrep-version": "v1.16.5"' in rendered
    assert "SocketDev/socket-basics@v3.1.0" in rendered


def test_canonical_version_matches_pyproject() -> None:
    pyproject = tomllib.loads(check_release_docs.PYPROJECT_PATH.read_text())

    assert check_release_docs.read_canonical_version() == pyproject["project"]["version"]


def test_release_prep_invokes_docs_sync_in_dry_run(monkeypatch) -> None:
    calls = []

    def fake_run(command, *, cwd, check):
        calls.append((command, cwd, check))

    monkeypatch.setattr(prep_release.subprocess, "run", fake_run)

    prep_release._sync_release_docs("3.1.0", dry_run=True)

    command, cwd, check = calls[0]
    assert command[-4:] == ["--write", "--version", "3.1.0", "--dry-run"]
    assert cwd == prep_release.ROOT
    assert check is True
