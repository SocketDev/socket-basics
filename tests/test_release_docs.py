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
