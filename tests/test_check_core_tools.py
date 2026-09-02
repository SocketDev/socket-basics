import re

from scripts import check_core_tools


def test_trivy_release_discovery_uses_socket_ghcr_package(monkeypatch):
    packages = []

    def fake_ghcr_latest(org, package):
        packages.append((org, package))
        return "0.73.0"

    monkeypatch.setattr(check_core_tools, "_ghcr_latest", fake_ghcr_latest)

    trivy = next(tool for tool in check_core_tools.build_tools() if tool.key == "trivy")

    assert trivy.discover_latest() == "0.73.0"
    assert packages == [("SocketDev", "trivy")]


def test_ghcr_latest_ignores_floating_and_prerelease_tags(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        check_core_tools,
        "_get_json",
        lambda *_args: [
            {"metadata": {"container": {"tags": ["latest", "0.73.0"]}}},
            {"metadata": {"container": {"tags": ["v0.74.0-rc.1"]}}},
            {"metadata": {"container": {"tags": ["v0.72.0"]}}},
        ],
    )

    assert check_core_tools._ghcr_latest("SocketDev", "trivy") == "0.73.0"


def test_every_socket_tool_is_named_and_pinned_unambiguously():
    tools = {tool.key: tool for tool in check_core_tools.build_tools()}

    assert tools["socket_sdk"].label == "Socket SDK (socket-sdk-python)"
    assert tools["socket_python_cli"].label == "Socket Python CLI (socket-python-cli)"
    assert tools["socket_npm_cli"].label == "Socket npm CLI (socket-cli)"

    # Multiple images may carry a tool, but they must all agree on one exact pin.
    assert len(tools["socket_sdk"].read_pinned()) == 1
    assert len(tools["socket_python_cli"].read_pinned()) == 1
    assert len(tools["socket_npm_cli"].read_pinned()) == 1


def test_socket_cli_installs_are_version_pinned():
    for dockerfile in check_core_tools.DOCKERFILES:
        contents = dockerfile.read_text()
        if "npm install -g" in contents:
            assert '"socket@${SOCKET_NPM_CLI_VERSION}"' in contents
            assert re.search(r"^ARG SOCKET_NPM_CLI_VERSION=\d+\.\d+\.\d+$", contents, re.MULTILINE)

    app_tests = (check_core_tools.REPO_ROOT / "app_tests" / "Dockerfile").read_text()
    # Collapse line continuations so the pin assertion is not sensitive to how
    # the RUN is wrapped or to intervening flags (e.g. --refresh-package).
    app_tests_joined = re.sub(r"\\\s*\n\s*", " ", app_tests)
    assert re.search(
        r'uv tool install [^\n]*"socketsecurity==\$\{SOCKET_PYTHON_CLI_VERSION\}"',
        app_tests_joined,
    )
    assert re.search(r"^ARG SOCKET_PYTHON_CLI_VERSION=\d+\.\d+\.\d+$", app_tests, re.MULTILINE)


def test_trivy_pin_comes_from_socket_image_tag():
    tools = {tool.key: tool for tool in check_core_tools.build_tools()}

    assert tools["trivy"].read_pinned() == ["0.73.0"]
    assert all(
        "ARG TRIVY_IMAGE=ghcr.io/socketdev/trivy:" in dockerfile.read_text()
        for dockerfile in check_core_tools.DOCKERFILES
    )


def test_incomplete_discovery_report_cannot_be_mistaken_for_no_drift():
    report = check_core_tools.render_markdown([], token_present=False, discovery_complete=False)

    assert "Latest-version discovery incomplete" in report
    assert "must not be used to resolve the drift issue" in report
