import json
import re
import sys
from functools import partial

import pytest

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


def test_ghcr_latest_ranks_socket_rebuilds_above_their_base(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        check_core_tools,
        "_get_json",
        lambda *_args: [
            {"metadata": {"container": {"tags": ["0.73.0-socket.2"]}}},
            {"metadata": {"container": {"tags": ["latest", "0.73.0-socket.10"]}}},
            {"metadata": {"container": {"tags": ["0.73.0"]}}},
            {"metadata": {"container": {"tags": ["v0.74.0-rc.1"]}}},
        ],
    )

    assert check_core_tools._ghcr_latest("SocketDev", "trivy") == "0.73.0-socket.10"


def test_trivy_purl_uses_the_upstream_version_for_socket_rebuilds():
    trivy = next(tool for tool in check_core_tools.build_tools() if tool.key == "trivy")

    assert trivy.purl("0.73.0-socket.1") == "pkg:golang/github.com/aquasecurity/trivy@v0.73.0"
    assert trivy.purl("0.73.0") == "pkg:golang/github.com/aquasecurity/trivy@v0.73.0"


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

    assert tools["trivy"].read_pinned() == ["0.76.1"]
    assert all(
        "ARG TRIVY_IMAGE=ghcr.io/socketdev/trivy:" in dockerfile.read_text()
        for dockerfile in check_core_tools.DOCKERFILES
    )


def test_incomplete_discovery_report_cannot_be_mistaken_for_no_drift():
    report = check_core_tools.render_markdown([], token_present=False, discovery_complete=False)

    assert "Latest-version discovery incomplete" in report
    assert "must not be used to resolve the drift issue" in report


def _raise_from(exc, cause):
    """Raise exc inside an except block for cause, as socketdev does."""
    try:
        raise cause
    except type(cause):
        try:
            raise exc
        except type(exc) as raised:
            return raised


def test_scoring_retries_transient_api_errors_then_succeeds():
    from socketdev.exceptions import APIBadGateway, APIConnectionError

    failures = [APIBadGateway(), APIConnectionError()]
    sleeps = []

    def flaky_analyze(purls, token):
        if failures:
            raise failures.pop(0)
        return {"pkg:npm/socket@1.16.0": {"score": {}}}

    result, error = check_core_tools.score_purls_with_retry(
        ["pkg:npm/socket@1.16.0"], "token", analyze=flaky_analyze, sleep=sleeps.append
    )

    assert result == {"pkg:npm/socket@1.16.0": {"score": {}}}
    assert error is None
    assert sleeps == list(check_core_tools.SCORING_RETRY_DELAYS_SEC)


def test_scoring_gives_up_after_the_last_transient_failure():
    from socketdev.exceptions import APITimeout

    calls = []

    def always_times_out(purls, token):
        calls.append(1)
        raise APITimeout()

    result, error = check_core_tools.score_purls_with_retry(
        ["p"], "token", analyze=always_times_out, sleep=lambda _: None
    )
    assert result == {}
    assert isinstance(error, APITimeout)
    assert len(calls) == len(check_core_tools.SCORING_RETRY_DELAYS_SEC) + 1


@pytest.mark.parametrize(
    "error",
    [
        "APIAccessDenied",
        "APIInsufficientQuota",
        "RuntimeError",
    ],
)
def test_scoring_does_not_retry_deterministic_errors(error):
    import socketdev.exceptions as sdk_errors

    exc_type = getattr(sdk_errors, error, None) or RuntimeError
    calls = []

    def fails(purls, token):
        calls.append(1)
        raise exc_type("nope")

    result, error = check_core_tools.score_purls_with_retry(
        ["p"], "token", analyze=fails, sleep=lambda _: None
    )
    assert result == {}
    assert isinstance(error, exc_type)
    assert len(calls) == 1


def test_describe_api_error_names_messageless_sdk_errors():
    import requests
    from socketdev.exceptions import APIBadGateway, APIConnectionError

    assert check_core_tools.describe_api_error(APIBadGateway()) == "APIBadGateway | HTTP 502"

    exc = _raise_from(APIConnectionError(), requests.ConnectionError("Connection reset by peer"))
    assert check_core_tools.describe_api_error(exc) == (
        "APIConnectionError | caused by ConnectionError: Connection reset by peer"
    )


PINNED = "pkg:npm/socket@1.16.0"
LATEST = "pkg:npm/socket@1.17.0"


def _row(status=None):
    return {"status": status, "alerts": [], "malware": [], "critical": []}


def test_scoring_rescores_only_pending_required_coordinates():
    pending_row = _row("pending")
    calls = []
    sleeps = []

    def analyze(purls, token):
        calls.append(list(purls))
        if len(calls) == 1:
            # Pending row indexed under two keys, as analyze_purls does.
            return {PINNED: pending_row, "pkg:npm/socket@1.16.0#echo": pending_row, LATEST: _row()}
        # The rescored row comes back under a different key than the pending one.
        return {"npm/socket@1.16.0": _row()}

    result, error = check_core_tools.score_purls_with_retry(
        [PINNED, LATEST],
        "token",
        required=frozenset({PINNED}),
        analyze=analyze,
        sleep=sleeps.append,
    )

    assert calls == [[PINNED, LATEST], [PINNED]]
    assert error is None
    assert sleeps == [check_core_tools.SCORING_RETRY_DELAYS_SEC[0]]
    assert check_core_tools._match_analysis(result, PINNED)["status"] is None
    assert pending_row not in result.values()
    assert LATEST in result


def test_scoring_returns_pending_rows_after_the_last_attempt():
    calls = []

    def analyze(purls, token):
        calls.append(1)
        return {PINNED: _row("pending")}

    result, error = check_core_tools.score_purls_with_retry(
        [PINNED], "token", required=frozenset({PINNED}), analyze=analyze, sleep=lambda _: None
    )

    assert len(calls) == len(check_core_tools.SCORING_RETRY_DELAYS_SEC) + 1
    assert error is None
    assert result[PINNED]["status"] == "pending"


def test_scoring_does_not_wait_on_pending_report_only_coordinates():
    calls = []

    def analyze(purls, token):
        calls.append(1)
        return {PINNED: _row(), LATEST: _row("pending")}

    check_core_tools.score_purls_with_retry(
        [PINNED, LATEST],
        "token",
        required=frozenset({PINNED}),
        analyze=analyze,
        sleep=lambda _: pytest.fail("should not wait"),
    )

    assert len(calls) == 1


def test_build_reports_critical_pin_when_another_pin_exhausts_rescores(
    monkeypatch, tmp_path, capsys
):
    from socketdev.exceptions import APIBadGateway

    sdk_purl = "pkg:pypi/socketdev@3.6.3"
    tools = [
        check_core_tools.Tool(
            "npm", "Socket npm CLI", lambda: ["1.16.0"], lambda: None, lambda _: PINNED
        ),
        check_core_tools.Tool(
            "sdk", "Socket SDK", lambda: ["3.6.3"], lambda: None, lambda _: sdk_purl
        ),
    ]
    calls = []

    def analyze(purls, token):
        calls.append(purls)
        if len(calls) == 1:
            return {PINNED: _row("pending"), sdk_purl: {**_row(), "critical": ["test-alert"]}}
        raise APIBadGateway()

    report = tmp_path / "report.json"
    output = tmp_path / "github-output"
    retry = partial(check_core_tools.score_purls_with_retry, analyze=analyze, sleep=lambda _: None)
    monkeypatch.setattr(check_core_tools, "score_purls_with_retry", retry)
    monkeypatch.setattr(check_core_tools, "build_tools", lambda: tools)
    monkeypatch.setenv("SOCKET_API_TOKEN", "test-token")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_core_tools.py",
            "--mode",
            "build",
            "--fail-on-malware",
            "--json-out",
            str(report),
            "--github-output",
            str(output),
        ],
    )

    assert check_core_tools.main() == 1
    assert calls == [[PINNED, sdk_purl], [PINNED], [PINNED]]
    stdout, stderr = capsys.readouterr()
    assert "test-alert" in stdout
    assert "analysis pending upstream" in stdout
    assert "Socket analysis failed: APIBadGateway | HTTP 502" in stderr
    analysis_report = json.loads(report.read_text())
    assert analysis_report["scoring_error"] is True
    assert analysis_report["pending"] == [f"npm {PINNED}"]
    assert analysis_report["findings"][1]["analyses"]["3.6.3"]["critical"] == ["test-alert"]
    assert "critical=true" in output.read_text().splitlines()
