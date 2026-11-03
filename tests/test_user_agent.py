import json

import pytest
import requests

from socket_basics.core.config import Config, load_socket_basics_config
from socket_basics.socket_basics import SecurityScanner
from socket_basics.version import __version__


@pytest.fixture
def captured_requests(monkeypatch):
    captured = []

    def send(session, request, **kwargs):
        captured.append(request)
        if request.path_url == "/v0/organizations":
            organization = {"slug": "test-org", "plan": "enterprise"}
            body = {"organizations": {"test-org": organization}}
        elif request.method == "POST":
            body = {
                "id": "test-scan",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "organization_id": "test-org",
                "repository_id": "test-repo",
                "branch": "main",
                "html_report_url": "https://socket.dev/test-scan",
            }
        else:
            body = {}
        response = requests.Response()
        response.status_code = 201 if request.method == "POST" else 200
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps(body).encode()
        return response

    monkeypatch.setattr(requests.sessions.Session, "send", send)
    monkeypatch.setenv("SOCKET_SECURITY_API_KEY", "synthetic-test-token")
    monkeypatch.delenv("SKIP_SOCKET_SUBMISSION", raising=False)
    return captured


def test_dashboard_configuration_requests_identify_basics(captured_requests):
    config = load_socket_basics_config(org_slug_override="test-org")

    assert config["socket_org"] == "test-org"
    assert [request.path_url for request in captured_requests] == [
        "/v0/organizations",
        "/v0/orgs/test-org/settings/socket-basics",
    ]
    assert all(
        request.headers["User-Agent"] == f"socket-basics/{__version__}"
        for request in captured_requests
    )


def test_scan_upload_identifies_basics(captured_requests, tmp_path):
    facts = tmp_path / ".socket.facts.json"
    components = [{"type": "file", "name": "test"}]
    facts.write_text(json.dumps({"components": components}))
    config = Config(
        {
            "workspace": str(tmp_path),
            "socket_api_key": "synthetic-test-token",
            "socket_org": "test-org",
            "repo": "test-repo",
            "branch": "main",
        }
    )

    SecurityScanner(config).submit_socket_facts(facts, {})

    assert len(captured_requests) == 1
    request = captured_requests[0]
    assert request.method == "POST"
    assert request.path_url.startswith("/v0/orgs/test-org/full-scans?")
    assert request.headers["User-Agent"] == f"socket-basics/{__version__}"
    assert request.headers["Authorization"].startswith("Basic ")
    assert request.headers["Content-Type"].startswith("multipart/form-data;")
