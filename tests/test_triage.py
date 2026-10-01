"""Tests for socket_basics.core.triage module."""

import logging
import pytest
from socket_basics.core.triage import (
    TriageFilter,
    fetch_triage_data,
    stream_full_scan_alerts,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

ARTIFACT_ID = "abc123"


def _make_component(
    comp_id: str = ARTIFACT_ID,
    name: str = "lodash",
    comp_type: str = "npm",
    version: str = "4.17.21",
    alerts: list | None = None,
) -> dict:
    return {
        "id": comp_id,
        "name": name,
        "version": version,
        "type": comp_type,
        "qualifiers": {"ecosystem": comp_type, "version": version},
        "alerts": alerts or [],
    }


def _make_local_alert(
    title: str = "badEncoding",
    alert_type: str = "badEncoding",
    severity: str = "high",
    rule_id: str | None = None,
    detector_name: str | None = None,
    cve_id: str | None = None,
    generated_by: str = "opengrep-python",
) -> dict:
    props: dict = {}
    if rule_id:
        props["ruleId"] = rule_id
    if detector_name:
        props["detectorName"] = detector_name
    if cve_id:
        props["cveId"] = cve_id
    return {
        "title": title,
        "type": alert_type,
        "severity": severity,
        "generatedBy": generated_by,
        "props": props,
    }


def _make_triage_entry(
    alert_key: str,
    state: str = "ignore",
) -> dict:
    return {
        "uuid": "test-uuid",
        "alert_key": alert_key,
        "state": state,
        "note": "",
        "organization_id": "test-org",
    }


def _make_artifact_alerts(
    artifact_id: str = ARTIFACT_ID,
    alerts: list[dict] | None = None,
    name: str = "lodash",
    version: str = "4.17.21",
    pkg_type: str = "npm",
) -> dict[str, list[dict]]:
    """Build an artifact_alerts mapping with enriched _artifact metadata."""
    meta = {
        "artifact_id": artifact_id,
        "artifact_name": name,
        "artifact_version": version,
        "artifact_type": pkg_type,
        "artifact_namespace": None,
        "artifact_subpath": None,
    }
    enriched = [{**a, "_artifact": meta} for a in (alerts or [])]
    return {artifact_id: enriched}


def _socket_alert(key: str, alert_type: str) -> dict:
    """Create a minimal Socket alert dict (as returned by the full scan stream)."""
    return {"key": key, "type": alert_type}


# ---------------------------------------------------------------------------
# TriageFilter construction
# ---------------------------------------------------------------------------

class TestTriageFilterInit:
    def test_builds_triaged_keys_for_ignore(self):
        entries = [_make_triage_entry("hash-1", state="ignore")]
        artifact_alerts = _make_artifact_alerts(
            alerts=[_socket_alert("hash-1", "badEncoding")]
        )
        tf = TriageFilter(entries, artifact_alerts)
        assert "hash-1" in tf.triaged_keys

    def test_builds_triaged_keys_for_monitor(self):
        entries = [_make_triage_entry("hash-2", state="monitor")]
        artifact_alerts = _make_artifact_alerts(
            alerts=[_socket_alert("hash-2", "cve")]
        )
        tf = TriageFilter(entries, artifact_alerts)
        assert "hash-2" in tf.triaged_keys

    def test_excludes_block_warn_inherit_states(self):
        entries = [
            _make_triage_entry("h1", state="block"),
            _make_triage_entry("h2", state="warn"),
            _make_triage_entry("h3", state="inherit"),
        ]
        artifact_alerts = _make_artifact_alerts(
            alerts=[
                _socket_alert("h1", "a"),
                _socket_alert("h2", "b"),
                _socket_alert("h3", "c"),
            ]
        )
        tf = TriageFilter(entries, artifact_alerts)
        assert tf.triaged_keys == set()

    def test_builds_triaged_by_artifact_mapping(self):
        entries = [_make_triage_entry("hash-1", state="ignore")]
        artifact_alerts = _make_artifact_alerts(
            artifact_id="art-1",
            alerts=[_socket_alert("hash-1", "badEncoding")],
        )
        tf = TriageFilter(entries, artifact_alerts)
        assert "art-1" in tf._triaged_by_artifact
        assert "badEncoding" in tf._triaged_by_artifact["art-1"]

    def test_no_entries_means_empty_triaged_keys(self):
        tf = TriageFilter([], {})
        assert tf.triaged_keys == set()

    def test_entry_without_alert_key_ignored(self):
        entries = [{"state": "ignore", "alert_key": None}]
        tf = TriageFilter(entries, {})
        assert tf.triaged_keys == set()


# ---------------------------------------------------------------------------
# TriageFilter._local_alert_is_triaged
# ---------------------------------------------------------------------------

class TestLocalAlertIsTriaged:
    def test_direct_type_match(self):
        triaged_types = {"badEncoding"}
        alert = _make_local_alert(alert_type="badEncoding")
        assert TriageFilter._local_alert_is_triaged(alert, triaged_types) is True

    def test_direct_type_no_match(self):
        triaged_types = {"badEncoding"}
        alert = _make_local_alert(alert_type="cve")
        assert TriageFilter._local_alert_is_triaged(alert, triaged_types) is False

    def test_generic_type_falls_back_to_title(self):
        triaged_types = {"badEncoding"}
        alert = _make_local_alert(title="badEncoding", alert_type="generic")
        assert TriageFilter._local_alert_is_triaged(alert, triaged_types) is True

    def test_vulnerability_type_falls_back_to_cve(self):
        triaged_types = {"CVE-2024-1234"}
        alert = _make_local_alert(
            title="Some Vuln", alert_type="vulnerability", cve_id="CVE-2024-1234"
        )
        assert TriageFilter._local_alert_is_triaged(alert, triaged_types) is True

    def test_generic_type_falls_back_to_rule_id(self):
        triaged_types = {"python.lang.security.audit.xss"}
        alert = _make_local_alert(
            title="XSS", alert_type="generic",
            rule_id="python.lang.security.audit.xss",
        )
        assert TriageFilter._local_alert_is_triaged(alert, triaged_types) is True

    def test_generic_type_falls_back_to_detector_name(self):
        triaged_types = {"AWS"}
        alert = _make_local_alert(
            title="AWS Key", alert_type="generic", detector_name="AWS"
        )
        assert TriageFilter._local_alert_is_triaged(alert, triaged_types) is True

    def test_no_fallback_candidates_returns_false(self):
        triaged_types = {"something"}
        alert = {"type": "generic", "props": {}}
        assert TriageFilter._local_alert_is_triaged(alert, triaged_types) is False


# ---------------------------------------------------------------------------
# TriageFilter.filter_components
# ---------------------------------------------------------------------------

class TestFilterComponents:
    def test_removes_triaged_alert_by_type(self):
        """Component ID matches artifact, triaged alert type matches local alert type."""
        entries = [_make_triage_entry("hash-1")]
        artifact_alerts = _make_artifact_alerts(
            alerts=[_socket_alert("hash-1", "badEncoding")]
        )
        tf = TriageFilter(entries, artifact_alerts)

        comp = _make_component(
            comp_id=ARTIFACT_ID,
            alerts=[
                _make_local_alert(alert_type="badEncoding"),
                _make_local_alert(title="kept", alert_type="otherIssue"),
            ],
        )
        filtered, count = tf.filter_components([comp])
        assert count == 1
        assert len(filtered) == 1
        assert len(filtered[0]["alerts"]) == 1
        assert filtered[0]["alerts"][0]["title"] == "kept"

    def test_removes_component_when_all_alerts_triaged(self):
        entries = [_make_triage_entry("hash-1")]
        artifact_alerts = _make_artifact_alerts(
            alerts=[_socket_alert("hash-1", "badEncoding")]
        )
        tf = TriageFilter(entries, artifact_alerts)

        comp = _make_component(
            comp_id=ARTIFACT_ID,
            alerts=[_make_local_alert(alert_type="badEncoding")],
        )
        filtered, count = tf.filter_components([comp])
        assert count == 1
        assert len(filtered) == 0

    def test_no_triage_entries_returns_original(self):
        tf = TriageFilter([], {})
        comp = _make_component(alerts=[_make_local_alert()])
        filtered, count = tf.filter_components([comp])
        assert count == 0
        assert filtered == [comp]

    def test_component_id_mismatch_keeps_all_alerts(self):
        """When local component ID doesn't match any artifact, nothing is filtered."""
        entries = [_make_triage_entry("hash-1")]
        artifact_alerts = _make_artifact_alerts(
            artifact_id="different-artifact",
            alerts=[_socket_alert("hash-1", "badEncoding")],
        )
        tf = TriageFilter(entries, artifact_alerts)

        comp = _make_component(
            comp_id="unrelated-comp-id",
            alerts=[_make_local_alert(alert_type="badEncoding")],
        )
        filtered, count = tf.filter_components([comp])
        assert count == 0
        assert len(filtered) == 1

    def test_multiple_components_mixed(self):
        entries = [_make_triage_entry("hash-1")]
        artifact_alerts = _make_artifact_alerts(
            artifact_id="art-a",
            alerts=[_socket_alert("hash-1", "badEncoding")],
        )
        tf = TriageFilter(entries, artifact_alerts)

        comp1 = _make_component(
            comp_id="art-a", name="a",
            alerts=[_make_local_alert(alert_type="badEncoding")],
        )
        comp2 = _make_component(
            comp_id="art-b", name="b",
            alerts=[_make_local_alert(alert_type="otherIssue")],
        )
        comp3 = _make_component(
            comp_id="art-a", name="c",
            alerts=[
                _make_local_alert(alert_type="badEncoding"),
                _make_local_alert(title="keepMe", alert_type="keepMe"),
            ],
        )

        filtered, count = tf.filter_components([comp1, comp2, comp3])
        assert count == 2
        assert len(filtered) == 2
        names = [c["name"] for c in filtered]
        assert "a" not in names
        assert "b" in names
        assert "c" in names

    def test_multiple_triaged_alert_types_on_same_artifact(self):
        entries = [
            _make_triage_entry("hash-1", state="ignore"),
            _make_triage_entry("hash-2", state="monitor"),
        ]
        artifact_alerts = _make_artifact_alerts(
            alerts=[
                _socket_alert("hash-1", "badEncoding"),
                _socket_alert("hash-2", "cve"),
            ],
        )
        tf = TriageFilter(entries, artifact_alerts)

        comp = _make_component(
            comp_id=ARTIFACT_ID,
            alerts=[
                _make_local_alert(alert_type="badEncoding"),
                _make_local_alert(alert_type="cve"),
                _make_local_alert(title="safe", alert_type="safe"),
            ],
        )
        filtered, count = tf.filter_components([comp])
        assert count == 2
        assert len(filtered[0]["alerts"]) == 1
        assert filtered[0]["alerts"][0]["type"] == "safe"


# ---------------------------------------------------------------------------
# stream_full_scan_alerts
# ---------------------------------------------------------------------------

class TestStreamFullScanAlerts:
    def test_parses_artifacts_and_alerts(self):
        class FakeFullscansAPI:
            def stream(self, org, scan_id, use_types=False):
                return {
                    "artifact-1": {
                        "name": "lodash",
                        "version": "4.17.21",
                        "type": "npm",
                        "namespace": None,
                        "alerts": [
                            {"key": "hash-a", "type": "badEncoding"},
                            {"key": "hash-b", "type": "cve"},
                        ],
                    },
                    "artifact-2": {
                        "name": "express",
                        "version": "4.18.0",
                        "type": "npm",
                        "namespace": None,
                        "alerts": [],
                    },
                }

        class FakeSDK:
            fullscans = FakeFullscansAPI()

        result = stream_full_scan_alerts(FakeSDK(), "my-org", "scan-123")
        assert "artifact-1" in result
        assert "artifact-2" not in result  # empty alerts filtered out
        assert len(result["artifact-1"]) == 2
        assert result["artifact-1"][0]["key"] == "hash-a"
        assert result["artifact-1"][0]["_artifact"]["artifact_name"] == "lodash"

    def test_skips_alerts_without_key(self):
        class FakeFullscansAPI:
            def stream(self, org, scan_id, use_types=False):
                return {
                    "art-1": {
                        "name": "pkg",
                        "version": "1.0.0",
                        "type": "npm",
                        "alerts": [
                            {"key": "hash-a", "type": "badEncoding"},
                            {"type": "noKey"},  # missing key
                            {"key": "", "type": "emptyKey"},  # empty key
                        ],
                    },
                }

        class FakeSDK:
            fullscans = FakeFullscansAPI()

        result = stream_full_scan_alerts(FakeSDK(), "org", "scan")
        assert len(result["art-1"]) == 1

    def test_access_denied_returns_empty(self, caplog):
        class APIAccessDenied(Exception):
            pass

        class FakeFullscansAPI:
            def stream(self, org, scan_id, use_types=False):
                raise APIAccessDenied("Forbidden")

        class FakeSDK:
            fullscans = FakeFullscansAPI()

        with caplog.at_level(logging.DEBUG):
            result = stream_full_scan_alerts(FakeSDK(), "org", "scan")

        assert result == {}
        info_msgs = [r for r in caplog.records if r.levelno == logging.INFO]
        assert any("access denied" in m.message.lower() for m in info_msgs)

    def test_api_error_returns_empty(self):
        class FakeFullscansAPI:
            def stream(self, org, scan_id, use_types=False):
                raise RuntimeError("Network failure")

        class FakeSDK:
            fullscans = FakeFullscansAPI()

        result = stream_full_scan_alerts(FakeSDK(), "org", "scan")
        assert result == {}

    def test_non_dict_response_returns_empty(self):
        class FakeFullscansAPI:
            def stream(self, org, scan_id, use_types=False):
                return "unexpected string"

        class FakeSDK:
            fullscans = FakeFullscansAPI()

        result = stream_full_scan_alerts(FakeSDK(), "org", "scan")
        assert result == {}

    def test_subpath_handling(self):
        """Supports both camelCase and lowercase subpath field names."""
        class FakeFullscansAPI:
            def stream(self, org, scan_id, use_types=False):
                return {
                    "art-1": {
                        "name": "pkg",
                        "version": "1.0",
                        "type": "npm",
                        "subPath": "src/lib",
                        "alerts": [{"key": "k1", "type": "t1"}],
                    },
                }

        class FakeSDK:
            fullscans = FakeFullscansAPI()

        result = stream_full_scan_alerts(FakeSDK(), "org", "scan")
        assert result["art-1"][0]["_artifact"]["artifact_subpath"] == "src/lib"


# ---------------------------------------------------------------------------
# fetch_triage_data
# ---------------------------------------------------------------------------

class TestFetchTriageData:
    def test_single_page(self):
        class FakeTriageAPI:
            def list_alert_triage(self, org, params):
                return {"results": [{"alert_key": "a", "state": "ignore"}], "nextPage": None}

        class FakeSDK:
            triage = FakeTriageAPI()

        entries = fetch_triage_data(FakeSDK(), "my-org")
        assert len(entries) == 1
        assert entries[0]["alert_key"] == "a"

    def test_pagination(self):
        class FakeTriageAPI:
            def __init__(self):
                self.call_count = 0

            def list_alert_triage(self, org, params):
                self.call_count += 1
                if params.get("page") == 1:
                    return {"results": [{"alert_key": "a"}], "nextPage": 2}
                return {"results": [{"alert_key": "b"}], "nextPage": None}

        class FakeSDK:
            triage = FakeTriageAPI()

        entries = fetch_triage_data(FakeSDK(), "my-org")
        assert len(entries) == 2

    def test_api_error_returns_partial(self):
        class FakeTriageAPI:
            def __init__(self):
                self.calls = 0

            def list_alert_triage(self, org, params):
                self.calls += 1
                if self.calls == 1:
                    return {"results": [{"alert_key": "a"}], "nextPage": 2}
                raise RuntimeError("API error")

        class FakeSDK:
            triage = FakeTriageAPI()

        entries = fetch_triage_data(FakeSDK(), "my-org")
        assert len(entries) == 1

    def test_access_denied_returns_empty_and_logs_info(self, caplog):
        """Insufficient permissions should log an info message (not an error) and return empty."""

        class APIAccessDenied(Exception):
            pass

        class FakeTriageAPI:
            def list_alert_triage(self, org, params):
                raise APIAccessDenied("Insufficient permissions.")

        class FakeSDK:
            triage = FakeTriageAPI()

        with caplog.at_level(logging.DEBUG):
            entries = fetch_triage_data(FakeSDK(), "my-org")

        assert entries == []
        info_messages = [r for r in caplog.records if r.levelno == logging.INFO]
        assert any("access denied" in m.message.lower() for m in info_messages)
        error_messages = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert not error_messages


# ---------------------------------------------------------------------------
# SecurityScanner._connector_name_from_generated_by
# ---------------------------------------------------------------------------

class TestConnectorNameMapping:
    def test_opengrep_variants(self):
        from socket_basics.socket_basics import SecurityScanner
        assert SecurityScanner._connector_name_from_generated_by("opengrep-python") == "opengrep"
        assert SecurityScanner._connector_name_from_generated_by("sast-generic") == "opengrep"

    def test_trufflehog(self):
        from socket_basics.socket_basics import SecurityScanner
        assert SecurityScanner._connector_name_from_generated_by("trufflehog") == "trufflehog"

    def test_trivy_variants(self):
        from socket_basics.socket_basics import SecurityScanner
        assert SecurityScanner._connector_name_from_generated_by("trivy-dockerfile") == "trivy"
        assert SecurityScanner._connector_name_from_generated_by("trivy-image") == "trivy"
        assert SecurityScanner._connector_name_from_generated_by("trivy-npm") == "trivy"

    def test_socket_tier1(self):
        from socket_basics.socket_basics import SecurityScanner
        assert SecurityScanner._connector_name_from_generated_by("socket-tier1") == "socket_tier1"

    def test_unknown_returns_none(self):
        from socket_basics.socket_basics import SecurityScanner
        assert SecurityScanner._connector_name_from_generated_by("unknown-tool") is None


# ---------------------------------------------------------------------------
# SecurityScanner._inject_triage_summary
# ---------------------------------------------------------------------------

class TestInjectTriageSummary:
    def test_injects_after_heading(self):
        from socket_basics.socket_basics import SecurityScanner

        notifications = {
            "github_pr": [
                {
                    "title": "SAST Findings",
                    "content": "<!-- sast start -->\n# SAST Python Findings\n### Summary\nSome content\n<!-- sast end -->",
                }
            ]
        }
        SecurityScanner._inject_triage_summary(notifications, 3, "https://socket.dev/scan/123")

        content = notifications["github_pr"][0]["content"]
        assert "3 finding(s) triaged" in content
        assert "Socket Dashboard" in content
        lines = content.split("\n")
        heading_idx = next(i for i, l in enumerate(lines) if l.strip().startswith("# "))
        summary_idx = next(i for i, l in enumerate(lines) if "triaged" in l)
        assert summary_idx > heading_idx

    def test_no_github_pr_key_is_noop(self):
        from socket_basics.socket_basics import SecurityScanner

        notifications = {"slack": [{"title": "t", "content": "c"}]}
        SecurityScanner._inject_triage_summary(notifications, 5, "")
        assert "github_pr" not in notifications

    def test_uses_default_dashboard_link(self):
        from socket_basics.socket_basics import SecurityScanner

        notifications = {
            "github_pr": [{"title": "t", "content": "# Title\nBody"}]
        }
        SecurityScanner._inject_triage_summary(notifications, 1, "")
        assert "https://socket.dev/dashboard" in notifications["github_pr"][0]["content"]
