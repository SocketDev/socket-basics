"""Tests for socket_basics.core.triage module."""

import pytest
from socket_basics.core.triage import TriageFilter, fetch_triage_data


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_component(
    name: str = "lodash",
    comp_type: str = "npm",
    version: str = "4.17.21",
    alerts: list | None = None,
) -> dict:
    return {
        "id": f"pkg:{comp_type}/{name}@{version}",
        "name": name,
        "version": version,
        "type": comp_type,
        "qualifiers": {"ecosystem": comp_type, "version": version},
        "alerts": alerts or [],
    }


def _make_alert(
    title: str = "badEncoding",
    alert_type: str = "supplyChainRisk",
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
    package_name: str | None = None,
    package_type: str | None = None,
    package_version: str | None = None,
    package_namespace: str | None = None,
) -> dict:
    return {
        "uuid": "test-uuid",
        "alert_key": alert_key,
        "state": state,
        "package_name": package_name,
        "package_type": package_type,
        "package_version": package_version,
        "package_namespace": package_namespace,
        "note": "",
        "organization_id": "test-org",
    }


# ---------------------------------------------------------------------------
# TriageFilter.is_alert_triaged
# ---------------------------------------------------------------------------

class TestIsAlertTriaged:
    """Tests for the alert matching logic."""

    def test_broad_match_by_title(self):
        """Triage entry with no package info matches any component with matching alert_key."""
        entry = _make_triage_entry(alert_key="badEncoding")
        tf = TriageFilter([entry])
        comp = _make_component()
        alert = _make_alert(title="badEncoding")
        assert tf.is_alert_triaged(comp, alert) is True

    def test_broad_match_by_rule_id(self):
        entry = _make_triage_entry(alert_key="python.lang.security.audit.xss")
        tf = TriageFilter([entry])
        comp = _make_component()
        alert = _make_alert(title="XSS Vulnerability", rule_id="python.lang.security.audit.xss")
        assert tf.is_alert_triaged(comp, alert) is True

    def test_broad_match_by_detector_name(self):
        entry = _make_triage_entry(alert_key="AWS")
        tf = TriageFilter([entry])
        comp = _make_component()
        alert = _make_alert(title="AWS Key Detected", detector_name="AWS")
        assert tf.is_alert_triaged(comp, alert) is True

    def test_broad_match_by_cve(self):
        entry = _make_triage_entry(alert_key="CVE-2024-1234")
        tf = TriageFilter([entry])
        comp = _make_component()
        alert = _make_alert(title="Some Vuln", cve_id="CVE-2024-1234")
        assert tf.is_alert_triaged(comp, alert) is True

    def test_no_match_different_key(self):
        entry = _make_triage_entry(alert_key="differentRule")
        tf = TriageFilter([entry])
        comp = _make_component()
        alert = _make_alert(title="badEncoding")
        assert tf.is_alert_triaged(comp, alert) is False

    def test_package_scoped_match(self):
        """Triage entry with package info only matches the specific package."""
        entry = _make_triage_entry(
            alert_key="badEncoding",
            package_name="lodash",
            package_type="npm",
        )
        tf = TriageFilter([entry])

        comp_match = _make_component(name="lodash", comp_type="npm")
        comp_no_match = _make_component(name="express", comp_type="npm")
        alert = _make_alert(title="badEncoding")

        assert tf.is_alert_triaged(comp_match, alert) is True
        assert tf.is_alert_triaged(comp_no_match, alert) is False

    def test_package_version_exact_match(self):
        entry = _make_triage_entry(
            alert_key="badEncoding",
            package_name="lodash",
            package_type="npm",
            package_version="4.17.21",
        )
        tf = TriageFilter([entry])

        comp_match = _make_component(name="lodash", comp_type="npm", version="4.17.21")
        comp_no_match = _make_component(name="lodash", comp_type="npm", version="4.17.20")
        alert = _make_alert(title="badEncoding")

        assert tf.is_alert_triaged(comp_match, alert) is True
        assert tf.is_alert_triaged(comp_no_match, alert) is False

    def test_version_wildcard(self):
        entry = _make_triage_entry(
            alert_key="badEncoding",
            package_name="lodash",
            package_type="npm",
            package_version="4.17.*",
        )
        tf = TriageFilter([entry])
        alert = _make_alert(title="badEncoding")

        assert tf.is_alert_triaged(
            _make_component(name="lodash", comp_type="npm", version="4.17.21"), alert
        ) is True
        assert tf.is_alert_triaged(
            _make_component(name="lodash", comp_type="npm", version="4.17.0"), alert
        ) is True
        assert tf.is_alert_triaged(
            _make_component(name="lodash", comp_type="npm", version="4.18.0"), alert
        ) is False

    def test_version_star_matches_all(self):
        entry = _make_triage_entry(
            alert_key="badEncoding",
            package_name="lodash",
            package_type="npm",
            package_version="*",
        )
        tf = TriageFilter([entry])
        alert = _make_alert(title="badEncoding")
        assert tf.is_alert_triaged(
            _make_component(name="lodash", comp_type="npm", version="99.0.0"), alert
        ) is True

    def test_states_block_and_warn_not_suppressed(self):
        """Triage entries with block/warn/inherit states should not filter findings."""
        for state in ("block", "warn", "inherit"):
            entry = _make_triage_entry(alert_key="badEncoding", state=state)
            tf = TriageFilter([entry])
            assert tf.entries == [], f"state={state} should be excluded from filter entries"

    def test_state_monitor_suppressed(self):
        entry = _make_triage_entry(alert_key="badEncoding", state="monitor")
        tf = TriageFilter([entry])
        comp = _make_component()
        alert = _make_alert(title="badEncoding")
        assert tf.is_alert_triaged(comp, alert) is True

    def test_alert_with_no_matchable_keys(self):
        """Alert with no title, type, or relevant props should not match."""
        entry = _make_triage_entry(alert_key="something")
        tf = TriageFilter([entry])
        comp = _make_component()
        alert = {"severity": "high", "props": {}}
        assert tf.is_alert_triaged(comp, alert) is False


# ---------------------------------------------------------------------------
# TriageFilter.filter_components
# ---------------------------------------------------------------------------

class TestFilterComponents:
    def test_removes_triaged_alerts(self):
        entry = _make_triage_entry(alert_key="badEncoding")
        tf = TriageFilter([entry])

        alert_triaged = _make_alert(title="badEncoding")
        alert_kept = _make_alert(title="otherIssue")
        comp = _make_component(alerts=[alert_triaged, alert_kept])

        filtered, count = tf.filter_components([comp])
        assert count == 1
        assert len(filtered) == 1
        assert len(filtered[0]["alerts"]) == 1
        assert filtered[0]["alerts"][0]["title"] == "otherIssue"

    def test_removes_component_when_all_alerts_triaged(self):
        entry = _make_triage_entry(alert_key="badEncoding")
        tf = TriageFilter([entry])

        comp = _make_component(alerts=[_make_alert(title="badEncoding")])
        filtered, count = tf.filter_components([comp])
        assert count == 1
        assert len(filtered) == 0

    def test_no_triage_entries_returns_original(self):
        tf = TriageFilter([])
        comp = _make_component(alerts=[_make_alert()])
        filtered, count = tf.filter_components([comp])
        assert count == 0
        assert filtered is [comp] or filtered == [comp]

    def test_multiple_components_mixed(self):
        entry = _make_triage_entry(alert_key="badEncoding")
        tf = TriageFilter([entry])

        comp1 = _make_component(name="a", alerts=[_make_alert(title="badEncoding")])
        comp2 = _make_component(name="b", alerts=[_make_alert(title="otherIssue")])
        comp3 = _make_component(
            name="c",
            alerts=[
                _make_alert(title="badEncoding"),
                _make_alert(title="keepMe"),
            ],
        )

        filtered, count = tf.filter_components([comp1, comp2, comp3])
        assert count == 2
        assert len(filtered) == 2
        names = [c["name"] for c in filtered]
        assert "a" not in names
        assert "b" in names
        assert "c" in names


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
        # Summary line should appear after the # heading
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
