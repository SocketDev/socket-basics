"""Regression coverage for TruffleHog verification behavior.

``trufflehog_show_unverified`` selects which *result types* TruffleHog returns.
It must never disable verification itself: severity is derived from each
finding's ``Verified`` flag, so a run with verification turned off reports every
secret as unverified/low and nothing ever blocks. Unknown results remain visible
by default because they indicate that verification could not complete.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from socket_basics.core.connector.trufflehog import TruffleHogScanner


def _scanner(
    tmp_path,
    show_unverified,
    *,
    scan_all=True,
    secret_scanning_enabled=True,
):
    values = {
        "secret_scanning_enabled": secret_scanning_enabled,
        "scan_all": scan_all,
        "trufflehog_exclude_dir": "",
        "trufflehog_show_unverified": show_unverified,
    }
    config = SimpleNamespace(workspace=tmp_path, _config=values)
    config.get = lambda key, default=None: values.get(key, default)
    config.get_action_for_severity = lambda severity: {
        "critical": "error",
        "low": "ignore",
    }[severity]
    config.get_scan_targets = lambda: [str(tmp_path)]
    scanner = TruffleHogScanner.__new__(TruffleHogScanner)
    scanner.config = config
    return scanner


def _captured_cmd(tmp_path, monkeypatch, show_unverified):
    invocations = []

    def record_run(cmd, *args, **kwargs):
        invocations.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run", record_run
    )
    _scanner(tmp_path, show_unverified).scan()

    assert len(invocations) == 1
    return invocations[0]


def test_show_unverified_off_requests_high_confidence_results(tmp_path, monkeypatch):
    cmd = _captured_cmd(tmp_path, monkeypatch, show_unverified=False)

    assert "--results=verified,unknown" in cmd
    assert "--no-verification" not in cmd


def test_show_unverified_on_requests_every_result_type(tmp_path, monkeypatch):
    cmd = _captured_cmd(tmp_path, monkeypatch, show_unverified=True)

    assert "--results=verified,unverified,unknown" in cmd
    assert "--no-verification" not in cmd


def test_trufflehog_scan_errors_are_fatal(tmp_path, monkeypatch):
    cmd = _captured_cmd(tmp_path, monkeypatch, show_unverified=False)

    assert "--fail-on-scan-errors" in cmd


def test_string_false_from_a_dashboard_config_excludes_unverified(
    tmp_path, monkeypatch
):
    """A dashboard config is passed through verbatim, so "false" arrives as a string.

    Only the environment loader coerces bool params, and dashboard config
    outranks it. Reading the raw value for truthiness would report unverified
    secrets to someone who explicitly turned them off.
    """
    for raw in ("false", "False", "0", "no"):
        cmd = _captured_cmd(tmp_path, monkeypatch, show_unverified=raw)
        assert "--results=verified,unknown" in cmd, raw


def test_string_true_from_a_dashboard_config_widens_result_types(
    tmp_path, monkeypatch
):
    for raw in ("true", "True", "1", "yes"):
        cmd = _captured_cmd(tmp_path, monkeypatch, show_unverified=raw)
        assert "--results=verified,unverified,unknown" in cmd, raw


def test_unset_setting_defaults_to_high_confidence_results(tmp_path, monkeypatch):
    """An unset action input arrives as an empty string, not as None."""
    for raw in (None, ""):
        cmd = _captured_cmd(tmp_path, monkeypatch, show_unverified=raw)
        assert "--results=verified,unknown" in cmd, repr(raw)


def test_string_false_disables_secret_scanning(tmp_path, monkeypatch):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("TruffleHog should not run when scanning is disabled")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run", unexpected_run
    )

    for raw in ("false", "False", "0", "no"):
        assert _scanner(
            tmp_path,
            show_unverified=False,
            secret_scanning_enabled=raw,
        ).scan() == {}


def test_string_false_scan_all_uses_staged_file_fallback(tmp_path, monkeypatch):
    changed_file = tmp_path / "changed.py"
    changed_file.write_text("print('changed')\n", encoding="utf-8")
    invocations = []

    monkeypatch.setattr(
        "socket_basics.core.config._detect_git_changed_files",
        lambda *args, **kwargs: ["changed.py"],
    )
    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run",
        lambda cmd, *args, **kwargs: (
            invocations.append(cmd)
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )

    _scanner(tmp_path, show_unverified=False, scan_all="false").scan()

    assert len(invocations) == 1
    assert str(changed_file) in invocations[0]
    assert str(tmp_path) not in invocations[0]


def test_detector_selection_is_independent_of_the_setting(tmp_path, monkeypatch):
    """Toggling the setting must not change which detectors run."""
    off = _captured_cmd(tmp_path, monkeypatch, show_unverified=False)
    on = _captured_cmd(tmp_path, monkeypatch, show_unverified=True)

    detectors = [arg for arg in off if arg.startswith("--include-detectors")]
    assert detectors == ["--include-detectors=all"]
    assert detectors == [arg for arg in on if arg.startswith("--include-detectors")]


def _finding(verified, verification_error=None):
    finding = {
        "DetectorName": "AWS",
        "Verified": verified,
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "SourceMetadata": {
            "Data": {"Filesystem": {"file": "config/secrets.py", "line": 12}}
        },
    }
    if verification_error:
        finding["VerificationError"] = verification_error
    return finding


def test_verified_findings_are_critical_and_blocking(tmp_path):
    alert = _scanner(tmp_path, show_unverified=False)._create_alert(_finding(True))

    assert alert["severity"] == "critical"
    assert alert["action"] == "error"
    assert alert["props"]["verified"] is True
    assert alert["props"]["verificationStatus"] == "verified"
    assert alert["props"]["riskLevel"] == "critical"


def test_unverified_findings_are_low_and_nonblocking(tmp_path):
    alert = _scanner(tmp_path, show_unverified=True)._create_alert(_finding(False))

    assert alert["severity"] == "low"
    assert alert["action"] == "ignore"
    assert alert["props"]["verified"] is False
    assert alert["props"]["verificationStatus"] == "unverified"
    assert alert["props"]["riskLevel"] == "low"


def test_unknown_findings_are_low_and_identified_as_unknown(tmp_path):
    alert = _scanner(tmp_path, show_unverified=False)._create_alert(
        _finding(False, verification_error="network is unreachable")
    )

    assert alert["severity"] == "low"
    assert alert["action"] == "ignore"
    assert alert["props"]["verified"] is False
    assert alert["props"]["verificationStatus"] == "unknown"
    assert "validity is unknown" in alert["props"]["detailedReport"]["content"]


def test_a_failed_trufflehog_run_fails_the_scan(tmp_path, monkeypatch):
    """A non-zero exit must not be reported as a clean scan.

    Returning {} here exits green having scanned nothing, so a malformed
    exclude pattern or a broken install silently zeroes out every secret
    finding for the run (CE-347).
    """
    def failing_run(cmd, *args, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="trufflehog: error: flag 'exclude-paths' cannot be repeated",
        )

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run", failing_run
    )

    with pytest.raises(SystemExit) as excinfo:
        _scanner(tmp_path, show_unverified=False).scan()

    message = str(excinfo.value)
    assert "exited 1" in message
    assert "cannot be repeated" in message


def test_a_missing_trufflehog_binary_fails_the_scan(tmp_path, monkeypatch):
    def missing_binary(cmd, *args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "trufflehog")

    monkeypatch.setattr(
        "socket_basics.core.connector.trufflehog.subprocess.run", missing_binary
    )

    with pytest.raises(SystemExit) as excinfo:
        _scanner(tmp_path, show_unverified=False).scan()

    assert "not" in str(excinfo.value).lower()
