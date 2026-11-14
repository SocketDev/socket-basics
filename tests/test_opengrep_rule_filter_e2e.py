"""End-to-end check that ``<language>_enabled_rules`` narrows a real OpenGrep run.

Asserting on the command line is not enough here: OpenGrep prefixes the ID of
every rule it loads from a ``--config`` path with that path's directories, so a
command that looks right can still run every rule. These tests run the real
binary on the bundled JavaScript rules and check which rules report findings.

Skipped when ``opengrep`` is not on PATH, unless CI requires it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from socket_basics.core.config import Config
from socket_basics.core.connector.opengrep import OpenGrepScanner

REQUIRE_OPENGREP_ENV = "SOCKET_BASICS_REQUIRE_OPENGREP"

_HAVE_OPENGREP = shutil.which("opengrep") is not None
if not _HAVE_OPENGREP and os.environ.get(REQUIRE_OPENGREP_ENV):
    pytest.fail(
        f"{REQUIRE_OPENGREP_ENV} is set but opengrep is not on PATH", pytrace=False
    )

pytestmark = pytest.mark.skipif(
    not _HAVE_OPENGREP,
    reason="opengrep is not installed; rule filter end-to-end tests skipped",
)

# Reports js-code-injection-eval, js-weak-hash-md5, js-debugger-statement and
# others with the bundled javascript_typescript.yml rules.
APP_JS = """\
const crypto = require("crypto");
function handle(req) {
  eval(req.query.code);
  return crypto.createHash("md5").update(req.body).digest("hex");
}
debugger;
"""

_real_run = subprocess.run


def _scan(tmp_path: Path, monkeypatch, **overrides) -> set[str]:
    """Run the OpenGrep connector over APP_JS and return the reported rule IDs."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.js").write_text(APP_JS, encoding="utf-8")

    reported: set[str] = set()

    def _run_and_record(cmd, **kwargs):
        result = _real_run(cmd, **kwargs)
        out_file = Path(cmd[cmd.index("--output") + 1])
        for r in json.loads(out_file.read_text() or "{}").get("results", []):
            reported.add(r["check_id"].rsplit(".", 1)[-1])
        return result

    monkeypatch.setattr(
        "socket_basics.core.connector.opengrep.subprocess.run", _run_and_record
    )

    config = Config(
        {
            "workspace": str(workspace),
            "output_dir": str(workspace),
            "javascript_sast_enabled": True,
            "all_languages_enabled": False,
            "all_rules_enabled": False,
            "verbose": False,
            **overrides,
        }
    )
    scanner = OpenGrepScanner(config)
    scanner._convert_to_socket_facts = lambda _: {"components": []}
    scanner.generate_notifications = lambda _: {}
    scanner.scan()
    return reported


def test_without_an_allowlist_every_matching_rule_reports(tmp_path, monkeypatch):
    reported = _scan(tmp_path, monkeypatch, javascript_enabled_rules="")
    assert {"js-code-injection-eval", "js-weak-hash-md5", "js-debugger-statement"} <= reported


def test_allowlist_limits_findings_to_enabled_rules(tmp_path, monkeypatch):
    reported = _scan(
        tmp_path,
        monkeypatch,
        javascript_enabled_rules="js-code-injection-eval,js-weak-hash-md5",
    )
    assert reported == {"js-code-injection-eval", "js-weak-hash-md5"}


def test_all_rules_enabled_overrides_the_allowlist(tmp_path, monkeypatch):
    reported = _scan(
        tmp_path,
        monkeypatch,
        javascript_enabled_rules="js-code-injection-eval",
        all_rules_enabled=True,
    )
    assert "js-debugger-statement" in reported
