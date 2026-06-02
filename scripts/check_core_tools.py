#!/usr/bin/env python3
"""Supply-chain watch for the four core OSS tools bundled by Socket Basics.

Socket Basics is a thin orchestration layer over four upstream security tools.
Three of them ship as binaries / container images / GitHub releases that
Dependabot cannot cleanly track, and one (Socket's own SCA SDK) is a PyPI
package. This script closes that gap: it discovers the latest upstream version
of each tool, compares it against the version currently pinned in the repo, and
runs Socket supply-chain / malware analysis against the relevant package
coordinates -- dogfooding the `socketdev` SDK that Socket Basics already
depends on.

Tools tracked:
  - opengrep   (SAST engine)        pin: Dockerfile ARG OPENGREP_VERSION
  - trufflehog (secret scanner)     pin: Dockerfile ARG TRUFFLEHOG_VERSION
  - trivy      (container scanner)  pin: Dockerfile ARG TRIVY_VERSION
  - socketdev  (Socket SCA SDK)     pin: uv.lock / pyproject.toml

Two modes (the caller picks via flags):

  --mode build   Analyze the versions CURRENTLY PINNED in the repo. This is the
                 build-time guardrail: if Socket flags malware or a critical
                 alert on a version we are about to bake into the image, fail.

  --mode watch   Additionally discover the latest upstream version and analyze
                 THAT too, reporting drift. This is the scheduled watch: "is
                 there a newer version, and is it safe to adopt?"

Socket analysis requires a Socket API token (env SOCKET_API_TOKEN). Without it,
version discovery + drift reporting still run; the Socket scoring is skipped
with a notice (graceful degradation, mirroring the free/enterprise split in
dependency-review.yml).

Exit code is 0 unless --fail-on-malware is set AND a malware/critical alert is
found. Drift alone never fails the run; it is surfaced via the JSON report and
the `drift`/`malware` GitHub outputs so the workflow decides what to do.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
UV_LOCK = REPO_ROOT / "uv.lock"

# Alert types Socket uses for outright supply-chain compromise / active risk.
# Anything in this set on an analyzed version is treated as malware-grade and
# (with --fail-on-malware) fails the run.
MALWARE_ALERT_TYPES = {
    "malware",
    "gptMalware",
    "gptSecurity",
    "didYouMean",
    "obfuscatedFile",
    "obfuscatedRequire",
    "shellAccess",
    "suspiciousStarActivity",
    "cryptoMiner",
    "installScript",
    "telemetry",
    "trojan",
    "backdoor",
}
CRITICAL_SEVERITIES = {"critical", "high"}


@dataclass
class Tool:
    key: str
    label: str
    # Returns the version string currently pinned in the repo (no leading v
    # normalization -- as written).
    read_pinned: Callable[[], Optional[str]]
    # Returns the latest upstream version tag (as published).
    discover_latest: Callable[[], Optional[str]]
    # Builds a Socket PURL for a given version string.
    purl: Callable[[str], str]
    note: str = ""
    pinned: Optional[str] = None
    latest: Optional[str] = None
    analyses: dict[str, dict[str, Any]] = field(default_factory=dict)


# ── HTTP helpers ──────────────────────────────────────────────────────────────


def _get_json(url: str, token: Optional[str] = None) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "socket-basics-core-tool-watch"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (trusted hosts)
        return json.loads(resp.read().decode("utf-8"))


def _github_latest_release(repo: str) -> Optional[str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    try:
        data = _get_json(f"https://api.github.com/repos/{repo}/releases/latest", token)
        return data.get("tag_name")
    except Exception as exc:  # noqa: BLE001
        print(f"  ! GitHub latest-release lookup failed for {repo}: {exc}", file=sys.stderr)
        return None


def _pypi_latest(package: str) -> Optional[str]:
    try:
        data = _get_json(f"https://pypi.org/pypi/{package}/json")
        return data.get("info", {}).get("version")
    except Exception as exc:  # noqa: BLE001
        print(f"  ! PyPI latest lookup failed for {package}: {exc}", file=sys.stderr)
        return None


# ── pin readers ─────────────────────────────────────────────────────────────


def _read_dockerfile_arg(name: str) -> Optional[str]:
    if not DOCKERFILE.exists():
        return None
    m = re.search(rf"^ARG\s+{re.escape(name)}=(.+)$", DOCKERFILE.read_text(), re.MULTILINE)
    return m.group(1).strip() if m else None


def _read_locked_version(package: str) -> Optional[str]:
    """Read the resolved version of a package from uv.lock."""
    if not UV_LOCK.exists():
        return None
    # uv.lock is TOML with [[package]] blocks: name = "x"\nversion = "y"
    text = UV_LOCK.read_text()
    m = re.search(
        rf'name = "{re.escape(package)}"\s*\nversion = "([^"]+)"',
        text,
    )
    return m.group(1) if m else None


# ── version normalization for PURLs ───────────────────────────────────────────


def _strip_v(v: str) -> str:
    return v[1:] if v.startswith("v") else v


def _ensure_v(v: str) -> str:
    return v if v.startswith("v") else f"v{v}"


# ── tool registry ─────────────────────────────────────────────────────────────


def build_tools() -> list[Tool]:
    return [
        Tool(
            key="opengrep",
            label="OpenGrep (SAST engine)",
            read_pinned=lambda: _read_dockerfile_arg("OPENGREP_VERSION"),
            discover_latest=lambda: _github_latest_release("opengrep/opengrep"),
            # No package-registry coordinate; use the GitHub source PURL.
            purl=lambda v: f"pkg:github/opengrep/opengrep@{_ensure_v(v)}",
            note="GitHub-release binary; not Dependabot-trackable. Socket coverage of "
            "pkg:github coordinates may be limited -- a missing result is reported, not failed.",
        ),
        Tool(
            key="trufflehog",
            label="TruffleHog (secret scanner)",
            read_pinned=lambda: _read_dockerfile_arg("TRUFFLEHOG_VERSION"),
            discover_latest=lambda: _github_latest_release("trufflesecurity/trufflehog"),
            purl=lambda v: f"pkg:golang/github.com/trufflesecurity/trufflehog/v3@{_ensure_v(v)}",
        ),
        Tool(
            key="trivy",
            label="Trivy (container scanner)",
            read_pinned=lambda: _read_dockerfile_arg("TRIVY_VERSION"),
            discover_latest=lambda: _github_latest_release("aquasecurity/trivy"),
            purl=lambda v: f"pkg:golang/github.com/aquasecurity/trivy@{_ensure_v(v)}",
        ),
        Tool(
            key="socketdev",
            label="Socket SCA (socketdev SDK)",
            read_pinned=lambda: _read_locked_version("socketdev"),
            discover_latest=lambda: _pypi_latest("socketdev"),
            purl=lambda v: f"pkg:pypi/socketdev@{_strip_v(v)}",
        ),
    ]


# ── Socket analysis ────────────────────────────────────────────────────────────


def analyze_purls(purls: list[str], token: str) -> dict[str, dict[str, Any]]:
    """Score a batch of PURLs through the Socket API via the socketdev SDK.

    Returns a map of purl -> {score, alerts, malware: [...], critical: [...]}.
    """
    from socketdev import socketdev  # imported lazily; only needed with a token

    client = socketdev(token=token, timeout=60)
    components = [{"purl": p} for p in purls]
    results = client.purl.post(license="false", components=components) or []

    by_purl: dict[str, dict[str, Any]] = {}
    for item in results:
        # The purl API echoes type/name/version; rebuild a best-effort key and
        # also index by any returned id/purl so lookups are resilient.
        alerts = item.get("alerts") or []
        norm_alerts = []
        malware = []
        critical = []
        for a in alerts:
            a_type = a.get("type", "")
            a_sev = (a.get("severity") or "").lower()
            norm_alerts.append({"type": a_type, "severity": a_sev})
            if a_type in MALWARE_ALERT_TYPES:
                malware.append(a_type)
            if a_sev in CRITICAL_SEVERITIES:
                critical.append(a_type or a_sev)
        record = {
            "name": item.get("name"),
            "version": item.get("version"),
            "type": item.get("type"),
            "score": item.get("score"),
            "alerts": norm_alerts,
            "malware": sorted(set(malware)),
            "critical": sorted(set(critical)),
        }
        # Index under any purl-ish key we can derive.
        key = item.get("purl") or item.get("id")
        if key:
            by_purl[key] = record
        # Also index by reconstructed pkg coordinate for matching.
        t, n, ver = item.get("type"), item.get("name"), item.get("version")
        if t and n and ver:
            by_purl.setdefault(f"pkg:{t}/{n}@{ver}", record)
    return by_purl


def _match_analysis(analyses: dict[str, dict[str, Any]], purl: str) -> dict[str, Any]:
    if purl in analyses:
        return analyses[purl]
    # Loose match on name@version tail (handles type/namespace differences).
    tail = purl.split("/")[-1]  # e.g. socketdev@3.0.29 or trufflehog/v3@v3.93.8
    for k, v in analyses.items():
        if k.endswith(tail):
            return v
    return {}


# ── report rendering ────────────────────────────────────────────────────────


def render_markdown(tools: list[Tool], token_present: bool) -> str:
    lines: list[str] = []
    lines.append("## Core tool supply-chain watch\n")
    if not token_present:
        lines.append(
            "> **Socket analysis skipped** — no `SOCKET_API_TOKEN` present. "
            "Version-drift detection ran; package scoring did not. Add the "
            "`socket-firewall` environment secret to enable Socket scoring.\n"
        )
    lines.append("| Tool | Pinned | Latest | Drift | Socket (pinned) | Socket (latest) |")
    lines.append("|------|--------|--------|-------|-----------------|-----------------|")
    for t in tools:
        drift = "—"
        if t.pinned and t.latest:
            drift = "✅ current" if _strip_v(t.pinned) == _strip_v(t.latest) else f"⬆️ `{t.latest}`"

        def verdict(version: Optional[str]) -> str:
            if not version:
                return "—"
            if not token_present:
                return "skipped"
            a = _match_analysis(t.analyses, t.purl(version))
            if not a:
                return "no data"
            if a.get("malware"):
                return "🚨 MALWARE: " + ", ".join(a["malware"])
            if a.get("critical"):
                return "⚠️ " + ", ".join(sorted(set(a["critical"])))
            n_alerts = len(a.get("alerts", []))
            return f"✅ clean ({n_alerts} alerts)" if n_alerts else "✅ clean"

        lines.append(
            f"| {t.label} | `{t.pinned or '?'}` | `{t.latest or '?'}` | {drift} "
            f"| {verdict(t.pinned)} | {verdict(t.latest)} |"
        )
    notes = [t for t in tools if t.note]
    if notes:
        lines.append("\n### Notes\n")
        for t in notes:
            lines.append(f"- **{t.label}**: {t.note}")
    return "\n".join(lines) + "\n"


# ── main ───────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["build", "watch"], default="watch")
    parser.add_argument("--summary-file", help="Append a markdown report here (e.g. GITHUB_STEP_SUMMARY)")
    parser.add_argument("--json-out", help="Write the full structured report to this path")
    parser.add_argument("--github-output", help="Write drift/malware outputs here (e.g. GITHUB_OUTPUT)")
    parser.add_argument(
        "--fail-on-malware",
        action="store_true",
        help="Exit non-zero if any analyzed version has a malware/critical alert",
    )
    args = parser.parse_args()

    token = os.environ.get("SOCKET_API_TOKEN", "").strip()
    token_present = bool(token)

    tools = build_tools()

    print(f"== Core tool supply-chain watch (mode={args.mode}) ==")
    for t in tools:
        t.pinned = t.read_pinned()
        print(f"- {t.key}: pinned={t.pinned}")
        if args.mode == "watch":
            t.latest = t.discover_latest()
            print(f"    latest={t.latest}")

    # Collect the versions we actually want Socket to analyze.
    purls: list[str] = []
    for t in tools:
        for v in {t.pinned, t.latest if args.mode == "watch" else None}:
            if v:
                purls.append(t.purl(v))
    purls = sorted(set(purls))

    analyses: dict[str, dict[str, Any]] = {}
    if token_present and purls:
        print(f"== Scoring {len(purls)} PURLs through Socket ==")
        try:
            analyses = analyze_purls(purls, token)
        except Exception as exc:  # noqa: BLE001
            print(f"! Socket analysis failed: {exc}", file=sys.stderr)
    for t in tools:
        t.analyses = analyses

    # Determine drift + malware across analyzed versions.
    any_drift = False
    any_malware = False
    findings: list[dict[str, Any]] = []
    for t in tools:
        drift = bool(t.pinned and t.latest and _strip_v(t.pinned) != _strip_v(t.latest))
        any_drift = any_drift or drift
        tool_finding: dict[str, Any] = {
            "tool": t.key,
            "label": t.label,
            "pinned": t.pinned,
            "latest": t.latest,
            "drift": drift,
            "analyses": {},
        }
        for v in {t.pinned, t.latest}:
            if not v:
                continue
            a = _match_analysis(t.analyses, t.purl(v))
            if a:
                tool_finding["analyses"][v] = a
                if a.get("malware") or a.get("critical"):
                    any_malware = any_malware or bool(a.get("malware"))
        findings.append(tool_finding)

    markdown = render_markdown(tools, token_present)
    print("\n" + markdown)

    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as fh:
            fh.write(markdown)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {"mode": args.mode, "token_present": token_present, "findings": findings},
                indent=2,
            )
        )
        print(f"Wrote JSON report to {args.json_out}")

    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as fh:
            fh.write(f"drift={'true' if any_drift else 'false'}\n")
            fh.write(f"malware={'true' if any_malware else 'false'}\n")

    if args.fail_on_malware and any_malware:
        print("::error::Socket flagged malware/critical alerts on a core tool version.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
