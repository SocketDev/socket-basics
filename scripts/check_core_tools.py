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

Exit code is 0 unless --fail-on-malware is set AND a PINNED version trips the
thresholds: any alert type in MALWARE_ALERT_TYPES -- a curated list of
compromise and compromise-adjacent signals -- OR any alert of critical
severity. With a token present, a Socket scoring error also fails, as
does a covered pinned coordinate that comes back still pending analysis
(synthetic pendingScan row), unresolvable (synthetic notFound row), or missing
from the returned batch entirely (fail-closed: unverified pins must not ship;
OpenGrep's documented pkg:github coverage gap is the one exemption). The batch
call opts into poll=true + alerts=true so fresh-but-unanalyzed versions
surface as labeled pendingScan rows instead of being silently omitted by the
endpoint's fail-open default. Drift alone never fails the run,
and the discovered *latest* version is scored for reporting only; both are
surfaced via the JSON report and the `drift`/`malware`/`critical` GitHub
outputs so the workflow decides what to do.
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
# Both Dockerfiles pin the core tools and can drift independently, so scoring
# must cover every version pinned across all of them.
DOCKERFILES = [REPO_ROOT / "Dockerfile", REPO_ROOT / "app_tests" / "Dockerfile"]
UV_LOCK = REPO_ROOT / "uv.lock"

# Alert types treated as fail-worthy on a pinned version: outright compromise
# signals plus typosquat/fake-popularity hints and compromise-adjacent
# behaviors (install scripts, telemetry). Calibrated against real batch data
# once alerts=true started returning the full alert set (run 30504424787):
# capability signals (shellAccess -- present on ALL four tools; they spawn
# subprocesses by design) and heuristic/static signals (gptMalware,
# gptSecurity, obfuscatedFile -- a SAST engine ships malicious-looking test
# fixtures on purpose) are informational there, not compromise evidence, and
# were removed. Trim further rather than disabling --fail-on-malware if new
# noise appears.
MALWARE_ALERT_TYPES = {
    "malware",
    "didYouMean",
    "suspiciousStarActivity",
    "cryptoMiner",
    "installScript",
    "telemetry",
    "trojan",
    "backdoor",
}
# Severities that count as fail-worthy. "high" was included while the batch
# response carried no alert data (the pre-alerts=true fail-open default made
# this gate dead code); the full alert set carries high-severity heuristic and
# cve rows on perfectly healthy tools (gptMalware/obfuscatedFile on the
# OpenGrep repo artifact, cve on Trivy), so the hard gate is critical-only.
# High-severity findings still land in the report for human review.
CRITICAL_SEVERITIES = {"critical"}

# Synthetic batch-status alert types the purl endpoints emit when called with
# alerts=true (added upstream ~2026-04, depscan #18990). They mark inputs whose
# analysis is incomplete (pendingScan) or whose coordinate could not be
# resolved (notFound) -- without alerts=true such inputs are SILENTLY OMITTED
# from the response (the endpoint's documented fail-open default), which is
# what made fresh pins like pkg:pypi/socketdev@3.3.0 trip the unverified-pin
# guard with a misleading "batch dropped rows" message. These are batch-status
# markers, not package risk signals: they must never be classified through
# MALWARE_ALERT_TYPES / CRITICAL_SEVERITIES regardless of the severity label
# they carry.
SYNTHETIC_STATUS_ALERTS = {
    "pendingScan": "pending",
    "notFound": "not_found",
}


@dataclass
class Tool:
    key: str
    label: str
    # Returns every distinct version currently pinned in the repo (across both
    # Dockerfiles / uv.lock; no leading-v normalization -- as written).
    read_pinned: Callable[[], list[str]]
    # Returns the latest upstream version tag (as published).
    discover_latest: Callable[[], Optional[str]]
    # Builds a Socket PURL for a given version string.
    purl: Callable[[str], str]
    note: str = ""
    # Optional fallback coordinate scored when `purl` has no Socket coverage
    # (e.g. pkg:github). Returns a fully-formed PURL string (or None). Used for
    # reporting only -- a proxy is never build-failing.
    proxy_purl: Callable[[], Optional[str]] | None = None
    proxy_label: str = ""
    # Whether Socket is expected to have data for this tool's primary PURL.
    # When True, a pinned version with no matching analysis row is treated as
    # UNVERIFIED and fails a --fail-on-malware run (an incomplete batch must
    # not pass the guard). False only for tools with a documented coverage gap
    # (OpenGrep's pkg:github coordinate), where "no data" is the known state
    # and the proxy provides report-only signal instead.
    socket_coverage: bool = True
    pinned: list[str] = field(default_factory=list)
    latest: Optional[str] = None
    resolved_proxy_purl: Optional[str] = None
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


def _pypi_purl(package: str) -> Optional[str]:
    """Latest-version PyPI PURL for a package, or None if discovery fails."""
    v = _pypi_latest(package)
    return f"pkg:pypi/{package}@{v}" if v else None


# ── pin readers ─────────────────────────────────────────────────────────────


def _read_dockerfile_args(name: str) -> list[str]:
    """Distinct pinned versions of an ARG across all Dockerfiles (order preserved).

    The root and app_tests Dockerfiles pin the same tools independently, so a
    version can appear in one, both, or (if they diverge) at two different
    values -- all of which must be scored.
    """
    versions: list[str] = []
    for df in DOCKERFILES:
        if not df.exists():
            continue
        m = re.search(rf"^ARG\s+{re.escape(name)}=(.+)$", df.read_text(), re.MULTILINE)
        if m:
            v = m.group(1).strip()
            if v and v not in versions:
                versions.append(v)
    return versions


def _read_locked_versions(package: str) -> list[str]:
    """Resolved version of a package from uv.lock, as a (0- or 1-element) list."""
    if not UV_LOCK.exists():
        return []
    # uv.lock is TOML with [[package]] blocks: name = "x"\nversion = "y"
    m = re.search(
        rf'name = "{re.escape(package)}"\s*\nversion = "([^"]+)"',
        UV_LOCK.read_text(),
    )
    return [m.group(1)] if m else []


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
            read_pinned=lambda: _read_dockerfile_args("OPENGREP_VERSION"),
            discover_latest=lambda: _github_latest_release("opengrep/opengrep"),
            # No package-registry coordinate; use the GitHub source PURL.
            purl=lambda v: f"pkg:github/opengrep/opengrep@{_ensure_v(v)}",
            # OpenGrep is a hard fork of Semgrep and Socket has no data for the
            # pkg:github coordinate, so fall back to scoring the upstream Semgrep
            # lineage as a project-health proxy. (The npm `opengrep` package is a
            # single-version squat, not the official distribution -- not used.)
            proxy_purl=lambda: _pypi_purl("semgrep"),
            proxy_label="semgrep upstream proxy",
            socket_coverage=False,  # documented gap: pkg:github has no Socket data
            note="GitHub-release binary; not Dependabot-trackable and not covered by "
            "Socket's pkg:github coordinates. Falls back to the upstream Semgrep "
            "lineage (pkg:pypi/semgrep) as a project-health proxy -- this does NOT "
            "analyze OpenGrep's own release artifacts, so it is reported, never "
            "build-failing.",
        ),
        Tool(
            key="trufflehog",
            label="TruffleHog (secret scanner)",
            read_pinned=lambda: _read_dockerfile_args("TRUFFLEHOG_VERSION"),
            discover_latest=lambda: _github_latest_release("trufflesecurity/trufflehog"),
            purl=lambda v: f"pkg:golang/github.com/trufflesecurity/trufflehog/v3@{_ensure_v(v)}",
        ),
        Tool(
            key="trivy",
            label="Trivy (container scanner)",
            read_pinned=lambda: _read_dockerfile_args("TRIVY_VERSION"),
            discover_latest=lambda: _github_latest_release("aquasecurity/trivy"),
            purl=lambda v: f"pkg:golang/github.com/aquasecurity/trivy@{_ensure_v(v)}",
        ),
        Tool(
            key="socketdev",
            label="Socket SCA (socketdev SDK)",
            read_pinned=lambda: _read_locked_versions("socketdev"),
            discover_latest=lambda: _pypi_latest("socketdev"),
            purl=lambda v: f"pkg:pypi/socketdev@{_strip_v(v)}",
        ),
    ]


# ── Socket analysis ────────────────────────────────────────────────────────────


def analyze_purls(purls: list[str], token: str) -> dict[str, dict[str, Any]]:
    """Score a batch of PURLs through the Socket API via the socketdev SDK.

    Returns a map of purl -> {score, alerts, malware: [...], critical: [...]}.
    Raises on an empty API result: the SDK returns [] on ANY non-200 (expired
    token, dropped endpoint, outage) without raising, and every run scores
    coordinates Socket definitely has data for (pkg:pypi/socketdev at minimum),
    so an empty result is an API failure, not a clean bill -- surfacing it lets
    the caller fail closed instead of reporting "no data" and exiting 0.
    """
    import inspect

    from socketdev import socketdev  # imported lazily; only needed with a token

    # Client timeout must exceed the server-side poll bound (timeoutSec=120
    # below), or the HTTP call would abort before the server finishes waiting.
    client = socketdev(token=token, timeout=180)

    # Prefer the org-scoped purl endpoint. socketdev >= 3.1 deprecates the
    # legacy POST /v0/purl (used when org_slug is absent) in favor of
    # POST /v0/orgs/{org_slug}/purl, and a future major may drop the legacy
    # route entirely. The pinned 3.0.29 predates the parameter, so pass it
    # only when the installed SDK supports it (the scan env tracks main's
    # lockfile -- this activates automatically on the eventual SDK bump).
    kwargs: dict[str, Any] = {}
    if "org_slug" in inspect.signature(client.purl.post).parameters:
        # Match socket-python-cli's get_org_id_slug(): only trust the slug
        # when the token maps to exactly one org -- guessing among several
        # could score under the wrong org's policies.
        orgs = (client.org.get() or {}).get("organizations") or {}
        slug = next(iter(orgs.values())).get("slug") if len(orgs) == 1 else None
        if slug:
            kwargs["org_slug"] = slug
            print(f"  using org-scoped purl endpoint (org={slug})")
        else:
            print(
                f"  ! org slug not resolvable ({len(orgs)} orgs on token); using legacy purl endpoint",
                file=sys.stderr,
            )

    components = [{"purl": p} for p in purls]
    # The batch purl endpoints default to fail-open: inputs whose analysis is
    # pending or unresolvable are silently omitted from the response unless the
    # caller opts in. Opt in to fail-closed semantics: poll=True waits (bounded
    # by timeout_sec; the server may cap it) for pending analysis, and
    # alerts=True materializes still-unresolved inputs as synthetic
    # pendingScan/notFound rows instead of dropping them. These are first-class
    # typed params as of socketdev 3.4.2 (previously passed as stringly-typed
    # query-string kwargs); see CE-360.
    results = client.purl.post(
        license="false",
        components=components,
        poll=True,
        timeout_sec=120,
        alerts=True,
        **kwargs,
    ) or []
    if not results:
        raise RuntimeError(
            f"Socket purl API returned no results for {len(purls)} PURLs "
            "(the SDK swallows non-200s into an empty list) -- treating as a scoring failure"
        )

    by_purl: dict[str, dict[str, Any]] = {}
    for item in results:
        # The purl API echoes type/name/version; rebuild a best-effort key and
        # also index by any returned id/purl so lookups are resilient.
        alerts = item.get("alerts") or []
        norm_alerts = []
        malware = []
        critical = []
        status = None
        for a in alerts:
            a_type = a.get("type", "")
            a_sev = (a.get("severity") or "").lower()
            # Synthetic batch-status markers (from alerts=true) are handled
            # before severity classification: whatever severity/action labels
            # they carry after org-policy application, they describe the batch
            # row, not the package.
            if a_type in SYNTHETIC_STATUS_ALERTS:
                status = status or SYNTHETIC_STATUS_ALERTS[a_type]
                continue
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
            "status": status,
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
            current = all(_strip_v(p) == _strip_v(t.latest) for p in t.pinned)
            drift = "✅ current" if current else f"⬆️ `{t.latest}`"

        def verdict(version: Optional[str]) -> str:
            if not version:
                return "—"
            if not token_present:
                return "skipped"
            a = _match_analysis(t.analyses, t.purl(version))
            suffix = ""
            if not a and t.resolved_proxy_purl:
                a = _match_analysis(t.analyses, t.resolved_proxy_purl)
                if a:
                    suffix = f" _(via {t.proxy_label})_"
            if not a:
                return "no data"
            if a.get("status") == "pending":
                return "⏳ analysis pending upstream" + suffix
            if a.get("status") == "not_found":
                return "❓ coordinate not resolvable" + suffix
            if a.get("malware"):
                return "🚨 MALWARE: " + ", ".join(a["malware"]) + suffix
            if a.get("critical"):
                return "⚠️ " + ", ".join(sorted(set(a["critical"]))) + suffix
            n_alerts = len(a.get("alerts", []))
            base = f"✅ clean ({n_alerts} alerts)" if n_alerts else "✅ clean"
            return base + suffix

        pinned_cell = ", ".join(f"`{p}`" for p in t.pinned) if t.pinned else "`?`"
        if len(t.pinned) > 1:
            pinned_verdict = "; ".join(f"`{p}`: {verdict(p)}" for p in t.pinned)
        else:
            pinned_verdict = verdict(t.pinned[0]) if t.pinned else "—"
        lines.append(
            f"| {t.label} | {pinned_cell} | `{t.latest or '?'}` | {drift} "
            f"| {pinned_verdict} | {verdict(t.latest)} |"
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
        help="Exit non-zero if a PINNED version has a malware-class alert (see "
        "MALWARE_ALERT_TYPES -- deliberately broader than literal malware) or any "
        "high/critical severity alert, or (when a token is present) if Socket "
        "scoring itself errored -- fail-closed. The discovered latest version is "
        "report-only and never fails the run.",
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
        if t.proxy_purl:
            t.resolved_proxy_purl = t.proxy_purl()
            print(f"    proxy={t.resolved_proxy_purl}")

    # Collect the versions to analyze: every pinned version, plus the discovered
    # latest (watch mode) for drift reporting, plus any proxy coordinate.
    purls: list[str] = []
    for t in tools:
        for v in t.pinned:
            purls.append(t.purl(v))
        if args.mode == "watch" and t.latest:
            purls.append(t.purl(t.latest))
        if t.resolved_proxy_purl:
            purls.append(t.resolved_proxy_purl)
    purls = sorted(set(purls))

    analyses: dict[str, dict[str, Any]] = {}
    scoring_error = False
    if token_present and purls:
        print(f"== Scoring {len(purls)} PURLs through Socket ==")
        try:
            analyses = analyze_purls(purls, token)
        except Exception as exc:  # noqa: BLE001
            print(f"! Socket analysis failed: {exc}", file=sys.stderr)
            scoring_error = True
    for t in tools:
        t.analyses = analyses

    # Determine drift + fail-worthy alerts. Only PINNED versions (the ones
    # actually baked into an image / in use) can fail the run; the discovered
    # latest is analyzed for drift reporting only, so a scheduled watch never
    # blocks on an upstream release we have not adopted yet.
    any_drift = False
    any_malware = False
    any_critical = False
    unverified: list[str] = []
    pending: list[str] = []
    not_found: list[str] = []
    findings: list[dict[str, Any]] = []
    for t in tools:
        drift = bool(t.latest and any(_strip_v(p) != _strip_v(t.latest) for p in t.pinned))
        any_drift = any_drift or drift
        tool_finding: dict[str, Any] = {
            "tool": t.key,
            "label": t.label,
            "pinned": t.pinned,
            "latest": t.latest,
            "drift": drift,
            "analyses": {},
        }
        # Pinned versions are fail-worthy.
        for v in t.pinned:
            a = _match_analysis(t.analyses, t.purl(v))
            if a:
                tool_finding["analyses"][v] = a
                if a.get("malware"):
                    any_malware = True
                if a.get("critical"):
                    any_critical = True
                # Synthetic status on a covered pin: the batch answered, but
                # not with analysis. Same fail-closed posture as unverified,
                # tracked separately so the error names the actual condition.
                # Coverage-gap tools (OpenGrep's pkg:github) are exempt: with
                # alerts=true their known-uncovered pin now returns a notFound
                # row instead of being silently omitted.
                if t.socket_coverage and a.get("status") == "pending":
                    pending.append(f"{t.key} {t.purl(v)}")
                elif t.socket_coverage and a.get("status") == "not_found":
                    not_found.append(f"{t.key} {t.purl(v)}")
            elif token_present and not scoring_error and t.socket_coverage:
                # Scoring "succeeded" but this pinned coordinate has no row --
                # a partial batch or a purl/echo mismatch. The guard's job is
                # to verify every pin, so an unverified one is fail-worthy
                # (except documented coverage gaps like OpenGrep).
                unverified.append(f"{t.key} {t.purl(v)}")
        # Latest is report-only (a drift signal); it never fails the run.
        if t.latest:
            a = _match_analysis(t.analyses, t.purl(t.latest))
            if a:
                tool_finding["analyses"].setdefault(t.latest, a)
        # Proxy coverage (e.g. semgrep for opengrep) is reported, never build-failing.
        if t.resolved_proxy_purl:
            pa = _match_analysis(t.analyses, t.resolved_proxy_purl)
            if pa:
                tool_finding["proxy"] = {
                    "purl": t.resolved_proxy_purl,
                    "label": t.proxy_label,
                    "analysis": pa,
                }
        findings.append(tool_finding)

    markdown = render_markdown(tools, token_present)
    print("\n" + markdown)

    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as fh:
            fh.write(markdown)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "mode": args.mode,
                    "token_present": token_present,
                    "scoring_error": scoring_error,
                    "unverified": unverified,
                    "pending": pending,
                    "not_found": not_found,
                    "findings": findings,
                },
                indent=2,
            )
        )
        print(f"Wrote JSON report to {args.json_out}")

    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as fh:
            fh.write(f"drift={'true' if any_drift else 'false'}\n")
            fh.write(f"malware={'true' if any_malware else 'false'}\n")
            fh.write(f"critical={'true' if any_critical else 'false'}\n")

    if args.fail_on_malware:
        if any_malware or any_critical:
            print(
                "::error::Socket flagged malware/critical alerts on a pinned core tool version.",
                file=sys.stderr,
            )
            return 1
        # Fail closed: a token was provided but scoring errored, so the pinned
        # versions went unverified -- don't let a build pass unchecked.
        if scoring_error:
            print(
                "::error::Socket scoring failed (API error); pinned core tool versions "
                "could not be verified. Failing closed.",
                file=sys.stderr,
            )
            return 1
        # Fail closed: Socket knows the coordinate but analysis was still
        # running when the bounded poll expired. Distinct from a dropped row:
        # this is upstream latency, not an API anomaly.
        if pending:
            print(
                "::error::Socket analysis still pending after the bounded poll for pinned "
                "coordinate(s): " + "; ".join(pending)
                + ". Failing closed -- re-run later, or investigate Socket ingestion if it persists.",
                file=sys.stderr,
            )
            return 1
        # Fail closed: Socket could not resolve the coordinate at all. For a
        # published package version this is a registry/ingestion bug with a
        # one-line repro -- hand it to the API team.
        if not_found:
            print(
                "::error::Socket cannot resolve pinned coordinate(s): "
                + "; ".join(not_found)
                + ". Failing closed -- likely a Socket registry/ingestion gap; report it upstream.",
                file=sys.stderr,
            )
            return 1
        # Fail closed: scoring returned rows, but some covered pinned
        # coordinate has none -- with poll+alerts requested this should no
        # longer happen for merely-fresh versions, so a missing row is a
        # genuine anomaly (purl/echo mismatch or batch drop).
        if unverified:
            print(
                "::error::Socket scoring returned no analysis for pinned coordinate(s): "
                + "; ".join(unverified)
                + ". Failing closed (unverified pins must not ship).",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
