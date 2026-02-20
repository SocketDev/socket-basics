#!/usr/bin/env python3
"""Preview PR comment output from all formatters using realistic fixture data.

Usage:
    python scripts/preview_pr_comments.py [--output-dir DIR] [--scanner NAME]

Generates markdown files that approximate what GitHub PR comments will look like.
Open them in any markdown previewer or paste into a GitHub gist for true rendering.

Scanners: opengrep, trivy-image, trivy-dockerfile, trufflehog, tier1, all (default)
"""

import argparse
import sys
from pathlib import Path

# Add project root to path so we can import socket_basics
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))


# ---------------------------------------------------------------------------
# Mock config that mimics what the GHA pipeline passes to formatters
# ---------------------------------------------------------------------------
class MockConfig(dict):
    """Dict-like config that also supports attribute access (matches real config)."""

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


def make_mock_config(
    repo="SocketDev/example-app",
    commit="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    full_scan_url="https://socket.dev/dashboard/scan/12345",
):
    """Build a mock config object matching the real pipeline shape."""
    return MockConfig(
        repo=repo,
        commit_hash=commit,
        pr_comment_links_enabled=True,
        pr_comment_collapse_enabled=True,
        pr_comment_collapse_non_critical=True,
        pr_comment_code_fencing_enabled=True,
        pr_comment_show_rule_names=True,
        full_scan_html_url=full_scan_url,
    )


# ---------------------------------------------------------------------------
# Fixture data for each scanner
# ---------------------------------------------------------------------------

OPENGREP_FIXTURES = {
    "sast-javascript": [
        {
            "component": {"id": "comp-1"},
            "alert": {
                "severity": "critical",
                "title": "javascript.express.security.audit.xss.mustache-escape",
                "location": {"path": "src/server/app.ts"},
                "props": {
                    "filePath": "src/server/app.ts",
                    "ruleId": "express-xss-mustache-escape",
                    "startLine": 42,
                    "endLine": 45,
                    "codeSnippet": "app.get('/search', (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});",
                },
            },
        },
        {
            "component": {"id": "comp-2"},
            "alert": {
                "severity": "high",
                "title": "javascript.express.security.audit.path-traversal",
                "location": {"path": "src/server/app.ts"},
                "props": {
                    "filePath": "src/server/app.ts",
                    "ruleId": "express-path-traversal",
                    "startLine": 78,
                    "endLine": 80,
                    "codeSnippet": "app.get('/files/:name', (req, res) => {\n  res.sendFile(path.join('/data', req.params.name));\n});",
                },
            },
        },
        {
            "component": {"id": "comp-3"},
            "alert": {
                "severity": "medium",
                "title": "javascript.lang.security.detect-eval",
                "location": {"path": "src/utils/config-loader.js"},
                "props": {
                    "filePath": "src/utils/config-loader.js",
                    "ruleId": "detect-eval",
                    "startLine": 15,
                    "endLine": 15,
                    "codeSnippet": "const parsed = eval(rawConfigStr);",
                },
            },
        },
        {
            "component": {"id": "comp-4"},
            "alert": {
                "severity": "low",
                "title": "javascript.lang.best-practice.no-console-log",
                "location": {"path": "src/utils/config-loader.js"},
                "props": {
                    "filePath": "src/utils/config-loader.js",
                    "ruleId": "no-console-log",
                    "startLine": 22,
                    "endLine": 22,
                    "codeSnippet": "console.log('Config loaded:', parsed);",
                },
            },
        },
    ],
    "sast-python": [
        {
            "component": {"id": "comp-5"},
            "alert": {
                "severity": "critical",
                "title": "python.django.security.injection.sql.sql-injection-extra",
                "location": {"path": "backend/views.py"},
                "props": {
                    "filePath": "backend/views.py",
                    "ruleId": "sql-injection-extra",
                    "startLine": 31,
                    "endLine": 33,
                    "codeSnippet": 'query = f"SELECT * FROM users WHERE name = \'{request.GET[\'name\']}\'"  \ncursor.execute(query)',
                },
            },
        },
    ],
}


def _trivy_image_fixture():
    """Trivy image/vuln scan fixture (component mapping)."""
    return {
        "comp-lodash": {
            "name": "lodash",
            "version": "4.17.15",
            "qualifiers": {"ecosystem": "npm"},
            "alerts": [
                {
                    "severity": "critical",
                    "title": "CVE-2021-23337",
                    "description": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
                    "props": {
                        "vulnerabilityId": "CVE-2021-23337",
                        "ruleId": "CVE-2021-23337",
                        "cvssScore": 7.2,
                        "fixedVersion": "4.17.21",
                    },
                },
                {
                    "severity": "high",
                    "title": "CVE-2020-28500",
                    "description": "Lodash versions prior to 4.17.21 are vulnerable to Regular Expression Denial of Service (ReDoS) via the toNumber, trim, and trimEnd functions.",
                    "props": {
                        "vulnerabilityId": "CVE-2020-28500",
                        "ruleId": "CVE-2020-28500",
                        "cvssScore": 5.3,
                        "fixedVersion": "4.17.21",
                    },
                },
            ],
        },
        "comp-express": {
            "name": "express",
            "version": "4.17.1",
            "qualifiers": {"ecosystem": "npm"},
            "alerts": [
                {
                    "severity": "medium",
                    "title": "CVE-2024-29041",
                    "description": "Express.js minimalist web framework for Node.js Open Redirect vulnerability in versions before 4.19.2.",
                    "props": {
                        "vulnerabilityId": "CVE-2024-29041",
                        "ruleId": "CVE-2024-29041",
                        "cvssScore": 6.1,
                        "fixedVersion": "4.19.2",
                    },
                },
            ],
        },
    }


def _trivy_dockerfile_fixture():
    """Trivy dockerfile scan fixture."""
    return {
        "comp-df-1": {
            "name": "Dockerfile",
            "alerts": [
                {
                    "severity": "high",
                    "title": "DS002",
                    "description": "Last USER should not be root",
                    "props": {
                        "ruleId": "DS002",
                        "resolution": "Add a non-root USER statement at the end of the Dockerfile",
                        "detailedReport": {
                            "content": "```dockerfile\nUSER root\nRUN apt-get update\n# Missing: USER nonroot\n```"
                        },
                    },
                },
                {
                    "severity": "medium",
                    "title": "DS026",
                    "description": "No HEALTHCHECK defined",
                    "props": {
                        "ruleId": "DS026",
                        "resolution": "Add HEALTHCHECK instruction to the Dockerfile",
                    },
                },
            ],
        },
    }


TRUFFLEHOG_FIXTURES = {
    "comp-secret-1": {
        "alerts": [
            {
                "severity": "critical",
                "title": "AWS",
                "props": {
                    "detectorName": "AWS",
                    "filePath": "config/deploy.env",
                    "lineNumber": 12,
                    "redactedValue": "AKIA****EXAMPLE",
                    "verified": True,
                },
            },
            {
                "severity": "high",
                "title": "PrivateKey",
                "props": {
                    "detectorName": "PrivateKey",
                    "filePath": "scripts/deploy.sh",
                    "lineNumber": 5,
                    "redactedValue": "-----BEGIN RSA PRIVATE KEY-----\\nMIIE****",
                    "verified": False,
                },
            },
        ],
    },
    "comp-secret-2": {
        "alerts": [
            {
                "severity": "medium",
                "title": "Slack",
                "props": {
                    "detectorName": "SlackWebhook",
                    "filePath": "src/notifications.js",
                    "lineNumber": 88,
                    "redactedValue": "https://hooks.slack.com/services/T0****/B0****/xxxx",
                    "verified": False,
                },
            },
        ],
    },
}


TIER1_FIXTURES = [
    {
        "name": "lodash",
        "id": "lodash-4.17.15",
        "type": "npm",
        "namespace": "",
        "version": "4.17.15",
        "alerts": [
            {
                "severity": "critical",
                "title": "CVE-2021-23337",
                "props": {
                    "purl": "pkg:npm/lodash@4.17.15",
                    "cveId": "CVE-2021-23337",
                    "cvssScore": 7.2,
                    "reachability": "reachable",
                    "trace": [
                        "lodash - template.js 72:12-75:6",
                        "  -> my-app server.js 15:3",
                    ],
                },
            },
            {
                "severity": "high",
                "title": "CVE-2020-28500",
                "props": {
                    "purl": "pkg:npm/lodash@4.17.15",
                    "cveId": "CVE-2020-28500",
                    "cvssScore": 5.3,
                    "reachability": "unknown",
                },
            },
        ],
    },
    {
        "name": "jsonwebtoken",
        "id": "jsonwebtoken-8.5.1",
        "type": "npm",
        "namespace": "",
        "version": "8.5.1",
        "alerts": [
            {
                "severity": "high",
                "title": "GHSA-hjrf-2m68-5959",
                "props": {
                    "purl": "pkg:npm/jsonwebtoken@8.5.1",
                    "ghsaId": "GHSA-hjrf-2m68-5959",
                    "cvssScore": 7.6,
                    "reachability": "unreachable",
                },
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

SCANNERS = {
    "opengrep": "OpenGrep SAST",
    "trivy-image": "Trivy Container/CVE",
    "trivy-dockerfile": "Trivy Dockerfile",
    "trufflehog": "TruffleHog Secrets",
    "tier1": "Socket Tier 1",
}


def run_opengrep(config):
    from socket_basics.core.connector.opengrep.github_pr import format_notifications
    return format_notifications(OPENGREP_FIXTURES, config=config)


def run_trivy_image(config):
    from socket_basics.core.connector.trivy.github_pr import format_notifications
    return format_notifications(_trivy_image_fixture(), item_name="example-app:latest", scan_type="image", config=config)


def run_trivy_dockerfile(config):
    from socket_basics.core.connector.trivy.github_pr import format_notifications
    return format_notifications(_trivy_dockerfile_fixture(), item_name="Dockerfile", scan_type="dockerfile", config=config)


def run_trufflehog(config):
    from socket_basics.core.connector.trufflehog.github_pr import format_notifications
    return format_notifications(TRUFFLEHOG_FIXTURES, config=config)


def run_tier1(config):
    from socket_basics.core.connector.socket_tier1.github_pr import format_notifications
    return format_notifications(TIER1_FIXTURES, config=config)


RUNNER_MAP = {
    "opengrep": run_opengrep,
    "trivy-image": run_trivy_image,
    "trivy-dockerfile": run_trivy_dockerfile,
    "trufflehog": run_trufflehog,
    "tier1": run_tier1,
}


def main():
    parser = argparse.ArgumentParser(description="Preview PR comment markdown output")
    parser.add_argument(
        "--output-dir",
        default=str(project_root / "test_results" / "pr_previews"),
        help="Directory to write preview .md files (default: test_results/pr_previews/)",
    )
    parser.add_argument(
        "--scanner",
        default="all",
        choices=list(SCANNERS.keys()) + ["all"],
        help="Which scanner to preview (default: all)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    config = make_mock_config()
    scanners_to_run = list(SCANNERS.keys()) if args.scanner == "all" else [args.scanner]

    print(f"Generating PR comment previews in {output_dir}/\n")

    for scanner_key in scanners_to_run:
        label = SCANNERS[scanner_key]
        runner = RUNNER_MAP[scanner_key]

        try:
            results = runner(config)
        except Exception as e:
            print(f"  ERROR  {label}: {e}")
            continue

        for result in results:
            title = result.get("title", scanner_key)
            content = result.get("content", "")

            # Sanitize title for filename
            safe_name = title.lower().replace(" ", "-").replace("/", "-")
            out_path = output_dir / f"{safe_name}.md"
            out_path.write_text(content, encoding="utf-8")
            print(f"  OK  {label:30s} -> {out_path.relative_to(project_root)}")

    # Also write a combined file for easy side-by-side viewing
    combined_path = output_dir / "_combined.md"
    combined_parts = []
    for scanner_key in scanners_to_run:
        runner = RUNNER_MAP[scanner_key]
        try:
            results = runner(config)
            for result in results:
                combined_parts.append(result.get("content", ""))
        except Exception:
            pass

    combined_path.write_text("\n\n---\n\n".join(combined_parts), encoding="utf-8")
    print(f"\n  Combined -> {combined_path.relative_to(project_root)}")
    print("\nDone! Open the .md files in a markdown previewer or paste into a GitHub gist.")


if __name__ == "__main__":
    main()
