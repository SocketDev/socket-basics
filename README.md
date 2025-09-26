# Security Wrapper — socket-basics

Security Wrapper is a small, extensible CLI tool that orchestrates multiple security scanners (SAST, secret scanning, container scanning), normalizes their outputs into a single consolidated Socket facts JSON format, and delivers results to configured notifiers (console, Slack, Jira, webhooks, Sumo Logic, MS Sentinel, etc.).

This README is a first-time, clean-slate guide to installing, running, configuring, and extending the tool.

## Table of contents

- Overview
- Installation
- Quick start
- CLI reference
- Environment variables (INPUT_*)
- Connector architecture
- Notifiers
- Output format
- Docker usage
- Development & testing
- Troubleshooting
- Contributing
- License

## Overview

Security Wrapper provides:

- A unified CLI: `socket-basics`
- A plugin-style connector system for integrating scanners (OpenGrep, Trivy, TruffleHog, etc.)
- Configuration via CLI flags, environment variables, and `socket_basics/connectors.yaml`
- Consolidation of all scanner results into a single `.socket.facts.json` compatible structure
- Notification hooks to send results to external systems

Design goals:

- Make it easy to run multiple scanners in a single job
- Normalize outputs for downstream analysis and reporting
- Keep connectors isolated and pluggable

## Installation

Recommended: use a Python virtual environment and the `uv` tool (used in development here). The package exposes the `socket-basics` CLI through `pyproject.toml`.

On macOS / Linux (zsh):

```sh
python -m venv .venv
source .venv/bin/activate
# install uv if not already available
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync
# install this package in editable mode
pip install -e .
```

After installation you should have the `socket-basics` CLI available in your environment.


## Quick start

Build the container image and run a scan from your current working directory mounted as `/workspace`.

1) Build the Docker image (tagged `socket-basics`):

```sh
docker build -t socket-basics .
```

2) Create a `.env` file that enables Jira + Slack and provides Socket credentials. The example below includes the required `SOCKET_ORG` and `SOCKET_SECURITY_API_KEY` variables used in this quick run (replace placeholders with real values or secrets):

```env
# Socket credentials
SOCKET_ORG=socketdev-demo
SOCKET_SECURITY_API_KEY=your-socket-security-api-key

# Enable notifiers
INPUT_JIRA_ENABLED=true
INPUT_JIRA_URL=https://your-jira-instance.atlassian.net
INPUT_JIRA_EMAIL=you@example.com
INPUT_JIRA_API_TOKEN=your-jira-api-token
INPUT_JIRA_PROJECT=PROJ

INPUT_SLACK_ENABLED=true
INPUT_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX

# Optional: prefer tabular console output
INPUT_CONSOLE_ENABLED=true
INPUT_SOCKET_CONSOLE_MODE=tabular
```

3) Run the container mounting the current directory into `/workspace` and pass the CLI flags you provided. This example runs secrets scanning, JavaScript SAST, requests Socket tier1 reporting, and scans the `trickyhu/sigsci-rule-editor` container image:

```sh
docker run --rm -v "$PWD:/workspace" --env-file .env socket-basics \
	--workspace /workspace \
	--repo node_goat_17 \
	--branch main \
	--secrets \
	--console-tabular-enabled \
	--javascript \
	--socket-org socketdev-demo \
	--socket-tier1 \
	--container-images \
	--images trickyhu/sigsci-rule-editor
```

Notes:
- The container mounts your current project into `/workspace`, so the CLI option `--workspace /workspace` points to that path inside the container.
- The `.env` file is loaded by `--env-file` to provide credentials and notifier configuration; you can also set secrets via your environment or your CI provider.
- `SOCKET_ORG` and `SOCKET_SECURITY_API_KEY` in the example are included to show the minimum Socket-related env variables for SCA/Socket integrations. The tool also accepts `INPUT_SOCKET_ORG` / `INPUT_SOCKET_API_KEY` style env vars used elsewhere in this repo if you prefer that naming.

Quick local examples (alternate):

Run a basic scan from the repository root and print results to stdout:

```sh
socket-basics --python --secrets --containers --verbose
```

Save results to a file:

```sh
socket-basics --python --secrets --containers --output scan-results.socket.facts.json
```

Run with console notifications only (no output file):

```sh
INPUT_CONSOLE_ENABLED=true socket-basics --python --secrets
```

## CLI reference

Run `socket-basics --help` to see the up-to-date list of options. Below are the most commonly used flags:

- `--python` / `--no-python` — enable/disable Python SAST
- `--secrets` / `--no-secrets` — enable/disable secret scanning
- `--containers` / `--no-containers` — enable/disable container scanning
- `--all-languages` — run SAST for all languages configured by the connectors
- `--output <file>` — path to write the consolidated Socket facts JSON
- `--workspace <path>` — path to repository workspace (defaults to current directory)
- `--repo <owner/repo>` — repository identifier for integrations
- `--branch <branch>` — repository branch to analyze
- `--socket-tier1` / `--no-socket-tier1` — enable/disable Socket tier1 reporting
- `--socket-org <org>` — Socket organization slug (required for Socket API calls)
- `--console-tabular-enabled` / `--no-console-tabular-enabled` — prefer tabular console output
- `--verbose` / `--no-verbose` — enable/disable debug logging

Connector-specific CLI flags are declared dynamically in `socket_basics/connectors.yaml` and will appear in `--help` when available.

## Environment variables (INPUT_ prefix)

All environment variables used to configure scanning behavior follow the `INPUT_{PARAM_NAME}` pattern (uppercase). The precedence order is:

1. CLI arguments
2. Environment variables (`INPUT_*`)
3. `socket_basics/connectors.yaml`
4. Built-in defaults

Common environment variables used by the project (examples):

- `INPUT_PYTHON_SAST_ENABLED=true|false`
- `INPUT_SECRET_SCANNING_ENABLED=true|false`
- `INPUT_DOCKERFILES=Dockerfile,Dockerfile.prod`
- `INPUT_DOCKER_IMAGES=org/image:tag,org/other:tag`
- `INPUT_SOCKET_SCANNING_ENABLED=true|false`
- `INPUT_SOCKET_ORG=<org-slug>`
- `INPUT_SOCKET_API_KEY=<api-key>`
- `INPUT_CONSOLE_ENABLED=true|false`
- `INPUT_SOCKET_CONSOLE_MODE=json|tabular`
- `INPUT_SLACK_ENABLED=true|false`
- `INPUT_SLACK_WEBHOOK_URL=<url>`
- `INPUT_JIRA_ENABLED=true|false`
- `INPUT_JIRA_PROJECT=<PROJECTKEY>`

Connector-specific env vars are listed under each connector's `parameters` block in `socket_basics/connectors.yaml` (look for `env_variable` entries).

## Connector architecture

Connectors live under `socket_basics/core/connector/`. Each connector is a small adapter that:

- Implements a `scan()` method that executes the underlying tool and returns raw results
- Implements a `_process_results(raw_results)` method that converts raw output into the Socket facts structure

Connectors are registered and configured via `socket_basics/connectors.yaml`. Typical fields in the YAML mapping:

- `module_path`: Python import path for the connector
- `class`: connector class name
- `enabled_by_default`: boolean
- `parameters`: list of parameter mappings with `name`, `option`, `env_variable`, `type`, and `default`

Add a new connector by creating a directory under `socket_basics/core/connector/<tool>/`, implementing the connector class, and adding an entry to `connectors.yaml`.

## Testing connectors (app_tests)

Connector integration tests live in `app_tests/`. This folder is the authoritative place to run connector-level integration tests that exercise scanners against sample repositories or inputs. Do not rely on `local_tests/` or `samples/` for official connector testing — `app_tests/` is maintained for that purpose.

## Notifiers

Notifiers are responsible for delivering the consolidated report to different channels. Built-in notifiers include:

- Console (JSON or tabular)
- Slack
- Jira
- Webhook
- Sumo Logic
- MS Sentinel

Notifier behavior is configured via `socket_basics/notifications.yaml` or via connector-specific CLI flags and `INPUT_` environment variables.

## Output format

All scanners' findings are normalized into a consolidated Socket facts JSON structure. High-level shape:

```json
{
	"components": [
		{
			"type": "file",
			"name": "path/to/file",
			"alerts": [
				{
					"type": "sast|secret|container",
					"severity": "low|medium|high|critical",
					"message": "description",
					"location": {"path": "file/path", "line": 42}
				}
			]
		}
	]
}
```

If `--output` is specified the JSON is written to that file. If not specified and console notifier is enabled the output is printed to stdout in the selected console mode.

Sample consolidated outputs are provided in the `samples/` directory.

## Docker usage

Build the project Docker image and run a scan inside the container:

```sh
docker build -t socketdev/security-wrapper .

# Example run (prints to console; replace placeholders as needed)
docker run --rm -v "$PWD:/code" \
	-e "INPUT_CONSOLE_ENABLED=true" \
	-e "INPUT_PYTHON_SAST_ENABLED=true" \
	-e "INPUT_SECRET_SCANNING_ENABLED=true" \
	-e "INPUT_SOCKET_SCANNING_ENABLED=true" \
	-e "INPUT_SOCKET_ORG=your-socket-org" \
	-e "INPUT_SOCKET_API_KEY=your-api-key" \
	socketdev/security-wrapper \
	--python --secrets --containers --output /code/scan-results.socket.facts.json
```

Notes:

- Image scanning (`INPUT_DOCKER_IMAGES`) requires Docker/DIND access or pre-pulled images inside the container
- Dockerfile scanning only requires the Dockerfile(s) to be present in the workspace

## GitHub Actions usage

This repository exposes a GitHub Action (see `action.yml`) which runs the Docker image and accepts many inputs to configure scanning and notifications. Below is a comprehensive list of available inputs (names are the action inputs; when using environment variables in workflows they map to the same semantic names under `with:`):

Core inputs:

- `github_token` (required) — GitHub token used to post PR comments

Enable flags (true/false):

- `python_sast_enabled` — enable Python SAST
- `golang_sast_enabled` — enable Golang SAST
- `javascript_sast_enabled` — enable JavaScript SAST
- `dockerfile_enabled` — enable Dockerfile analysis
- `image_enabled` — enable image scanning
- `secret_scanning_enabled` — enable secret scanning
- `socket_scanning_enabled` — enable Socket reachability scanning
- `socket_sca_enabled` — enable Socket SCA scanning

Docker/trivy inputs:

- `docker_images` — comma-separated Docker images to scan
- `dockerfiles` — comma-separated Dockerfile paths to scan

Trufflehog inputs:

- `trufflehog_exclude_dir` — comma-separated dirs to exclude
- `trufflehog_rules` — rules to enable
- `trufflehog_show_unverified` — show unverified secrets

Socket configuration:

- `socket_org` — Socket organization slug (required for Socket integrations)
- `socket_api_key` — API key for Socket
- `socket_security_api_key` — API key for SCA scanning
- `socket_sca_files` — comma-separated manifest files to include in SCA

SAST and rule controls:

- `all_languages_enabled` — run SAST for all supported languages
- `all_rules_enabled` — run all bundled SAST rules
- Per-language enable flags (each accept `true|false`):
	- `python_sast_enabled`, `javascript_sast_enabled`, `typescript_sast_enabled`, `go_sast_enabled`, `golang_sast_enabled`, `java_sast_enabled`, `php_sast_enabled`, `ruby_sast_enabled`, `csharp_sast_enabled`, `dotnet_sast_enabled`, `c_sast_enabled`, `cpp_sast_enabled`, `kotlin_sast_enabled`, `scala_sast_enabled`, `swift_sast_enabled`, `rust_sast_enabled`, `elixir_sast_enabled`

- Per-language rule overrides (comma-separated lists):
	- `<lang>_enabled_rules` and `<lang>_disabled_rules` for languages such as `python`, `javascript`, `go`, `java`, `php`, `ruby`, `csharp`, `dotnet`, `c`, `cpp`, `kotlin`, `scala`, `swift`, `rust`, `elixir`

Trivy-specific:

- `trivy_exclude_dir` — comma-separated dirs to exclude from Trivy
- `trivy_rules` — rules to enable in Trivy
- `trivy_disabled_rules` — comma-separated rules to disable
- `trivy_image_scanning_disabled` — disable Trivy image scanning

Log forwarding / SIEM:

- `sumo_logic_enabled` — enable Sumo Logic forwarding
- `sumo_logic_http_source_url` — Sumo Logic HTTP source URL
- `ms_sentinel_enabled` — enable Microsoft Sentinel forwarding
- `ms_sentinel_workspace_id` — workspace id
- `ms_sentinel_shared_key` — shared key

Jira / ticketing:

- `jira_enabled` — enable Jira ticket creation
- `jira_url` — Jira instance URL
- `jira_email` — Jira account email
- `jira_api_token` — Jira API token
- `jira_project` — Jira project key

Slack / Teams / Webhook:

- `slack_enabled` — enable Slack notifications
- `slack_webhook_url` — Slack webhook URL
- `teams_enabled` — enable Teams notifications
- `teams_webhook_url` — Teams webhook URL
- `webhook_enabled` — enable generic webhook
- `webhook_url` — webhook URL
- `webhook_headers` — JSON string of custom headers for the webhook

Scan scope:

- `scan_all` — if true, scan the entire workspace regardless of git diff
- `scan_files` — comma-separated list of files to scan (if omitted, action will use git diff or `scan_all`)

Branding:

- The action configures brand icon/color via `branding` in `action.yml` (not user-configurable via inputs)

Example GitHub Actions workflow snippet:

```yaml
name: Security Scan
on:
	pull_request:
		types: [opened, synchronize, reopened]

jobs:
	security-scan:
		runs-on: ubuntu-latest
		steps:
			- uses: actions/checkout@v4
			- name: Run security wrapper
				uses: ./  # when running from the same repo; replace with org/repo@vX for published action
				with:
					github_token: ${{ secrets.GITHUB_TOKEN }}
					python_sast_enabled: 'true'
					secret_scanning_enabled: 'true'
					dockerfile_enabled: 'true'
					socket_scanning_enabled: 'true'
					socket_org: 'your-socket-org'
					socket_api_key: ${{ secrets.SOCKET_API_KEY }}
```

Make sure to set any secrets (Socket API keys, Jira tokens, Slack webhooks) using repository or organization secrets.

## GitHub PR notifier environment variables

When running in GitHub Actions or other CI, the GitHub PR notifier will attempt to discover repository and branch information from the environment first, then fall back to local `git` and finally any workspace `facts` that were provided. The notifier recognizes the following environment variables and action inputs (use whichever is most convenient in your workflow):

- `GITHUB_REPOSITORY` — owner/repo identifier (e.g., `org/repo`). Automatically provided by GitHub Actions.
- `GITHUB_EVENT_PATH` — path to the GitHub event JSON file (Actions provides this). The notifier will read the event payload to extract PR/head info when present.
- `GITHUB_REF` / `GITHUB_HEAD_REF` — branch refs provided by the Actions runner. `GITHUB_HEAD_REF` is set for pull_request workflows; otherwise `GITHUB_REF` may contain `refs/heads/<branch>`.
- `GITHUB_SHA` — commit SHA; used to build exact blob links when available.
- `GITHUB_PR_NUMBER` — optional environment variable you can set to force the PR number to use when posting comments.
- `INPUT_PR_NUMBER` — action input equivalent to `GITHUB_PR_NUMBER` (useful when invoking the action via `with:` in a workflow).
- `INPUT_GITHUB_API_URL` — override the GitHub API base (useful for GitHub Enterprise). When set, it will be normalized to a full URL if a host-only string is provided.

Priority for discovery is: explicit action inputs / environment variables → event payload → local `git` discovery → `facts` provided via `--workspace`.

If you need to force a PR comment to a specific PR, set `GITHUB_PR_NUMBER` (or `INPUT_PR_NUMBER` in the action `with:` block).


## Development & testing

- Run unit and local tests from `local_tests/` or `app_tests/`.
- Use `uv run` or `python -m` to execute modules while iterating.

Local quick test example:

```sh
# activate venv
source .venv/bin/activate
# run a subset of local tests
python -m pytest local_tests/test_simple_scan.py -q
```

Keep test artifacts under `test_results/` (do not create test files outside that directory).

## Troubleshooting

- If connectors fail to load, verify `module_path` and `class` in `socket_basics/connectors.yaml`.
- For Socket API or notifier errors, ensure `INPUT_SOCKET_ORG` and `INPUT_SOCKET_API_KEY` (or notifier secrets) are set.
- Enable `--verbose` (or `INPUT_VERBOSE=true`) to see debug logs.
- For image scanning failures, confirm Docker access inside the runtime environment.

## Contributing

1. Implement new connectors under `socket_basics/core/connector/`.
2. Add notifier implementations under `socket_basics/core/notification/` if needed.
3. Add configuration entries to `socket_basics/connectors.yaml` and `socket_basics/notifications.yaml`.
4. Add sample test apps to `app_tests/`.

## License

This project is licensed under the terms in `LICENSE` in the repository root.

