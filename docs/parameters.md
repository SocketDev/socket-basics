# Socket Basics Parameters Reference

Complete reference for all CLI options and environment variables supported by Socket Basics.

## Table of Contents

- [Core Options](#core-options)
- [Language Scanning](#language-scanning)
- [Secret Scanning](#secret-scanning)
- [Container Scanning](#container-scanning)
- [Socket Integration](#socket-integration)
- [Notification Options](#notification-options)
- [Environment Variables](#environment-variables)
- [Configuration File](#configuration-file)

## Core Options

### `--config CONFIG`
Path to JSON configuration file. JSON config is merged with environment variables (environment takes precedence).

**Example:**
```bash
socket-basics --config /path/to/config.json
```

### `--output OUTPUT`
Output file name for scan results.

**Default:** `.socket.facts.json`

**Example:**
```bash
socket-basics --output scan-results.json
```

### `--workspace WORKSPACE`
Workspace directory to scan.

**Default:** Current directory

**Example:**
```bash
socket-basics --workspace /path/to/project
```

### `--repo REPO`
Repository name (use when workspace is not a git repo).

**Example:**
```bash
socket-basics --repo myorg/myproject
```

### `--branch BRANCH`
Branch name (use when workspace is not a git repo).

**Example:**
```bash
socket-basics --branch main
```

### `--default-branch`
Explicitly mark this as the default branch (sets `make_default_branch=true` and `set_as_pending_head=true`).

**Example:**
```bash
socket-basics --default-branch
```

### `--commit-message COMMIT_MESSAGE`
Commit message for full scan submission.

**Example:**
```bash
socket-basics --commit-message "feat: add new feature"
```

### `--pull-request PULL_REQUEST`
Pull request number for full scan submission.

**Example:**
```bash
socket-basics --pull-request 123
```

### `--committers COMMITTERS`
Comma-separated list of committers for full scan submission.

**Example:**
```bash
socket-basics --committers "user1@example.com,user2@example.com"
```

### `--scan-files SCAN_FILES`
Comma-separated list of files to scan.

**Example:**
```bash
socket-basics --scan-files "src/app.py,src/utils.js"
```

### `--changed-files CHANGED_FILES`
Comma-separated list of files to scan or 'auto' to detect changed files from git.

**Example:**
```bash
socket-basics --changed-files auto
```

### `--console-tabular-enabled`
Enable consolidated console tabular output (displays results in formatted tables).

**Example:**
```bash
socket-basics --console-tabular-enabled
```

### `--console-json-enabled`
Enable consolidated console JSON output (displays results as JSON).

**Example:**
```bash
socket-basics --console-json-enabled
```

### `--verbose`, `-v`
Enable verbose logging for debugging.

**Example:**
```bash
socket-basics --verbose
```

### `--enable-s3-upload`
Enable uploading the output file to S3 using `SOCKET_S3_*` environment variables.

**Example:**
```bash
socket-basics --enable-s3-upload
```

## Language Scanning

### Enabling Languages

Use these flags to enable SAST (Static Application Security Testing) scanning for specific languages:

- `--python` - Enable Python SAST scanning
- `--javascript` - Enable JavaScript/TypeScript SAST scanning
- `--go` or `--golang` - Enable Go SAST scanning
- `--java` - Enable Java SAST scanning
- `--php` - Enable PHP SAST scanning
- `--ruby` - Enable Ruby SAST scanning
- `--csharp` or `--dotnet` - Enable C#/.NET SAST scanning
- `--c` - Enable C SAST scanning
- `--cpp` - Enable C++ SAST scanning
- `--kotlin` - Enable Kotlin SAST scanning
- `--scala` - Enable Scala SAST scanning
- `--swift` - Enable Swift SAST scanning
- `--rust` - Enable Rust SAST scanning
- `--elixir` - Enable Elixir SAST scanning
- `--erlang` - Enable Erlang SAST scanning

**Example:**
```bash
socket-basics --python --javascript --go
```

### `--all-languages`
Enable SAST for all supported languages.

**Example:**
```bash
socket-basics --all-languages
```

### `--all-rules`
Run all bundled SAST rules regardless of language filters.

**Example:**
```bash
socket-basics --all-rules
```

### `--use-custom-sast-rules`
Use custom SAST rules instead of bundled rules (falls back to bundled rules for languages without custom rules).

**Environment Variable:** `INPUT_USE_CUSTOM_SAST_RULES`

**Default:** `false`

**Example:**
```bash
socket-basics --python --use-custom-sast-rules
```

### `--custom-sast-rule-path CUSTOM_SAST_RULE_PATH`
Relative path to custom SAST rules directory (relative to workspace if set, otherwise cwd).

**Environment Variable:** `INPUT_CUSTOM_SAST_RULE_PATH`

**Default:** `custom_rules`

**Example:**
```bash
socket-basics --python --use-custom-sast-rules --custom-sast-rule-path "my_custom_rules"
```

### Language-Specific Rule Configuration

For each language, you can enable or disable specific rules:

**Pattern:** `--<language>-enabled-rules` or `--<language>-disabled-rules`

**Examples:**
```bash
# Enable specific Python rules
socket-basics --python --python-enabled-rules "sql-injection,xss-detection"

# Disable specific JavaScript rules
socket-basics --javascript --javascript-disabled-rules "console-log,debugger-statement"

# Enable specific Go rules
socket-basics --go --go-enabled-rules "error-handling,sql-injection"
```

**Available for:**
- `--python-enabled-rules` / `--python-disabled-rules`
- `--javascript-enabled-rules` / `--javascript-disabled-rules`
- `--go-enabled-rules` / `--go-disabled-rules`
- `--java-enabled-rules` / `--java-disabled-rules`
- `--php-enabled-rules` / `--php-disabled-rules`
- `--ruby-enabled-rules` / `--ruby-disabled-rules`
- `--csharp-enabled-rules` / `--csharp-disabled-rules`
- `--dotnet-enabled-rules` / `--dotnet-disabled-rules`
- `--c-enabled-rules` / `--c-disabled-rules`
- `--cpp-enabled-rules` / `--cpp-disabled-rules`
- `--kotlin-enabled-rules` / `--kotlin-disabled-rules`
- `--scala-enabled-rules` / `--scala-disabled-rules`
- `--swift-enabled-rules` / `--swift-disabled-rules`
- `--rust-enabled-rules` / `--rust-disabled-rules`
- `--elixir-enabled-rules` / `--elixir-disabled-rules`

### `--opengrep-notify OPENGREP_NOTIFY`
Notification method for OpenGrep SAST results (e.g., console, slack).

**Example:**
```bash
socket-basics --python --opengrep-notify console
```

## Secret Scanning

### `--secrets`
Enable secret scanning using TruffleHog.

**Example:**
```bash
socket-basics --secrets
```

### `--disable-secrets`
Disable all secret scanning features.

**Example:**
```bash
socket-basics --disable-secrets
```

### `--exclude-dir EXCLUDE_DIR`
Comma-separated list of directories to exclude from secret scanning.

**Example:**
```bash
socket-basics --secrets --exclude-dir "node_modules,vendor,dist,.git"
```

### `--trufflehog-notify TRUFFLEHOG_NOTIFY`
Notification method for TruffleHog secret scanning results.

**Example:**
```bash
socket-basics --secrets --trufflehog-notify slack
```

### `--show-unverified`
Show unverified secrets in TruffleHog results (by default only verified secrets are shown).

**Example:**
```bash
socket-basics --secrets --show-unverified
```

## Container Scanning

### `--images IMAGES`
Comma-separated list of container images to scan (auto-enables image scanning).

**Example:**
```bash
socket-basics --images "nginx:latest,redis:7,postgres:15"
```

### `--dockerfiles DOCKERFILES`
Comma-separated list of Dockerfiles to scan (auto-enables Dockerfile scanning).

**Example:**
```bash
socket-basics --dockerfiles "Dockerfile,docker/Dockerfile.prod"
```

### `--trivy-notify TRIVY_NOTIFY`
Notification method for Trivy container scanning results.

**Example:**
```bash
socket-basics --images "nginx:latest" --trivy-notify console
```

### `--trivy-disabled-rules TRIVY_DISABLED_RULES`
Comma-separated list of Trivy rules to disable.

**Example:**
```bash
socket-basics --images "nginx:latest" --trivy-disabled-rules "CVE-2023-1234,CVE-2023-5678"
```

### `--trivy-image-scanning-disabled`
Disable Trivy image scanning.

**Example:**
```bash
socket-basics --trivy-image-scanning-disabled
```

### `--trivy-vuln-enabled`
Enable Trivy vulnerability scanning for all supported language ecosystems.

**Example:**
```bash
socket-basics --trivy-vuln-enabled
```

## Socket Integration

### `--socket-tier1`
Enable Socket Tier 1 reachability analysis for dependency scanning.

**Example:**
```bash
socket-basics --socket-tier1
```

### `--socket-additional-params SOCKET_ADDITIONAL_PARAMS`
Additional CLI params for 'socket scan reach' (comma or space separated).

**Example:**
```bash
socket-basics --socket-tier1 --socket-additional-params "--view=full,--all"
```

## Notification Options

### Slack

**CLI Option:** `--slack-webhook-url SLACK_WEBHOOK_URL`

**Environment Variables:** `SLACK_WEBHOOK_URL`, `INPUT_SLACK_WEBHOOK_URL`

**Example:**
```bash
socket-basics --slack-webhook-url "https://hooks.slack.com/services/T00/B00/XXXX"
```

### Generic Webhook

**CLI Option:** `--webhook-url WEBHOOK_URL`

**Environment Variable:** `WEBHOOK_URL`

**Example:**
```bash
socket-basics --webhook-url "https://api.example.com/webhook"
```

### Microsoft Sentinel

**CLI Options:**
- `--ms-sentinel-workspace-id MS_SENTINEL_WORKSPACE_ID`
- `--ms-sentinel-key MS_SENTINEL_KEY`

**Environment Variables:**
- `MS_SENTINEL_WORKSPACE_ID`, `INPUT_MS_SENTINEL_WORKSPACE_ID`
- `MS_SENTINEL_SHARED_KEY`, `INPUT_MS_SENTINEL_SHARED_KEY`

**Example:**
```bash
socket-basics --ms-sentinel-workspace-id "your-id" --ms-sentinel-key "your-key"
```

### Sumo Logic

**CLI Option:** `--sumologic-endpoint SUMOLOGIC_ENDPOINT`

**Environment Variables:** `SUMOLOGIC_ENDPOINT`, `INPUT_SUMOLOGIC_ENDPOINT`, `SUMO_LOGIC_HTTP_SOURCE_URL`

**Example:**
```bash
socket-basics --sumologic-endpoint "https://endpoint.sumologic.com/..."
```

### Jira

**CLI Options:**
- `--jira-url JIRA_URL`
- `--jira-project JIRA_PROJECT`
- `--jira-email JIRA_EMAIL`
- `--jira-api-token JIRA_API_TOKEN`

**Environment Variables:**
- `JIRA_URL`, `INPUT_JIRA_URL`
- `JIRA_PROJECT`, `INPUT_JIRA_PROJECT`
- `JIRA_EMAIL`, `INPUT_JIRA_EMAIL`
- `JIRA_API_TOKEN`, `INPUT_JIRA_API_TOKEN`

**Example:**
```bash
socket-basics \
  --jira-url "https://your-org.atlassian.net" \
  --jira-project "SEC" \
  --jira-email "you@example.com" \
  --jira-api-token "your-token"
```

**Local Verification (No Jira API Calls)**
Use the helper script to confirm dashboard/env Jira settings are wired into the notifier:
```bash
./venv/bin/python scripts/verify_jira_dashboard_config.py
```
Notes:
- The script only loads config and inspects notifier parameters; it does not contact Jira.
- It requires `SOCKET_SECURITY_API_KEY` (and usually `SOCKET_ORG`) to fetch dashboard config.
- You can use `INPUT_JIRA_*` env vars to simulate dashboard values.

### GitHub Pull Request Comments

**CLI Options:**
- `--github-token GITHUB_TOKEN`
- `--github-api-url GITHUB_API_URL`

**Environment Variables:**
- `GITHUB_TOKEN`, `INPUT_GITHUB_TOKEN`
- `GITHUB_API_URL` (optional, defaults to public GitHub API)

**Example:**
```bash
socket-basics --github-token "ghp_your_token"
```

### Microsoft Teams

**CLI Option:** `--msteams-webhook-url MSTEAMS_WEBHOOK_URL`

**Environment Variables:** `MSTEAMS_WEBHOOK_URL`, `INPUT_MSTEAMS_WEBHOOK_URL`

**Example:**
```bash
socket-basics --msteams-webhook-url "https://outlook.office.com/webhook/..."
```

## Environment Variables

### Socket Configuration

| Variable | Aliases | Description |
|----------|---------|-------------|
| `SOCKET_SECURITY_API_KEY` | `SOCKET_API_KEY`, `SOCKET_SECURITY_API_TOKEN`, `INPUT_SOCKET_SECURITY_API_KEY`, `INPUT_SOCKET_API_KEY` | Socket Security API key |
| `SOCKET_ORG` | `SOCKET_ORG_SLUG`, `INPUT_SOCKET_ORG` | Socket organization slug |

### GitHub Integration

| Variable | Aliases | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | `INPUT_GITHUB_TOKEN` | GitHub token for API access and PR comments |
| `GITHUB_REPOSITORY` | `INPUT_GITHUB_REPOSITORY` | Repository name (owner/repo) |
| `GITHUB_PR_NUMBER` | `INPUT_PR_NUMBER` | Pull request number |
| `GITHUB_WORKSPACE` | - | Workspace directory (auto-set in GitHub Actions) |
| `GITHUB_ACTOR` | - | GitHub username who triggered the action |
| `GITHUB_HEAD_REF` | - | Source branch for pull request |
| `GITHUB_SHA` | - | Commit SHA |
| `GITHUB_REF_NAME` | - | Branch or tag name |
| `GITHUB_EVENT_PATH` | - | Path to event payload file |

### Scanning Configuration

| Variable | Description |
|----------|-------------|
| `OUTPUT_DIR` | Directory for output files (default: current directory) |
| `INPUT_SCAN_ALL` | Set to 'true' to scan all files |
| `INPUT_SCAN_FILES` | Comma-separated list of files to scan |
| `INPUT_CONSOLE_TABULAR_ENABLED` | Enable tabular console output |
| `INPUT_VERBOSE` | Enable verbose logging |

### S3 Upload Configuration

| Variable | Description |
|----------|-------------|
| `SOCKET_S3_ENABLED` | Set to 'true', '1', or 'yes' to enable S3 upload |
| `SOCKET_S3_BUCKET` | S3 bucket name |
| `SOCKET_S3_REGION` | S3 bucket region |
| `SOCKET_S3_ACCESS_KEY_ID` | AWS access key ID |
| `SOCKET_S3_SECRET_ACCESS_KEY` | AWS secret access key |

### Notification Configuration

All notification integrations support environment variables as alternatives to CLI options. See [Notification Options](#notification-options) for details.

### OpenGrep/SAST Configuration

| Variable | Description |
|----------|-------------|
| `INPUT_OPENGREP_RULES_DIR` | Custom directory containing SAST rules |

## Configuration File

You can provide configuration via a JSON file using `--config`:

### Example Configuration File

```json
{
  "workspace": "/path/to/project",
  "output": "security-scan.json",
  "console_tabular_enabled": true,
  "verbose": false,
  
  "python_sast_enabled": true,
  "javascript_sast_enabled": true,
  "go_sast_enabled": true,
  
  "secrets_enabled": true,
  "trufflehog_exclude_dir": "node_modules,vendor,dist,.git",
  "show_unverified": false,
  
  "socket_tier_1_enabled": true,
  "socket_org": "your-org-slug",
  "socket_api_key": "scrt_your_api_key",
  
  "images": "nginx:latest,redis:7",
  "trivy_vuln_enabled": true,
  
  "slack_webhook_url": "https://hooks.slack.com/services/T00/B00/XXXX",
  "github_token": "ghp_your_token"
}
```

### Configuration Precedence

Configuration is merged in the following order (later sources override earlier ones):

1. Default values
2. JSON configuration file (via `--config`)
3. Environment variables
4. Command-line arguments

**Example:**
```bash
# JSON file sets python_sast_enabled: true
# Environment has PYTHON_SAST_ENABLED=false
# CLI has --javascript
# Result: JavaScript enabled, Python disabled (env override), other settings from JSON
socket-basics --config config.json --javascript
```

## Common Usage Patterns

### Scan Python and JavaScript with Secrets

```bash
socket-basics \
  --workspace /path/to/project \
  --python \
  --javascript \
  --secrets \
  --console-tabular-enabled
```

### Full Scan with All Features

```bash
socket-basics \
  --workspace /path/to/project \
  --all-languages \
  --secrets \
  --socket-tier1 \
  --images "myapp:latest" \
  --console-tabular-enabled \
  --verbose
```

### Scan with Notifications

```bash
socket-basics \
  --workspace /path/to/project \
  --python \
  --secrets \
  --slack-webhook-url "https://hooks.slack.com/..." \
  --github-token "ghp_..."
```

### CI/CD Scan (Changed Files Only)

```bash
socket-basics \
  --changed-files auto \
  --python \
  --javascript \
  --secrets \
  --console-json-enabled
```

### Docker Container Scan

```bash
socket-basics \
  --images "nginx:latest,postgres:15" \
  --dockerfiles "Dockerfile" \
  --trivy-vuln-enabled \
  --console-tabular-enabled
```
