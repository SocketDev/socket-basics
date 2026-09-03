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
Explicit comma-separated list of files to scan. Scopes **all** scanners —
SAST/OpenGrep, secrets, and container scanning — to just these files instead of
the whole workspace. Used when `--changed-files` is not set (`--changed-files`
takes precedence when both are provided). Paths that do not exist are skipped;
if none exist, the scanners are skipped rather than scanning the whole repo.

**Example:**
```bash
socket-basics --scan-files "src/app.py,src/utils.js"
```

### `--changed-files CHANGED_FILES`
Diff-only mode: scope **all** scanners (SAST/OpenGrep, secrets, containers) to
changed files only, the way Socket SCA Pull Request alerts behave. Accepts:

- a comma-separated file list (e.g. `src/app.py,src/utils.js`)
- a commit hash — files changed in that commit
- `auto` — the PR base diff in CI; staged (`--cached`) changes only in a local
  run with no PR context
- `pr` — the PR base diff, and nothing else
- `current-commit` — files in the `HEAD` commit

The same value works from the CLI (`--changed-files`), the `changed_files`
action input, the `INPUT_CHANGED_FILES` environment variable, a `--config` JSON
file, and a Socket dashboard config. Whichever way it arrives, it is resolved
against git once, in the same place.

Deletions are excluded from PR/`auto`/`pr` diffs so removed paths never become
scan targets. When the diff resolves to no existing files (e.g. a delete-only
PR), the scanners are skipped rather than falling back to scanning the whole
repository. For PR/`auto`/`pr` modes, check out with full history (e.g.
`actions/checkout` with `fetch-depth: 0`) so the base branch is available.

**Finding the pull request base.** `auto` and `pr` try, in order:

1. `GITHUB_BASE_REF` — set by GitHub on `pull_request` and
   `pull_request_target` triggers only
2. `pull_request.base.sha` from the event payload at `GITHUB_EVENT_PATH` — an
   exact commit, so it works even when no remote-tracking branch exists
3. `pull_request.base.ref` from the same payload

Each candidate is tried as `origin/<ref>` and then bare. If none resolves, the
run logs the underlying reason (shallow checkout, workspace is not a git
repository, git refused to read the repository, no PR base at all) and fails
with a configuration error. It never reports a green scan of nothing and never
silently widens to the whole repository.

Set **`scan_all`** to opt into widening on that failure path. An unresolvable
scope then falls back to a full-workspace scan with a warning, consistently
across every enabled scanner. A scope that resolves successfully remains
authoritative even when `scan_all` is set; a genuinely empty diff still skips
the scoped scanners.

Steps 2 and 3 cover the triggers whose payload carries a top-level
`pull_request`: `pull_request`, `pull_request_target`, `pull_request_review`
and `pull_request_review_comment`. They do **not** cover `issue_comment`. That
payload has `issue.pull_request` instead, which is a set of URLs with no base
ref or sha in it, so there is nothing to diff against without a GitHub API
call. If you run the scan from a comment trigger, look the base up in the
workflow and pass it in yourself:

```yaml
- id: prbase
  run: echo "ref=$(gh pr view ${{ github.event.issue.number }} --json baseRefName -q .baseRefName)" >> "$GITHUB_OUTPUT"
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
- uses: SocketDev/socket-basics@v2
  env:
    GITHUB_BASE_REF: ${{ steps.prbase.outputs.ref }}
  with:
    changed_files: 'auto'
```

Otherwise the run explains that it was triggered by a comment on a pull request
and fails because it cannot work the base out on its own.

**Socket Tier 1 reachability is not diff-scoped.** It runs `socket scan reach`
over the whole workspace because reachability needs the full dependency graph,
so a `changed_files` scope does not narrow it. That is unchanged behavior, and
the scanners this setting does scope are SAST/OpenGrep, secrets and containers.

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

When this is enabled, custom rules are loaded from YAML files under
`--custom-sast-rule-path`. Each rule must include a `languages` list so Socket
Basics can map it to the correct OpenGrep language rule file.

### `--custom-sast-rule-path CUSTOM_SAST_RULE_PATH`
Relative path to custom SAST rules directory (relative to workspace if set, otherwise cwd).

**Environment Variable:** `INPUT_CUSTOM_SAST_RULE_PATH`

**Default:** `custom_rules`

**Example:**
```bash
socket-basics --python --use-custom-sast-rules --custom-sast-rule-path "my_custom_rules"
```

Custom rule file notes:
- `.yml` and `.yaml` files are discovered recursively.
- Files ending in `.test.yml` or `.test.yaml` are ignored.
- Rules without `languages` are skipped.

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

### `--sast-ignore-overrides SAST_IGNORE_OVERRIDES`
Comma-separated list of SAST ignore overrides in `rule_id` or `rule_id:path` format.

**Environment Variable:** `INPUT_SAST_IGNORE_OVERRIDES`

**Examples:**
```bash
# Ignore a rule everywhere in the repo
socket-basics --javascript --sast-ignore-overrides "js-sql-injection"

# Ignore a rule only for one exact repo-relative file
socket-basics --javascript --sast-ignore-overrides "js-sql-injection:index.js"

# Mix rule-only and rule+path overrides in one comma-separated list
socket-basics --javascript --sast-ignore-overrides "js-express-async-no-error-handler,js-sql-injection:index.js,js-missing-helmet"
```

Notes:
- Paths must be exact repo-relative paths.
- Paths are normalized to forward-slash form, so Windows-style input such as `src\\unsafe\\demo.js` is accepted.
- Globs and directory-prefix matching are not supported in this first version.
- A `rule_id:path` entry uses exact `rule_id AND path` matching. A bad path does not degrade into a rule-only ignore.
- If the configured path does not exist under the current workspace, Socket Basics logs a warning to help catch typos or copied paths from another repo.
- If the same rule is also disabled via `<language>-disabled-rules` or dashboard policy, that broader ignore still applies across the repo.
- Ignored alerts in `.socket.facts.json` include `actionReason` so you can distinguish `sast_ignore_override` from `disabled_rule`.

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
Comma-separated literal directory/file names or glob patterns to exclude from
secret scanning beneath the workspace root. Matching is case-sensitive. For
example, `**/appsettings.*.json` matches files at any directory depth. Excluded
paths are removed from the scan entirely — they are not scanned for verified or
unverified secrets.

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
Include unverified and unknown secrets in TruffleHog results. TruffleHog always performs
verification; this flag only widens which result types are reported. By default only
verified secrets are returned (`--results=verified`); with this flag, verified, unverified,
and unknown results are all returned (`--results=verified,unverified,unknown`).

Verified findings are reported as critical and block; unverified findings are reported as
low and do not block.

> **Verification makes live network requests.** TruffleHog validates candidate secrets
> against third-party endpoints (AWS, GitHub, Slack, and so on). If a runner cannot reach
> those endpoints, the result is classified as `unknown`, which is *not* returned in the
> default verified-only mode — an air-gapped scan will report zero findings rather than
> failing. Set `--show-unverified` on egress-restricted runners so `unknown` results are
> still reported.

**Example:**
```bash
socket-basics --secrets --show-unverified
```

## Container Scanning

> [!NOTE]
> Container scanning is backed by Trivy, which is bundled in the pre-built
> GitHub Action and Docker images (a Socket-built distribution, digest-pinned).
> These parameters work out of the box on those paths, and equally with a
> [native installation](local-installation.md#trivy-container-scanning).

### `--images IMAGES`
Comma-separated list of container images to scan (auto-enables image scanning).

**Example:**
```bash
socket-basics --images "nginx:1.27.4,redis:7.4,postgres:15.8"
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
socket-basics --images "nginx:1.27.4" --trivy-notify console
```

### `--trivy-disabled-rules TRIVY_DISABLED_RULES`
Comma-separated list of Trivy rules to disable.

**Example:**
```bash
socket-basics --images "nginx:1.27.4" --trivy-disabled-rules "CVE-2023-1234,CVE-2023-5678"
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
| `INPUT_OPENGREP_RULES_DIR` | Override directory for bundled OpenGrep rule files (`*.yml`) |
| `INPUT_USE_CUSTOM_SAST_RULES` | Enable repository custom SAST rules |
| `INPUT_CUSTOM_SAST_RULE_PATH` | Relative directory path for repository custom SAST rules |
| `INPUT_SAST_IGNORE_OVERRIDES` | Comma-separated `rule_id` or `rule_id:path` SAST ignore overrides |

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
  "use_custom_sast_rules": true,
  "custom_sast_rule_path": ".socket/rules",
  "go_sast_enabled": true,
  "sast_ignore_overrides": "js-sql-injection:index.js",
  
  "secrets_enabled": true,
  "trufflehog_exclude_dir": "node_modules,vendor,dist,.git",
  "trufflehog_show_unverified": false,
  
  "socket_tier_1_enabled": true,
  "socket_org": "your-org-slug",
  "socket_api_key": "scrt_your_api_key",
  
  "images": "nginx:1.27.4,redis:7.4",
  "trivy_vuln_enabled": true,
  
  "slack_webhook_url": "https://hooks.slack.com/services/T00/B00/XXXX",
  "github_token": "ghp_your_token"
}
```

### Configuration Precedence

Configuration is merged in the following order (later sources override earlier ones):

1. Default values
2. Environment variables
3. Socket Basics API configuration (when available and no `--config` file is used)
4. JSON configuration file (via `--config`)
5. Command-line arguments

**Example:**
```bash
# Environment sets python_sast_enabled=true
# Dashboard/API sets python_sast_enabled=false
# CLI has --javascript
# Result: JavaScript enabled, Python follows dashboard/API value, other settings from env/API
socket-basics --javascript
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
  --images "myapp:1.0.0" \
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

Scope every scanner — SAST/OpenGrep included — to only the files the PR changed,
so each PR reports findings for its own changes rather than the whole repo:

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
  --images "nginx:1.27.4,postgres:15.8" \
  --dockerfiles "Dockerfile" \
  --trivy-vuln-enabled \
  --console-tabular-enabled
```
