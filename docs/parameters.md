# Socket Basics Parameters Reference

Complete reference for all CLI options and environment variables supported by Socket Basics.

## Table of Contents

- [Name Mapping](#name-mapping) — CLI flag ↔ action input ↔ environment variable ↔ JSON key
- [Core Options](#core-options)
- [Language Scanning](#language-scanning)
- [Secret Scanning](#secret-scanning)
- [Container Scanning](#container-scanning)
- [Socket Integration](#socket-integration)
- [Notification Options](#notification-options)
- [Environment Variables](#environment-variables)
- [Configuration File](#configuration-file)

## Name Mapping

The same setting is spelled differently on each interface, and the CLI is
strict: an unknown flag such as `--python-sast-enabled` exits with
`unrecognized arguments`. Use this table to translate between them. Every
GitHub Action input is delivered to the container as the environment variable
`INPUT_<NAME>` (the input name upper-cased); a JSON key is the name used in a
`--config` file and in Socket dashboard configuration.

### Core, scope and credentials

| CLI flag | GitHub Action input | Environment variable | JSON key | Description |
|---|---|---|---|---|
| `--workspace` | —<sup>1</sup> | `GITHUB_WORKSPACE` | `workspace` | Directory to scan. Defaults to the current directory (`GITHUB_WORKSPACE` in Actions). |
| `--output` | — | `OUTPUT_DIR` (directory only) | — | Facts file name, default `.socket.facts.json`. Must stay inside the workspace when uploading to the dashboard. |
| `--config` | — | — | — | Path to a JSON configuration file. |
| `--changed-files` | `changed_files` | `INPUT_CHANGED_FILES` | `changed_files` | Diff-only scope: `auto`, `pr`, `current-commit`, a commit hash or a file list. |
| `--scan-files` | `scan_files` | `INPUT_SCAN_FILES` | `scan_files` | Explicit comma-separated file list. |
| — | `scan_all` | `INPUT_SCAN_ALL` | `scan_all` | Fail-open fallback when a `changed_files` scope cannot be resolved. |
| `--verbose`, `-v` | `verbose` | `INPUT_VERBOSE` | `verbose` | DEBUG logging. |
| `--console-tabular-enabled` | `console_tabular_enabled` | `INPUT_CONSOLE_TABULAR_ENABLED` | `console_tabular_enabled` | Print consolidated findings as tables. |
| `--console-json-enabled` | `console_json_enabled` | `INPUT_CONSOLE_JSON_ENABLED` | `console_json_enabled` | Print consolidated findings as JSON. |
| —<sup>2</sup> | `socket_org` | `SOCKET_ORG` (also `SOCKET_ORG_SLUG`, `INPUT_SOCKET_ORG`) | `socket_org` | Socket organization slug. Not the same thing as `--repo`. |
| —<sup>2</sup> | `socket_security_api_key` | `SOCKET_SECURITY_API_KEY` (also `SOCKET_SECURITY_API_TOKEN`, `SOCKET_API_KEY`, `INPUT_SOCKET_SECURITY_API_KEY`) | `socket_api_key`<sup>3</sup> | Socket API key (`full-scans` scope to upload, `socket-basics` scope to load dashboard config). |
| `--repo` | — | `GITHUB_REPOSITORY` | `repo` | `owner/repo` recorded on the scan and used to find the PR. Discovered from git when omitted. |
| `--branch` | — | `GITHUB_HEAD_REF`, `GITHUB_REF_NAME` | `branch` | Branch recorded on the scan. Discovered from git when omitted. |
| `--pull-request` | — | `GITHUB_PR_NUMBER` (also `INPUT_PR_NUMBER`) | — | PR number. The PR notifier reads the environment variable. |
| `--default-branch` | — | `SOCKET_DEFAULT_BRANCH` | — | Mark the scan as the repository default branch. |
| `--enable-s3-upload` | — | `SOCKET_S3_ENABLED` | — | Upload the facts file to S3 (see [S3 Upload Configuration](#s3-upload-configuration)). |

<sup>1</sup> The action declares a `workspace` input but does not currently honor it; the action always scans `GITHUB_WORKSPACE`. Narrow the scope with `changed_files` / `scan_files` instead.
<sup>2</sup> No CLI flag exists. Set the environment variable, or `socket_org` in a JSON file.
<sup>3</sup> A JSON `socket_api_key` is used to upload results but not to load dashboard configuration; prefer the environment variable.

### SAST languages (OpenGrep)

| CLI flag | GitHub Action input | Environment variable | JSON key | Description |
|---|---|---|---|---|
| `--python` | `python_sast_enabled` | `INPUT_PYTHON_SAST_ENABLED` | `python_sast_enabled` | Enable Python SAST scanning |
| `--javascript` | `javascript_sast_enabled` | `INPUT_JAVASCRIPT_SAST_ENABLED` | `javascript_sast_enabled` | Enable JavaScript/TypeScript SAST scanning |
| `--go` | `go_sast_enabled` | `INPUT_GO_SAST_ENABLED` | `go_sast_enabled` | Enable Go SAST scanning |
| `--golang` | `golang_sast_enabled` | `INPUT_GOLANG_SAST_ENABLED` | `golang_sast_enabled` | Enable Golang SAST scanning |
| `--java` | `java_sast_enabled` | `INPUT_JAVA_SAST_ENABLED` | `java_sast_enabled` | Enable Java SAST scanning |
| `--php` | `php_sast_enabled` | `INPUT_PHP_SAST_ENABLED` | `php_sast_enabled` | Enable PHP SAST scanning |
| `--ruby` | `ruby_sast_enabled` | `INPUT_RUBY_SAST_ENABLED` | `ruby_sast_enabled` | Enable Ruby SAST scanning |
| `--csharp` | `csharp_sast_enabled` | `INPUT_CSHARP_SAST_ENABLED` | `csharp_sast_enabled` | Enable C# SAST scanning |
| `--dotnet` | `dotnet_sast_enabled` | `INPUT_DOTNET_SAST_ENABLED` | `dotnet_sast_enabled` | Enable .NET SAST scanning |
| `--c` | `c_sast_enabled` | `INPUT_C_SAST_ENABLED` | `c_sast_enabled` | Enable C SAST scanning |
| `--cpp` | `cpp_sast_enabled` | `INPUT_CPP_SAST_ENABLED` | `cpp_sast_enabled` | Enable C++ SAST scanning |
| `--kotlin` | `kotlin_sast_enabled` | `INPUT_KOTLIN_SAST_ENABLED` | `kotlin_sast_enabled` | Enable Kotlin SAST scanning |
| `--scala` | `scala_sast_enabled` | `INPUT_SCALA_SAST_ENABLED` | `scala_sast_enabled` | Enable Scala SAST scanning |
| `--swift` | `swift_sast_enabled` | `INPUT_SWIFT_SAST_ENABLED` | `swift_sast_enabled` | Enable Swift SAST scanning |
| `--rust` | `rust_sast_enabled` | `INPUT_RUST_SAST_ENABLED` | `rust_sast_enabled` | Enable Rust SAST scanning |
| `--elixir` | `elixir_sast_enabled` | `INPUT_ELIXIR_SAST_ENABLED` | `elixir_sast_enabled` | Enable Elixir SAST scanning |
| `--erlang` | `erlang_sast_enabled` | `INPUT_ERLANG_SAST_ENABLED` | `erlang_sast_enabled` | Enable Erlang SAST scanning |

`--javascript` / `javascript_sast_enabled` covers TypeScript; there is no separate TypeScript setting.

### SAST rules and options

| CLI flag | GitHub Action input | Environment variable | JSON key | Description |
|---|---|---|---|---|
| `--all-languages` | `all_languages_enabled` | `INPUT_ALL_LANGUAGES_ENABLED` | `all_languages_enabled` | Enable SAST for all supported languages |
| `--all-rules` | `all_rules_enabled` | `INPUT_ALL_RULES_ENABLED` | `all_rules_enabled` | Run all bundled SAST rules regardless of language filters |
| `--opengrep-notify` | `opengrep_notification_method` | `INPUT_OPENGREP_NOTIFICATION_METHOD` | `notification_method` | Notification method for OpenGrep (e.g., console, slack) |
| `--use-custom-sast-rules` | `use_custom_sast_rules` | `INPUT_USE_CUSTOM_SAST_RULES` | `use_custom_sast_rules` | Use custom SAST rules instead of bundled rules (falls back to bundled rules for languages without custom rules) |
| `--custom-sast-rule-path` | `custom_sast_rule_path` | `INPUT_CUSTOM_SAST_RULE_PATH` | `custom_sast_rule_path` | Relative path to custom SAST rules directory (relative to workspace if set, otherwise cwd) |
| `--sast-ignore-overrides` | `sast_ignore_overrides` | `INPUT_SAST_IGNORE_OVERRIDES` | `sast_ignore_overrides` | Comma-separated list of SAST ignore overrides in rule_id or rule_id:path format |
| `--<lang>-enabled-rules` | `<lang>_enabled_rules` | `INPUT_<LANG>_ENABLED_RULES` | `<lang>_enabled_rules` | Comma-separated allowlist of rules for one language (defaults to the high-confidence set). |
| `--<lang>-disabled-rules` | `<lang>_disabled_rules` | `INPUT_<LANG>_DISABLED_RULES` | `<lang>_disabled_rules` | Comma-separated rules to disable for one language. |

`<lang>` is one of: `c`, `cpp`, `csharp`, `dotnet`, `elixir`, `go`, `java`, `javascript`, `kotlin`, `php`, `python`, `ruby`, `rust`, `scala`, `swift`.

### Secret scanning (TruffleHog)

| CLI flag | GitHub Action input | Environment variable | JSON key | Description |
|---|---|---|---|---|
| `--secrets` | `secret_scanning_enabled` | `INPUT_SECRET_SCANNING_ENABLED` | `secret_scanning_enabled` | Enable secret scanning |
| `--disable-secrets` | `disable_all_secrets` | `INPUT_DISABLE_ALL_SECRETS` | `disable_all_secrets` | Disable all secret scanning features |
| `--exclude-dir` | `trufflehog_exclude_dir` | `INPUT_TRUFFLEHOG_EXCLUDE_DIR` | `trufflehog_exclude_dir` | Comma-separated literal directory/file names or glob patterns to exclude from secret scanning beneath the workspace root; matching is case-sensitive |
| `--trufflehog-notify` | `trufflehog_notification_method` (alias `notification_method`) | `INPUT_TRUFFLEHOG_NOTIFICATION_METHOD` | `notification_method` | Notification method for TruffleHog (e.g., console, slack) |
| `--show-unverified` | `trufflehog_show_unverified` | `INPUT_TRUFFLEHOG_SHOW_UNVERIFIED` | `trufflehog_show_unverified` | Show unverified secrets in TruffleHog results |

### Socket Tier 1 reachability

| CLI flag | GitHub Action input | Environment variable | JSON key | Description |
|---|---|---|---|---|
| `--socket-tier1` | `socket_tier_1_enabled` | `SOCKET_TIER_1_ENABLED` | `socket_tier_1_enabled` | Enable Socket Tier 1 reachability analysis |
| `--socket-additional-params` | `socket_additional_params` | `SOCKET_ADDITIONAL_PARAMS` | `socket_additional_params` | Additional CLI params for 'socket scan reach' (comma or space separated). Also reads SOCKET_ADDITIONAL_PARAMS |

Note the environment variable names here have no `INPUT_` prefix.

### Container scanning (Trivy)

| CLI flag | GitHub Action input | Environment variable | JSON key | Description |
|---|---|---|---|---|
| `--images` | `container_images` | `INPUT_CONTAINER_IMAGES_TO_SCAN` | `container_images` | Comma-separated list of container images to scan (auto-enables image scanning) |
| `--dockerfiles` | `dockerfiles` | `INPUT_DOCKERFILES` | `dockerfiles` | Comma-separated list of Dockerfiles to scan (auto-enables Dockerfile scanning) |
| `--trivy-notify` | `trivy_notification_method` | `INPUT_TRIVY_NOTIFICATION_METHOD` | `trivy_notification_method` | Notification method for Trivy (e.g., console, slack) |
| `--trivy-disabled-rules` | `trivy_disabled_rules` | `INPUT_TRIVY_DISABLED_RULES` | `trivy_disabled_rules` | Comma-separated list of Trivy rules to disable |
| `--trivy-image-scanning-disabled` | `trivy_image_scanning_disabled` | `INPUT_TRIVY_IMAGE_SCANNING_DISABLED` | `trivy_image_scanning_disabled` | Disable Trivy image scanning |
| `--trivy-vuln-enabled` | `trivy_vuln_enabled` | `INPUT_TRIVY_VULN_ENABLED` | `trivy_vuln_enabled` | Enable Trivy vulnerability scanning for all supported language ecosystems |

### Notifications

A notifier turns on when its endpoint or token is present from any source.

| CLI flag | GitHub Action input | Environment variable | JSON key | Description |
|---|---|---|---|---|
| `--slack-webhook-url` | `slack_webhook_url` | `INPUT_SLACK_WEBHOOK_URL` (also `SLACK_WEBHOOK_URL`) | `slack_webhook_url` | Slack webhook URL (also reads SLACK_WEBHOOK_URL or INPUT_SLACK_WEBHOOK_URL) |
| `--webhook-url` | `webhook_url` | `INPUT_WEBHOOK_URL` (also `WEBHOOK_URL`) | `webhook_url` | Generic webhook URL for WebhookNotifier |
| `--msteams-webhook-url` | `msteams_webhook_url` | `INPUT_MSTEAMS_WEBHOOK_URL` (also `MSTEAMS_WEBHOOK_URL`) | `msteams_webhook_url` | MS Teams incoming webhook URL (also reads MSTEAMS_WEBHOOK_URL or INPUT_MSTEAMS_WEBHOOK_URL) |
| `--jira-url` | `jira_url` (alias `server`) | `INPUT_JIRA_URL` (also `JIRA_URL`) | `jira_url` | Jira base URL (turns the Jira notifier on) |
| `--jira-project` | `jira_project` (alias `project`) | `INPUT_JIRA_PROJECT` (also `JIRA_PROJECT`) | `jira_project` | Jira project key |
| `--jira-email` | `jira_email` | `INPUT_JIRA_EMAIL` (also `JIRA_EMAIL`) | `jira_email` | Jira account email |
| `--jira-api-token` | `jira_api_token` | `INPUT_JIRA_API_TOKEN` (also `JIRA_API_TOKEN`) | `jira_api_token` | Jira API token |
| `--sumologic-endpoint` | `sumologic_endpoint` | `INPUT_SUMOLOGIC_ENDPOINT` (also `SUMOLOGIC_ENDPOINT`, `SUMO_LOGIC_HTTP_SOURCE_URL`) | `sumologic_endpoint` | Sumo Logic HTTP source URL |
| `--ms-sentinel-workspace-id` | `ms_sentinel_workspace_id` | `INPUT_MS_SENTINEL_WORKSPACE_ID` (also `MS_SENTINEL_WORKSPACE_ID`) | `ms_sentinel_workspace_id` | Microsoft Sentinel workspace ID |
| `--ms-sentinel-key` | `ms_sentinel_key` (alias `ms_sentinel_shared_key`) | `INPUT_MS_SENTINEL_KEY` (also `MS_SENTINEL_SHARED_KEY`, `INPUT_MS_SENTINEL_SHARED_KEY`) | `ms_sentinel_key` | Microsoft Sentinel shared key |

### GitHub PR comments and labels

| CLI flag | GitHub Action input | Environment variable | JSON key | Description |
|---|---|---|---|---|
| `--github-token` | `github_token` | `GITHUB_TOKEN` (also `INPUT_GITHUB_TOKEN`) | `github_token` | GitHub token (turns the PR notifier on) |
| `--github-api-url` | — | `GITHUB_API_URL` | `GITHUB_API_URL` | GitHub API base URL; set automatically by GitHub Actions |
| `--pr-comment` | `pr_comment_enabled` | `INPUT_PR_COMMENT_ENABLED` | `pr_comment_enabled` | Post/update the findings comment on the PR (scanning and dashboard upload are unaffected) |
| `--pr-comment-links` | `pr_comment_links_enabled` | `INPUT_PR_COMMENT_LINKS_ENABLED` | `pr_comment_links_enabled` | Enable clickable file/line links in PR comments |
| `--pr-comment-collapse` | `pr_comment_collapse_enabled` | `INPUT_PR_COMMENT_COLLAPSE_ENABLED` | `pr_comment_collapse_enabled` | Enable collapsible sections in PR comments |
| `--pr-comment-collapse-non-critical` | `pr_comment_collapse_non_critical` | `INPUT_PR_COMMENT_COLLAPSE_NON_CRITICAL` | `pr_comment_collapse_non_critical` | Auto-collapse non-critical findings (critical stays expanded) |
| `--pr-comment-collapse-all` | `pr_comment_collapse_all` | `INPUT_PR_COMMENT_COLLAPSE_ALL` | `pr_comment_collapse_all` | Collapse the SAST and Socket Tier 1 sections, critical findings included |
| `--pr-comment-code-fencing` | `pr_comment_code_fencing_enabled` | `INPUT_PR_COMMENT_CODE_FENCING_ENABLED` | `pr_comment_code_fencing_enabled` | Enable language-aware code fencing for trace output |
| `--pr-comment-show-rules` | `pr_comment_show_rule_names` | `INPUT_PR_COMMENT_SHOW_RULE_NAMES` | `pr_comment_show_rule_names` | Show explicit rule names for each finding |
| `--pr-labels` | `pr_labels_enabled` | `INPUT_PR_LABELS_ENABLED` | `pr_labels_enabled` | Add severity-based labels to PRs |
| `--pr-label-critical` | `pr_label_critical` | `INPUT_PR_LABEL_CRITICAL` | `pr_label_critical` | Label name for critical severity findings |
| `--pr-label-high` | `pr_label_high` | `INPUT_PR_LABEL_HIGH` | `pr_label_high` | Label name for high severity findings |
| `--pr-label-medium` | `pr_label_medium` | `INPUT_PR_LABEL_MEDIUM` | `pr_label_medium` | Label name for medium severity findings |
| `--pr-label-low` | `pr_label_low` | `INPUT_PR_LABEL_LOW` | `pr_label_low` | Label name for low severity findings |

Boolean PR options that default to `true` have a `--no-<flag>` form on the CLI (for example `--no-pr-comment`). See the [PR Comment Guide](github-pr-comment-guide.md).

## Core Options

### `--config CONFIG`
Path to JSON configuration file. JSON values override environment variables, and CLI flags override both (see [Configuration Precedence](#configuration-precedence)).

**Example:**
```bash
socket-basics --config /path/to/config.json
```

### `--output OUTPUT`
Output file name for scan results. A relative name is written inside the workspace.

**Default:** `.socket.facts.json`

When results are uploaded to the Socket dashboard the file **must be inside the
scanned workspace**: the upload uses the workspace as its base path, and a file
elsewhere is discarded with `Need at least one file to be uploaded`. In Docker
that means a path under `/workspace`, not a separate results mount.

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
Repository name in `owner/repo` form (use when the workspace is not a git repo).
This is the repository recorded on the full scan and used to look up the pull
request. It is **not** the Socket organization: that comes from `SOCKET_ORG`,
for which there is no CLI flag.

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
- uses: SocketDev/socket-basics@v3.1.0
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

On a large repository this is the slowest and noisiest option, and the facts
file records every non-gitignored file in the workspace regardless of findings.
Prefer the languages the code uses, and `--changed-files` for PR and pre-commit
runs. See [Large Repositories and Monorepos](local-install-docker.md#large-repositories-and-monorepos).

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
example, `**/appsettings.*.json` matches files at any directory depth.

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

### Socket organization and API key

There are **no CLI flags** for the organization or the API key. Set them in the
environment (or `socket_org` in a JSON file):

| Setting | Environment variable | Also accepted |
|---------|----------------------|---------------|
| Organization slug | `SOCKET_ORG` | `SOCKET_ORG_SLUG`, `INPUT_SOCKET_ORG` |
| API key | `SOCKET_SECURITY_API_KEY` | `SOCKET_SECURITY_API_TOKEN`, `SOCKET_API_KEY`, `INPUT_SOCKET_SECURITY_API_KEY`, `INPUT_SOCKET_API_KEY` |

The key needs the `full-scans` scope to upload results and the `socket-basics`
scope to load dashboard configuration. With the latter the organization is
discovered from the key; otherwise set `SOCKET_ORG` explicitly or the run logs
`No Socket organization configured` and uploads nothing. `--repo` names the
repository, not the organization.

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
| `GITHUB_REPOSITORY` | `INPUT_GITHUB_REPOSITORY` | Repository name (owner/repo); discovered from the git remote when unset |
| `GITHUB_PR_NUMBER` | `INPUT_PR_NUMBER` | Pull request number; looked up by branch through the API when unset |

GitHub Actions sets everything below automatically. Outside Actions (a plain
`docker run` or a native install) set the first three yourself to post PR
comments deterministically; see
[Posting PR Comments from a Docker Run](local-install-docker.md#posting-pr-comments-from-a-docker-run).
| `GITHUB_WORKSPACE` | - | Workspace directory (auto-set in GitHub Actions) |
| `GITHUB_ACTOR` | - | GitHub username who triggered the action |
| `GITHUB_HEAD_REF` | - | Source branch for pull request |
| `GITHUB_SHA` | - | Commit SHA |
| `GITHUB_REF_NAME` | - | Branch or tag name |
| `GITHUB_EVENT_PATH` | - | Path to event payload file |

### Scanning Configuration

| Variable | Description |
|----------|-------------|
| `OUTPUT_DIR` | Directory for output files (default: current directory, or the `--workspace` when one is given) |
| `INPUT_CHANGED_FILES` | Diff-only scope; same values as `--changed-files` |
| `INPUT_SCAN_FILES` | Comma-separated list of files to scan |
| `INPUT_SCAN_ALL` | `'true'` widens to a full scan when a `changed_files` scope cannot be resolved (fail-open) |
| `INPUT_CONSOLE_TABULAR_ENABLED` | Enable tabular console output |
| `INPUT_CONSOLE_JSON_ENABLED` | Enable JSON console output |
| `INPUT_VERBOSE` | Enable verbose logging |

Scanner and notifier settings use the `INPUT_<ACTION INPUT NAME>` form, e.g.
`INPUT_PYTHON_SAST_ENABLED=true`; see the [Name Mapping](#name-mapping).

### S3 Upload Configuration

| Variable | Description |
|----------|-------------|
| `SOCKET_S3_ENABLED` | Set to 'true', '1', or 'yes' to enable S3 upload (or pass `--enable-s3-upload`) |
| `SOCKET_S3_BUCKET` | S3 bucket name (required) |
| `SOCKET_S3_ACCESS_KEY` | AWS access key ID (required) |
| `SOCKET_S3_SECRET_KEY` | AWS secret access key (required) |
| `SOCKET_S3_REGION` | Bucket region (default `us-east-1`) |
| `SOCKET_S3_ENDPOINT` | Custom S3-compatible endpoint URL (optional) |

These are environment variables only; the GitHub Action has no `s3_*` inputs, so
set them in the step `env:` block.

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

Keys are the **JSON key** column of the [Name Mapping](#name-mapping). Keep
credentials in the environment rather than in the file.

```json
{
  "workspace": "/path/to/project",
  "console_tabular_enabled": true,
  "verbose": false,

  "python_sast_enabled": true,
  "javascript_sast_enabled": true,
  "go_sast_enabled": true,
  "use_custom_sast_rules": true,
  "custom_sast_rule_path": ".socket/rules",
  "sast_ignore_overrides": "js-sql-injection:index.js",

  "secret_scanning_enabled": true,
  "trufflehog_exclude_dir": "node_modules,vendor,dist,.git",
  "trufflehog_show_unverified": false,

  "socket_tier_1_enabled": true,
  "socket_org": "your-org-slug",

  "container_images": "nginx:1.27.4,redis:7.4",
  "dockerfiles": "Dockerfile",
  "trivy_vuln_enabled": true,

  "slack_webhook_url": "https://hooks.slack.com/services/T00/B00/XXXX"
}
```

The output file name is a CLI-only option (`--output`); set
`SOCKET_SECURITY_API_KEY` and `GITHUB_TOKEN` in the environment.

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
