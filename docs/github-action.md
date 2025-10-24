# GitHub Actions Integration

Complete guide to integrating Socket Basics into your GitHub Actions workflows for automated security scanning.

## Table of Contents

- [Quick Start](#quick-start)
- [Basic Configuration](#basic-configuration)
- [Enterprise Features](#enterprise-features)
- [Advanced Workflows](#advanced-workflows)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

## Quick Start

Add Socket Basics to your workflow in 3 steps:

1. **Create workflow file** at `.github/workflows/security-scan.yml`
2. **Add required secrets** to your repository
3. **Configure scanning options**

### Minimal Example

```yaml
name: Security Scan
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-scan:
    permissions:
      issues: write
      contents: read
      pull-requests: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      
      - name: Run Socket Basics
        uses: SocketDev/socket-basics@1.0.13
        env:
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number }}
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          python_sast_enabled: 'true'
          secret_scanning_enabled: 'true'
```

This will:
- ✅ Run Python SAST on all `.py` files
- ✅ Scan for leaked secrets
- ✅ Post results as a PR comment
- ✅ Post results as a PR comment

## Basic Configuration

### Required Permissions

Socket Basics requires the following permissions to post PR comments and create issues:

```yaml
permissions:
  issues: write        # Create and update issues for findings
  contents: read       # Read repository contents
  pull-requests: write # Post comments on pull requests
```

Include these in your workflow's `jobs.<job_id>.permissions` section.

### Required Inputs

**`github_token`** (required)
- GitHub token for posting PR comments and API access
- Use `${{ secrets.GITHUB_TOKEN }}` (automatically provided)

### Common Scanning Options

**SAST (Static Analysis):**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    # Enable SAST for specific languages
    python_sast_enabled: 'true'
    javascript_sast_enabled: 'true'
    go_sast_enabled: 'true'
    java_sast_enabled: 'true'
    # Or enable all languages
    all_languages_enabled: 'true'
```

**Secret Scanning:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    secret_scanning_enabled: 'true'
    # Optional: exclude directories
    trufflehog_exclude_dir: 'node_modules,vendor,dist'
    # Optional: show unverified secrets
    trufflehog_show_unverified: 'true'
```

**Container Scanning:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    # Scan Docker images (auto-enables container scanning)
    container_images: 'myorg/myapp:latest,redis:7'
    # Scan Dockerfiles (auto-enables Dockerfile scanning)
    dockerfiles: 'Dockerfile,docker/Dockerfile.prod'
```

**Socket Tier 1 Reachability:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    socket_tier_1_enabled: 'true'
```

### Output Configuration

```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    python_sast_enabled: 'true'
    # Enable tabular console output
    console_tabular_enabled: 'true'
    # Or enable JSON output
    console_json_enabled: 'true'
    # Enable verbose logging for debugging
    verbose: 'true'
```

## Enterprise Features

Socket Basics Enterprise features require a [Socket Enterprise](https://socket.dev/enterprise) subscription.

### Dashboard Configuration

Configure Socket Basics centrally from the [Socket Dashboard](https://socket.dev/dashboard):

![Socket Basics Settings](screenshots/socket_basics_settings.png)

**Setup:**
1. Log in to [Socket Dashboard](https://socket.dev/dashboard)
2. Navigate to Settings → Socket Basics
3. Configure scanning policies, notification channels, and rule sets
4. Save your configuration

**Enable in workflow:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  env:
    GITHUB_PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number }}
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    # Dashboard configuration (Enterprise required)
    socket_org: 'your-org-slug'
    socket_security_api_key: ${{ secrets.SOCKET_SECURITY_API_KEY }}
```

> **Note:** You can also pass credentials using environment variables instead of the `with:` section:
> ```yaml
> - uses: SocketDev/socket-basics@1.0.13
>   env:
>     SOCKET_SECURITY_API_KEY: ${{ secrets.SOCKET_SECURITY_API_KEY }}
>   with:
>     github_token: ${{ secrets.GITHUB_TOKEN }}
> ```
> Both approaches work identically. Use whichever fits your workflow style.

Your workflow will automatically use the settings configured in the dashboard.

![Socket Basics Section Configuration](screenshots/socket_basics_section_config.png)

### Notification Integrations

All notification integrations require Socket Enterprise.

**Slack Notifications:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    socket_org: ${{ secrets.SOCKET_ORG }}
    socket_security_api_key: ${{ secrets.SOCKET_SECURITY_API_KEY }}
    python_sast_enabled: 'true'
    # Slack webhook (Enterprise required)
    slack_webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
```

**Jira Issue Creation:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    socket_org: ${{ secrets.SOCKET_ORG }}
    socket_security_api_key: ${{ secrets.SOCKET_SECURITY_API_KEY }}
    python_sast_enabled: 'true'
    # Jira integration (Enterprise required)
    jira_url: 'https://your-org.atlassian.net'
    jira_email: ${{ secrets.JIRA_EMAIL }}
    jira_api_token: ${{ secrets.JIRA_API_TOKEN }}
    jira_project: 'SEC'
```

**Microsoft Teams:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    socket_org: ${{ secrets.SOCKET_ORG }}
    socket_security_api_key: ${{ secrets.SOCKET_SECURITY_API_KEY }}
    python_sast_enabled: 'true'
    # MS Teams webhook (Enterprise required)
    msteams_webhook_url: ${{ secrets.MSTEAMS_WEBHOOK_URL }}
```

**Generic Webhook:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    socket_org: ${{ secrets.SOCKET_ORG }}
    socket_security_api_key: ${{ secrets.SOCKET_SECURITY_API_KEY }}
    python_sast_enabled: 'true'
    # Generic webhook (Enterprise required)
    webhook_url: ${{ secrets.WEBHOOK_URL }}
```

**SIEM Integration:**
```yaml
- uses: SocketDev/socket-basics@1.0.13
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    socket_org: ${{ secrets.SOCKET_ORG }}
    socket_security_api_key: ${{ secrets.SOCKET_SECURITY_API_KEY }}
    python_sast_enabled: 'true'
    # Microsoft Sentinel (Enterprise required)
    ms_sentinel_workspace_id: ${{ secrets.MS_SENTINEL_WORKSPACE_ID }}
    ms_sentinel_shared_key: ${{ secrets.MS_SENTINEL_SHARED_KEY }}
    # Sumo Logic (Enterprise required)
    sumologic_endpoint: ${{ secrets.SUMOLOGIC_ENDPOINT }}
```

## Advanced Workflows

### Multi-Language Scan

```yaml
name: Comprehensive Security Scan
on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main, develop]

jobs:
  security-scan:
    permissions:
      issues: write
      contents: read
      pull-requests: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      
      - name: Run Socket Basics
        uses: SocketDev/socket-basics@1.0.13
        env:
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number }}
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          socket_org: ${{ secrets.SOCKET_ORG }}
          socket_security_api_key: ${{ secrets.SOCKET_SECURITY_API_KEY }}
          
          # Enable multiple languages
          python_sast_enabled: 'true'
          javascript_sast_enabled: 'true'
          typescript_sast_enabled: 'true'
          go_sast_enabled: 'true'
          
          # Security scans
          secret_scanning_enabled: 'true'
          socket_tier_1_enabled: 'true'
          
          # Container scanning
          dockerfiles: 'Dockerfile'
          
          # Notifications (Enterprise)
          slack_webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Scheduled Scanning

```yaml
name: Weekly Security Audit
on:
  schedule:
    # Run every Monday at 9 AM UTC
    - cron: '0 9 * * 1'
  workflow_dispatch:  # Allow manual trigger

jobs:
  security-audit:
    permissions:
      issues: write
      contents: read
      pull-requests: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      
      - name: Run Full Security Scan
        uses: SocketDev/socket-basics@1.0.13
        env:
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number }}
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          socket_org: ${{ secrets.SOCKET_ORG }}
          socket_security_api_key: ${{ secrets.SOCKET_SECURITY_API_KEY }}
          
          # Scan all supported languages
          all_languages_enabled: 'true'
          
          # Enable all security features
          secret_scanning_enabled: 'true'
          socket_tier_1_enabled: 'true'
          
          # Verbose output for audit trail
          verbose: 'true'
          console_tabular_enabled: 'true'
          
          # Send to multiple channels (Enterprise)
          slack_webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
          jira_url: ${{ secrets.JIRA_URL }}
          jira_email: ${{ secrets.JIRA_EMAIL }}
          jira_api_token: ${{ secrets.JIRA_API_TOKEN }}
          jira_project: 'SEC'
```

### Container Security Pipeline

```yaml
name: Container Security
on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main]
    paths:
      - 'Dockerfile*'
      - 'docker/**'

jobs:
  container-scan:
    permissions:
      issues: write
      contents: read
      pull-requests: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      
      - name: Build Docker Image
        run: docker build -t myapp:1.0.13:${{ github.sha }} .
      
      - name: Scan Container
        uses: SocketDev/socket-basics@1.0.13
        env:
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number }}
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          
          # Scan built image and Dockerfile
          container_images: 'myapp:${{ github.sha }}'
          dockerfiles: 'Dockerfile'
          
          # Additional Trivy options
          trivy_vuln_enabled: 'true'
```

### Custom Rule Configuration

```yaml
name: Security Scan with Custom Rules
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-scan:
    permissions:
      issues: write
      contents: read
      pull-requests: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      
      - name: Run Socket Basics
        uses: SocketDev/socket-basics@1.0.13
        env:
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number }}
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          
          # Enable Python SAST
          python_sast_enabled: 'true'
          
          # Enable specific Python rules
          python_enabled_rules: 'sql-injection,xss,hardcoded-credentials'
          
          # Disable noisy rules
          python_disabled_rules: 'unused-import,line-too-long'
          
          # JavaScript with custom rules
          javascript_sast_enabled: 'true'
          javascript_enabled_rules: 'eval-usage,prototype-pollution'
```

## Configuration Reference

### All Available Inputs

See [`action.yml`](../action.yml) for the complete list of inputs.

**Core Configuration:**
- `socket_org` — Socket organization slug (Enterprise)
- `socket_security_api_key` — Socket Security API key (Enterprise)
- `github_token` — GitHub token (required)
- `verbose` — Enable verbose logging
- `console_tabular_enabled` — Tabular console output
- `console_json_enabled` — JSON console output

**SAST Languages:**
- `all_languages_enabled` — Enable all languages
- `python_sast_enabled`, `javascript_sast_enabled`, `typescript_sast_enabled`
- `go_sast_enabled`, `golang_sast_enabled`
- `java_sast_enabled`, `php_sast_enabled`, `ruby_sast_enabled`
- `csharp_sast_enabled`, `dotnet_sast_enabled`
- `c_sast_enabled`, `cpp_sast_enabled`
- `kotlin_sast_enabled`, `scala_sast_enabled`, `swift_sast_enabled`
- `rust_sast_enabled`, `elixir_sast_enabled`

**Rule Configuration (per language):**
- `<language>_enabled_rules` — Comma-separated rules to enable
- `<language>_disabled_rules` — Comma-separated rules to disable

**Security Scanning:**
- `secret_scanning_enabled` — Enable secret scanning
- `trufflehog_exclude_dir` — Directories to exclude
- `trufflehog_show_unverified` — Show unverified secrets
- `socket_tier_1_enabled` — Socket Tier 1 reachability

**Container Scanning:**
- `container_images` — Comma-separated images to scan
- `dockerfiles` — Comma-separated Dockerfiles to scan
- `trivy_disabled_rules` — Trivy rules to disable
- `trivy_vuln_enabled` — Enable vulnerability scanning

**Notifications (Enterprise Required):**
- `slack_webhook_url` — Slack webhook
- `jira_url`, `jira_email`, `jira_api_token`, `jira_project` — Jira config
- `msteams_webhook_url` — MS Teams webhook
- `webhook_url` — Generic webhook
- `ms_sentinel_workspace_id`, `ms_sentinel_shared_key` — MS Sentinel
- `sumologic_endpoint` — Sumo Logic

**Storage:**
- `s3_enabled`, `s3_bucket`, `s3_access_key`, `s3_secret_key` — S3 upload

### Environment Variables

All inputs support both standard and `INPUT_` prefixed environment variables:

```yaml
env:
  INPUT_PYTHON_SAST_ENABLED: 'true'
  INPUT_SECRET_SCANNING_ENABLED: 'true'
  SOCKET_ORG: ${{ secrets.SOCKET_ORG }}
  SOCKET_SECURITY_API_KEY: ${{ secrets.SOCKET_SECURITY_API_KEY }}
```

## Troubleshooting

### Action Not Finding Files

**Problem:** Scanner reports no files found.

**Solution:** Ensure `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` runs before Socket Basics:
```yaml
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 - Must be first
  - uses: SocketDev/socket-basics@1.0.13
```

### PR Comments Not Appearing

**Problem:** Security findings don't appear as PR comments.

**Solutions:**
1. Verify `github_token` is provided
2. Check workflow permissions:
```yaml
permissions:
  contents: read
  pull-requests: write
```

### Container Scanning Fails

**Problem:** Container image scanning fails.

**Solutions:**
1. Ensure Docker is available in runner
2. For private images, add authentication:
```yaml
- name: Login to Registry
  run: echo "${{ secrets.DOCKER_PASSWORD }}" | docker login -u "${{ secrets.DOCKER_USERNAME }}" --password-stdin
```

### Enterprise Features Not Working

**Problem:** Dashboard configuration or notifications not working.

**Solutions:**
1. Verify Socket Enterprise subscription is active
2. Check that `socket_org` and `socket_security_api_key` are set correctly
3. Confirm API key has required permissions in Socket Dashboard

### High Memory Usage

**Problem:** Action runs out of memory.

**Solutions:**
1. Exclude large directories:
```yaml
trufflehog_exclude_dir: 'node_modules,vendor,dist,.git'
```
2. Scan specific languages instead of `all_languages_enabled`
3. Use self-hosted runner with more resources

### Rate Limiting

**Problem:** GitHub API rate limit exceeded.

**Solution:** Use a personal access token with higher limits:
```yaml
with:
  github_token: ${{ secrets.GITHUB_PAT }}
```

## Example Results

![Socket Basics Example Results](screenshots/socket_basics_example_results.png)

---

**Next Steps:**
- [Pre-Commit Hook Setup](pre-commit-hook.md) — Catch issues before commit
- [Local Installation](local-installation.md) — Run scans from your terminal
- [Configuration Guide](configuration.md) — Detailed configuration options
