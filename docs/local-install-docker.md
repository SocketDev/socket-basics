# Local Docker Installation

Run Socket Basics locally using Docker without installing security tools on your host machine. This guide covers the supported pre-built images from GHCR / Docker Hub and building from source when you need to inspect or customize the image.

## Table of Contents

- [Quick Start](#quick-start)
- [Using Pre-built Images](#using-pre-built-images)
- [Building the Docker Image](#building-the-docker-image)
- [Running Scans](#running-scans)
- [Environment Configuration](#environment-configuration)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## Quick Start

```bash
# 1. Pull a pinned release from GHCR (no build step required)
docker pull ghcr.io/socketdev/socket-basics:3.1.0

# 2. Create .env file with your credentials (environment variables only;
#    there is no --socket-org or --socket-api-key flag)
cat > .env << 'EOF'
SOCKET_SECURITY_API_KEY=your-api-key-here
SOCKET_ORG=your-org-slug
EOF

# 3. Run a scan on your project
docker run --rm \
  -v "$PWD:/workspace" \
  --env-file .env \
  ghcr.io/socketdev/socket-basics:3.1.0 \
  --workspace /workspace \
  --python \
  --secrets \
  --console-tabular-enabled
```

The Docker image should always be pinned to an exact version such as `3.1.0`. Avoid
floating tags like `:latest` in CI/CD.

## Using Pre-built Images

Socket Basics publishes versioned, immutable images to both registries on every release.
The baked-in security tool versions are recorded in the image labels so you can always
inspect exactly what's inside:

```bash
docker inspect ghcr.io/socketdev/socket-basics:3.1.0 \
  | jq '.[0].Config.Labels'
# {
#   "com.socket.trivy-version": "0.73.0",
#   "com.socket.trufflehog-version": "3.96.0",
#   "com.socket.opengrep-version": "v1.26.0",
#   "org.opencontainers.image.version": "3.1.0",
#   ...
# }
```

> [!NOTE]
> The pre-built Docker image bundles Trivy — a Socket-built distribution,
> rebuilt from unmodified upstream source and pinned by digest — so container
> and Dockerfile scanning work out of the box.
> See [Local Installation](local-installation.md#trivy-container-scanning) for
> native-install guidance (including versions to avoid).

### Registries

| Registry | Image |
|----------|-------|
| GitHub Container Registry | `ghcr.io/socketdev/socket-basics:<version>` |
| Docker Hub | `docker.io/socketdev/socket-basics:<version>` |
| GHCR (app tests) | `ghcr.io/socketdev/socket-basics-app-tests:<version>` |

### Image Variants

| Tag | Contents | Use it when |
|-----|----------|-------------|
| `socket-basics:<version>` | Socket Basics with every bundled scanner (OpenGrep, TruffleHog, Socket-built Trivy) and the Socket npm CLI for Tier 1 reachability | **Always, unless Socket has told you otherwise.** This is the image the GitHub Action runs and the one every example in these docs uses. |
| `socket-basics:<version>-heavy` | The standard image plus a pinned copy of the Socket **Python** CLI (`socketcli`) | Only when a pipeline must run the Python Socket CLI and Socket Basics from one container and cannot pull a second image. |

The heavy variant was built for a single customer deployment with that
constraint. It adds no scanners, no features and no extra findings to Socket
Basics; it is larger, pulls more slowly and carries a second CLI to keep
patched. The larger image does not produce a more thorough scan. If you are not
certain you need `socketcli` inside the same container, use the standard image.

The heavy image also has a different entrypoint. Its first argument selects the
tool: `socketcli` runs the Python CLI; `socket-basics`, or any other argument,
runs Socket Basics:

```bash
docker run --rm -v "$PWD:/workspace" ghcr.io/socketdev/socket-basics:3.1.0-heavy socketcli --help
docker run --rm -v "$PWD:/workspace" ghcr.io/socketdev/socket-basics:3.1.0-heavy --workspace /workspace --python
```

`latest` and `latest-heavy` are floating aliases published for onboarding
convenience. Pin an exact version (or digest) in anything automated.

### Pinning in CI/CD

**GitHub Actions** — prefer the [action itself](github-action.md), which adds PR
comments and labels. If you must run the image directly, pin the exact version:

```yaml
- name: Security scan
  run: |
    docker run --rm \
      -v "$GITHUB_WORKSPACE:/workspace" \
      -e SOCKET_SECURITY_API_KEY=${{ secrets.SOCKET_SECURITY_API_KEY }} \
      -e SOCKET_ORG=${{ secrets.SOCKET_ORG }} \
      ghcr.io/socketdev/socket-basics:3.1.0 \
      --workspace /workspace \
      --python \
      --javascript \
      --secrets \
      --console-tabular-enabled
```

**GitLab CI** — reference the image directly:

```yaml
security-scan:
  image:
    name: ghcr.io/socketdev/socket-basics:3.1.0
    entrypoint: [""]   # GitLab needs a shell; the image's entrypoint is socket-basics
  stage: test
  script:
    - socket-basics
        --workspace "$CI_PROJECT_DIR"
        --python
        --javascript
        --secrets
        --console-tabular-enabled
  variables:
    SOCKET_SECURITY_API_KEY: $SOCKET_SECURITY_API_KEY
    SOCKET_ORG: $SOCKET_ORG
```

**Your own Dockerfile** — use the image as a base or copy tools from it:

```dockerfile
# Pin socket-basics and let Dependabot send upgrade PRs automatically
FROM ghcr.io/socketdev/socket-basics:3.1.0
```

### Staying Up to Date with Dependabot

If you reference the pre-built image in your own Dockerfile or Compose file,
Dependabot can automatically open PRs when a new version is published.
Add or extend `.github/dependabot.yml` in your repo:

```yaml
version: 2
updates:
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot will detect the `FROM ghcr.io/socketdev/socket-basics:3.1.0` reference
and open a PR with the version bump when a new release is available.

## Building the Docker Image

### Using the Pre-built Image (Recommended)

Pull a specific release without building locally:

```bash
# GHCR (preferred)
docker pull ghcr.io/socketdev/socket-basics:3.1.0

# Docker Hub
docker pull socketdev/socket-basics:3.1.0
```

### Build from Source

Build locally when you need to customise tool versions or test unreleased changes:

```bash
# Clone the repository
git clone https://github.com/SocketDev/socket-basics.git
cd socket-basics

# Build with version tag (multi-stage; first build is slower, subsequent ones are fast)
docker build -t socket-basics:3.1.0 .

# Verify the build
docker images | grep socket-basics
```

### Build for a Specific Platform (M1/M2 Macs)

```bash
docker build --platform linux/amd64 -t socket-basics:3.1.0 .
```

### Build with Custom Tool Versions

The image pins the bundled tools to specific versions. You can override them at build time:

```bash
docker build \
  --build-arg TRUFFLEHOG_VERSION=3.96.0 \
  --build-arg OPENGREP_VERSION=v1.26.0 \
  -t socket-basics:3.1.0 .
```

Trivy comes from a Socket-built image pinned by digest via the `TRIVY_IMAGE`
build arg (`TRIVY_VERSION` feeds the image label and must match its tag).
Building locally requires pull access to that registry; contributors without it
can override with `--build-arg TRIVY_IMAGE=aquasec/trivy:<version>`. For the app
tests image, build from the `app_tests` directory and use the same build args.

### Verify Installation

```bash
# The image's entrypoint is `socket-basics`, so its own flags need no prefix
docker run --rm socket-basics:3.1.0 --version

# Other bundled tools need --entrypoint
docker run --rm --entrypoint socket     socket-basics:3.1.0 --version
docker run --rm --entrypoint opengrep   socket-basics:3.1.0 --version
docker run --rm --entrypoint trufflehog socket-basics:3.1.0 --version
docker run --rm --entrypoint trivy      socket-basics:3.1.0 --version
```

### Smoke Test

To test that the pinned tool versions still work, run:

```bash
./scripts/smoke-test-docker.sh
```

Add `--build-progress plain` when you want verbose Docker build logs:

```bash
./scripts/smoke-test-docker.sh --build-progress plain
```

With `--app-tests` to also test the app_tests image (requires full build context):

```bash
./scripts/smoke-test-docker.sh --app-tests
```

This builds the image(s) and verifies the currently bundled tools are installed and executable. A GitHub Action runs this on Dockerfile changes and daily.

## Running Scans

### Basic Scan with Volume Mount

Mount your project directory into the container:

```bash
# Scan current directory
docker run --rm \
  -v "$PWD:/workspace" \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --python \
  --secrets \
  --console-tabular-enabled
```

**Important:** The `-v` flag mounts your local directory into the container:
- `-v "$PWD:/workspace"` — Mounts current directory to `/workspace` in container
- `--workspace /workspace` — Tells Socket Basics where to find your code inside the container

### Scan Different Directory

```bash
# Scan a specific project directory
docker run --rm \
  -v "/path/to/your/project:/workspace" \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --javascript \
  --secrets
```

### Multiple Language Scan

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --all-languages \
  --secrets \
  --console-tabular-enabled
```

## Environment Configuration

### Method 1: Using .env File (Recommended)

Create a `.env` file in your project (add to `.gitignore`):

```bash
# .env
# Socket Configuration (required to upload results and load dashboard config).
# Environment variables only: there is no --socket-org flag, and --repo names
# the repository, not the organization.
SOCKET_SECURITY_API_KEY=scrt_your_api_key_here
SOCKET_ORG=your-organization-slug

# GitHub Integration (PR comments on a GitHub repository; see
# "Posting PR Comments from a Docker Run" below)
GITHUB_TOKEN=ghp_your_github_token
GITHUB_REPOSITORY=owner/repo
GITHUB_PR_NUMBER=123

# Notification Integrations (Enterprise)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/XXXX
JIRA_URL=https://your-org.atlassian.net
JIRA_EMAIL=you@example.com
JIRA_API_TOKEN=your-jira-api-token
JIRA_PROJECT=SEC

# Microsoft Teams (Enterprise)
MSTEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...

# SIEM Integration (Enterprise)
MS_SENTINEL_WORKSPACE_ID=your-workspace-id
MS_SENTINEL_SHARED_KEY=your-shared-key
SUMOLOGIC_ENDPOINT=https://endpoint.sumologic.com/...

# Scanning Options (INPUT_* names mirror the CLI flags; see parameters.md#name-mapping)
INPUT_CONSOLE_TABULAR_ENABLED=true
INPUT_VERBOSE=false
```

**Run with .env file:**

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  --env-file .env \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --python \
  --secrets
```

### Method 2: Inline Environment Variables

Pass environment variables directly with `-e` flag:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -e "SOCKET_SECURITY_API_KEY=scrt_your_api_key" \
  -e "SOCKET_ORG=your-org-slug" \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --python \
  --secrets \
  --console-tabular-enabled
```

### Method 3: Multiple .env Files

Load multiple configuration files:

```bash
# Create separate config files
# .env.socket - Socket credentials
# .env.notifiers - Notification settings
# .env.scanning - Scanning preferences

docker run --rm \
  -v "$PWD:/workspace" \
  --env-file .env.socket \
  --env-file .env.notifiers \
  --env-file .env.scanning \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --all-languages
```

### Method 4: Environment Variables from Host

Use environment variables already set in your shell:

```bash
# Export variables in your shell
export SOCKET_SECURITY_API_KEY="scrt_your_api_key"
export SOCKET_ORG="your-org-slug"

# Pass specific variables to container
docker run --rm \
  -v "$PWD:/workspace" \
  -e "SOCKET_SECURITY_API_KEY=$SOCKET_SECURITY_API_KEY" \
  -e "SOCKET_ORG=$SOCKET_ORG" \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --python
```

### Posting PR Comments from a Docker Run

The GitHub Action wires this up for you. From a plain `docker run` (Jenkins,
CircleCI, a laptop) Socket Basics needs three things to comment on a GitHub
pull request:

| Variable | Purpose | If omitted |
|----------|---------|------------|
| `GITHUB_TOKEN` | Token with `pull-requests: write` (and `issues: write` for labels) | The PR notifier stays off |
| `GITHUB_REPOSITORY` | `owner/repo` of the pull request | Discovered from the `origin` remote of the mounted checkout |
| `GITHUB_PR_NUMBER` | The pull request number | Looked up through the GitHub API by branch name; nothing is posted if the branch has no open PR or the branch cannot be discovered |

Set all three for deterministic behavior:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -e SOCKET_SECURITY_API_KEY \
  -e SOCKET_ORG \
  -e GITHUB_TOKEN \
  -e GITHUB_REPOSITORY=owner/repo \
  -e GITHUB_PR_NUMBER=123 \
  ghcr.io/socketdev/socket-basics:3.1.0 \
  --workspace /workspace \
  --python --javascript --secrets
```

Notes:
- `-e NAME` with no value forwards the variable from your shell.
- To report only the PR's own changes, add `-e GITHUB_BASE_REF=main` (with the
  base branch fetched in the checkout) and `--changed-files pr`. Without a base
  ref, `--changed-files auto` falls back to *staged* changes, which are empty
  in CI, so nothing would be scanned. `--changed-files current-commit` or an
  explicit file list are the alternatives.
- The PR notifier reads `GITHUB_PR_NUMBER`; `--pull-request` only sets the
  number recorded on the full scan, so use the environment variable.
- Uploading to the dashboard still needs `SOCKET_SECURITY_API_KEY` and
  `SOCKET_ORG`; PR comments and the dashboard are independent.

## Advanced Usage

### Container Scanning Status

> [!NOTE]
> Trivy-backed container and Dockerfile scanning is included in the pre-built
> image (Socket-built Trivy distribution, digest-pinned). No separate Trivy
> setup is required. For native installs, see
> [Local Installation](local-installation.md#trivy-container-scanning).

### Save Results to File

The facts file defaults to `.socket.facts.json` inside the workspace, so with
`-v "$PWD:/workspace"` it already lands in your project directory. To use a
different name or subdirectory, keep it **inside the workspace**:

```bash
mkdir -p ./scan-results

docker run --rm \
  -v "$PWD:/workspace" \
  --env-file .env \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --python \
  --secrets \
  --output /workspace/scan-results/scan-results.json
```

> [!WARNING]
> Do not write the facts file outside the workspace, for example to a second
> `-v .../results:/results` mount with `--output /results/...`. The dashboard
> upload uses the workspace as the base path of the upload, so a file outside
> it is discarded and the run logs `Need at least one file to be uploaded`.
> The scan looks green but nothing reaches the Socket dashboard. Add
> `scan-results/` to `.gitignore` if you keep results in the repository.

### Interactive Mode

Run the container interactively for debugging:

```bash
# Start interactive shell
docker run --rm -it \
  -v "$PWD:/workspace" \
  --env-file .env \
  --entrypoint /bin/bash \
  socket-basics:3.1.0

# Inside container, run commands manually:
# cd /workspace
# socket-basics --python --verbose
# exit
```

### Run with Custom Configuration File

Mount a configuration file into the container:

```bash
# Create config file
cat > socket-config.json << 'EOF'
{
  "python_sast_enabled": true,
  "javascript_sast_enabled": true,
  "secret_scanning_enabled": true,
  "console_tabular_enabled": true,
  "trufflehog_exclude_dir": "node_modules,vendor,dist"
}
EOF

# Run with config file
docker run --rm \
  -v "$PWD:/workspace" \
  -v "$PWD/socket-config.json:/config.json" \
  --env-file .env \
  socket-basics:3.1.0 \
  --workspace /workspace \
  --config /config.json
```

### Scan Multiple Projects

Create a script to scan multiple projects:

```bash
#!/bin/bash
# scan-all.sh

PROJECTS=(
  "/path/to/project1"
  "/path/to/project2"
  "/path/to/project3"
)

for PROJECT in "${PROJECTS[@]}"; do
  echo "Scanning $PROJECT..."
  docker run --rm \
    -v "$PROJECT:/workspace" \
    --env-file .env \
    socket-basics:3.1.0 \
    --workspace /workspace \
    --all-languages \
    --secrets \
    --console-tabular-enabled
done
```

### Large Repositories and Monorepos

`--all-languages` over an entire monorepo is the slowest and noisiest way to run
Socket Basics, and the facts file grows with the repository rather than with the
findings: the SAST connector records one component for every non-gitignored file
in the workspace, so a media-heavy or vendored tree yields a very large
`.socket.facts.json` and upload.

- Scope to what changed: `--changed-files auto` (staged changes locally),
  `--changed-files pr` with `GITHUB_BASE_REF` set in CI, or `--changed-files <commit>`.
- Scope to a project: mount and scan one project at a time
  (`-v "$PWD/services/api:/workspace"`), or pass an explicit `--scan-files` list.
- Enable only the languages the code uses; `--all-languages` runs every rule set.
- Keep generated, vendored and media files out of git or in `.gitignore`;
  ignored files are excluded from the inventory. `--exclude-dir` affects secret
  scanning only.

### CI/CD Integration

> **Using GitHub Actions?** Socket Basics has first-class GitHub Actions support with automatic PR comments, labels, and more — no Docker setup needed. See the [Quick Start](../README.md#-quick-start---github-actions) or the [GitHub Actions Guide](github-action.md).

For other CI/CD platforms, pull the pre-built image from GHCR:

**Example: Jenkins**

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                script {
                    // --entrypoint='' is required: Jenkins runs `cat` to keep the
                    // container alive, and the image's entrypoint is socket-basics.
                    docker.image('ghcr.io/socketdev/socket-basics:3.1.0').inside(
                        "--entrypoint='' -v ${WORKSPACE}:/workspace --env-file .env"
                    ) {
                        sh '''
                            socket-basics \
                              --workspace /workspace \
                              --all-languages \
                              --secrets \
                              --console-tabular-enabled
                        '''
                    }
                }
            }
        }
    }
}
```

**Example: GitLab CI**

```yaml
security-scan:
  image:
    name: ghcr.io/socketdev/socket-basics:3.1.0
    entrypoint: [""]   # GitLab needs a shell; the image's entrypoint is socket-basics
  stage: test
  script:
    - socket-basics
        --workspace "$CI_PROJECT_DIR"
        --python
        --javascript
        --secrets
        --console-tabular-enabled
  variables:
    SOCKET_SECURITY_API_KEY: $SOCKET_SECURITY_API_KEY
    SOCKET_ORG: $SOCKET_ORG
```

## Troubleshooting

### Permission Issues

**Problem:** Cannot write to mounted volumes or files.

**Solutions:**

1. Fix ownership after the scan. The image runs as root (OpenGrep lives under
   `/root`, so `--user` breaks SAST), which means files it writes into the
   mount are root-owned:
   ```bash
   sudo chown -R "$USER:$USER" .socket.facts.json scan-results
   ```

2. Or point `--output` at a workspace subdirectory you pre-create, and `chown`
   only that directory afterwards.

### Volume Mount Not Working

**Problem:** Container can't see project files.

**Solutions:**

1. Use absolute paths:
   ```bash
   docker run --rm \
     -v "$(pwd):/workspace" \  # Use $(pwd) instead of $PWD
     socket-basics:3.1.0
   ```

2. Verify mount (the entrypoint is `socket-basics`, so override it to run `ls`):
   ```bash
   docker run --rm \
     -v "$PWD:/workspace" \
     --entrypoint ls \
     socket-basics:3.1.0 \
     -la /workspace
   ```

### Environment Variables Not Loaded

**Problem:** `.env` file variables not available in container.

**Solutions:**

1. Verify `.env` file location:
   ```bash
   ls -la .env
   cat .env
   ```

2. Check file format (no spaces around `=`):
   ```bash
   # Correct:
   SOCKET_ORG=myorg
   
   # Incorrect:
   SOCKET_ORG = myorg
   ```

3. Use absolute path to .env:
   ```bash
   docker run --rm \
     -v "$PWD:/workspace" \
     --env-file "$(pwd)/.env" \
     socket-basics:3.1.0
   ```

### Container Image Too Large

**Problem:** Docker image takes too much disk space.

**Solutions:**

1. Clean up old images:
   ```bash
   docker system prune -a
   ```

2. Use multi-stage build (already optimized in Dockerfile)

3. Remove unused containers:
   ```bash
   docker container prune
   ```

### Slow Scan Performance

**Problem:** Scans take too long.

**Solutions:**

1. Exclude unnecessary directories:
   ```bash
   docker run --rm \
     -v "$PWD:/workspace" \
     socket-basics:3.1.0 \
     --workspace /workspace \
     --python \
     --secrets \
     --exclude-dir "node_modules,vendor,dist,.git"
   ```

2. Scan specific languages only instead of `--all-languages`

3. Increase Docker resources (CPU/Memory) in Docker Desktop settings

### Can't Access Results File

**Problem:** Output file not accessible after scan.

**Solutions:**

1. Check mount path:
   ```bash
   docker run --rm \
     -v "$PWD:/workspace" \
     socket-basics:3.1.0 \
     --workspace /workspace \
     --output /workspace/results.json  # Save to mounted directory
   ```

2. Keep the file inside the workspace. A separate `/results` volume breaks the
   dashboard upload (see [Save Results to File](#save-results-to-file)):
   ```bash
   mkdir -p ./scan-results
   docker run --rm \
     -v "$PWD:/workspace" \
     socket-basics:3.1.0 \
     --workspace /workspace \
     --output /workspace/scan-results/scan.json
   ```

### Results Missing From the Dashboard

**Problem:** The scan finishes but no full scan appears in the Socket dashboard.

**Solutions:**

1. `Need at least one file to be uploaded` in the log: the facts file was
   written outside the workspace. Use a path under `/workspace` for `--output`.
2. `No Socket organization configured` in the log: set `SOCKET_ORG`, or use an
   API key with the `socket-basics` scope so the organization can be discovered.
3. `Socket API key not detected - running in free plan mode`: the key did not
   reach the container. Check the `.env` file or `-e` flags and the variable
   name (`SOCKET_SECURITY_API_KEY`).
4. `Insufficient permissions`: the key is missing the `full-scans` scope (upload)
   or the `socket-basics` scope (dashboard configuration).

### PR Comment Not Posted

See [Posting PR Comments from a Docker Run](#posting-pr-comments-from-a-docker-run):
`GITHUB_TOKEN`, `GITHUB_REPOSITORY` and `GITHUB_PR_NUMBER` must all reach the
container, and `GithubPRNotifier` lines in the log say what was decided.

## Shell Aliases

Add these to your `~/.bashrc` or `~/.zshrc` for quick access:

```bash
# Socket Basics Docker aliases
alias sb-docker='docker run --rm -v "$PWD:/workspace" --env-file .env ghcr.io/socketdev/socket-basics:3.1.0 --workspace /workspace'
alias sb-quick='sb-docker --secrets --console-tabular-enabled'
alias sb-python='sb-docker --python --secrets --console-tabular-enabled'
alias sb-js='sb-docker --javascript --secrets --console-tabular-enabled'
alias sb-all='sb-docker --all-languages --secrets --socket-tier1 --console-tabular-enabled'

# Rebuild image
alias sb-build='docker build -t socket-basics:local .'
```

Usage:
```bash
# Quick secret scan
sb-quick

# Full Python scan
sb-python

# Comprehensive scan
sb-all
```

## Best Practices

1. **Use pre-built images** — Pull `ghcr.io/socketdev/socket-basics:<version>` instead of building locally
2. **Use the standard image** — `-heavy` exists for one deployment constraint (see [Image Variants](#image-variants)); it adds nothing to Socket Basics
3. **Pin to a specific version** — Avoid `:latest` in production CI; pin to `3.1.0` and upgrade deliberately
4. **Use Dependabot** — Reference the image in your Dockerfile/Compose to get automatic upgrade PRs
5. **Inspect baked-in labels** — Run `docker inspect <image> | jq '.[0].Config.Labels'` to verify tool versions
6. **Use .env files** — Keep credentials out of command history
7. **Add .env to .gitignore** — Never commit secrets
8. **Mount minimal volumes** — Only mount what you need to scan
9. **Keep `--output` inside the workspace** — Anything else is not uploaded to the dashboard
10. **Resource limits** — Set CPU/memory limits for long-running scans

## Example: Complete Workflow

```bash
#!/bin/bash
# complete-scan.sh - Full Docker-based security scan workflow

set -e

# Configuration
PROJECT_DIR="$(pwd)"
RESULTS_DIR="scan-results"   # relative to the project: it must stay inside the workspace
IMAGE_NAME="ghcr.io/socketdev/socket-basics:3.1.0"
ENV_FILE=".env"

# Create results directory (add it to .gitignore)
mkdir -p "$PROJECT_DIR/$RESULTS_DIR"

# Verify .env exists
if [ ! -f "$ENV_FILE" ]; then
    echo "❌ .env file not found. Creating template..."
    cat > "$ENV_FILE" << 'EOF'
SOCKET_SECURITY_API_KEY=your-api-key-here
SOCKET_ORG=your-org-slug
INPUT_CONSOLE_TABULAR_ENABLED=true
EOF
    echo "⚠️  Please edit .env with your credentials"
    exit 1
fi

echo "🔍 Starting security scan..."

# Run the scan. Enable the languages the project uses rather than
# --all-languages on a large monorepo (see "Large Repositories and Monorepos").
docker run --rm \
  -v "$PROJECT_DIR:/workspace" \
  --env-file "$ENV_FILE" \
  "$IMAGE_NAME" \
  --workspace /workspace \
  --all-languages \
  --secrets \
  --socket-tier1 \
  --console-tabular-enabled \
  --output "/workspace/$RESULTS_DIR/scan-$(date +%Y%m%d-%H%M%S).json"

echo "✅ Scan complete! Results saved to $RESULTS_DIR"
```

---

**Next Steps:**
- [Parameters Reference](parameters.md) — Complete CLI and environment variable reference
- [GitHub Actions Integration](github-action.md) — Automate in CI/CD
- [Pre-Commit Hook Setup](pre-commit-hook.md) — Catch issues before commit
- [Local Installation](local-installation.md) — Install tools natively
