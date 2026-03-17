# Local Docker Installation

Run Socket Basics locally using Docker without installing any security tools on your host machine. This guide covers using the pre-built images from GHCR / Docker Hub and building from source.

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
# 1. Pull a pinned release from Docker Hub (no build step required)
docker pull socketdev/socket-basics:1.1.3

# 2. Create .env file with your credentials
cat > .env << 'EOF'
SOCKET_SECURITY_API_KEY=your-api-key-here
SOCKET_ORG=your-org-slug
EOF

# 3. Run a scan on your project
docker run --rm \
  -v "$PWD:/workspace" \
  --env-file .env \
  socketdev/socket-basics:1.1.3 \
  --workspace /workspace \
  --python \
  --secrets \
  --console-tabular-enabled
```

## Using Pre-built Images

Socket Basics publishes versioned, immutable images to both registries on every release.
The baked-in security tool versions are recorded in the image labels so you can always
inspect exactly what's inside:

```bash
docker inspect ghcr.io/socketdev/socket-basics:1.1.3 \
  | jq '.[0].Config.Labels'
# {
#   "com.socket.trivy-version": "0.69.2",
#   "com.socket.trufflehog-version": "3.93.6",
#   "com.socket.opengrep-version": "v1.16.2",
#   "org.opencontainers.image.version": "1.1.3",
#   ...
# }
```

### Registries

| Registry | Image |
|----------|-------|
| GitHub Container Registry | `ghcr.io/socketdev/socket-basics:<version>` |
| Docker Hub | `docker.io/socketdev/socket-basics:<version>` |
| GHCR (app tests) | `ghcr.io/socketdev/socket-basics-app-tests:<version>` |

### Pinning in CI/CD

**GitHub Actions** — pin to the exact version and only bump when you're ready:

```yaml
- name: Security scan
  run: |
    docker run --rm \
      -v "$GITHUB_WORKSPACE:/workspace" \
      -e SOCKET_SECURITY_API_KEY=${{ secrets.SOCKET_API_KEY }} \
      -e SOCKET_ORG=${{ secrets.SOCKET_ORG }} \
      ghcr.io/socketdev/socket-basics:1.1.3 \
      --workspace /workspace \
      --all-languages \
      --secrets \
      --console-tabular-enabled
```

**GitLab CI** — reference the image directly:

```yaml
security-scan:
  image: ghcr.io/socketdev/socket-basics:1.1.3
  stage: test
  script:
    - socket-basics
        --workspace /builds/$CI_PROJECT_PATH
        --all-languages
        --secrets
        --console-tabular-enabled
  variables:
    SOCKET_SECURITY_API_KEY: $SOCKET_SECURITY_API_KEY
    SOCKET_ORG: $SOCKET_ORG
```

**Your own Dockerfile** — use the image as a base or copy tools from it:

```dockerfile
# Pin socket-basics and let Dependabot send upgrade PRs automatically
FROM ghcr.io/socketdev/socket-basics:1.1.3
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

Dependabot will detect the `FROM ghcr.io/socketdev/socket-basics:1.1.3` reference
and open a PR with the version bump when a new release is available.

## Building the Docker Image

### Using the Pre-built Image (Recommended)

Pull a specific release without building locally:

```bash
# GHCR (preferred)
docker pull ghcr.io/socketdev/socket-basics:1.1.3

# Docker Hub
docker pull socketdev/socket-basics:1.1.3
```

### Build from Source

Build locally when you need to customise tool versions or test unreleased changes:

```bash
# Clone the repository
git clone https://github.com/SocketDev/socket-basics.git
cd socket-basics

# Build with version tag (multi-stage; first build is slower, subsequent ones are fast)
docker build -t socket-basics:1.1.3 .

# Verify the build
docker images | grep socket-basics
```

### Build for a Specific Platform (M1/M2 Macs)

```bash
docker build --platform linux/amd64 -t socket-basics:1.1.3 .
```

### Build with Custom Tool Versions

The image pins Trivy, TruffleHog, and OpenGrep to specific versions. You can override any of them at build time:

```bash
docker build \
  --build-arg TRIVY_VERSION=v0.69.2 \
  --build-arg TRUFFLEHOG_VERSION=3.93.6 \
  --build-arg OPENGREP_VERSION=v1.16.2 \
  -t socket-basics:1.1.3 .
```

Omit any `--build-arg` to use the default version for that tool. For the app tests image, build from the `app_tests` directory and use the same build args.

### Verify Installation

```bash
# Check that all tools are available in the container
docker run --rm socket-basics:1.1.3 socket-basics --version
docker run --rm socket-basics:1.1.3 socket --version
docker run --rm socket-basics:1.1.3 trivy --version
docker run --rm socket-basics:1.1.3 opengrep --version
docker run --rm socket-basics:1.1.3 trufflehog --version
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

This builds the image(s) and verifies Trivy, TruffleHog, and OpenGrep are installed and executable. A GitHub Action runs this on Dockerfile changes and daily.

## Running Scans

### Basic Scan with Volume Mount

Mount your project directory into the container:

```bash
# Scan current directory
docker run --rm \
  -v "$PWD:/workspace" \
  socket-basics:1.1.3 \
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
  socket-basics:1.1.3 \
  --workspace /workspace \
  --javascript \
  --secrets
```

### Multiple Language Scan

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  socket-basics:1.1.3 \
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
# Socket Configuration (Required for Enterprise features)
SOCKET_SECURITY_API_KEY=scrt_your_api_key_here
SOCKET_ORG=your-organization-slug

# GitHub Integration (for PR comments)
GITHUB_TOKEN=ghp_your_github_token

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

# Scanning Options
CONSOLE_TABULAR_ENABLED=true
VERBOSE=false
```

**Run with .env file:**

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  --env-file .env \
  socket-basics:1.1.3 \
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
  socket-basics:1.1.3 \
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
  socket-basics:1.1.3 \
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
  socket-basics:1.1.3 \
  --workspace /workspace \
  --python
```

## Advanced Usage

### Container Scanning with Docker-in-Docker

To scan Docker images, you need to provide Docker socket access:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -v "/var/run/docker.sock:/var/run/docker.sock" \
  --env-file .env \
  socket-basics:1.1.3 \
  --workspace /workspace \
  --images "nginx:latest,redis:7" \
  --console-tabular-enabled
```

**Security Note:** Mounting the Docker socket gives the container full Docker access. Only use with trusted images.

### Save Results to File

Mount a volume to save scan results:

```bash
# Create results directory
mkdir -p ./scan-results

# Run scan and save output
docker run --rm \
  -v "$PWD:/workspace" \
  -v "$PWD/scan-results:/results" \
  --env-file .env \
  socket-basics:1.1.3 \
  --workspace /workspace \
  --python \
  --secrets \
  --output /results/scan-results.json
```

### Interactive Mode

Run the container interactively for debugging:

```bash
# Start interactive shell
docker run --rm -it \
  -v "$PWD:/workspace" \
  --env-file .env \
  --entrypoint /bin/bash \
  socket-basics:1.1.3

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
  "secrets_enabled": true,
  "console_tabular_enabled": true,
  "trufflehog_exclude_dir": "node_modules,vendor,dist"
}
EOF

# Run with config file
docker run --rm \
  -v "$PWD:/workspace" \
  -v "$PWD/socket-config.json:/config.json" \
  --env-file .env \
  socket-basics:1.1.3 \
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
    socket-basics:1.1.3 \
    --workspace /workspace \
    --all-languages \
    --secrets \
    --console-tabular-enabled
done
```

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
                    docker.image('ghcr.io/socketdev/socket-basics:1.1.3').inside(
                        "-v ${WORKSPACE}:/workspace --env-file .env"
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
  image: ghcr.io/socketdev/socket-basics:1.1.3
  stage: test
  script:
    - socket-basics
        --workspace /builds/$CI_PROJECT_PATH
        --all-languages
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

1. Run as current user:
   ```bash
   docker run --rm \
     -v "$PWD:/workspace" \
     --user "$(id -u):$(id -g)" \
     socket-basics:1.1.3 \
     --workspace /workspace
   ```

2. Fix ownership after scan:
   ```bash
   sudo chown -R $USER:$USER ./scan-results
   ```

### Volume Mount Not Working

**Problem:** Container can't see project files.

**Solutions:**

1. Use absolute paths:
   ```bash
   docker run --rm \
     -v "$(pwd):/workspace" \  # Use $(pwd) instead of $PWD
     socket-basics:1.1.3
   ```

2. Verify mount:
   ```bash
   docker run --rm \
     -v "$PWD:/workspace" \
     socket-basics:1.1.3 \
     ls -la /workspace
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
     socket-basics:1.1.3
   ```

### Docker Socket Permission Denied

**Problem:** Cannot scan Docker images (permission denied on `/var/run/docker.sock`).

**Solutions:**

1. Add user to docker group:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

2. Run with sudo (not recommended):
   ```bash
   sudo docker run ...
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
     socket-basics:1.1.3 \
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
     socket-basics:1.1.3 \
     --workspace /workspace \
     --output /workspace/results.json  # Save to mounted directory
   ```

2. Use separate results volume:
   ```bash
   mkdir -p ./results
   docker run --rm \
     -v "$PWD:/workspace" \
     -v "$PWD/results:/results" \
     socket-basics:1.1.3 \
     --workspace /workspace \
     --output /results/scan.json
   ```

## Shell Aliases

Add these to your `~/.bashrc` or `~/.zshrc` for quick access:

```bash
# Socket Basics Docker aliases
alias sb-docker='docker run --rm -v "$PWD:/workspace" --env-file .env ghcr.io/socketdev/socket-basics:1.1.3 --workspace /workspace'
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
2. **Pin to a specific version** — Avoid `:latest` in production CI; pin to `1.1.3` and upgrade deliberately
3. **Use Dependabot** — Reference the image in your Dockerfile/Compose to get automatic upgrade PRs
4. **Inspect baked-in labels** — Run `docker inspect <image> | jq '.[0].Config.Labels'` to verify tool versions
5. **Use .env files** — Keep credentials out of command history
6. **Add .env to .gitignore** — Never commit secrets
7. **Mount minimal volumes** — Only mount what you need to scan
8. **Resource limits** — Set CPU/memory limits for long-running scans

## Example: Complete Workflow

```bash
#!/bin/bash
# complete-scan.sh - Full Docker-based security scan workflow

set -e

# Configuration
PROJECT_DIR="$(pwd)"
RESULTS_DIR="./scan-results"
IMAGE_NAME="socket-basics:1.1.3"
ENV_FILE=".env"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Verify .env exists
if [ ! -f "$ENV_FILE" ]; then
    echo "❌ .env file not found. Creating template..."
    cat > "$ENV_FILE" << 'EOF'
SOCKET_SECURITY_API_KEY=your-api-key-here
SOCKET_ORG=your-org-slug
CONSOLE_TABULAR_ENABLED=true
EOF
    echo "⚠️  Please edit .env with your credentials"
    exit 1
fi

echo "🔍 Starting security scan..."

# Run comprehensive scan
docker run --rm \
  -v "$PROJECT_DIR:/workspace" \
  -v "$RESULTS_DIR:/results" \
  --env-file "$ENV_FILE" \
  "$IMAGE_NAME" \
  --workspace /workspace \
  --all-languages \
  --secrets \
  --socket-tier1 \
  --console-tabular-enabled \
  --output /results/scan-$(date +%Y%m%d-%H%M%S).json

echo "✅ Scan complete! Results saved to $RESULTS_DIR"
```

---

**Next Steps:**
- [Parameters Reference](parameters.md) — Complete CLI and environment variable reference
- [GitHub Actions Integration](github-action.md) — Automate in CI/CD
- [Pre-Commit Hook Setup](pre-commit-hook.md) — Catch issues before commit
- [Local Installation](local-installation.md) — Install tools natively
