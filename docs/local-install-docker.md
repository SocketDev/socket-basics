# Local Docker Installation

Run Socket Basics locally using Docker without installing any security tools on your host machine. This guide covers building the Docker image, mounting your code, and configuring environment variables.

## Table of Contents

- [Quick Start](#quick-start)
- [Building the Docker Image](#building-the-docker-image)
- [Running Scans](#running-scans)
- [Environment Configuration](#environment-configuration)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## Quick Start

```bash
# 1. Clone and build
git clone https://github.com/SocketDev/socket-basics.git
cd socket-basics
docker build -t socket-basics:1.0.23 .

# 2. Create .env file with your credentials
cat > .env << 'EOF'
SOCKET_SECURITY_API_KEY=your-api-key-here
SOCKET_ORG=your-org-slug
EOF

# 3. Run a scan on your project
docker run --rm \
  -v "$PWD:/workspace" \
  --env-file .env \
  socket-basics:1.0.23 \
  --workspace /workspace \
  --python \
  --secrets \
  --console-tabular-enabled
```

## Building the Docker Image

### Standard Build

```bash
# Clone the repository
git clone https://github.com/SocketDev/socket-basics.git
cd socket-basics

# Build with version tag
docker build -t socket-basics:1.0.23 .

# Or build with latest tag
docker build -t socket-basics:1.0.23:latest .

# Verify the build
docker images | grep socket-basics
```

### Build with Custom Name

```bash
# Use your own image name
docker build -t myorg/security-scanner:1.0.23 .

# Build for specific platform (e.g., for M1/M2 Macs)
docker build --platform linux/amd64 -t socket-basics:1.0.23 .
```

### Verify Installation

```bash
# Check that all tools are available in the container
docker run --rm socket-basics:1.0.23 socket-basics --version
docker run --rm socket-basics:1.0.23 socket --version
docker run --rm socket-basics:1.0.23 trivy --version
docker run --rm socket-basics:1.0.23 opengrep --version
docker run --rm socket-basics:1.0.23 trufflehog --version
```

## Running Scans

### Basic Scan with Volume Mount

Mount your project directory into the container:

```bash
# Scan current directory
docker run --rm \
  -v "$PWD:/workspace" \
  socket-basics:1.0.23 \
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
  socket-basics:1.0.23 \
  --workspace /workspace \
  --javascript \
  --secrets
```

### Multiple Language Scan

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  socket-basics:1.0.23 \
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
  socket-basics:1.0.23 \
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
  socket-basics:1.0.23 \
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
  socket-basics:1.0.23 \
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
  socket-basics:1.0.23 \
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
  socket-basics:1.0.23 \
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
  socket-basics:1.0.23 \
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
  socket-basics:1.0.23

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
  socket-basics:1.0.23 \
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
    socket-basics:1.0.23 \
    --workspace /workspace \
    --all-languages \
    --secrets \
    --console-tabular-enabled
done
```

### CI/CD Integration

**Example: Jenkins**

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    docker.image('socket-basics:1.0.23').inside(
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
  image: socket-basics:1.0.23
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
     socket-basics:1.0.23 \
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
     socket-basics:1.0.23
   ```

2. Verify mount:
   ```bash
   docker run --rm \
     -v "$PWD:/workspace" \
     socket-basics:1.0.23 \
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
     socket-basics:1.0.23
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
     socket-basics:1.0.23 \
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
     socket-basics:1.0.23 \
     --workspace /workspace \
     --output /workspace/results.json  # Save to mounted directory
   ```

2. Use separate results volume:
   ```bash
   mkdir -p ./results
   docker run --rm \
     -v "$PWD:/workspace" \
     -v "$PWD/results:/results" \
     socket-basics:1.0.23 \
     --workspace /workspace \
     --output /results/scan.json
   ```

## Shell Aliases

Add these to your `~/.bashrc` or `~/.zshrc` for quick access:

```bash
# Socket Basics Docker aliases
alias sb-docker='docker run --rm -v "$PWD:/workspace" --env-file .env socket-basics:1.0.23 --workspace /workspace'
alias sb-quick='sb-docker --secrets --console-tabular-enabled'
alias sb-python='sb-docker --python --secrets --console-tabular-enabled'
alias sb-js='sb-docker --javascript --secrets --console-tabular-enabled'
alias sb-all='sb-docker --all-languages --secrets --socket-tier1 --console-tabular-enabled'

# Rebuild image
alias sb-build='docker build -t socket-basics:1.0.23 .'
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

1. **Use .env files** — Keep credentials out of command history
2. **Add .env to .gitignore** — Never commit secrets
3. **Use version tags** — Build with specific version tags for reproducibility
4. **Mount minimal volumes** — Only mount what you need to scan
5. **Regular updates** — Pull latest changes and rebuild periodically
6. **Resource limits** — Set CPU/memory limits for long-running scans
7. **Verify mounts** — Check that your code is visible in the container

## Example: Complete Workflow

```bash
#!/bin/bash
# complete-scan.sh - Full Docker-based security scan workflow

set -e

# Configuration
PROJECT_DIR="$(pwd)"
RESULTS_DIR="./scan-results"
IMAGE_NAME="socket-basics:1.0.23"
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
