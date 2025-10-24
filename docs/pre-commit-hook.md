# Pre-Commit Hook Setup

Catch security issues before they're committed to your repository using Socket Basics as a pre-commit hook.

## Table of Contents

- [Quick Start](#quick-start)
- [Docker Installation (Recommended)](#docker-installation-recommended)
- [Native Installation](#native-installation)
- [Configuration](#configuration)
- [Customization](#customization)
- [Troubleshooting](#troubleshooting)

## Quick Start

**Choose your installation method:**

1. **Docker** (Recommended) — No tool installation required, everything runs in a container
2. **Native** — Install tools directly on your system for faster execution

Both methods integrate with Git's pre-commit hook system to automatically scan your code before each commit.

## Docker Installation (Recommended)

Best for: Teams wanting consistent environments without installing security tools locally.

### Prerequisites

- Docker installed and running
- Git repository initialized

### Setup Steps

**1. Build the Socket Basics Docker image:**

```bash
# Clone the repository (if not already)
git clone https://github.com/SocketDev/socket-basics.git
cd socket-basics

# Build the Docker image with version tag
docker build -t socket-basics:1.0.19 .
```

**2. Create pre-commit hook:**

Create `.git/hooks/pre-commit` in your project:

```bash
#!/bin/bash
set -e

echo "🔍 Running Socket Basics security scan..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
  echo "No files to scan"
  exit 0
fi

# Run Socket Basics in Docker
docker run --rm \
  -v "$PWD:/workspace" \
  -e INPUT_CONSOLE_ENABLED=true \
  socket-basics \
  --workspace /workspace \
  --python-sast-enabled \
  --javascript-sast-enabled \
  --secret-scanning-enabled \
  --console-tabular-enabled

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Security scan failed! Please fix the issues above before committing."
  exit 1
fi

echo "✅ Security scan passed!"
exit 0
```

**3. Make the hook executable:**

```bash
chmod +x .git/hooks/pre-commit
```

**4. Test the hook:**

```bash
# Try to commit a file
git add .
git commit -m "Test commit"
```

### Docker Pre-Commit Configuration

**Scan only changed files:**

```bash
#!/bin/bash
set -e

echo "🔍 Running Socket Basics security scan on staged files..."

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
  echo "No files to scan"
  exit 0
fi

# Create temporary file list
TEMP_FILE=$(mktemp)
echo "$STAGED_FILES" > "$TEMP_FILE"

# Run scan only on staged files
docker run --rm \
  -v "$PWD:/workspace" \
  -v "$TEMP_FILE:/tmp/scan-files.txt" \
  -e INPUT_CONSOLE_ENABLED=true \
  socket-basics \
  --workspace /workspace \
  --python-sast-enabled \
  --secret-scanning-enabled \
  --console-tabular-enabled

EXIT_CODE=$?
rm "$TEMP_FILE"

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Security issues found! Please fix before committing."
  exit 1
fi

echo "✅ Security scan passed!"
exit 0
```

**With Enterprise features:**

```bash
#!/bin/bash
set -e

echo "🔍 Running Socket Basics security scan..."

# Load environment variables if .env exists
if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | xargs)
fi

docker run --rm \
  -v "$PWD:/workspace" \
  -e INPUT_CONSOLE_ENABLED=true \
  -e SOCKET_ORG="$SOCKET_ORG" \
  -e SOCKET_SECURITY_API_KEY="$SOCKET_SECURITY_API_KEY" \
  -e INPUT_SLACK_WEBHOOK_URL="$SLACK_WEBHOOK_URL" \
  socket-basics \
  --workspace /workspace \
  --python-sast-enabled \
  --javascript-sast-enabled \
  --secret-scanning-enabled \
  --socket-tier-1-enabled \
  --console-tabular-enabled

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Security scan failed!"
  exit 1
fi

echo "✅ Security scan passed!"
exit 0
```

## Native Installation

Best for: Developers who want faster scan times and don't mind installing tools locally.

### Prerequisites

Install the required security tools:

**Python environment:**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

**Socket Basics:**
```bash
pip install socket-basics
# Or for development:
git clone https://github.com/SocketDev/socket-basics.git
cd socket-basics
pip install -e .
```

**Security tools:**

See [Local Installation Guide](local-installation.md) for detailed instructions on installing:
- Socket CLI
- Trivy
- Semgrep (OpenGrep)
- TruffleHog

### Setup Steps

**1. Create pre-commit hook:**

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

echo "🔍 Running Socket Basics security scan..."

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
  source .venv/bin/activate
fi

# Run Socket Basics
socket-basics \
  --python-sast-enabled \
  --javascript-sast-enabled \
  --secret-scanning-enabled \
  --console-tabular-enabled

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Security scan failed! Please fix the issues above before committing."
  exit 1
fi

echo "✅ Security scan passed!"
exit 0
```

**2. Make executable:**

```bash
chmod +x .git/hooks/pre-commit
```

**3. Test the hook:**

```bash
git add .
git commit -m "Test commit"
```

### Native Pre-Commit Configuration

**Fast scan (secrets only):**

```bash
#!/bin/bash
set -e

echo "🔍 Quick security check..."

if [ -d ".venv" ]; then
  source .venv/bin/activate
fi

socket-basics \
  --secret-scanning-enabled \
  --console-tabular-enabled

if [ $? -ne 0 ]; then
  echo "❌ Security issues found!"
  exit 1
fi

echo "✅ Scan passed!"
exit 0
```

**Comprehensive scan:**

```bash
#!/bin/bash
set -e

echo "🔍 Running comprehensive security scan..."

if [ -d ".venv" ]; then
  source .venv/bin/activate
fi

# Load environment variables if .env exists
if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | xargs)
fi

socket-basics \
  --all-languages-enabled \
  --secret-scanning-enabled \
  --socket-tier-1-enabled \
  --console-tabular-enabled \
  --verbose

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Security scan failed!"
  echo "Run 'socket-basics --help' for more information"
  exit 1
fi

echo "✅ Security scan passed!"
exit 0
```

## Configuration

### Speed vs Coverage Trade-offs

**Fast (< 10 seconds):**
```bash
socket-basics --secret-scanning-enabled
```
- Only scans for leaked secrets
- Best for quick feedback during development

**Balanced (30-60 seconds):**
```bash
socket-basics \
  --python-sast-enabled \
  --secret-scanning-enabled
```
- Language-specific SAST + secrets
- Good balance of speed and coverage

**Comprehensive (2-5 minutes):**
```bash
socket-basics \
  --all-languages-enabled \
  --secret-scanning-enabled \
  --socket-tier-1-enabled
```
- All security features enabled
- Best for final checks or CI/CD

### Conditional Scanning

Only scan relevant languages based on file extensions:

```bash
#!/bin/bash
set -e

STAGED_FILES=$(git diff --cached --name-only)

SCAN_ARGS=""

# Check for Python files
if echo "$STAGED_FILES" | grep -q "\.py$"; then
  SCAN_ARGS="$SCAN_ARGS --python-sast-enabled"
fi

# Check for JavaScript/TypeScript files
if echo "$STAGED_FILES" | grep -qE "\.(js|ts|jsx|tsx)$"; then
  SCAN_ARGS="$SCAN_ARGS --javascript-sast-enabled --typescript-sast-enabled"
fi

# Check for Go files
if echo "$STAGED_FILES" | grep -q "\.go$"; then
  SCAN_ARGS="$SCAN_ARGS --go-sast-enabled"
fi

# Always scan for secrets
SCAN_ARGS="$SCAN_ARGS --secret-scanning-enabled"

if [ -z "$SCAN_ARGS" ]; then
  echo "No scannable files in commit"
  exit 0
fi

socket-basics $SCAN_ARGS --console-tabular-enabled

if [ $? -ne 0 ]; then
  echo "❌ Security issues found!"
  exit 1
fi

echo "✅ Scan passed!"
exit 0
```

### Environment Variables

Create `.env` in your project root (add to `.gitignore`):

```bash
# Socket Configuration (Enterprise)
SOCKET_ORG=your-org-slug
SOCKET_SECURITY_API_KEY=your-api-key

# Notification webhooks (optional, Enterprise)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Scanning options
INPUT_CONSOLE_ENABLED=true
INPUT_VERBOSE=false
```

### Configuration File

Create `.socket-basics.json` in your project root:

```json
{
  "python_sast_enabled": true,
  "javascript_sast_enabled": true,
  "secret_scanning_enabled": true,
  "console_tabular_enabled": true,
  "trufflehog_exclude_dir": "node_modules,vendor,dist",
  "python_disabled_rules": "unused-import"
}
```

Reference in hook:

```bash
socket-basics --config .socket-basics.json
```

## Customization

### Skip Hook When Needed

```bash
# Skip pre-commit hook for emergency commits
git commit --no-verify -m "Emergency fix"
```

### Warning-Only Mode

Make the hook non-blocking but still show warnings:

```bash
#!/bin/bash
set -e

echo "🔍 Running Socket Basics security scan..."

socket-basics \
  --python-sast-enabled \
  --secret-scanning-enabled \
  --console-tabular-enabled

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "⚠️  Security issues found, but allowing commit."
  echo "Please review and fix these issues soon."
  # Don't exit with error - allow commit
  exit 0
fi

echo "✅ Security scan passed!"
exit 0
```

### Severity Threshold

Only fail on high/critical issues:

```bash
#!/bin/bash
set -e

OUTPUT=$(socket-basics \
  --python-sast-enabled \
  --secret-scanning-enabled \
  --console-json-enabled 2>&1)

echo "$OUTPUT"

# Check if high or critical issues exist
if echo "$OUTPUT" | jq -e '.components[].alerts[] | select(.severity == "high" or .severity == "critical")' > /dev/null 2>&1; then
  echo "❌ High or critical security issues found!"
  exit 1
fi

echo "✅ No high/critical issues found!"
exit 0
```

### Team-Wide Hook Distribution

**Using pre-commit framework:**

Install [pre-commit](https://pre-commit.com/):
```bash
pip install pre-commit
```

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: socket-basics
        name: Socket Basics Security Scan
        entry: docker run --rm -v "$PWD:/workspace" socket-basics --workspace /workspace --python-sast-enabled --secret-scanning-enabled
        language: system
        pass_filenames: false
```

Team members install with:
```bash
pre-commit install
```

## Troubleshooting

### Hook Not Running

**Problem:** Pre-commit hook doesn't execute.

**Solutions:**
1. Verify hook is executable: `chmod +x .git/hooks/pre-commit`
2. Check shebang is correct: `#!/bin/bash`
3. Ensure no syntax errors: `bash -n .git/hooks/pre-commit`

### Docker Permission Issues

**Problem:** Docker commands fail with permission errors.

**Solutions:**
1. Add user to docker group: `sudo usermod -aG docker $USER`
2. Run with sudo (not recommended): `sudo docker run ...`
3. Use Docker Desktop (macOS/Windows)

### Slow Scan Times

**Problem:** Pre-commit hook takes too long.

**Solutions:**
1. Scan only changed files (see conditional scanning above)
2. Reduce scan scope:
   ```bash
   socket-basics --secret-scanning-enabled  # Fast
   ```
3. Use warning-only mode for local commits
4. Run comprehensive scans only in CI/CD

### Python Virtual Environment Issues

**Problem:** Hook can't find socket-basics command.

**Solutions:**
1. Activate venv in hook:
   ```bash
   source .venv/bin/activate
   ```
2. Use absolute path:
   ```bash
   /path/to/.venv/bin/socket-basics
   ```
3. Install globally: `pip install --user socket-basics`

### False Positives

**Problem:** Scanner reports false positives.

**Solutions:**
1. Disable specific rules:
   ```bash
   socket-basics \
     --python-sast-enabled \
     --python-disabled-rules "rule-id-1,rule-id-2"
   ```
2. Exclude directories:
   ```bash
   socket-basics \
     --secret-scanning-enabled \
     --trufflehog-exclude-dir "test,fixtures,samples"
   ```
3. Use configuration file with exceptions

### Enterprise Features Not Working

**Problem:** Dashboard configuration or notifications not working.

**Solutions:**
1. Verify `.env` file exists and is loaded in hook
2. Check `SOCKET_ORG` and `SOCKET_SECURITY_API_KEY` are set
3. Confirm Socket Enterprise subscription is active

---

**Next Steps:**
- [GitHub Actions Integration](github-action.md) — Automated CI/CD scanning
- [Local Installation](local-installation.md) — Install security tools natively
- [Configuration Guide](configuration.md) — Detailed configuration options
