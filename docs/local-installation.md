# Local Installation Guide

Complete guide to installing Socket Basics and all security tools for native execution on your local machine.

## Table of Contents

- [Quick Install](#quick-install)
- [Prerequisites](#prerequisites)
- [Socket Basics Installation](#socket-basics-installation)
- [Security Tools Installation](#security-tools-installation)
- [Verification](#verification)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)

## Quick Install

For experienced users on macOS/Linux with Homebrew:

```bash
# Install Socket Basics
pip install socket-basics

# Install security tools
brew install socket trivy semgrep trufflehog

# Verify installation
socket-basics --version
socket --version
trivy --version
semgrep --version
trufflehog --version
```

For detailed installation instructions, continue reading below.

## Prerequisites

### Required Software

**Python 3.8 or higher:**

```bash
# Check Python version
python --version  # or python3 --version

# Install Python if needed
# macOS with Homebrew:
brew install python

# Ubuntu/Debian:
sudo apt update && sudo apt install python3 python3-pip python3-venv

# Windows:
# Download from https://www.python.org/downloads/
```

**pip (Python package manager):**

```bash
# Usually included with Python, verify:
pip --version  # or pip3 --version

# Install/upgrade if needed:
python -m ensurepip --upgrade
```

**Git:**

```bash
# Verify Git is installed
git --version

# Install if needed
# macOS: (included with Xcode Command Line Tools)
xcode-select --install

# Ubuntu/Debian:
sudo apt install git

# Windows:
# Download from https://git-scm.com/download/win
```

### Optional but Recommended

**Virtual environment manager:**

```bash
# Using venv (built-in)
python -m venv --help

# Or install virtualenv
pip install virtualenv

# Or use uv (faster, modern alternative)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Socket Basics Installation

### Method 1: From PyPI (Recommended for Users)

```bash
# Create and activate virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install Socket Basics
pip install socket-basics

# Verify installation
socket-basics --version
```

### Method 2: From Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/SocketDev/socket-basics.git
cd socket-basics

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .

# Or using uv (faster)
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync
pip install -e .

# Verify installation
socket-basics --version
```

### Method 3: Using uv (Fastest)

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone https://github.com/SocketDev/socket-basics.git
cd socket-basics

# Create venv and install dependencies
uv venv
source .venv/bin/activate
uv sync
pip install -e .
```

## Security Tools Installation

Socket Basics orchestrates multiple security tools. Install the ones you need:

### Socket CLI (Dependency Analysis)

**Required for:** Socket Tier 1 reachability analysis

**Installation:**

```bash
# macOS/Linux with Homebrew:
brew install socket

# Using npm (if you have Node.js):
npm install -g @socketsecurity/cli

# Manual installation (Linux):
curl -sSL https://socket.dev/install.sh | sh

# Manual installation (macOS):
curl -sSL https://socket.dev/install.sh | sh

# Verify installation
socket --version
```

**Configuration:**

```bash
# Login to Socket (requires Socket account)
socket login

# Or set API key directly
export SOCKET_SECURITY_API_KEY="your-api-key"
```

**Documentation:** https://docs.socket.dev/docs/cli

### Trivy (Container Scanning)

**Required for:** Container image and Dockerfile vulnerability scanning

**Installation:**

```bash
# macOS with Homebrew:
brew install trivy

# Ubuntu/Debian:
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# RHEL/CentOS:
sudo tee /etc/yum.repos.d/trivy.repo << 'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=0
enabled=1
EOF
sudo yum -y install trivy

# Using Docker (alternative):
docker pull aquasec/trivy:latest

# Verify installation
trivy --version
```

**Documentation:** https://github.com/aquasecurity/trivy

### Semgrep/OpenGrep (SAST)

**Required for:** Static Application Security Testing (SAST) for all languages

**Installation:**

```bash
# macOS/Linux with Homebrew:
brew install semgrep

# Using pip:
pip install semgrep

# Using Docker (alternative):
docker pull semgrep/semgrep:latest

# Verify installation
semgrep --version
```

**Configuration:**

```bash
# Login to Semgrep (optional, for custom rules):
semgrep login

# Or run without login using bundled rules
semgrep --config=auto
```

**Documentation:** https://semgrep.dev/docs/

### TruffleHog (Secret Scanning)

**Required for:** Detecting leaked credentials, API keys, and secrets

**Installation:**

```bash
# macOS/Linux with Homebrew:
brew install trufflehog

# Using Docker (alternative):
docker pull trufflesecurity/trufflehog:latest

# Manual installation (Linux):
wget https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64.tar.gz
tar -xzf trufflehog_linux_amd64.tar.gz
sudo mv trufflehog /usr/local/bin/

# Manual installation (macOS):
wget https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_darwin_arm64.tar.gz
tar -xzf trufflehog_darwin_arm64.tar.gz
sudo mv trufflehog /usr/local/bin/

# Verify installation
trufflehog --version
```

**Documentation:** https://github.com/trufflesecurity/trufflehog

## Verification

### Test Socket Basics Installation

```bash
# Activate your virtual environment
source .venv/bin/activate

# Check version
socket-basics --version

# View help
socket-basics --help

# Test basic scan (dry run)
socket-basics --python-sast-enabled --verbose
```

### Test Individual Tools

```bash
# Test Socket CLI
socket --version
socket cdxgen --help

# Test Trivy
trivy --version
trivy image --help

# Test Semgrep
semgrep --version
semgrep --help

# Test TruffleHog
trufflehog --version
trufflehog --help
```

### Complete System Check

Create a test script `check-installation.sh`:

```bash
#!/bin/bash

echo "Checking Socket Basics installation..."

ERRORS=0

# Check Python
if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
    echo "❌ Python not found"
    ERRORS=$((ERRORS+1))
else
    echo "✅ Python found: $(python --version 2>&1 || python3 --version 2>&1)"
fi

# Check Socket Basics
if ! command -v socket-basics &> /dev/null; then
    echo "❌ socket-basics not found"
    ERRORS=$((ERRORS+1))
else
    echo "✅ socket-basics found: $(socket-basics --version)"
fi

# Check Socket CLI
if ! command -v socket &> /dev/null; then
    echo "⚠️  socket CLI not found (needed for Socket Tier 1)"
else
    echo "✅ socket CLI found: $(socket --version)"
fi

# Check Trivy
if ! command -v trivy &> /dev/null; then
    echo "⚠️  trivy not found (needed for container scanning)"
else
    echo "✅ trivy found: $(trivy --version | head -1)"
fi

# Check Semgrep
if ! command -v semgrep &> /dev/null; then
    echo "⚠️  semgrep not found (needed for SAST)"
else
    echo "✅ semgrep found: $(semgrep --version)"
fi

# Check TruffleHog
if ! command -v trufflehog &> /dev/null; then
    echo "⚠️  trufflehog not found (needed for secret scanning)"
else
    echo "✅ trufflehog found: $(trufflehog --version 2>&1 | head -1)"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Core installation complete!"
    echo "⚠️  Missing tools will limit functionality but Socket Basics will still run."
else
    echo "❌ Installation incomplete. Please install missing components."
    exit 1
fi
```

Run the check:

```bash
chmod +x check-installation.sh
./check-installation.sh
```

## Configuration

### Environment Variables

Create `.env` file in your project (add to `.gitignore`):

```bash
# Socket Configuration (Enterprise)
SOCKET_ORG=your-org-slug
SOCKET_SECURITY_API_KEY=your-socket-api-key

# GitHub Integration (for PR comments)
GITHUB_TOKEN=your-github-token

# Notification Integrations (Enterprise)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
JIRA_URL=https://your-org.atlassian.net
JIRA_EMAIL=you@example.com
JIRA_API_TOKEN=your-jira-token
JIRA_PROJECT=SEC

# Scanning Options
INPUT_CONSOLE_ENABLED=true
INPUT_VERBOSE=false
INPUT_CONSOLE_TABULAR_ENABLED=true
```

Load environment variables:

```bash
# Option 1: Source the file
source .env

# Option 2: Use with export
export $(cat .env | grep -v '^#' | xargs)

# Option 3: Run with env prefix
env $(cat .env | grep -v '^#' | xargs) socket-basics --python-sast-enabled
```

### Configuration File

Create `.socket-basics.json`:

```json
{
  "workspace": ".",
  "python_sast_enabled": true,
  "javascript_sast_enabled": true,
  "secret_scanning_enabled": true,
  "console_tabular_enabled": true,
  "verbose": false,
  "trufflehog_exclude_dir": "node_modules,vendor,dist,.git",
  "python_disabled_rules": "unused-import,line-too-long",
  "socket_tier_1_enabled": false
}
```

Use configuration file:

```bash
socket-basics --config .socket-basics.json
```

### Shell Aliases

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
# Quick security scans
alias sb='socket-basics'
alias sb-quick='socket-basics --secret-scanning-enabled --console-tabular-enabled'
alias sb-python='socket-basics --python-sast-enabled --secret-scanning-enabled --console-tabular-enabled'
alias sb-js='socket-basics --javascript-sast-enabled --secret-scanning-enabled --console-tabular-enabled'
alias sb-full='socket-basics --all-languages-enabled --secret-scanning-enabled --socket-tier-1-enabled --console-tabular-enabled'

# With venv activation
alias sb-activate='source .venv/bin/activate && socket-basics'
```

Reload shell:

```bash
source ~/.bashrc  # or source ~/.zshrc
```

## Usage Examples

### Basic Scans

```bash
# Activate virtual environment
source .venv/bin/activate

# Quick secret scan
socket-basics --secret-scanning-enabled

# Python SAST + secrets
socket-basics --python-sast-enabled --secret-scanning-enabled

# JavaScript/TypeScript SAST + secrets
socket-basics --javascript-sast-enabled --typescript-sast-enabled --secret-scanning-enabled

# All languages
socket-basics --all-languages-enabled --secret-scanning-enabled
```

### Advanced Scans

```bash
# With Socket Tier 1 reachability
socket-basics \
  --python-sast-enabled \
  --secret-scanning-enabled \
  --socket-tier-1-enabled \
  --socket-org your-org

# Container scanning
socket-basics \
  --container-images nginx:latest,redis:7 \
  --dockerfiles Dockerfile,docker/Dockerfile.prod

# Scan specific workspace
socket-basics \
  --workspace /path/to/project \
  --python-sast-enabled \
  --secret-scanning-enabled

# Custom output file
socket-basics \
  --python-sast-enabled \
  --output ./security-results.json
```

### With Enterprise Features

```bash
# Load environment variables
source .env

# Scan with Slack notifications
socket-basics \
  --python-sast-enabled \
  --secret-scanning-enabled \
  --socket-org $SOCKET_ORG \
  --console-tabular-enabled

# Scan with Jira ticket creation
socket-basics \
  --all-languages-enabled \
  --secret-scanning-enabled \
  --socket-org $SOCKET_ORG \
  --console-tabular-enabled

# Full enterprise scan
socket-basics \
  --all-languages-enabled \
  --secret-scanning-enabled \
  --socket-tier-1-enabled \
  --socket-org $SOCKET_ORG \
  --verbose
```

### Continuous Scanning

Watch for file changes and re-scan:

```bash
# Install fswatch (macOS)
brew install fswatch

# Install inotify-tools (Linux)
sudo apt install inotify-tools

# Watch and scan on changes (macOS)
fswatch -o . | xargs -n1 -I{} socket-basics --python-sast-enabled --secret-scanning-enabled

# Watch and scan on changes (Linux)
while inotifywait -r -e modify .; do
  socket-basics --python-sast-enabled --secret-scanning-enabled
done
```

## Troubleshooting

### Virtual Environment Issues

**Problem:** `socket-basics: command not found`

**Solutions:**
```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Verify socket-basics is installed
pip list | grep socket-basics

# Reinstall if needed
pip install -e .
```

### Tool Not Found Errors

**Problem:** Scanner reports tool not found (e.g., "trivy not found")

**Solutions:**
```bash
# Check if tool is in PATH
which trivy  # or semgrep, trufflehog, socket

# Add to PATH if needed
export PATH="/usr/local/bin:$PATH"

# Verify tool is executable
ls -l $(which trivy)
```

### Permission Denied

**Problem:** Permission errors when running scans

**Solutions:**
```bash
# Ensure files are readable
chmod -R u+r /path/to/project

# Check directory permissions
ls -la /path/to/project

# Run with appropriate user permissions
```

### Slow Scan Performance

**Problem:** Scans take too long

**Solutions:**
1. Exclude unnecessary directories:
   ```bash
   socket-basics \
     --python-sast-enabled \
     --trufflehog-exclude-dir "node_modules,vendor,dist,.git"
   ```

2. Scan specific languages only:
   ```bash
   # Instead of --all-languages-enabled
   socket-basics --python-sast-enabled --javascript-sast-enabled
   ```

3. Use faster storage (SSD vs HDD)

4. Increase available RAM

### Socket CLI Authentication

**Problem:** Socket CLI authentication errors

**Solutions:**
```bash
# Login interactively
socket login

# Or set API key
export SOCKET_SECURITY_API_KEY="your-api-key"

# Verify authentication
socket info
```

### Semgrep/OpenGrep Errors

**Problem:** Semgrep crashes or fails

**Solutions:**
```bash
# Update Semgrep
pip install --upgrade semgrep

# Clear Semgrep cache
rm -rf ~/.semgrep/cache

# Test Semgrep standalone
semgrep --config=auto --test test_file.py
```

### Python Version Conflicts

**Problem:** Conflicts between Python 2 and Python 3

**Solutions:**
```bash
# Always use python3 explicitly
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install socket-basics

# Or set Python 3 as default
alias python=python3
alias pip=pip3
```

### macOS-Specific Issues

**Problem:** Command line tools not found on macOS

**Solutions:**
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add Homebrew to PATH
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

---

**Next Steps:**
- [GitHub Actions Integration](github-action.md) — Automate in CI/CD
- [Pre-Commit Hook Setup](pre-commit-hook.md) — Catch issues before commit
- [Configuration Guide](configuration.md) — Detailed configuration options
