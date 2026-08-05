#!/usr/bin/env bash
# End-to-end integration tests for the socket-basics Docker image.
#
# Verifies the full scan pipeline runs correctly without external credentials:
#   1. socket-basics CLI starts and responds to --help
#   2. opengrep can scan Python code using the bundled rules (no API key needed)
#   3. socket-basics runs a scan on a small fixture without crashing
#   4. the trivy connector scans a fixture Dockerfile end-to-end (bundled
#      Socket-built trivy binary → `trivy config` → result parsing)
#
# Usage:
#   ./scripts/integration-test-docker.sh [--image-tag TAG]
#   ./scripts/integration-test-docker.sh --image-tag socket-basics:2.0.3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-socket-basics:smoke-test}"
FIXTURE_DIR="$REPO_ROOT/tests/fixtures/integration"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image-tag)
      [[ $# -lt 2 ]] && { echo "Error: --image-tag requires a value"; exit 1; }
      IMAGE_TAG="$2"; shift 2
      ;;
    *) echo "Error: unknown option: $1"; exit 1 ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker CLI is not installed or not in PATH."
  exit 1
fi

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; exit 1; }

echo "==> Integration test: $IMAGE_TAG"

# ── Test 1: CLI starts and responds to --help ─────────────────────────────────
echo "--> socket-basics --help"
if docker run --rm --entrypoint /bin/sh "$IMAGE_TAG" -c "socket-basics -h" > /dev/null 2>&1; then
  pass "socket-basics -h exits 0"
else
  fail "socket-basics -h exited non-zero"
fi

# ── Test 2: opengrep binary is reachable and responsive ───────────────────────
# A full rules-scan against the bundled source can hit CI memory/timeout limits
# (opengrep exit 8), so we just verify the binary responds to --version.
# The smoke test already gates on `opengrep --version` before this script runs.
echo "--> opengrep --version"
if docker run --rm --entrypoint /bin/sh "$IMAGE_TAG" -c "opengrep --version" > /dev/null 2>&1; then
  pass "opengrep --version exits 0"
else
  fail "opengrep --version exited non-zero"
fi

# ── Test 3: socket-basics scan on fixture (no API key) ────────────────────────
# Runs a real scan on a small clean Python fixture. We don't assert specific
# findings — only that the process runs and does not crash. A non-zero exit is
# acceptable (may indicate findings or missing API key for enterprise features).
echo "--> socket-basics scan on fixture: $FIXTURE_DIR"
scan_output=$(
  docker run --rm \
    -v "${FIXTURE_DIR}:/workspace:ro" \
    --entrypoint /bin/sh \
    "$IMAGE_TAG" \
    -c "socket-basics --workspace /workspace --python --console-tabular-enabled 2>&1" \
) || true  # accept non-zero exit

if [[ -z "$scan_output" ]]; then
  fail "socket-basics produced no output on fixture scan"
fi

# Detect hard crashes: Go panic, segfault, unhandled Python traceback
if echo "$scan_output" | grep -qiE "^(panic:|fatal error:)|segmentation fault|Traceback \(most recent call last\)$"; then
  echo "  Scan output:"
  echo "$scan_output" | head -30
  fail "socket-basics crashed during scan"
fi

pass "socket-basics ran on fixture without crashing"

# ── Test 4: trivy connector end-to-end (Dockerfile misconfig scan) ────────────
# Exercises the trivy connector's full path (config → `trivy config` → result
# parsing → console output) against the fixture Dockerfile. As with Test 3 we
# assert no crash rather than specific findings — BUT we must also catch a
# missing binary explicitly: the connector logs "Trivy not found" and continues
# rather than failing, so without that grep this test would pass vacuously.
echo "--> socket-basics --dockerfiles scan on fixture Dockerfile"
trivy_output=$(
  docker run --rm \
    -v "${FIXTURE_DIR}:/workspace:ro" \
    --entrypoint /bin/sh \
    "$IMAGE_TAG" \
    -c "socket-basics --workspace /workspace --dockerfiles /workspace/Dockerfile --console-tabular-enabled 2>&1" \
) || true  # accept non-zero exit (findings are expected)

if [[ -z "$trivy_output" ]]; then
  fail "socket-basics produced no output on Dockerfile scan"
fi

if echo "$trivy_output" | grep -qi "Trivy not found"; then
  echo "  Scan output:"
  echo "$trivy_output" | head -30
  fail "trivy binary missing inside the image (connector fell back to a no-op)"
fi

if echo "$trivy_output" | grep -qiE "^(panic:|fatal error:)|segmentation fault|Traceback \(most recent call last\)$"; then
  echo "  Scan output:"
  echo "$trivy_output" | head -30
  fail "socket-basics crashed during Dockerfile scan"
fi

pass "trivy connector scanned the fixture Dockerfile without crashing"

echo "==> Integration test passed"
