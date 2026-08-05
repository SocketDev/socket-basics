#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-socket-basics:smoke-test}"
APP_TESTS_IMAGE_TAG="${APP_TESTS_IMAGE_TAG:-socket-basics-app-tests:smoke-test}"
RUN_APP_TESTS=false
SKIP_BUILD=false
CHECK_SET="main"
DOCKERFILE="Dockerfile"
DOCKERFILE_SET=false
BUILD_PROGRESS="${SMOKE_TEST_BUILD_PROGRESS:-}"

MAIN_TOOLS=(
  "socket-basics -h"
  "command -v socket"
  "trivy --version"
  "trufflehog --version"
  "opengrep --version"
)

APP_TESTS_TOOLS=(
  "trivy --version"
  "trufflehog --version"
  "opengrep --version"
  "command -v socket"
)

HEAVY_TOOLS=(
  "socket-basics -h"
  "socketcli --help"
  "command -v socket"
  "trivy --version"
  "trufflehog --version"
  "opengrep --version"
)

usage() {
  echo "Usage: $0 [--image-tag TAG] [--app-tests] [--skip-build] [--check-set main|app-tests|heavy] [--dockerfile FILE] [--build-progress MODE]"
  echo "  --skip-build:     skip docker build; verify tools in a pre-built image"
  echo "  --check-set:      which tool set to verify: main (default), app-tests, or heavy"
  echo "  --dockerfile:     Dockerfile to build in non-skip mode (default: Dockerfile)"
  echo "  --build-progress: auto|plain|tty (default: auto locally, plain in CI)"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --image-tag)
      [[ $# -lt 2 ]] && { echo "Error: --image-tag requires a value"; exit 1; }
      IMAGE_TAG="$2"; shift 2
      ;;
    --app-tests) RUN_APP_TESTS=true; shift ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --check-set)
      [[ $# -lt 2 ]] && { echo "Error: --check-set requires a value"; exit 1; }
      CHECK_SET="$2"; shift 2
      ;;
    --dockerfile)
      [[ $# -lt 2 ]] && { echo "Error: --dockerfile requires a value"; exit 1; }
      DOCKERFILE="$2"; DOCKERFILE_SET=true; shift 2
      ;;
    --build-progress)
      [[ $# -lt 2 ]] && { echo "Error: --build-progress requires a value"; exit 1; }
      BUILD_PROGRESS="$2"; shift 2
      ;;
    *) echo "Error: unknown option: $1"; usage; exit 1 ;;
  esac
done

case "$CHECK_SET" in
  main|app-tests|heavy) ;;
  *) echo "Error: invalid --check-set '$CHECK_SET' (must be 'main', 'app-tests', or 'heavy')"; exit 1 ;;
esac

if [[ "$CHECK_SET" == "heavy" && "$DOCKERFILE_SET" == "false" ]]; then
  DOCKERFILE="Dockerfile.heavy"
fi

if [[ -z "$BUILD_PROGRESS" ]]; then
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    BUILD_PROGRESS="plain"
  else
    BUILD_PROGRESS="auto"
  fi
fi

case "$BUILD_PROGRESS" in
  auto|plain|tty) ;;
  *) echo "Error: invalid --build-progress '$BUILD_PROGRESS'"; exit 1 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker CLI is not installed or not in PATH."
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not reachable."
  exit 1
fi

build_args_for_tag() {
  local tag="$1"
  BUILD_ARGS=(--progress "$BUILD_PROGRESS" -t "$tag")
  [[ -n "${TRIVY_IMAGE:-}" ]] && BUILD_ARGS+=(--build-arg "TRIVY_IMAGE=$TRIVY_IMAGE")
  [[ -n "${TRIVY_VERSION:-}" ]] && BUILD_ARGS+=(--build-arg "TRIVY_VERSION=$TRIVY_VERSION")
  [[ -n "${TRUFFLEHOG_VERSION:-}" ]] && BUILD_ARGS+=(--build-arg "TRUFFLEHOG_VERSION=$TRUFFLEHOG_VERSION")
  [[ -n "${OPENGREP_VERSION:-}" ]] && BUILD_ARGS+=(--build-arg "OPENGREP_VERSION=$OPENGREP_VERSION")
  return 0
}

run_checks() {
  local tag="$1"
  shift
  local checks=("$@")
  for cmd in "${checks[@]}"; do
    if docker run --rm --entrypoint /bin/sh "$tag" -c "$cmd" > /dev/null 2>&1; then
      echo "  OK: $cmd"
    else
      echo "  FAIL: $cmd"
      docker run --rm --entrypoint /bin/sh "$tag" -c "$cmd" 2>&1 || true
      return 1
    fi
  done
}

# Socket-built trivy assertions, beyond presence:
#   1. the binary's reported version must agree with the version tag pinned in
#      the Dockerfile's TRIVY_IMAGE ARG (catches pin/binary drift), and
#   2. `trivy config` — the exact subcommand the trivy connector invokes — must
#      succeed against a trivial fixture, with the connector's flags.
run_trivy_checks() {
  local tag="$1"
  local dockerfile="$2"
  local expected
  expected="$(sed -n 's/^ARG TRIVY_IMAGE=[^:]*:\([^@]*\)@.*/\1/p' "$dockerfile")"
  if [[ -z "$expected" ]]; then
    echo "  FAIL: could not parse the TRIVY_IMAGE version tag from $dockerfile"
    return 1
  fi
  if docker run --rm --entrypoint /bin/sh "$tag" -c "trivy --version | grep -q 'Version: $expected'"; then
    echo "  OK: trivy version matches the Dockerfile pin ($expected)"
  else
    echo "  FAIL: trivy version does not match the Dockerfile pin ($expected)"
    docker run --rm --entrypoint /bin/sh "$tag" -c "trivy --version" 2>&1 || true
    return 1
  fi
  if docker run --rm --entrypoint /bin/sh "$tag" \
      -c "printf 'FROM alpine:3.20\n' > /tmp/smoke.Dockerfile && trivy config --format json --output /tmp/smoke-result.json /tmp/smoke.Dockerfile"; then
    echo "  OK: trivy config scan succeeds (connector code path)"
  else
    echo "  FAIL: trivy config scan failed"
    return 1
  fi
}

trivy_ref_dockerfile() {
  case "$CHECK_SET" in
    app-tests) echo "app_tests/Dockerfile" ;;
    heavy)     echo "Dockerfile.heavy" ;;
    *)         echo "Dockerfile" ;;
  esac
}

cd "$REPO_ROOT"

if $SKIP_BUILD; then
  # ── Skip build: verify tools in a pre-built image ────────────────────────
  echo "==> Verify tools (skip-build mode)"
  echo "Image: $IMAGE_TAG"
  echo "Check set: $CHECK_SET"
  if [[ "$CHECK_SET" == "app-tests" ]]; then
    run_checks "$IMAGE_TAG" "${APP_TESTS_TOOLS[@]}"
  elif [[ "$CHECK_SET" == "heavy" ]]; then
    run_checks "$IMAGE_TAG" "${HEAVY_TOOLS[@]}"
  else
    run_checks "$IMAGE_TAG" "${MAIN_TOOLS[@]}"
  fi
  run_trivy_checks "$IMAGE_TAG" "$(trivy_ref_dockerfile)"
else
  # ── Normal mode: build then verify ────────────────────────────────────────
  echo "==> Build main image"
  echo "Image: $IMAGE_TAG"
  echo "Dockerfile: $DOCKERFILE"
  echo "Docker build progress mode: $BUILD_PROGRESS"
  build_args_for_tag "$IMAGE_TAG"
  main_build_start="$(date +%s)"
  docker build -f "$DOCKERFILE" "${BUILD_ARGS[@]}" .
  main_build_end="$(date +%s)"
  echo "Main image build completed in $((main_build_end - main_build_start))s"

  echo "==> Verify tools in main image"
  if [[ "$CHECK_SET" == "heavy" ]]; then
    run_checks "$IMAGE_TAG" "${HEAVY_TOOLS[@]}"
  else
    run_checks "$IMAGE_TAG" "${MAIN_TOOLS[@]}"
  fi
  run_trivy_checks "$IMAGE_TAG" "$DOCKERFILE"

  if $RUN_APP_TESTS; then
    echo "==> Build app_tests image"
    echo "Image: $APP_TESTS_IMAGE_TAG"
    build_args_for_tag "$APP_TESTS_IMAGE_TAG"
    app_build_start="$(date +%s)"
    docker build -f app_tests/Dockerfile "${BUILD_ARGS[@]}" .
    app_build_end="$(date +%s)"
    echo "app_tests image build completed in $((app_build_end - app_build_start))s"

    echo "==> Verify tools in app_tests image"
    run_checks "$APP_TESTS_IMAGE_TAG" "${APP_TESTS_TOOLS[@]}"
    run_trivy_checks "$APP_TESTS_IMAGE_TAG" "app_tests/Dockerfile"
  fi
fi

echo "==> Smoke test passed"
