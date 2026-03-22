#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-socket-basics:smoke-test}"
APP_TESTS_IMAGE_TAG="${APP_TESTS_IMAGE_TAG:-socket-basics-app-tests:smoke-test}"
RUN_APP_TESTS=false
SKIP_BUILD=false
CHECK_SET="main"
BUILD_PROGRESS="${SMOKE_TEST_BUILD_PROGRESS:-}"

MAIN_TOOLS=(
  "socket-basics -h"
  "command -v socket"
  "trufflehog --version"
  "opengrep --version"
)

APP_TESTS_TOOLS=(
  "trufflehog --version"
  "opengrep --version"
  "command -v socket"
)

# TEMPORARY: trivy is being removed to assess impact. These checks FAIL if the
# tool is still present in the image — ensures removal is complete.
MUST_NOT_EXIST_TOOLS=(
  "trivy"
)

usage() {
  echo "Usage: $0 [--image-tag TAG] [--app-tests] [--skip-build] [--check-set main|app-tests] [--build-progress MODE]"
  echo "  --skip-build:     skip docker build; verify tools in a pre-built image"
  echo "  --check-set:      which tool set to verify: main (default) or app-tests"
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
    --build-progress)
      [[ $# -lt 2 ]] && { echo "Error: --build-progress requires a value"; exit 1; }
      BUILD_PROGRESS="$2"; shift 2
      ;;
    *) echo "Error: unknown option: $1"; usage; exit 1 ;;
  esac
done

case "$CHECK_SET" in
  main|app-tests) ;;
  *) echo "Error: invalid --check-set '$CHECK_SET' (must be 'main' or 'app-tests')"; exit 1 ;;
esac

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

# TEMPORARY: verify tools have been fully removed from the image.
# Fails if any tool in the list is still present.
run_must_not_exist_checks() {
  local tag="$1"
  shift
  local tools=("$@")
  for tool in "${tools[@]}"; do
    if docker run --rm --entrypoint /bin/sh "$tag" -c "command -v $tool" > /dev/null 2>&1; then
      echo "  FAIL: $tool is still present in the image (expected removal)"
      return 1
    else
      echo "  OK: $tool not found (removal confirmed)"
    fi
  done
}

cd "$REPO_ROOT"

if $SKIP_BUILD; then
  # ── Skip build: verify tools in a pre-built image ────────────────────────
  echo "==> Verify tools (skip-build mode)"
  echo "Image: $IMAGE_TAG"
  echo "Check set: $CHECK_SET"
  if [[ "$CHECK_SET" == "app-tests" ]]; then
    run_checks "$IMAGE_TAG" "${APP_TESTS_TOOLS[@]}"
  else
    run_checks "$IMAGE_TAG" "${MAIN_TOOLS[@]}"
  fi
  run_must_not_exist_checks "$IMAGE_TAG" "${MUST_NOT_EXIST_TOOLS[@]}"
else
  # ── Normal mode: build then verify ────────────────────────────────────────
  echo "==> Build main image"
  echo "Image: $IMAGE_TAG"
  echo "Docker build progress mode: $BUILD_PROGRESS"
  build_args_for_tag "$IMAGE_TAG"
  main_build_start="$(date +%s)"
  docker build "${BUILD_ARGS[@]}" .
  main_build_end="$(date +%s)"
  echo "Main image build completed in $((main_build_end - main_build_start))s"

  echo "==> Verify tools in main image"
  run_checks "$IMAGE_TAG" "${MAIN_TOOLS[@]}"
  run_must_not_exist_checks "$IMAGE_TAG" "${MUST_NOT_EXIST_TOOLS[@]}"

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
    run_must_not_exist_checks "$APP_TESTS_IMAGE_TAG" "${MUST_NOT_EXIST_TOOLS[@]}"
  fi
fi

echo "==> Smoke test passed"
