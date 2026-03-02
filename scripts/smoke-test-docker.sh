#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-socket-basics:smoke-test}"
APP_TESTS_IMAGE_TAG="${APP_TESTS_IMAGE_TAG:-socket-basics-app-tests:smoke-test}"
RUN_APP_TESTS=false
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

usage() {
  echo "Usage: $0 [--image-tag TAG] [--app-tests] [--build-progress MODE]"
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
    --build-progress)
      [[ $# -lt 2 ]] && { echo "Error: --build-progress requires a value"; exit 1; }
      BUILD_PROGRESS="$2"; shift 2
      ;;
    *) echo "Error: unknown option: $1"; usage; exit 1 ;;
  esac
done

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

cd "$REPO_ROOT"

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
fi

echo "==> Smoke test passed"
