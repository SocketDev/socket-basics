#!/usr/bin/env python3
"""
ci_matrix.py — Dynamic CI pipeline configuration for socket-basics.

This script runs early in the CI pipeline to generate the matrix of images and Python versions to test.

The benefit: pipeline configuration lives in Python, not scattered across YAML.
Add a new Docker image or expand Python version support here — CI follows.

Usage:
    python scripts/ci_matrix.py                          # → Docker matrix (default)
    python scripts/ci_matrix.py --target docker          # explicit
    python scripts/ci_matrix.py --target python          # Python version matrix
    python scripts/ci_matrix.py --pretty                 # pretty-print for debugging

Typical GHA usage (capture output into GITHUB_OUTPUT):
    JSON=$(python scripts/ci_matrix.py --target docker)
    echo "json=$JSON" >> "$GITHUB_OUTPUT"
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

# ── Docker image definitions ──────────────────────────────────────────────────
# Each entry describes one image to build. The script reads the referenced
# Dockerfile to enrich the entry with its pinned ARG versions.
DOCKER_IMAGES: list[dict] = [
    {
        "name": "socket-basics",
        "dockerfile": "Dockerfile",
        "context": ".",
        "check_set": "main",
    },
    # TODO: re-enable once app_tests/Dockerfile source files are committed.
    # The Dockerfile references src/socket_external_tools_runner.py, src/version.py,
    # src/core/, and entrypoint.sh which do not yet exist in the repo.
    # {
    #     "name": "socket-basics-app-tests",
    #     "dockerfile": "app_tests/Dockerfile",
    #     "context": ".",
    #     "check_set": "app-tests",
    # },
]

# ── Python versions to test ───────────────────────────────────────────────────
# All versions listed here must be >= the requires-python floor in pyproject.toml.
# Extend this list when adding support for a new Python release.
_PYTHON_TEST_VERSIONS = ["3.12"]  # expand to ["3.10", "3.11", "3.12"] when ready


def _parse_dockerfile_args(dockerfile_path: Path) -> dict[str, str]:
    """Extract ARG pins from a Dockerfile (e.g. ARG TRIVY_VERSION=0.69.2)."""
    versions: dict[str, str] = {}
    for match in re.finditer(r"^ARG\s+(\w+)=(.+)$", dockerfile_path.read_text(), re.MULTILINE):
        versions[match.group(1)] = match.group(2).strip()
    return versions


def _min_python_version() -> tuple[int, int]:
    """Parse requires-python from pyproject.toml and return (major, minor)."""
    try:
        import tomllib  # stdlib >= 3.11
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return (3, 10)  # safe fallback if neither is available

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    requires = pyproject.get("project", {}).get("requires-python", ">=3.10")
    # Handle ">=3.10", "==3.12.*", "~=3.10" etc. — just grab the first version.
    match = re.search(r"(\d+)\.(\d+)", requires)
    if match:
        return int(match.group(1)), int(match.group(2))
    return (3, 10)


def docker_matrix() -> list[dict]:
    """
    Build the Docker image matrix.

    Each entry is enriched with the ARG version pins read directly from its
    Dockerfile — the matrix therefore reflects exactly what's baked into each
    image, with no duplication of version numbers.
    """
    matrix = []
    for image in DOCKER_IMAGES:
        dockerfile = REPO_ROOT / image["dockerfile"]
        if not dockerfile.exists():
            print(f"Warning: {dockerfile} not found, skipping.", file=sys.stderr)
            continue
        entry = {
            **image,
            "pinned_versions": _parse_dockerfile_args(dockerfile),
        }
        matrix.append(entry)
    return matrix


def python_matrix() -> list[dict]:
    """
    Build the Python test matrix.

    Reads the minimum supported version from pyproject.toml and cross-references
    it with _PYTHON_TEST_VERSIONS so CI always stays inside the declared support
    window. Add versions to _PYTHON_TEST_VERSIONS above to expand coverage.
    """
    min_version = _min_python_version()
    versions = [
        v for v in _PYTHON_TEST_VERSIONS
        if tuple(int(x) for x in v.split(".")[:2]) >= min_version
    ]
    return [{"python-version": v} for v in versions]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        choices=["docker", "python"],
        default="docker",
        help="Matrix type to generate (default: docker)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output (for local debugging)",
    )
    args = parser.parse_args()

    matrix = docker_matrix() if args.target == "docker" else python_matrix()
    print(json.dumps(matrix, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
