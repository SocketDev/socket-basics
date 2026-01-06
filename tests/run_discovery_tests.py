#!/usr/bin/env python3
"""Standalone tests for Dockerfile auto-discovery functionality.

This script tests the discovery logic without requiring the full package to be installed.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add the package to the path
sys.path.insert(0, str(Path(__file__).parent.parent))


def discover_dockerfiles(workspace: Path) -> list:
    """Copy of the discovery logic for testing."""
    if not workspace or not workspace.exists():
        return []

    exclude_dirs = {
        'node_modules', 'vendor', '.git', '.svn', '.hg',
        'test', 'tests', 'testing', '__tests__',
        'spec', 'specs',
        'fixture', 'fixtures', 'testdata', 'test_data',
        'example', 'examples', 'sample', 'samples',
        'mock', 'mocks',
        'dist', 'build', 'out', 'target',
        '.cache', '.tox', '.nox', '.pytest_cache',
        'venv', '.venv', 'env', '.env',
        'app_tests',
    }

    discovered = []

    try:
        for root, dirs, files in os.walk(workspace):
            dirs[:] = [d for d in dirs if d.lower() not in exclude_dirs]

            for filename in files:
                lower_name = filename.lower()
                if (filename == 'Dockerfile' or
                    lower_name == 'dockerfile' or
                    lower_name.startswith('dockerfile.') or
                    lower_name.endswith('.dockerfile')):

                    full_path = Path(root) / filename
                    try:
                        rel_path = full_path.relative_to(workspace)
                        discovered.append(str(rel_path))
                    except ValueError:
                        discovered.append(str(full_path))

    except Exception as e:
        print(f"Error during discovery: {e}")
        return []

    return discovered


class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def add(self, name: str, passed: bool, message: str = ""):
        if passed:
            self.passed += 1
            self.results.append(f"  ✓ {name}")
        else:
            self.failed += 1
            self.results.append(f"  ✗ {name}: {message}")

    def summary(self):
        return f"\n".join(self.results) + f"\n\nResults: {self.passed} passed, {self.failed} failed"


def run_tests():
    """Run all tests and return results."""
    results = TestResult()

    # Test 1: Discovers Dockerfile at root
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM python:3.11\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "discovers_dockerfile_at_root",
            len(discovered) == 1 and "Dockerfile" in discovered,
            f"Got: {discovered}"
        )

    # Test 2: Discovers Dockerfile in subdirectory
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        docker_dir = workspace / "docker"
        docker_dir.mkdir()
        (docker_dir / "Dockerfile").write_text("FROM node:18\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "discovers_dockerfile_in_subdirectory",
            len(discovered) == 1 and ("docker/Dockerfile" in discovered or "docker\\Dockerfile" in discovered),
            f"Got: {discovered}"
        )

    # Test 3: Discovers Dockerfile with suffix
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile.prod").write_text("FROM python:3.11\n")
        (workspace / "Dockerfile.dev").write_text("FROM python:3.11-slim\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "discovers_dockerfile_with_suffix",
            len(discovered) == 2 and "Dockerfile.prod" in discovered and "Dockerfile.dev" in discovered,
            f"Got: {discovered}"
        )

    # Test 4: Discovers *.dockerfile pattern
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "app.dockerfile").write_text("FROM golang:1.21\n")
        (workspace / "backend.dockerfile").write_text("FROM rust:1.70\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "discovers_dockerfile_extension",
            len(discovered) == 2 and "app.dockerfile" in discovered and "backend.dockerfile" in discovered,
            f"Got: {discovered}"
        )

    # Test 5: Excludes node_modules
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM node:18\n")
        node_modules = workspace / "node_modules" / "some-package"
        node_modules.mkdir(parents=True)
        (node_modules / "Dockerfile").write_text("FROM alpine\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "excludes_node_modules",
            len(discovered) == 1 and not any("node_modules" in d for d in discovered),
            f"Got: {discovered}"
        )

    # Test 6: Excludes vendor directory
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM golang:1.21\n")
        vendor = workspace / "vendor" / "github.com" / "some-dep"
        vendor.mkdir(parents=True)
        (vendor / "Dockerfile").write_text("FROM alpine\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "excludes_vendor_directory",
            len(discovered) == 1 and not any("vendor" in d for d in discovered),
            f"Got: {discovered}"
        )

    # Test 7: Excludes test directories
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM python:3.11\n")
        for test_dir in ["test", "tests", "testing", "__tests__"]:
            test_path = workspace / test_dir
            test_path.mkdir(exist_ok=True)
            (test_path / "Dockerfile").write_text("FROM alpine\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "excludes_test_directories",
            len(discovered) == 1 and "Dockerfile" in discovered,
            f"Got: {discovered}"
        )

    # Test 8: Excludes fixture directories
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM python:3.11\n")
        for fixture_dir in ["fixture", "fixtures", "testdata"]:
            fixture_path = workspace / fixture_dir
            fixture_path.mkdir(exist_ok=True)
            (fixture_path / "Dockerfile").write_text("FROM alpine\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "excludes_fixture_directories",
            len(discovered) == 1 and "Dockerfile" in discovered,
            f"Got: {discovered}"
        )

    # Test 9: Excludes example directories
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM python:3.11\n")
        for example_dir in ["example", "examples", "sample", "samples"]:
            example_path = workspace / example_dir
            example_path.mkdir(exist_ok=True)
            (example_path / "Dockerfile").write_text("FROM alpine\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "excludes_example_directories",
            len(discovered) == 1 and "Dockerfile" in discovered,
            f"Got: {discovered}"
        )

    # Test 10: Excludes build directories
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM node:18\n")
        for build_dir in ["dist", "build", "out", "target"]:
            build_path = workspace / build_dir
            build_path.mkdir(exist_ok=True)
            (build_path / "Dockerfile").write_text("FROM alpine\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "excludes_build_directories",
            len(discovered) == 1 and "Dockerfile" in discovered,
            f"Got: {discovered}"
        )

    # Test 11: Excludes app_tests directory
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM python:3.11\n")
        app_tests = workspace / "app_tests" / "NodeGoat"
        app_tests.mkdir(parents=True)
        (app_tests / "Dockerfile").write_text("FROM node:18\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "excludes_app_tests_directory",
            len(discovered) == 1 and not any("app_tests" in d for d in discovered),
            f"Got: {discovered}"
        )

    # Test 12: Discovers multiple Dockerfiles
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM python:3.11\n")
        docker_dir = workspace / "docker"
        docker_dir.mkdir()
        (docker_dir / "Dockerfile.prod").write_text("FROM python:3.11\n")
        (docker_dir / "Dockerfile.dev").write_text("FROM python:3.11-slim\n")
        services_dir = workspace / "services" / "api"
        services_dir.mkdir(parents=True)
        (services_dir / "Dockerfile").write_text("FROM node:18\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "discovers_multiple_dockerfiles",
            len(discovered) == 4,
            f"Expected 4, got {len(discovered)}: {discovered}"
        )

    # Test 13: Empty workspace returns empty list
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        discovered = discover_dockerfiles(workspace)
        results.add(
            "empty_workspace_returns_empty_list",
            discovered == [],
            f"Got: {discovered}"
        )

    # Test 14: No Dockerfiles returns empty list
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "README.md").write_text("# Test\n")
        (workspace / "main.py").write_text("print('hello')\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "no_dockerfiles_returns_empty_list",
            discovered == [],
            f"Got: {discovered}"
        )

    # Test 15: Case insensitive exclusions
    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        (workspace / "Dockerfile").write_text("FROM python:3.11\n")
        for dir_name in ["Node_Modules", "VENDOR", "Tests"]:
            dir_path = workspace / dir_name
            dir_path.mkdir(exist_ok=True)
            (dir_path / "Dockerfile").write_text("FROM alpine\n")
        discovered = discover_dockerfiles(workspace)
        results.add(
            "case_insensitive_exclusions",
            len(discovered) == 1 and "Dockerfile" in discovered,
            f"Got: {discovered}"
        )

    return results


if __name__ == "__main__":
    print("Running Dockerfile auto-discovery tests...\n")
    results = run_tests()
    print(results.summary())
    sys.exit(0 if results.failed == 0 else 1)
