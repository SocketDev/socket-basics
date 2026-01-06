"""Tests for Dockerfile auto-discovery functionality."""

import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest


class MockConfig:
    """Mock config object for testing."""

    def __init__(self, workspace: Path):
        self._workspace = workspace
        self._config = {}

    @property
    def workspace(self) -> Path:
        return self._workspace

    def get(self, key, default=None):
        return self._config.get(key, default)


class TestDockerfileDiscovery:
    """Test cases for Dockerfile auto-discovery."""

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        workspace = tempfile.mkdtemp()
        yield Path(workspace)
        shutil.rmtree(workspace, ignore_errors=True)

    @pytest.fixture
    def trivy_scanner(self, temp_workspace):
        """Create a TrivyScanner instance with mock config."""
        from socket_basics.core.connector.trivy.trivy import TrivyScanner

        config = MockConfig(temp_workspace)
        return TrivyScanner(config)

    def test_discovers_dockerfile_at_root(self, temp_workspace, trivy_scanner):
        """Test discovery of Dockerfile at workspace root."""
        dockerfile = temp_workspace / "Dockerfile"
        dockerfile.write_text("FROM python:3.11\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert "Dockerfile" in discovered

    def test_discovers_dockerfile_in_subdirectory(self, temp_workspace, trivy_scanner):
        """Test discovery of Dockerfile in subdirectory."""
        docker_dir = temp_workspace / "docker"
        docker_dir.mkdir()
        dockerfile = docker_dir / "Dockerfile"
        dockerfile.write_text("FROM node:18\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert "docker/Dockerfile" in discovered or "docker\\Dockerfile" in discovered

    def test_discovers_dockerfile_with_suffix(self, temp_workspace, trivy_scanner):
        """Test discovery of Dockerfile.prod, Dockerfile.dev patterns."""
        (temp_workspace / "Dockerfile.prod").write_text("FROM python:3.11\n")
        (temp_workspace / "Dockerfile.dev").write_text("FROM python:3.11-slim\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 2
        assert "Dockerfile.prod" in discovered
        assert "Dockerfile.dev" in discovered

    def test_discovers_dockerfile_extension(self, temp_workspace, trivy_scanner):
        """Test discovery of *.dockerfile pattern."""
        (temp_workspace / "app.dockerfile").write_text("FROM golang:1.21\n")
        (temp_workspace / "backend.dockerfile").write_text("FROM rust:1.70\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 2
        assert "app.dockerfile" in discovered
        assert "backend.dockerfile" in discovered

    def test_excludes_node_modules(self, temp_workspace, trivy_scanner):
        """Test that node_modules directory is excluded."""
        # Create Dockerfile at root (should be found)
        (temp_workspace / "Dockerfile").write_text("FROM node:18\n")

        # Create Dockerfile in node_modules (should be excluded)
        node_modules = temp_workspace / "node_modules" / "some-package"
        node_modules.mkdir(parents=True)
        (node_modules / "Dockerfile").write_text("FROM alpine\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert "Dockerfile" in discovered
        assert not any("node_modules" in d for d in discovered)

    def test_excludes_vendor_directory(self, temp_workspace, trivy_scanner):
        """Test that vendor directory is excluded."""
        (temp_workspace / "Dockerfile").write_text("FROM golang:1.21\n")

        vendor = temp_workspace / "vendor" / "github.com" / "some-dep"
        vendor.mkdir(parents=True)
        (vendor / "Dockerfile").write_text("FROM alpine\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert not any("vendor" in d for d in discovered)

    def test_excludes_test_directories(self, temp_workspace, trivy_scanner):
        """Test that test/tests/testing directories are excluded."""
        (temp_workspace / "Dockerfile").write_text("FROM python:3.11\n")

        for test_dir in ["test", "tests", "testing", "__tests__"]:
            test_path = temp_workspace / test_dir
            test_path.mkdir(exist_ok=True)
            (test_path / "Dockerfile").write_text("FROM alpine\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert "Dockerfile" in discovered

    def test_excludes_fixture_directories(self, temp_workspace, trivy_scanner):
        """Test that fixture/fixtures directories are excluded."""
        (temp_workspace / "Dockerfile").write_text("FROM python:3.11\n")

        for fixture_dir in ["fixture", "fixtures", "testdata"]:
            fixture_path = temp_workspace / fixture_dir
            fixture_path.mkdir(exist_ok=True)
            (fixture_path / "Dockerfile").write_text("FROM alpine\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert "Dockerfile" in discovered

    def test_excludes_example_directories(self, temp_workspace, trivy_scanner):
        """Test that example/examples directories are excluded."""
        (temp_workspace / "Dockerfile").write_text("FROM python:3.11\n")

        for example_dir in ["example", "examples", "sample", "samples"]:
            example_path = temp_workspace / example_dir
            example_path.mkdir(exist_ok=True)
            (example_path / "Dockerfile").write_text("FROM alpine\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert "Dockerfile" in discovered

    def test_excludes_build_directories(self, temp_workspace, trivy_scanner):
        """Test that build/dist/out directories are excluded."""
        (temp_workspace / "Dockerfile").write_text("FROM node:18\n")

        for build_dir in ["dist", "build", "out", "target"]:
            build_path = temp_workspace / build_dir
            build_path.mkdir(exist_ok=True)
            (build_path / "Dockerfile").write_text("FROM alpine\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert "Dockerfile" in discovered

    def test_excludes_app_tests_directory(self, temp_workspace, trivy_scanner):
        """Test that app_tests directory (Socket Basics fixtures) is excluded."""
        (temp_workspace / "Dockerfile").write_text("FROM python:3.11\n")

        app_tests = temp_workspace / "app_tests" / "NodeGoat"
        app_tests.mkdir(parents=True)
        (app_tests / "Dockerfile").write_text("FROM node:18\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert not any("app_tests" in d for d in discovered)

    def test_discovers_multiple_dockerfiles(self, temp_workspace, trivy_scanner):
        """Test discovery of multiple Dockerfiles in different locations."""
        # Root Dockerfile
        (temp_workspace / "Dockerfile").write_text("FROM python:3.11\n")

        # Docker directory
        docker_dir = temp_workspace / "docker"
        docker_dir.mkdir()
        (docker_dir / "Dockerfile.prod").write_text("FROM python:3.11\n")
        (docker_dir / "Dockerfile.dev").write_text("FROM python:3.11-slim\n")

        # Services directory
        services_dir = temp_workspace / "services" / "api"
        services_dir.mkdir(parents=True)
        (services_dir / "Dockerfile").write_text("FROM node:18\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 4

    def test_empty_workspace_returns_empty_list(self, temp_workspace, trivy_scanner):
        """Test that empty workspace returns empty list."""
        discovered = trivy_scanner._discover_dockerfiles()
        assert discovered == []

    def test_no_dockerfiles_returns_empty_list(self, temp_workspace, trivy_scanner):
        """Test workspace with files but no Dockerfiles returns empty list."""
        (temp_workspace / "README.md").write_text("# Test\n")
        (temp_workspace / "main.py").write_text("print('hello')\n")

        discovered = trivy_scanner._discover_dockerfiles()
        assert discovered == []

    def test_case_insensitive_exclusions(self, temp_workspace, trivy_scanner):
        """Test that exclusions work case-insensitively."""
        (temp_workspace / "Dockerfile").write_text("FROM python:3.11\n")

        # Create with various cases
        for dir_name in ["Node_Modules", "VENDOR", "Tests"]:
            dir_path = temp_workspace / dir_name
            dir_path.mkdir(exist_ok=True)
            (dir_path / "Dockerfile").write_text("FROM alpine\n")

        discovered = trivy_scanner._discover_dockerfiles()

        assert len(discovered) == 1
        assert "Dockerfile" in discovered


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
