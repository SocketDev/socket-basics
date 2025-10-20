#!/usr/bin/env python3
"""
Version management script for Socket Basics.

This script:
1. Ensures version.py and pyproject.toml are in sync
2. Auto-bumps version on commits if unchanged
3. Automatically updates version references in:
   - README.md (GitHub Action versions and Docker build tags)
   - docs/github-action.md (all action version references)
   - docs/pre-commit-hook.md (Docker build tags)

Pattern matching:
- GitHub Actions: SocketDev/socket-basics@vX.X.X -> @vNEW_VERSION
- Docker builds: docker build -t IMAGE_NAME -> docker build -t IMAGE_NAME:NEW_VERSION

Usage:
- Normal commit: Will auto-bump patch version if unchanged
- Dev mode: python3 .hooks/version-check.py --dev
"""
import subprocess
import pathlib
import re
import sys
import urllib.request
import json

VERSION_FILE = pathlib.Path("socket_basics/version.py")
PYPROJECT_FILE = pathlib.Path("pyproject.toml")
README_FILES = [
    pathlib.Path("README.md"),
    pathlib.Path("docs/github-action.md"),
    pathlib.Path("docs/pre-commit-hook.md"),
]

VERSION_PATTERN = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")
PYPROJECT_PATTERN = re.compile(r'^version\s*=\s*"([^"]+)"$', re.MULTILINE)
# Pattern to match SocketDev/socket-basics@vX.X.X or @vX.X.X
ACTION_VERSION_PATTERN = re.compile(r'(SocketDev/socket-basics|socket-basics)@v\d+\.\d+\.\d+')
# Pattern to match docker build with version tag
DOCKER_BUILD_PATTERN = re.compile(r'docker build -t (socketdev/socket-basics|socket-basics)(?::\d+\.\d+\.\d+)?')
# Update this URL to match your actual PyPI package if you publish it
PYPI_API = "https://pypi.org/pypi/security-wrapper/json"

def read_version_from_version_file(path: pathlib.Path) -> str:
    if not path.exists():
        print(f"❌ Version file {path} does not exist")
        sys.exit(1)
    content = path.read_text()
    match = VERSION_PATTERN.search(content)
    if not match:
        print(f"❌ Could not find __version__ in {path}")
        sys.exit(1)
    return match.group(1)

def read_version_from_pyproject(path: pathlib.Path) -> str:
    if not path.exists():
        print(f"❌ pyproject.toml file {path} does not exist")
        sys.exit(1)
    content = path.read_text()
    match = PYPROJECT_PATTERN.search(content)
    if not match:
        print(f"❌ Could not find version in {path}")
        sys.exit(1)
    return match.group(1)

def read_version_from_git(path: str) -> str:
    try:
        output = subprocess.check_output(["git", "show", f"HEAD:{path}"], text=True)
        match = VERSION_PATTERN.search(output)
        if not match:
            return None
        return match.group(1)
    except subprocess.CalledProcessError:
        return None

def bump_patch_version(version: str) -> str:
    if ".dev" in version:
        version = version.split(".dev")[0]
    parts = version.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)

def fetch_existing_versions() -> set:
    try:
        with urllib.request.urlopen(PYPI_API) as response:
            data = json.load(response)
            return set(data.get("releases", {}).keys())
    except Exception as e:
        print(f"⚠️ Warning: Failed to fetch existing versions from PyPI: {e}")
        return set()

def find_next_available_dev_version(base_version: str) -> str:
    existing_versions = fetch_existing_versions()
    for i in range(1, 100):
        candidate = f"{base_version}.dev{i}"
        if candidate not in existing_versions:
            return candidate
    print("❌ Could not find available .devN slot after 100 attempts.")
    sys.exit(1)

def update_readme_versions(version: str):
    """Update version references in README files"""
    for readme_file in README_FILES:
        if not readme_file.exists():
            print(f"⚠️ {readme_file} not found, skipping")
            continue
        
        content = readme_file.read_text()
        original_content = content
        
        # Update action version references (SocketDev/socket-basics@vX.X.X)
        content = ACTION_VERSION_PATTERN.sub(rf'\1@v{version}', content)
        
        # Update docker build commands to include version tag
        def docker_replacement(match):
            image_name = match.group(1)
            return f'docker build -t {image_name}:{version}'
        content = DOCKER_BUILD_PATTERN.sub(docker_replacement, content)
        
        if content != original_content:
            readme_file.write_text(content)
            print(f"✅ Updated version references in {readme_file}")
        else:
            print(f"ℹ️  No version updates needed in {readme_file}")

def inject_version(version: str):
    print(f"🔁 Updating version to: {version}")

    # Update version.py
    VERSION_FILE.write_text(f'__version__ = "{version}"\n')

    # Update pyproject.toml
    pyproject = PYPROJECT_FILE.read_text()
    if PYPROJECT_PATTERN.search(pyproject):
        new_pyproject = PYPROJECT_PATTERN.sub(f'version = "{version}"', pyproject)
        PYPROJECT_FILE.write_text(new_pyproject)
        print(f"✅ Updated {PYPROJECT_FILE}")
    else:
        print(f"⚠️ Could not find version field in {PYPROJECT_FILE}")
    
    # Update README files with version references
    update_readme_versions(version)

def check_version_sync():
    """Ensure version.py and pyproject.toml are in sync"""
    version_py = read_version_from_version_file(VERSION_FILE)
    version_toml = read_version_from_pyproject(PYPROJECT_FILE)
    
    if version_py != version_toml:
        print(f"❌ Version mismatch: {VERSION_FILE} has {version_py}, {PYPROJECT_FILE} has {version_toml}")
        print("🔁 Syncing versions...")
        inject_version(version_toml)  # Use pyproject.toml as source of truth
        return version_toml
    
    return version_py

def main():
    dev_mode = "--dev" in sys.argv
    
    # Ensure versions are synced
    current_version = check_version_sync()
    previous_version = read_version_from_git("socket_basics/version.py")

    print(f"Current: {current_version}, Previous: {previous_version}")

    if current_version == previous_version:
        if dev_mode:
            base_version = current_version.split(".dev")[0] if ".dev" in current_version else current_version
            new_version = find_next_available_dev_version(base_version)
            inject_version(new_version)
            print("⚠️ Version was unchanged — auto-bumped. Please git add + commit again.")
            sys.exit(0)
        else:
            new_version = bump_patch_version(current_version)
            inject_version(new_version)
            print("⚠️ Version was unchanged — auto-bumped. Please git add + commit again.")
            sys.exit(1)
    else:
        print("✅ Version already bumped — proceeding.")
        sys.exit(0)

if __name__ == "__main__":
    main()
