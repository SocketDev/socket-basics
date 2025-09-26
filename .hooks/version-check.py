#!/usr/bin/env python3
import subprocess
import pathlib
import re
import sys
import urllib.request
import json

VERSION_FILE = pathlib.Path("socket_basics/version.py")
PYPROJECT_FILE = pathlib.Path("pyproject.toml")

VERSION_PATTERN = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")
PYPROJECT_PATTERN = re.compile(r'^version\s*=\s*"([^"]+)"$', re.MULTILINE)
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
    previous_version = read_version_from_git("src/version.py")

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
