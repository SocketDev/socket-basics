#!/usr/bin/env python3
"""
Setup script to install pre-commit hooks for version management.
"""
import pathlib
import subprocess
import sys

def setup_pre_commit_hook():
    """Set up the pre-commit hook for version checking."""
    git_hooks_dir = pathlib.Path(".git/hooks")
    pre_commit_hook = git_hooks_dir / "pre-commit"
    
    if not git_hooks_dir.exists():
        print("❌ .git/hooks directory not found. Are you in a git repository?")
        sys.exit(1)
    
    hook_content = '''#!/bin/bash
# Version check pre-commit hook
python3 .hooks/version-check.py
'''
    
    # Create or update the pre-commit hook
    if pre_commit_hook.exists():
        print("⚠️ Pre-commit hook already exists.")
        response = input("Do you want to overwrite it? (y/N): ")
        if response.lower() != 'y':
            print("❌ Aborted.")
            sys.exit(1)
    
    pre_commit_hook.write_text(hook_content)
    pre_commit_hook.chmod(0o755)
    
    print("✅ Pre-commit hook installed successfully!")
    print("Now version changes will be automatically checked on each commit.")
    print("")
    print("Usage:")
    print("  Normal commit: Will auto-bump patch version if unchanged")
    print("  Dev mode: python3 .hooks/version-check.py --dev")

def main():
    if "--install-hook" in sys.argv:
        setup_pre_commit_hook()
    else:
        print("Version management setup script")
        print("")
        print("Options:")
        print("  --install-hook    Install pre-commit hook for version checking")
        print("")
        print("Manual usage:")
        print("  python3 .hooks/version-check.py       # Check and auto-bump if needed")
        print("  python3 .hooks/version-check.py --dev # Use dev versioning")

if __name__ == "__main__":
    main()
