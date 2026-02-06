Bump the project version. The bump type is: $ARGUMENTS (default to "patch" if empty or not one of: patch, minor, major).

Follow these steps exactly:

1. **Parse bump type**: Use "$ARGUMENTS". If blank or not one of `patch`, `minor`, `major`, default to `patch`.

2. **Read current version**: Read `pyproject.toml` and extract the current version from the `version = "X.Y.Z"` line.

3. **Compute new version**: Given current version `X.Y.Z`:
   - `patch` → `X.Y.(Z+1)`
   - `minor` → `X.(Y+1).0`
   - `major` → `(X+1).0.0`

4. **Update all version files**: Run the following Python command from the project root to invoke the existing hook logic, which updates `pyproject.toml`, `socket_basics/version.py`, and all doc files:
   ```
   python3 -c "import importlib.util; spec = importlib.util.spec_from_file_location('version_check', '.hooks/version-check.py'); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); mod.inject_version('NEW_VERSION')"
   ```
   Replace `NEW_VERSION` with the computed version string.

5. **Update `socket_basics/__init__.py`**: This file is NOT handled by the hook. Use the Edit tool to replace the old `__version__ = "OLD"` line with `__version__ = "NEW_VERSION"`.

6. **Regenerate lock file**: Run `uv lock` to update `uv.lock` with the new version.

7. **Verify**: Use grep to confirm no remaining references to the OLD version in these files:
   - `pyproject.toml`
   - `socket_basics/version.py`
   - `socket_basics/__init__.py`
   - `uv.lock`
   - `README.md`
   - `docs/github-action.md`
   - `docs/pre-commit-hook.md`

8. **Report**: Summarize what version was bumped (OLD → NEW) and list all files that were modified.

Do NOT commit the changes. Just make the edits and report.
