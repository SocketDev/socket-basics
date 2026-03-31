<!-- PR TITLE: use Conventional Commits format — the commit-lint CI check enforces this.
     type(scope): Description    →    feat(docker): Add versioned Node stage
     Valid types: feat · fix · docs · chore · ci · refactor · test · perf · revert
     Breaking change: add ! after type  →  feat!: Switch to pre-built images -->

## Summary

<!-- What does this PR do? Why? -->

## Changes

<!-- Bullet points are fine. Link to relevant issues/tickets if applicable. -->

## Testing

<!-- How was this tested? Local smoke test, CI, manual verification, etc. -->

---

### Release checklist (skip for non-release PRs)

<!-- Only fill this out if this PR is cutting a new release (e.g. v2.1.0). -->

- [ ] `pyproject.toml` `version:` field updated to new version
- [ ] `python3 scripts/sync_release_version.py --write` run after updating `pyproject.toml`
- [ ] `socket_basics/version.py` updated to new version
- [ ] `socket_basics/__init__.py` updated to the same version
- [ ] `action.yml` `image:` ref updated to `docker://ghcr.io/socketdev/socket-basics:<new-version>`
- [ ] `CHANGELOG.md` `[Unreleased]` section reviewed
