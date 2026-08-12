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

<!-- Only fill this out if this PR is cutting a new release (e.g. v3.1.0). -->

- [ ] `python3 scripts/prep_release.py --version <new-version>` completed successfully
- [ ] Release metadata and `uv.lock` are synchronized
- [ ] Current-release references in README and docs are synchronized
- [ ] `CHANGELOG.md` contains reviewed, human-authored notes for this version
- [ ] Release PR will be merged before its merge commit is tagged
