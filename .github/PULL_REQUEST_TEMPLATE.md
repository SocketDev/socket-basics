## Summary

<!-- What does this PR do? Why? -->

## Changes

<!-- Bullet points are fine. Link to relevant issues/tickets if applicable. -->

## Testing

<!-- How was this tested? Local smoke test, CI, manual verification, etc. -->

---

### Release checklist (skip for non-release PRs)

<!-- Only fill this out if this PR is cutting a new release (e.g. v2.1.0). -->

- [ ] `socket_basics/version.py` updated to new version
- [ ] `pyproject.toml` updated to match
- [ ] `action.yml` `image:` ref updated to `docker://ghcr.io/socketdev/socket-basics:<new-version>`
- [ ] `CHANGELOG.md` `[Unreleased]` section reviewed and accurate

> ⚠️ **After merging:** run `publish-docker.yml` via `workflow_dispatch` with the new version
> **before** creating the git tag. The image must exist in GHCR before the tag is pushed.
> See [Release workflow](../docs/github-action.md#release-workflow-publish--tag-never-tag--publish) for the full process.
