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

- [ ] `socket_basics/version.py` updated to new version
- [ ] `pyproject.toml` `version:` field updated to match
- [ ] `action.yml` `image:` ref updated to `docker://ghcr.io/socketdev/socket-basics:<new-version>` *(auto-updated by `publish-docker.yml` after v2.0.0; manual update required only for the initial v2.0.0 release)*
- [ ] `CHANGELOG.md` `[Unreleased]` section reviewed *(note: this content is replaced by auto-generated release notes when the tag fires — see [docs/releasing.md](../docs/releasing.md#changelog-and-release-notes))*

> See [docs/releasing.md](../docs/releasing.md) for the full release process.
