# Releasing socket-basics

This document is for **maintainers** cutting a new release.
For usage documentation, see [github-action.md](github-action.md).

## Release workflow: publish → tag (never tag → publish)

Pushing a tag before the image is published creates a race condition where
`uses: SocketDev/socket-basics@vX.Y.Z` resolves an `action.yml` that references
a GHCR image that doesn't exist yet. Follow this order every time:

```
1. Open a release PR using the [PR template](../.github/PULL_REQUEST_TEMPLATE.md) — the release checklist is pre-filled
2. Merge release PR to main (version bump + action.yml image ref update)
3. workflow_dispatch → publish-docker.yml with the new version
   (builds, integration-tests, and pushes images to GHCR + Docker Hub)
4. Create git tag (e.g. v2.1.0) — image already exists, zero race condition
```

The release PR **must** include all three of these changes together:

- [ ] [`socket_basics/version.py`](../socket_basics/version.py) updated to new version
- [ ] [`pyproject.toml`](../pyproject.toml) `version:` field updated to match
- [ ] [`action.yml`](../action.yml) `image:` ref updated to `docker://ghcr.io/socketdev/socket-basics:<new-version>`

> 💡 [`python-tests.yml`](../.github/workflows/python-tests.yml) CI will fail if `action.yml` and `pyproject.toml` versions diverge,
> so a mismatch cannot be merged accidentally.

## `CHANGELOG` and release notes

The changelog process has two phases:

**Before the release PR (ongoing, optional but recommended):**
As PRs land, you can manually add notes to the `[Unreleased]` section of
[`CHANGELOG.md`](../CHANGELOG.md). Think of it as a running human-readable
summary of what's accumulating. The PR template checklist asks you to review
this section before merging the release PR.

**After the tag is pushed (fully automated):**
[`scripts/update_changelog.py`](../scripts/update_changelog.py) runs as part of
the publish pipeline and:

1. Fetches the GitHub Release's auto-generated notes (built from merged PR titles,
   categorised by PR labels per [`.github/release.yml`](../.github/release.yml))
2. **Replaces** the `[Unreleased]` section content with those generated notes
3. Inserts a new `## [VERSION] - DATE` section
4. Updates the comparison links at the bottom
5. Commits the result back to `main` via `socket-release-bot`

> ⚠️ **The auto-generated notes replace whatever was in `[Unreleased]`** — they are
> not merged with it. If you want specific wording in the CHANGELOG, the best lever
> is the PR title and description, since that's what GitHub's note generator pulls from.
> The `[Unreleased]` section is useful as a preview during development but should be
> treated as disposable, not authoritative.

## After the tag is pushed

[`publish-docker.yml`](../.github/workflows/publish-docker.yml) runs automatically and:

1. Builds and tests the Docker image
2. Pushes to `ghcr.io/socketdev/socket-basics:<version>` and `socketdev/socket-basics:<version>`
3. Creates the GitHub Release with auto-generated notes (categorised by PR labels)
4. Commits an updated [`CHANGELOG.md`](../CHANGELOG.md) back to `main` via `socket-release-bot`
5. Force-updates the floating `v2` major version tag

## Making GHCR packages public

After the **first** publish, a GitHub org owner needs to flip the package visibility
to public: **Package settings → Change visibility → Public**. One-time step.
