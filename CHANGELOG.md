# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added
- `--version` CLI flag. (CE-445)
- GitHub Action inputs `verbose`, `console_tabular_enabled` and
  `console_json_enabled`, delivered as `INPUT_VERBOSE`,
  `INPUT_CONSOLE_TABULAR_ENABLED` and `INPUT_CONSOLE_JSON_ENABLED` and honored
  from the environment the same way as the matching CLI flags. (CE-445)
- GitHub Action inputs `jira_url` and `jira_project`, matching the names used in
  the documentation; `server` and `project` remain as aliases. Also added
  `ms_sentinel_shared_key` (alias of `ms_sentinel_key`),
  `opengrep_notification_method` and `trufflehog_notification_method`
  (`notification_method` remains as an alias). (CE-445)
- `docs/parameters.md` gains a **Name Mapping** section listing every setting as
  CLI flag, GitHub Action input, environment variable and JSON key, generated
  from `connectors.yaml`, `notifications.yaml` and `action.yml`. A new test
  keeps `action.yml` and the parameter declarations in step. (CE-445)
- `scripts/check_release_docs.py` now also checks that action references use an
  exact release tag and that the bundled scanner versions quoted in the guides
  match the Dockerfile pins; `--write` updates both. (CE-445)
- Documentation for the `-heavy` image variant and for when the standard image
  is the right choice. (CE-445)

### Fixed
- The Sentinel and Sumo Logic notifiers now read `ms_sentinel_workspace_id`,
  `ms_sentinel_key` and `sumologic_endpoint` from CLI flags, action inputs and
  dashboard configuration, in addition to the `MS_SENTINEL_*` and
  `SUMO_LOGIC_HTTP_SOURCE_URL` environment variables. (CE-445)
- Documentation consistency pass across the GitHub Action, Docker and local
  installation guides (CE-445). CLI examples use the flag names that
  `socket-basics --help` prints. Docker examples keep the facts file inside the
  workspace so the dashboard upload succeeds, and show the environment variables
  needed for PR comments outside GitHub Actions. The GitHub Action guide reflects
  the bundled Trivy scanner, lists only declared inputs, and passes discovered
  Dockerfiles through in the auto-discovery example. JSON configuration examples
  use the keys the loader reads, the S3 variable names and `--config` precedence
  match the code, GitLab and Jenkins examples override the image entrypoint,
  pre-commit hook examples use the published image name, and the installation
  guide states the Python 3.10 requirement and the npm install path for the
  Socket CLI. New guidance covers large repositories and facts-file size.

## [3.1.0] - 2026-09-02

### Added
- `pr_comment_enabled` (default `true`): set to `false` to run scans without
  posting or updating the pull request comment. Findings still reach the Socket
  dashboard, since the facts upload runs before any notifier. (#97)
- `pr_comment_collapse_all` (default `false`): starts the collapsible OpenGrep
  (SAST) and Socket Tier 1 sections collapsed, including critical findings.
  Flat-table outputs (TruffleHog, Trivy Dockerfile) are unaffected. (#97)
- Negative `--no-*` forms for every default-true boolean CLI flag, e.g.
  `--no-pr-comment`. (#97)
- The resolved `changed_files` scope is logged on every scoped run — file count
  at INFO, full list at DEBUG — so an empty diff and a failed lookup are
  distinguishable in run logs. (#105)
- `scan_all` is now a declared action input, and doubles as the fail-open escape
  hatch for `changed_files`: when the scope cannot be resolved, widen to a
  full-repo scan with a warning instead of failing. Every enabled scanner widens
  consistently on that path. (#98, #105)

### Changed
- **Behavioral:** a `changed_files` scope that cannot be resolved (unreadable
  repository, missing base ref, shallow checkout with no base) now **fails the
  run** with a configuration error instead of scanning. Previously this exited
  green having scanned nothing. Pipelines with a broken diff-only setup will
  start failing on the first run after upgrading — read the error, which names
  the underlying git problem. Set `scan_all` to widen instead of failing.
  (#98, #105)
- A successfully resolved `changed_files` scope is now authoritative over
  `scan_all`, which previously overrode it. `scan_all` applies only on the
  failure path. A genuinely empty diff (e.g. a delete-only PR) still skips the
  scoped scanners. (#98)
- Socket toolchain refresh: Socket npm CLI 1.1.154 → 1.1.165 in every image,
  and Socket Python CLI 2.6.3 → 2.7.0 in the heavy and app-tests images. The
  socketdev Python SDK is already current at 3.5.0.
- Notifier parameters from `notifications.yaml` now take CLI overrides through
  the same path as connector parameters, fixing flags that parsed but never
  reached the effective config. Absent boolean flags resolve to "unset" rather
  than `false`, so CLI defaults no longer clobber environment, JSON, or
  dashboard config. (#97)

### Fixed
- `changed_files` diff-only mode resolved to zero files on every run of the
  pre-built Docker action, so scans exited green having scanned nothing: the
  container runs as root over a runner-owned checkout, and git refuses to read a
  repository it does not own. Git subprocesses now mark the workspace
  `safe.directory` via command-scope `GIT_CONFIG_*` entries, and any
  caller-supplied `GIT_CONFIG_*` entries are preserved. The same mismatch broke
  git-based repository, branch, and commit discovery in local Docker runs. (#105)
- `changed_files` was only resolved for CLI-built configs, so environment, JSON,
  and dashboard configs silently scanned the whole repository, and a literal
  `"auto"` was iterated character by character into an empty scope. Every config
  source now runs through one resolver. (#98)
- Pull request base detection falls back to `pull_request.base.sha`/`.ref` from
  the event payload when `GITHUB_BASE_REF` is unset, covering
  `pull_request_target`, `pull_request_review` and `pull_request_review_comment`.
  `issue_comment` carries no usable base and now warns to pass `GITHUB_BASE_REF`
  from the workflow. (#98)
- TruffleHog and Trivy no longer substitute their own staged-file scope when an
  explicit `changed_files` request is in effect. Trivy's Dockerfile scan skips
  when no Dockerfile changed, and TruffleHog drops changed paths that no longer
  exist on disk. (#98)

### Internal
- core-tool-watch reconciles one canonical `core-tool-drift` issue on `main`
  pushes, tracks the Socket Python and npm CLIs plus `Dockerfile.heavy`, and
  reads Trivy releases from `ghcr.io/socketdev/trivy`. The npm `socket` CLI is
  pinned in every image, and Docker publish no longer authors a GitHub
  Release. (#104)
- Release prep keeps action and image references in README and `docs/**` in sync
  with the release version; 73 stale `2.0.3` references normalized. (#106)
- Dependency updates: pyyaml (#107), docker/setup-buildx-action (#108).
- app-tests image refreshes `socketsecurity` index metadata on install, so a
  stale cached index cannot make a freshly published pin look nonexistent.

## [3.0.0] - 2026-08-06

Major release: Trivy-backed scanning returns, now built and published through
Socket's own supply chain.

### Added
- Container image and Dockerfile scanning (Trivy) restored in the pre-built
  GitHub Action and Docker images. Trivy now comes from a **Socket-built
  distribution** — rebuilt from unmodified upstream source (v0.73.0) by
  Socket's own release pipeline and pinned by digest in the Dockerfiles
  (`TRIVY_IMAGE` build arg; overridable for builds without registry access).
- `latest` and `latest-heavy` floating Docker tag aliases. Exact version tags
  remain immutable registry-side; pin an exact version or digest for
  reproducible pipelines.
- End-to-end integration test for the Trivy connector (fixture Dockerfile scan
  through `--dockerfiles`), plus smoke-test assertions that the bundled trivy
  matches the pinned version and can execute the connector's scan path.

### Changed
- **Behavioral (the reason this is a major):** Trivy-backed scanning was
  intentionally disabled in the 2.x pre-built images following the March 2026
  upstream Trivy supply-chain incident, and documented as such throughout the
  project. With this release it is deliberately re-enabled: configurations
  that set Trivy parameters (`--images`, `--dockerfiles`,
  `trivy_vuln_enabled`, …) will begin producing container/Dockerfile findings
  again, so pipelines that gate on findings should expect new results on the
  first run after upgrading.
- OSS toolchain refresh: TruffleHog 3.96.0, OpenGrep v1.26.0 (SAST rule
  updates may shift findings), uv 0.12.1, gosec v2.28.0, Go 1.26.5
  (app-tests), Socket CLI 2.6.3 (heavy image), and the socketdev Python SDK to
  3.5.0 (typed fail-closed batch purl parameters; adopted by core-tool-watch in
  a follow-up). Runtime bases (`python:3.12`,
  `node:22`) are unchanged.
- Docker Hub publish credentials are now scoped to the `publish` GitHub
  environment (deployment restricted to `main` and `v*` tags) instead of
  repo-level secrets.
- Manual re-publish (`workflow_dispatch`) is recovery-only: re-pushing an
  already-published version tag is rejected by the registry's immutable-tag
  rule.
- Dependabot no longer tracks the trivy base image; Trivy updates flow through
  Socket's release process, never independent bumps.
- CI: GitHub Actions dependency updates (#95, #96).

### Fixed
- The app-tests image had been unbuildable since the repository layout
  migration (stale source references, wrong build context, dereferenced npm
  symlinks, corrupt `uv.lock`) — repaired and building in CI again.
- Documentation: removed the now-outdated "temporarily ships without Trivy"
  notices repo-wide (they described the intentional 2.x posture); APT install
  instructions now use upstream's `generic` distribution (required since
  Trivy v0.72.0); warnings against Trivy 0.69.4–0.69.6 retained for native
  installs.

## [2.2.1] - 2026-07-30

### Fixed

- Fixed TruffleHog secret scanning when `trufflehog_exclude_dir` is configured:
  all entries now pass through one filter file and are honored for changed-file
  and explicit-file scans. Previously, configured values could be interpreted
  as filter filenames and fail or alter scans.
- Added glob-pattern support for exclusions such as
  `**/appsettings.*.json`, with matching anchored beneath the workspace and
  root-relative globs kept distinct from recursive `**` globs.
- Normalized exclusion entries before pattern generation so dot segments and
  repeated path separators behave consistently.
- Fixed exclusion matching when the configured workspace is the filesystem root.
- Normalized in-workspace TruffleHog finding paths relative to the workspace so
  host paths do not appear in facts and component identifiers remain stable
  across runs, working directories, and operating systems.

## [2.2.0] - 2026-07-29

### Added
- Publish multi-arch Docker images for `linux/amd64` and `linux/arm64`.
- Add a heavy image variant (`socket-basics:<version>-heavy` tag suffix) bundling
  Socket Basics with the pinned Python Socket CLI.

### Fixed
- Normalize manual Docker release tag inputs before checkout.
- core-tool-watch now opts into fail-closed Socket purl batch semantics
  (`poll` + `alerts`), so fresh-but-unanalyzed pins surface as labeled
  pending/not-found failures instead of silently dropped rows.

## [2.1.0] - 2026-07-22

### Added
- Diff-only scan scoping now applies to SAST/OpenGrep via `changed_files` and
  `scan_files`.
- Added GitHub Action inputs for `changed_files` and `scan_files`.

### Fixed
- Delete-only changed-file scans now skip instead of falling back to a full
  workspace scan.
- Updated parameter docs to reflect SAST/OpenGrep diff-only scoping.

## [2.0.3] - 2026-04-24

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🔧 Other Changes
* fix: Harden GHA workflows by @reberhardt7 in https://github.com/SocketDev/socket-basics/pull/58
* docs: cleanup docs guidance, additional workflow hardening by @lelia in https://github.com/SocketDev/socket-basics/pull/60
* fix(rules): improve precision of 4 high-FP dotnet opengrep rules by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/63

## New Contributors
* @reberhardt7 made their first contribution in https://github.com/SocketDev/socket-basics/pull/58

**Full Changelog**: https://github.com/SocketDev/socket-basics/compare/v2.0.2...v2.0.3

## [2.0.2] - 2026-03-23

<!-- Release notes generated using configuration in .github/release.yml at v2.0.2 -->

## What's Changed
### 📦 Dependencies
* Bump urllib3 from 2.5.0 to 2.6.3 by @dependabot[bot] in https://github.com/SocketDev/socket-basics/pull/21
### 🔧 Other Changes
* Removed qualifiers by @dacoburn in https://github.com/SocketDev/socket-basics/pull/1
* Doug/fix trivy socket results by @dacoburn in https://github.com/SocketDev/socket-basics/pull/2
* Fix action.yml configuration and add GitHub token by @dacoburn in https://github.com/SocketDev/socket-basics/pull/3
* Update action.yml description for clarity by @dacoburn in https://github.com/SocketDev/socket-basics/pull/4
* docs: fix link by @ahmadnassri in https://github.com/SocketDev/socket-basics/pull/5
* Added back in transitive logic and fixed format of integration messages by @dacoburn in https://github.com/SocketDev/socket-basics/pull/6
* Fixed documentation and version checks by @dacoburn in https://github.com/SocketDev/socket-basics/pull/7
* Added action inputs by @dacoburn in https://github.com/SocketDev/socket-basics/pull/8
* Updated examples with PR check and pinning to commit hashes by @dacoburn in https://github.com/SocketDev/socket-basics/pull/9
* Fixing issue of the git detection logic not using the workspace or GI… by @dacoburn in https://github.com/SocketDev/socket-basics/pull/10
* Doug/add node and socket back into container by @dacoburn in https://github.com/SocketDev/socket-basics/pull/11
* Fix for caching result by @dacoburn in https://github.com/SocketDev/socket-basics/pull/12
* Doug/improve default sast ruleset by @dacoburn in https://github.com/SocketDev/socket-basics/pull/13
* Fixed hard coded detection for golang by @dacoburn in https://github.com/SocketDev/socket-basics/pull/14
* Fixing regression in rule name by @dacoburn in https://github.com/SocketDev/socket-basics/pull/15
* Remove non-existent install options from local-installation.md by @graydonhope in https://github.com/SocketDev/socket-basics/pull/16
* Fix: Empty CLI string defaults no longer override env/API config by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/17
* Bump version to 1.0.26 by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/20
* docs: add Dockerfile auto-discovery workflow pattern by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/25
* Add scan_type parameter to full scan API calls by @mtorp in https://github.com/SocketDev/socket-basics/pull/24
* Upgrade 1.0.28 by @mtorp in https://github.com/SocketDev/socket-basics/pull/27
* feat: add SKIP_SOCKET_REACH and SKIP_SOCKET_SUBMISSION env vars for Node.js Socket CLI integration by @jdalton in https://github.com/SocketDev/socket-basics/pull/29
* Remove CODEOWNERS entry for @SocketDev/eng by @Raynos in https://github.com/SocketDev/socket-basics/pull/31
* Improve usefulness of generic output by @trevnorris in https://github.com/SocketDev/socket-basics/pull/28
* Pin trufflehog to known-good version tag by @lelia in https://github.com/SocketDev/socket-basics/pull/32
* Fix notifiers reading repo/branch from wrong source by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/30
* Fix: Jira dashboard config params not reaching notifier by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/22
* Update CODEOWNERS to reference GitHub Enterprise team name by @lelia in https://github.com/SocketDev/socket-basics/pull/33
* Enhance GitHub PR comment experience by @lelia in https://github.com/SocketDev/socket-basics/pull/26
* Fix `CODEOWNERS` syntax  by @lelia in https://github.com/SocketDev/socket-basics/pull/35
* Fix webhook notifier not reading URL from dashboard config by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/34
* Final `CODEOWNERS` update with new team name by @lelia in https://github.com/SocketDev/socket-basics/pull/36
* Bump Trivy from v0.67.2 to v0.69.2 by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/39
* Bump version to prep for release by @lelia in https://github.com/SocketDev/socket-basics/pull/40
* Pin `opengrep` version, add Docker smoketest by @lelia in https://github.com/SocketDev/socket-basics/pull/41
* Add GitHub workflow for `pytest` by @lelia in https://github.com/SocketDev/socket-basics/pull/42
* Fix Slack and MS Teams notifiers not reading URL from dashboard config by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/37
* Add structured findings to webhook payload by @dc-larsen in https://github.com/SocketDev/socket-basics/pull/38
* feat: 🐳 multi-stage Docker builds, immutable release pipeline, `CHANGELOG` automation by @lelia in https://github.com/SocketDev/socket-basics/pull/46
* fix(ci): add conventional commit prefixes to Dependabot config by @lelia in https://github.com/SocketDev/socket-basics/pull/53
* fix(ci): support breaking change indicator (!) in commit-lint pattern by @lelia in https://github.com/SocketDev/socket-basics/pull/54
* fix(ci): accept full tag name in workflow_dispatch, drop auto-v-prefix by @lelia in https://github.com/SocketDev/socket-basics/pull/55
* feat!: switch to pre-built GHCR images by @lelia in https://github.com/SocketDev/socket-basics/pull/48
* fix: remove trivy from Docker build while assessing compromise impact by @dacoburn in https://github.com/SocketDev/socket-basics/pull/56
* chore: fix release and updater script by @lelia in https://github.com/SocketDev/socket-basics/pull/57

## New Contributors
* @dacoburn made their first contribution in https://github.com/SocketDev/socket-basics/pull/1
* @ahmadnassri made their first contribution in https://github.com/SocketDev/socket-basics/pull/5
* @graydonhope made their first contribution in https://github.com/SocketDev/socket-basics/pull/16
* @dc-larsen made their first contribution in https://github.com/SocketDev/socket-basics/pull/17
* @mtorp made their first contribution in https://github.com/SocketDev/socket-basics/pull/24
* @jdalton made their first contribution in https://github.com/SocketDev/socket-basics/pull/29
* @Raynos made their first contribution in https://github.com/SocketDev/socket-basics/pull/31
* @dependabot[bot] made their first contribution in https://github.com/SocketDev/socket-basics/pull/21
* @trevnorris made their first contribution in https://github.com/SocketDev/socket-basics/pull/28
* @lelia made their first contribution in https://github.com/SocketDev/socket-basics/pull/32

**Full Changelog**: https://github.com/SocketDev/socket-basics/commits/v2.0.2
