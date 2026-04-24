# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

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
