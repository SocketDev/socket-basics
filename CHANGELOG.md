# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Versioning note:** Releases through `1.1.3` used bare semver tags (e.g. `1.1.3`).
> Starting with `v2.0.0` the project uses a `v` prefix (e.g. `v2.0.0`). Floating major
> tags (`v2`) are intentionally not published — immutable version tags and SHA pinning
> are the recommended consumption pattern for a security tool.

---

## [Unreleased]

## [2.0.0] - 2026-03-20

<!-- Release notes generated using configuration in .github/release.yml at v2.0.0 -->

## What's Changed
### 🔧 Other Changes
* feat: 🐳 multi-stage Docker builds, immutable release pipeline, `CHANGELOG` automation by @lelia in https://github.com/SocketDev/socket-basics/pull/46
* fix(ci): add conventional commit prefixes to Dependabot config by @lelia in https://github.com/SocketDev/socket-basics/pull/53
* fix(ci): support breaking change indicator (!) in commit-lint pattern by @lelia in https://github.com/SocketDev/socket-basics/pull/54
* fix(ci): accept full tag name in workflow_dispatch, drop auto-v-prefix by @lelia in https://github.com/SocketDev/socket-basics/pull/55
* feat!: switch to pre-built GHCR images by @lelia in https://github.com/SocketDev/socket-basics/pull/48


**Full Changelog**: https://github.com/SocketDev/socket-basics/compare/1.1.3...v2.0.0
## [1.1.3] - 2026-03-03

### Added
- Smoke test Docker workflow with scheduled runs every 12 hours ([#41])
- `pytest` GitHub Actions workflow for Python unit tests ([#42])
- Structured findings added to webhook payload ([#38])

### Fixed
- Slack and MS Teams notifiers not reading URL from dashboard config ([#37])

[#37]: https://github.com/SocketDev/socket-basics/pull/37
[#38]: https://github.com/SocketDev/socket-basics/pull/38
[#41]: https://github.com/SocketDev/socket-basics/pull/41
[#42]: https://github.com/SocketDev/socket-basics/pull/42

## [1.1.2] - 2026-03-02

### Changed
- Bump Trivy from `v0.67.2` to `v0.69.2` ([#39])
- `CODEOWNERS` updated with new team name ([#36])

[#36]: https://github.com/SocketDev/socket-basics/pull/36
[#39]: https://github.com/SocketDev/socket-basics/pull/39

## [1.1.0] - 2026-02-20

### Fixed
- Jira dashboard config params not reaching notifier ([#22])
- Notifiers reading repo/branch from wrong source ([#30])
- GitHub PR comment enhancement and layout improvements ([#26])

### Changed
- `CODEOWNERS` updated to reference new GHEC team name ([#33])

[#22]: https://github.com/SocketDev/socket-basics/pull/22
[#26]: https://github.com/SocketDev/socket-basics/pull/26
[#30]: https://github.com/SocketDev/socket-basics/pull/30
[#33]: https://github.com/SocketDev/socket-basics/pull/33

## [1.0.29] - 2026-02-19

### Added
- `SKIP_SOCKET_SUBMISSION` and `SKIP_SOCKET_REACH` environment variables for Node.js
  Socket CLI integration ([#29])

### Changed
- Pin TruffleHog to known-good version tag ([#32])
- Enrich OpenGrep alerts with full vulnerability metadata and detailed reports ([#28])

[#28]: https://github.com/SocketDev/socket-basics/pull/28
[#29]: https://github.com/SocketDev/socket-basics/pull/29
[#32]: https://github.com/SocketDev/socket-basics/pull/32

## [1.0.28] - 2026-02-06

### Changed
- Dependency upgrades and internal maintenance ([#27])

[#27]: https://github.com/SocketDev/socket-basics/pull/27

## [1.0.27] - 2026-02-06

### Added
- Dockerfile auto-discovery workflow pattern documentation ([#25])
- `scan_type` parameter added to full scan API calls ([#24])

[#24]: https://github.com/SocketDev/socket-basics/pull/24
[#25]: https://github.com/SocketDev/socket-basics/pull/25

## [1.0.26] - 2026-01-20

### Fixed
- Empty CLI string defaults no longer override env/API config ([#17])

### Changed
- Bump `urllib3` from `2.5.0` to `2.6.3` ([#21])

[#17]: https://github.com/SocketDev/socket-basics/pull/17
[#21]: https://github.com/SocketDev/socket-basics/pull/21

## [1.0.25] - 2025-10-28

### Fixed
- Regression in rule name detection ([#15])

[#15]: https://github.com/SocketDev/socket-basics/pull/15

## [1.0.24] - 2025-10-28

### Fixed
- Hard-coded detection for Golang ([#14])

[#14]: https://github.com/SocketDev/socket-basics/pull/14

## [1.0.23] - 2025-10-28

### Changed
- Improve default SAST ruleset ([#13])

[#13]: https://github.com/SocketDev/socket-basics/pull/13

## [1.0.21] - 2025-10-24

### Fixed
- Caching result fix ([#12])

[#12]: https://github.com/SocketDev/socket-basics/pull/12

## [1.0.20] - 2025-10-24

### Fixed
- Restore Node.js and Socket CLI in container ([#11])

[#11]: https://github.com/SocketDev/socket-basics/pull/11

## [1.0.10] - 2025-10-22

### Changed
- Updated examples with PR check and commit hash pinning ([#9])

[#9]: https://github.com/SocketDev/socket-basics/pull/9

## [1.0.9] - 2025-10-22

### Added
- Action inputs for configuring scan behavior ([#8])

### Fixed
- Documentation and version check issues ([#7])

[#7]: https://github.com/SocketDev/socket-basics/pull/7
[#8]: https://github.com/SocketDev/socket-basics/pull/8

## [1.0.3] - 2025-10-21

### Added
- GitHub token support in `action.yml` ([#3])

### Fixed
- `action.yml` configuration issues ([#3])
- Documentation link ([#5])

[#3]: https://github.com/SocketDev/socket-basics/pull/3
[#5]: https://github.com/SocketDev/socket-basics/pull/5

## [1.0.2] - 2025-10-20

### Fixed
- Initial Trivy + Socket results integration fixes ([#2])

[#2]: https://github.com/SocketDev/socket-basics/pull/2

---

<!-- Comparison links — updated automatically by scripts/update_changelog.py on each release -->
[Unreleased]: https://github.com/SocketDev/socket-basics/compare/v2.0.0...HEAD
[2.0.0]:      https://github.com/SocketDev/socket-basics/compare/1.1.3...v2.0.0
[1.1.3]:      https://github.com/SocketDev/socket-basics/compare/1.1.2...1.1.3
[1.1.2]:      https://github.com/SocketDev/socket-basics/compare/1.1.0...1.1.2
[1.1.0]:      https://github.com/SocketDev/socket-basics/compare/1.0.29...1.1.0
[1.0.29]:     https://github.com/SocketDev/socket-basics/compare/1.0.28...1.0.29
[1.0.28]:     https://github.com/SocketDev/socket-basics/compare/1.0.27...1.0.28
[1.0.27]:     https://github.com/SocketDev/socket-basics/compare/1.0.26...1.0.27
[1.0.26]:     https://github.com/SocketDev/socket-basics/compare/1.0.25...1.0.26
[1.0.25]:     https://github.com/SocketDev/socket-basics/compare/1.0.24...1.0.25
[1.0.24]:     https://github.com/SocketDev/socket-basics/compare/1.0.23...1.0.24
[1.0.23]:     https://github.com/SocketDev/socket-basics/compare/1.0.21...1.0.23
[1.0.21]:     https://github.com/SocketDev/socket-basics/compare/1.0.20...1.0.21
[1.0.20]:     https://github.com/SocketDev/socket-basics/compare/1.0.10...1.0.20
[1.0.10]:     https://github.com/SocketDev/socket-basics/compare/1.0.9...1.0.10
[1.0.9]:      https://github.com/SocketDev/socket-basics/compare/1.0.3...1.0.9
[1.0.3]:      https://github.com/SocketDev/socket-basics/compare/1.0.2...1.0.3
[1.0.2]:      https://github.com/SocketDev/socket-basics/commits/1.0.2
