# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Documentation set: getting started, repo layout, commit gate, architecture (C4), ADRs, CLI reference, security
- `scripts/intake_manifest.py` for clean-output checksum registry
- `SECURITY.md`, product comparison, examples index
- Public extract renamed from `pii-intake-scrubber-servicenow` to `pii-intake-pseudonymizer-sn`

### Fixed

- Doc review: promote on same write pass, key path defaults, `blob/main` → `v0.1.0` links, troubleshooting table, ADR sync policy, ci-check doc file gate

## [0.1.0] - TBD

### Added

- ServiceNow story-monorepo layout: `inbox/raw` → `inbox/clean`, `--promote STORY-id`
- Commit detect-only gate on `src/stories/` (`--summary`; refused on `inbox/raw`)
- Shared pseudonymizer engine with generic [pii-intake-pseudonymizer](https://github.com/alkitect/pii-intake-pseudonymizer)
- Install/verify wrappers and `ci-check.sh` release gate

[Unreleased]: https://github.com/alkitect/pii-intake-pseudonymizer-sn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alkitect/pii-intake-pseudonymizer-sn/releases/tag/v0.1.0
