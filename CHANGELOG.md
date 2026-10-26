# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-10-26

### Security

- Commit gate refuses force-staged quarantine payloads under `inbox/raw`, `inbox/instance-upload`, and `inbox/clean` (empty `.gitkeep` only)
- Gitignore keeps only empty `.gitkeep` under quarantine dirs plus root `inbox/README.md` (no README imposters)
- `ci-check` must-not-ship: hooks, map/key globs, quarantine payloads, `ESM-*` in tracked text, index scan; runs pytest

### Changed

- `--promote` / `--promote-to` **merge** checksum-verified staging by default (siblings preserved)
- Opt-in `--replace-target` for destructive full replace
- Promote fails when `skipped_binary > 0` unless `--allow-skipped-binary`
- Manifest missing/stale fails closed before promote

### Added

- Gold fixtures `LOCK.txt` + `sn_display_value.xml`
- `docs/WORKDIR_SYNC.md` provenance pointer

## [0.1.0] - 2026-08-19

### Added

- Opt-in technical scrub: `--also-machines`, `--also-paths`, `--also-commands`, `--also-certificates`, and **`--also-technical`** bundle (default off; shared engine with generic product)
- Documentation set: getting started, repo layout, commit gate, architecture (C4), ADRs, CLI reference, security
- `scripts/intake_manifest.py` for clean-output checksum registry
- `SECURITY.md`, product comparison, examples index
- Public extract renamed from `pii-intake-scrubber-servicenow` to `pii-intake-pseudonymizer-sn`
- ServiceNow story-monorepo layout: `inbox/raw` → `inbox/clean`, `--promote STORY-id`
- Commit detect-only gate on `src/stories/` (`--summary`; refused on `inbox/raw`)
- Shared pseudonymizer engine with generic [pii-intake-pseudonymizer](https://github.com/alkitect/pii-intake-pseudonymizer)
- Install/verify wrappers and `ci-check.sh` release gate

[0.2.0]: https://github.com/alkitect/pii-intake-pseudonymizer-sn/releases/tag/v0.2.0
[0.1.0]: https://github.com/alkitect/pii-intake-pseudonymizer-sn/releases/tag/v0.1.0
