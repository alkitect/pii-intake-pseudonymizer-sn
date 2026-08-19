# Product comparison — generic vs ServiceNow

> **Maintainers:** edit the generic repo copy first; sync the table row to the SN repo before tagging.

| Topic | [pii-intake-pseudonymizer](https://github.com/alkitect/pii-intake-pseudonymizer) | [pii-intake-pseudonymizer-sn](https://github.com/alkitect/pii-intake-pseudonymizer-sn) |
|-------|---------------------|------------------------|
| Default I/O | `input/` → `output/` | `inbox/raw/` → `inbox/clean/` |
| Story layout | Optional (any paths) | `src/stories/<STORY-id>/` |
| `--summary` scope | Any path except `.local/` | **`src/stories/` only** — refused on `inbox/raw` |
| Post-write copy | `--copy-to DEST` → `DEST/intake-clean/` | `--promote STORY-id` → `src/stories/.../intake-clean/` |
| Intake manifest | None | `.local/intake-manifest.json` |
| Commit gate helper | Optional `pii_commit_gate.py` (needs `src/stories/`) | Same + [commit gate](commit-gate.md) docs |
| Cursor / editor hooks | Not shipped (CLI only) | Not shipped (CLI only) |
| Technical scrub flags | `--also-*` + **`--also-technical`** (shared engine, default off) | Same |

Pick **generic** for ad-hoc folders. Pick **SN** when your repo already uses inbox quarantine + story trees.
