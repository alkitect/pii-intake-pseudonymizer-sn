# Layout assumptions (this product)

This extract is for scrubbing ServiceNow XML record exports (markdown/text beside them are fine too), usually inside a local tree with `inbox/raw` and optional `src/stories/<STORY-id>/`. It is not a separate public “generic folder” sibling at this time.

| Topic | This product |
|-------|--------------|
| Default I/O | `inbox/raw/` → `inbox/clean/` |
| Story layout | `src/stories/<STORY-id>/` |
| `--summary` scope | `src/stories/` only (refused on `inbox/raw`) |
| Post-write copy | `--promote STORY-id` → `src/stories/.../intake-clean/` |
| Intake manifest | `.local/intake-manifest.json` |
| Commit gate | `pii_commit_gate.py` + [commit gate](commit-gate.md) docs |
| Editor hooks | Not shipped (CLI only) |
| Technical scrub | `--also-*` + `--also-technical` (default off) |

If your tree has no `inbox/` or `src/stories/`, you can still pass explicit paths to the CLI, but promote and the commit-gate docs assume the story layout above.
