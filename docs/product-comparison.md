# Layout assumptions (this product)

This extract is for ServiceNow-style story monorepos. It is not a general-purpose folder scrubber with a separate public sibling at this time.

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
