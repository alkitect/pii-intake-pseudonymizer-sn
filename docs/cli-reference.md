# CLI reference

Entry point: `pii-intake-pseudonymizer-sn` or `python scripts/anonymize_intake.py`.

Defaults: read `inbox/raw/`, write `inbox/clean/`. See [Repo layout](repo-layout.md).

## ServiceNow-specific flags

| Flag | Description |
|------|-------------|
| `--promote STORY-id` | On the **same write pass** as intake: copy remaining `inbox/clean/` → `src/stories/<STORY-id>/intake-clean/`, then clear staging and update manifest |
| _(default paths)_ | `inbox/raw` → `inbox/clean` when no paths given |

Story ID pattern: `STORY-\d+` or `STRY\d+` (case-insensitive). Generic equivalent: `--copy-to DEST` → `DEST/intake-clean/` — see [product comparison](product-comparison.md).

## Shared flags (summary)

| Category | Flags |
|----------|-------|
| Modes | `--dry-run`, `--summary`, `--per-file-summary`, `--fail-on-hits`, `--report`, `--in-place` |
| Detection | `--ner`, `--also-ip`, `--also-machines`, `--also-paths`, `--also-commands`, `--also-certificates`, **`--also-technical`**, `--also-nl-id`, `--also-p2`, `--harvest-names`, `--scrub-orgs` |
| Map | `--map`, `--map-migrate`, `--map-rollback`, `--map-prune-unused`, `--irreversible`, `--map-audit` |
| Layout | `--out`, `--force-path`, `--keep-raw`, `--keep-clean` |
| Config | `--allowlist`, `--org-list` |

> **`--report`** prints original PII. Human interactive use only — never in CI or shared logs.

Full flag descriptions and **What is replaced** table: [generic CLI reference](https://github.com/alkitect/pii-intake-pseudonymizer/blob/main/docs/cli-reference.md) (same engine; SN adds `--promote` and different defaults). Technical categories (`MACHINE_NNN`, `PATH_NNN`, `CMD_NNN`, `CERT_NNN`) require **`--also-technical`** or individual `--also-*` flags — default off.

## Gate vs intake

| Target | `--summary` | Write pass |
|--------|-------------|------------|
| `inbox/raw` | **Refused** | Yes (intake); add `--promote STORY-id` on same command |
| `src/stories/...` | Yes (commit gate) | Use deliberate `--in-place` only after dry-run |

## Examples

```bash
# Intake dry-run
pii-intake-pseudonymizer-sn inbox/raw --dry-run

# Intake + promote (key required)
pii-intake-pseudonymizer-sn inbox/raw --promote STORY-1000

# Infra-heavy log/PEM drops
pii-intake-pseudonymizer-sn inbox/raw --also-technical --promote STORY-1000

# Commit gate on docs
pii-intake-pseudonymizer-sn src/stories/STORY-1000/docs --summary
```
