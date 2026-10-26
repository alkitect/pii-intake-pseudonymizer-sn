# Inbox — PII quarantine

Local drop zone for personal-data exports before agents or story docs see them.
One README for the whole tree; subdirs only keep `.gitkeep`.

See [Getting started](../docs/getting-started.md) and [Security](../docs/security.md).

## Layout

| Path | Role |
|------|------|
| `raw/` | Unscrubbed drops (Jira, email, CSV/XML, …) |
| `clean/` | This-run scrub staging (checksum-gated) |
| `instance-upload/` | Combined Import XML bundles (**not** scrubbed) |

Payloads under `raw/` and `instance-upload/` are gitignored.
Only empty `.gitkeep` keepers under those dirs are exempt.
**This file** (`inbox/README.md`) is the only docs path — a `README.md` dropped
under `raw/` or `instance-upload/` is treated as a payload, not documentation.

## Flow

1. Drop text exports in `raw/`.
2. Preview: `pii-intake-pseudonymizer-sn inbox/raw --dry-run`
3. Scrub (key required): `pii-intake-pseudonymizer-sn inbox/raw`
4. Promote (optional): `pii-intake-pseudonymizer-sn inbox/raw --promote STORY-1000`
   - Merge verified staging into `src/stories/STORY-1000/intake-clean/` (siblings kept)
   - Use `--replace-target` to wipe the target first
   - Promote refuses skipped Excel/PDF unless `--allow-skipped-binary`

## Map

- Pseudonym map: `.local/pii-map.json` (local only — never commit)
- Functional addresses: `config/pii-allowlist.txt`
