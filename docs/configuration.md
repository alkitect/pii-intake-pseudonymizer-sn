# Configuration

Same core settings as the [generic product](https://github.com/alkitect/pii-intake-pseudonymizer/blob/v0.1.0/docs/configuration.md), with ServiceNow layout defaults below.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `PII_MAP_KEY` | Raw Fernet key |
| `PII_MAP_KEY_FILE` | Path to key file (outside repo / sync root) |

Detect-only (`--summary` on `src/stories`) works without a key.

Platform defaults if unset:

- Windows: `%LOCALAPPDATA%/ServiceNow-PII/pii-map.key`
- Linux/macOS: `~/.config/servicenow-pii/pii-map.key`

Example paths like `$HOME/.config/pii-intake/pii-map.key` are fine if outside cloud sync.

## Config files (`config/`)

| File | Role |
|------|------|
| `pii-allowlist.txt` | Non-personal emails to preserve |
| `pii-org-scrub.txt` | Org/product names → `ORG_NNN` |
| `pii-person-fields.json` | ServiceNow/Jira field harvest rules |
| `pii-ner.json` | Presidio config when `--ner` is on |

## ServiceNow layout paths

| Path | Role |
|------|------|
| `inbox/raw/` | Default intake input |
| `inbox/clean/` | Default output staging |
| `src/stories/<STORY-id>/` | `--promote` destination root |
| `.local/pii-map.json` | Encrypted map |
| `.local/intake-manifest.json` | SHA-256 allow-list for promoted / clean outputs |

Override with explicit path arguments or `--out`. See [Repo layout](repo-layout.md).

## Intake manifest

After a successful write, `scripts/intake_manifest.py` records checksums of clean outputs. Downstream automation can verify files came from a successful pseudonymize run.

## Calibration

1. Customize allowlist/org list for your org.
2. Run `--summary` on a story subtree before changing production configs.
3. Enable `--ner` only when needed — default is off.
