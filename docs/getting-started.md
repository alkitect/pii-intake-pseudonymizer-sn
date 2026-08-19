# Getting started

ServiceNow / Jira story-monorepo flavor: quarantine raw exports under `inbox/raw/`, pseudonymize to `inbox/clean/`, optionally `--promote` into `src/stories/<STORY-id>/`.

## Prerequisites

- Python 3.10+ with `pip`
- Git Bash or a Unix shell for `install-to-local.sh` (Windows) or any POSIX shell (Linux/macOS)

## Install

```bash
git clone https://github.com/alkitect/pii-intake-pseudonymizer-sn.git
cd pii-intake-pseudonymizer-sn

./scripts/install-to-local.sh
python -m pip install -r requirements-pii.txt pytest
```

Wrappers: `pii-intake-pseudonymizer-sn`, `verify-pii-intake-pseudonymizer-sn`.

## Layout (first-time)

```bash
mkdir -p inbox/raw inbox/clean .local src/stories/STORY-1000/docs
```

See [Repo layout](repo-layout.md) for the full tree.

## Step 1 — commit gate (detect-only, no key)

Scan story docs before you commit — no map key required:

```bash
pii-intake-pseudonymizer-sn src/stories/STORY-1000/docs --summary
```

`--summary` implies `--dry-run` and `--fail-on-hits`. On `inbox/raw` it is **refused** (intake vs commit gate). See [Commit gate](commit-gate.md).

## Step 2 — intake (copy exports, then pseudonymize)

Copy ServiceNow/Jira exports into `inbox/raw/` (do not point editors at raw paths until pseudonymized):

```bash
cp /path/to/export.xml inbox/raw/

# Dry-run first
pii-intake-pseudonymizer-sn inbox/raw --dry-run

# Real pass + optional promote (set key first — see Map key below)
# Example path outside sync; platform defaults: see Map key section
export PII_MAP_KEY_FILE="$HOME/.config/pii-intake/pii-map.key"
pii-intake-pseudonymizer-sn inbox/raw --promote STORY-1000
```

Omit `--promote STORY-1000` if you only need `inbox/clean/` staging.

Output lands in `inbox/clean/` with stable tokens. Raw text sources are deleted after successful write unless `--keep-raw`.

When drops contain hostnames, paths, shell lines, or PEM blocks, add **`--also-technical`** on the write pass:

```bash
pii-intake-pseudonymizer-sn inbox/raw --also-technical --promote STORY-1000
```

Default scrub leaves those technical categories intact. See [CLI reference](cli-reference.md).

## Map key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store outside cloud sync; set `PII_MAP_KEY` or `PII_MAP_KEY_FILE`. Platform defaults if unset:

- Windows: `%LOCALAPPDATA%/ServiceNow-PII/pii-map.key`
- Linux/macOS: `~/.config/servicenow-pii/pii-map.key`

Detect-only modes work without a key.

## Verify

```bash
verify-pii-intake-pseudonymizer-sn
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `--summary` refused on `inbox/raw` | Expected — gate is for `src/stories/` only | Use write pass for intake; see [commit gate](commit-gate.md) |
| Gate fails on `src/stories` | Residual PII in story docs | Run intake on exports; fix allowlist |
| `residual=…` abort, no output | High-confidence email/IBAN left | Fix source or allowlist; see [Security](security.md) |
| Binary files skipped | `.xlsx`, `.pdf` not pseudonymized as text | Export to CSV/text first |
| Empty `intake-clean/` after promote | No successful write or empty `inbox/clean/` | Run intake with key and `--promote` on same command |
| `map=unavailable` on gate | Normal without key | Expected for `--summary` |

## Next steps

- [Product comparison](product-comparison.md)
- [Configuration](configuration.md)
- [Architecture](architecture/README.md)
- Generic layout without story folders → [pii-intake-pseudonymizer](https://github.com/alkitect/pii-intake-pseudonymizer)
