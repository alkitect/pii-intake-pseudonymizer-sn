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
echo 'Contact jane.doe@example.com for access.' > inbox/raw/sample.txt
```

See [Repo layout](repo-layout.md) for the full tree.

## Step 1 — intake dry-run (no key)

Preview tokenization on quarantined exports — no output or map writes:

```bash
pii-intake-pseudonymizer-sn inbox/raw --dry-run
```

`--summary` on `inbox/raw` is **refused** (intake vs commit gate). Use `--dry-run` for intake preview.

## Step 2 — real pass + optional promote (key required)

Generate a key file outside cloud sync (any path is fine; platform default below):

```bash
mkdir -p ~/.config/servicenow-pii
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" \
  > ~/.config/servicenow-pii/pii-map.key
chmod 600 ~/.config/servicenow-pii/pii-map.key   # Unix
export PII_MAP_KEY_FILE="$HOME/.config/servicenow-pii/pii-map.key"
```

Platform defaults if you set no env var (CLI auto-loads when the file exists):

- Windows: `%LOCALAPPDATA%/ServiceNow-PII/pii-map.key`
- Linux/macOS: `~/.config/servicenow-pii/pii-map.key`

Copy ServiceNow/Jira exports into `inbox/raw/` (do not point editors at raw paths until pseudonymized):

```bash
pii-intake-pseudonymizer-sn inbox/raw --promote STORY-1000
```

Omit `--promote STORY-1000` if you only need `inbox/clean/` staging.

Output lands in `inbox/clean/` with stable tokens. Raw text sources are deleted after successful write unless `--keep-raw`.

When drops contain hostnames, paths, shell lines, or PEM blocks, add **`--also-technical`** on the write pass:

```bash
pii-intake-pseudonymizer-sn inbox/raw --also-technical --promote STORY-1000
```

Default scrub leaves those technical categories intact. See [CLI reference](cli-reference.md).

**Success check:** `grep user_001 inbox/clean/sample.txt` should show `user_001@example.test`.

## Step 3 — commit gate before git push (no key)

Scan story docs before you commit — meaningful after docs contain real or promoted content:

```bash
pii-intake-pseudonymizer-sn src/stories/STORY-1000/docs --summary
```

`--summary` implies `--dry-run` and `--fail-on-hits`. Non-zero exit when hits are found is expected. See [Commit gate](commit-gate.md).

## Verify install

Runs unit tests from the cloned repo (confirms wrapper + dependencies; does not process your sample):

```bash
verify-pii-intake-pseudonymizer-sn
```

Re-run `./scripts/install-to-local.sh` after `git pull` so `~/.local/share/…` matches your clone.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `--summary` refused on `inbox/raw` | Expected — gate is for `src/stories/` only | Use `--dry-run` for intake preview; see [commit gate](commit-gate.md) |
| Gate on empty `src/stories/.../docs` | No files to scan yet | Run intake + `--promote` first, or add docs to scan |
| Gate fails on `src/stories` | Residual PII in story docs | Run intake on exports; fix allowlist |
| `residual=…` abort, no output | High-confidence email/IBAN left | Fix source or allowlist; see [Security](security.md) |
| Binary files skipped | `.xlsx`, `.pdf` not pseudonymized as text | Export to CSV/text first |
| Empty `intake-clean/` after promote | No successful write or empty `inbox/clean/` | Run intake with key and `--promote` on same command |
| `map=unavailable` on gate | Normal without a key | Expected for `--summary` |

## Ready to share

You are ready to push story docs when: promoted or edited files under `src/stories/` pass `--summary`, and `inbox/raw/` + `.local/` stay out of git.

## Next steps

- [Product comparison](product-comparison.md)
- [Configuration](configuration.md)
- [Architecture](architecture/README.md)
- Generic layout without story folders → [pii-intake-pseudonymizer](https://github.com/alkitect/pii-intake-pseudonymizer)
