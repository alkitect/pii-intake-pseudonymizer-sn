# Contributing

## README conventions
Public README required H2s (exact strings; enforced by `./scripts/ci-check.sh`):

```text
## What this does
## Who this is for
## Quick start
## Check it works
## Uninstall
## Limits & safety
## License
```

Recommended optional H2s (not ci-enforced; keep if present):

```text
## Configure
## How it works
```

Place `## Configure` key-setup content before real-write steps in Quick start, or link to it inline. `## How it works` follows Configure.

Also enforced:
- `.github/FUNDING.yml` with `ko_fi: alkitect`
- README Ko-fi button (`githubbutton_sm.svg` → `ko-fi.com/alkitect`) under the tagline
- README soft tip containing `ko-fi.com/alkitect` (after License)
- README must not link Patreon or Buy Me a Coffee

Gate: `bash scripts/ci-check.sh`.

## Versioning
First public tag is recorded in `docs/PUBLISH.md` (`First public tag:`). Default is **0.1.0**.

## Bug reports
When reporting issues, include:
- What input file(s) you pseudonymized (or a redacted example)
- Whether you used `--summary` (detect-only), `--dry-run`, or a real write
- Whether you provided an encryption key (`PII_MAP_KEY` / `PII_MAP_KEY_FILE`)

## Run before PR

```bash
find scripts -type f -name '*.sh' -print0 | xargs -0 -r bash -n
bash scripts/ci-check.sh
```

Shell scripts must be executable in git (`100755`). After checkout on Windows, run `git update-index --chmod=+x scripts/*.sh` if CI reports mode errors.

