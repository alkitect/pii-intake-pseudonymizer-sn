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

Also enforced:
- `.github/FUNDING.yml` with `ko_fi: alkitect`
- README Ko-fi button (`githubbutton_sm.svg` → `ko-fi.com/alkitect`) under the tagline
- README soft tip containing `ko-fi.com/alkitect` (after License)
- README must not link Patreon or Buy Me a Coffee

Gate: `./scripts/ci-check.sh`.

## Versioning
First public tag is recorded in `docs/PUBLISH.md` (`First public tag:`). Default is **0.1.0**.

## Bug reports
When reporting issues, include:
- What input file(s) you scrubbed (or a redacted example)
- Whether you used `--summary` / `--dry-run` / real scrub
- Whether you provided an encryption key (`PII_MAP_KEY` / `PII_MAP_KEY_FILE`)

## Run before PR

```bash
find scripts -type f -name '*.sh' -print0 | xargs -0 -r bash -n
./scripts/ci-check.sh
```

