# Examples

Synthetic fixture used by unit tests — safe to read (no real PII):

- [`tests/fixtures/pii-gold/nl_synthetic.md`](../../tests/fixtures/pii-gold/nl_synthetic.md) — NL-style fields the stdlib detectors target

**Typical token shapes after pseudonymization:**

- `jane@company.example` → `user_001@example.test`
- Display names → `PERSON_001`
- Org names (when `--scrub-orgs` is on) → `ORG_001`
- Labeled hostnames (when `--also-machines` or `--also-technical`) → `MACHINE_001`
- Absolute paths (when `--also-paths` or `--also-technical`) → `PATH_001`
- Command-like lines (when `--also-commands` or `--also-technical`) → `CMD_001`
- PEM blocks (when `--also-certificates` or `--also-technical`) → `CERT_001`

Intake preview (no writes) on a copy under `inbox/raw/`:

```bash
pii-intake-pseudonymizer-sn inbox/raw --dry-run
```

Commit gate (detect-only) on story docs:

```bash
pii-intake-pseudonymizer-sn src/stories/STORY-1000/docs --summary
```

Generic layout (`input/` → `output/`): [pii-intake-pseudonymizer examples](https://github.com/alkitect/pii-intake-pseudonymizer/blob/main/docs/examples/README.md).
