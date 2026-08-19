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

Run detect-only on a copy under `input/`:

```bash
pii-intake-pseudonymizer input --summary
```
