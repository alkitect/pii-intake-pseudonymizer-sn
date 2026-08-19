# Examples

Synthetic fixture used by unit tests — safe to read (no real PII):

- [`tests/fixtures/pii-gold/nl_synthetic.md`](../../tests/fixtures/pii-gold/nl_synthetic.md) — NL-style fields the stdlib detectors target

Copy into quarantine, then dry-run intake:

```bash
cp tests/fixtures/pii-gold/nl_synthetic.md inbox/raw/
pii-intake-pseudonymizer-sn inbox/raw --dry-run
```

See [getting started](../getting-started.md) for promote and commit-gate flows.
