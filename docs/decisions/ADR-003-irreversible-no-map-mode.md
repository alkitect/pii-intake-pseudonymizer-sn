# ADR-003: Irreversible / no-map mode for external share

## Status

Accepted (2026-08)

## Context

Teaching-stable tokens plus an encrypted map are **pseudonymization**. Sharing scrubbed text externally while retaining a reverse table increases re-identification risk. ADR-002 points external-share callers here.

## Decision

1. **`--irreversible`:** Scrub with ephemeral in-memory tokens; **do not** write or update `.local/pii-map.json`.
2. **Not a substitute** for residual fail-closed on high-confidence leftovers (email, checksum IBAN).
3. Default workflow remains reversible encrypted map for stable tokens across runs.

## Consequences

- Clear path for external analysis without a reverse table
- Tokens are **not** stable across runs in irreversible mode (by design)

## Alternatives considered

- Always irreversible — rejected (breaks multi-run teaching stability)
- Cloud anonymization service — out of scope

## References

- [CLI reference](../cli-reference.md) (`--irreversible`)
- [ADR-002](ADR-002-map-encryption-key-separation.md)
