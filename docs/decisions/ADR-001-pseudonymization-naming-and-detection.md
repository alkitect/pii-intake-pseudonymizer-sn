# ADR-001: Pseudonymization naming + hybrid detection

## Status

Accepted (2026-08)

## Context

The tool replaces identifiers with stable tokens while optionally keeping a reversible map. Calling that output "anonymous" is misleading under GDPR Art. 4(5) when additional information (the map + key) exists. Stdlib regex/harvest alone misses some free-text PERSON spans; optional NLP can help but must not become a silent hard dependency.

## Decision

1. **Naming:** Mapped tokens are **pseudonyms**. Documentation and CLI say *pseudonymize*, not *anonymize*, except when ADR-003 `--irreversible` mode is used.
2. **Hybrid detection:** Layer 1 is always stdlib (`pii_detectors`, field harvest). Layer 2 is **opt-in** Presidio NER via `--ner` (default **off**). Counts report `ner=skipped` when NER extras are absent.
3. **IP scrubbing:** Single flag `--also-ip`, default **off**, to avoid over-redacting infrastructure noise in exports.

## Consequences

- Offline, agent-safe defaults remain the common path
- Optional NER improves PERSON recall where installed
- Clearer privacy language for adopters

## Alternatives considered

- Always-on NER when importable — rejected (silent cross-machine quality skew)
- Cloud redaction API — out of scope (offline constraint)

## References

- [ADR-002](ADR-002-map-encryption-key-separation.md)
- [ADR-003](ADR-003-irreversible-no-map-mode.md)
- [C3 CLI components](../architecture/c3-cli-components.md)
