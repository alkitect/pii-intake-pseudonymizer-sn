# ADR-002: PII map encryption + key separation

## Status

Accepted (2026-08)

## Context

`.local/pii-map.json` holds reversible real→token pairs. Plaintext under a cloud-synced tree risks version-history retention. The map is additional information under GDPR Art. 4(5): with the map and key, tokens are re-identifiable.

## Decision

1. **Encrypt at rest** with Fernet (`cryptography` in `requirements-pii.txt`).
2. **Key outside sync root:** `PII_MAP_KEY`, `PII_MAP_KEY_FILE`, or platform default:
   - Windows: `%LOCALAPPDATA%/ServiceNow-PII/pii-map.key`
   - Linux/macOS: `~/.config/servicenow-pii/pii-map.key`
   
   Paths like `$HOME/.config/pii-intake/pii-map.key` are valid **examples** only — do not store the key file next to the map in a synced repo.
3. **Migrate:** `--map-migrate` (plaintext → encrypted, `.bak` dual-read); `--map-rollback` restores `.bak`.
4. **Mutating writes fail closed** without key/crypto. **Detect-only / `--summary`** soft-fail: `map=unavailable`, empty map, no abort.
5. **Never commit** map, key, `.bak`, or audit log. Prefer excluding `.local/` from cloud sync.

## Consequences

- Ciphertext in sync is less useful without the off-tree key
- CI and detect-only workflows stay green without provisioning secrets
- Humans must back up keys; lost key ⇒ unreadable map

## Alternatives considered

- Plaintext map — rejected (sync/history risk)
- Key beside map in repo — rejected

## References

- [Security](../security.md)
- [Configuration](../configuration.md)
- [ADR-003](ADR-003-irreversible-no-map-mode.md)
