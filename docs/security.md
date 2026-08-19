# Security

Same core model as the [generic product](https://github.com/alkitect/pii-intake-pseudonymizer/blob/v0.1.0/docs/security.md), plus ServiceNow layout notes.

## Quarantine discipline

- Treat `inbox/raw/` as **hot** — never commit, never point agents at it without pseudonymizing first.
- Only `inbox/clean/`, promoted `intake-clean/`, and pseudonymized `src/stories/**/docs/` belong in shared workflows.

## Intake vs commit gate

- **`inbox/raw` write pass** — pseudonymizes quarantined exports.
- **`src/stories` `--summary`** — detect-only; refuses to run on `inbox/raw`. See [Commit gate](commit-gate.md).

`--summary` never authorizes `--in-place` backfill.

## Manifest

`.local/intake-manifest.json` records SHA-256 checksums of clean outputs after a successful write. It supports **honest-agent** workflow verification (did this file come from a pseudonymize run?) — not cryptographic proof against a malicious local actor.

## Key and sync

Store map keys outside cloud-synced repo roots. Exclude `.local/` from OneDrive when possible. See [ADR-002](decisions/ADR-002-map-encryption-key-separation.md).

## Not a compliance product

This tool reduces accidental PII exposure in local story repos. It does not certify HIPAA/GDPR compliance or replace org-wide DLP.

## Reporting issues

Redact samples; no real PII in public issues. See [CONTRIBUTING.md](../CONTRIBUTING.md).
