# ADR-004: Intake vs commit gate (ServiceNow layout)

## Status

Accepted (2026-08)

## Context

The ServiceNow monorepo uses two different path classes:

- **`inbox/raw`** — hot quarantine for exports that may contain PII
- **`src/stories/**`** — long-lived story docs that should reach git only after pseudonymization

Using the same `--summary` detect-only mode for both conflates “scan before commit” with “intake quarantine,” and invites running detect-only on raw paths without a clear write workflow.

## Decision

1. **`--summary` on `src/stories/...`** — allowed: commit-time detect-only gate (implies `--dry-run`, `--fail-on-hits`).
2. **`--summary` on `inbox/raw`** — **refused** with an error that points to the intake write command.
3. **`--summary` never authorizes `--in-place`** — backfill is a separate deliberate write pass after dry-run review.
4. **Intake manifest** (`.local/intake-manifest.json`) records successful clean writes; optional verification for promoted outputs.

## Consequences

- Clear operator mental model: intake = write on raw; gate = detect on stories
- Prevents treating detect-only hits as automatic mass-rewrite orders
- Public repo stays CLI-only (no editor hooks required)

## Alternatives considered

- Single mode for all paths — rejected (ambiguous safety story)
- Auto `--in-place` when `--summary` finds hits — rejected (corruption risk)

## References

- [Commit gate](../commit-gate.md)
- [Repo layout](../repo-layout.md)
