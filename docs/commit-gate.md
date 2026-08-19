# Commit gate (detect-only)

Detect-only scan of **story** paths before commit. Complements intake (`inbox/raw` → write); it does not replace it.

## Canonical command

```bash
pii-intake-pseudonymizer-sn src/stories/STORY-1000/docs --summary
```

Or scan all stories:

```bash
pii-intake-pseudonymizer-sn src/stories --summary
```

`--summary` implies `--dry-run` and `--fail-on-hits`.

## Gate rules

| Rule | Behavior |
|------|----------|
| `--summary` | Implies `--dry-run` and `--fail-on-hits` |
| Targets | Must be under `src/stories/` |
| `inbox/raw` + `--summary` | **Rejected** — use a write pass for intake, not the commit gate |
| Map key | **Not required** — `map=unavailable` is OK |
| Output | Redacted hit counts only — never use `--report` in gates |
| `--in-place` | **Never** authorized by `--summary` |

## What the gate checks

- Email and high-confidence residual patterns
- Harvested / seeded person-name hits
- **Not** a guarantee of zero PII (NER off by default; no git history scrub)

## Staged git index scan

After `git add` on story paths:

```bash
python scripts/pii_commit_gate.py
```

Requirements: git repo, staged paths under `src/stories/`, no `PII_MAP_KEY`. Optional pre-commit hook wiring is not installed by default.

## If hits are found

1. Stop — do not mass `--in-place` rewrite in the same session as tooling fixes.
2. Fix scope or run intake on the relevant exports.
3. Re-run `--summary` on the story subtree.

See [ADR-004](decisions/ADR-004-intake-vs-commit-gate.md) and [Security](security.md).

Compare with the generic CLI: [product comparison](product-comparison.md).
