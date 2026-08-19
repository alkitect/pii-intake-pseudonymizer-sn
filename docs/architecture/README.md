# Architecture (C4 hub)

ServiceNow story-monorepo flavor: quarantine → pseudonymize → optional promote → commit detect-only.

| Level | Doc | Scope |
|-------|-----|-------|
| **C1 Context** | [c1-context.md](c1-context.md) | Actors, exports, story repo |
| **C2 Containers** | [c2-containers.md](c2-containers.md) | CLI, inbox, manifest, map |
| **C3 Components** | [c3-cli-components.md](c3-cli-components.md) | Shared with generic CLI + manifest |

**Decisions:** [decisions/README.md](../decisions/README.md)

## End-to-end flow

```mermaid
flowchart TB
  human[Human]
  raw[inbox_raw]
  cli[pii-intake-pseudonymizer_sn]
  clean[inbox_clean]
  manifest[intake_manifest]
  promote["--promote STORY_id"]
  story[intake_clean_under_story]
  gate["--summary on src_stories"]
  human --> raw --> cli --> clean
  cli --> manifest
  clean --> promote --> story
  gate -.->|detect_only| story
```

## Extra module (SN)

| Module | Role |
|--------|------|
| `scripts/intake_manifest.py` | SHA-256 registry for clean / promoted outputs |

Generic C3 details: [pii-intake-pseudonymizer architecture](https://github.com/alkitect/pii-intake-pseudonymizer/tree/v0.1.0/docs/architecture).
