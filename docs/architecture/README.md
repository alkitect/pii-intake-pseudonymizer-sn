# Architecture (C4 hub)

Local, offline pseudonymization CLI — no network service, no editor dependency.

| Level | Doc | Scope |
|-------|-----|-------|
| **C1 Context** | [c1-context.md](c1-context.md) | Actors, system boundary, external systems |
| **C2 Containers** | [c2-containers.md](c2-containers.md) | CLI, config, map, I/O stores |
| **C3 Components** | [c3-cli-components.md](c3-cli-components.md) | Inside `anonymize_intake.py` |

**Decisions:** [decisions/README.md](../decisions/README.md)

**Operate:** [getting-started.md](../getting-started.md) · [cli-reference.md](../cli-reference.md)

## End-to-end flow (default write)

```mermaid
flowchart TB
  human[Human]
  input[input_or_paths]
  cli[pii-intake-pseudonymizer]
  layer1[Layer1_stdlib_detectors]
  layer1b[Layer1b_opt_in_technical]
  layer2[Layer2_opt_in_NER]
  residual[Residual_gate]
  write[Write_output]
  map[Encrypted_pii_map]
  key[Key_outside_repo]
  abort[Abort_no_write]
  human --> input --> cli
  cli --> layer1 --> layer1b --> layer2 --> residual
  residual -->|pass| write
  residual -->|fail| abort
  write --> map
  key -.-> map
```

## Module map

| Module | Role |
|--------|------|
| `scripts/anonymize_intake.py` | CLI entry, modes, staging, residual abort |
| `scripts/pii_detectors.py` | Phones, IBAN, BSN, MAC, postcode, DOB, residual scan; flag-gated machine/path/command/PEM finders |
| `scripts/pii_map_crypto.py` | Fernet encrypt/decrypt, key resolution |
| `scripts/pii_ner.py` | Opt-in Presidio PERSON (`--ner`) |
| `config/*` | Allowlist, org list, person fields, NER config |

View diagrams in GitHub, VS Code, or Cursor Markdown preview (Mermaid enabled).
