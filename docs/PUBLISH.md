# Publish notes

Before tag: README must pass `./scripts/ci-check.sh`. See [CONTRIBUTING.md](../CONTRIBUTING.md) § README conventions.

First public tag: v0.1.0

Repo URL: `https://github.com/alkitect/pii-intake-pseudonymizer-sn`

## GitHub About

| Field | Value |
|-------|--------|
| Description | Offline PII intake pseudonymizer for ServiceNow story repos — inbox/raw stable token replacement with an encrypted map |
| Website | _(empty — tip via README Ko-fi badge)_ |
| Topics | `pii`, `privacy`, `pseudonymization`, `security`, `offline`, `python`, `servicenow` |

```bash
gh repo create pii-intake-pseudonymizer-sn --public --source=. --remote=origin
gh repo edit alkitect/pii-intake-pseudonymizer-sn \
  --description "Offline PII intake pseudonymizer for ServiceNow story repos — inbox/raw stable token replacement with an encrypted map" \
  --homepage "" \
  --add-topic pii --add-topic privacy --add-topic pseudonymization --add-topic security \
  --add-topic offline --add-topic python --add-topic servicenow
```

Sidebar (manual if shown): Releases ✓ · Packages ✗ · Deployments ✗

## Linux monorepo submodule (human gate)

After GitHub is live:

```bash
cd /path/to/Linux
git submodule add -b v0.1.0 https://github.com/alkitect/pii-intake-pseudonymizer-sn.git public/pii-intake-pseudonymizer-sn
```

Pin submodule gitlink to tag `v0.1.0`, not `main`.

## ADR sync (shared with generic repo)

Before tagging, copy ADR-001–003 from [pii-intake-pseudonymizer](https://github.com/alkitect/pii-intake-pseudonymizer). ADR-004 is SN-only — edit here, not in the generic repo.
