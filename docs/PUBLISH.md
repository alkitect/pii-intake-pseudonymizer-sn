# Publish notes

Before tag: README must pass `bash scripts/ci-check.sh`. See [CONTRIBUTING.md](../CONTRIBUTING.md) § README conventions.

First public tag: v0.1.0

Current tag: v0.2.2

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
git submodule add -b v0.2.2 https://github.com/alkitect/pii-intake-pseudonymizer-sn.git public/pii-intake-pseudonymizer-sn
```

Pin submodule gitlink to tag `v0.2.2`, not `main`.

## ADR edits

Edit ADR-001–004 in this tree before tagging. There is no public sibling extract to sync against right now.
