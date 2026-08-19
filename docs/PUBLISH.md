# Publish notes

Before tag: README must pass `./scripts/ci-check.sh`. See [CONTRIBUTING.md](../CONTRIBUTING.md) § README conventions.

First public tag: v0.1.0

Repo URL: `https://github.com/alkitect/pii-intake-scrubber-servicenow`

## GitHub About

| Field | Value |
|-------|--------|
| Description | Offline PII intake scrubber for ServiceNow story repos — inbox/raw pseudonymization with a stable encrypted map |
| Website | _(empty — tip via README Ko-fi badge)_ |
| Topics | `pii`, `privacy`, `anonymization`, `security`, `offline`, `python`, `servicenow` |

```bash
gh repo create pii-intake-scrubber-servicenow --public --source=. --remote=origin
gh repo edit alkitect/pii-intake-scrubber-servicenow \
  --description "Offline PII intake scrubber for ServiceNow story repos — inbox/raw pseudonymization with a stable encrypted map" \
  --homepage "" \
  --add-topic pii --add-topic privacy --add-topic anonymization --add-topic security \
  --add-topic offline --add-topic python --add-topic servicenow
```

Sidebar (manual if shown): Releases ✓ · Packages ✗ · Deployments ✗

## Linux monorepo submodule (human gate)

After GitHub is live:

```bash
cd /path/to/Linux
git submodule add -b v0.1.0 https://github.com/alkitect/pii-intake-scrubber-servicenow.git public/pii-intake-scrubber-servicenow
```

Pin submodule gitlink to tag `v0.1.0`, not `main`.
