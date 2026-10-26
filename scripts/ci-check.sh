#!/usr/bin/env bash
# Release gate for pii-intake-pseudonymizer-sn (local + CI).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

FORBIDDEN_RE='\.cursor/plans|topics/'
hike_hits="$(grep -rE "${FORBIDDEN_RE}" \
  --include='*.sh' --include='*.md' --include='*.yml' --include='*.yaml' --include='*.example' --include='*.config' . \
  --exclude-dir=.git --exclude='ci-check.sh' 2>/dev/null || true)"
if [[ -n "${hike_hits}" ]]; then
  echo "ci-check: forbidden path refs found:" >&2
  echo "${hike_hits}" >&2
  exit 1
fi

if grep -rE '/home/alex' --include='*.md' . --exclude-dir=.git >/dev/null 2>&1; then
  echo "ci-check: public markdown must not contain /home/alex host paths" >&2
  grep -rE '/home/alex' --include='*.md' . --exclude-dir=.git >&2 || true
  exit 1
fi

REQUIRED_H2=(
  "## What this does"
  "## Who this is for"
  "## Quick start"
  "## Check it works"
  "## Uninstall"
  "## Limits & safety"
  "## License"
)
for h in "${REQUIRED_H2[@]}"; do
  grep -qFx "${h}" README.md || {
    echo "ci-check: README missing H2: ${h}" >&2
    exit 1
  }
done

grep -qE '\bSSOT\b' README.md && { echo "ci-check: README must not use SSOT" >&2; exit 1; }

if grep -qiE 'patreon\.com|buymeacoffee\.com' README.md; then
  echo "ci-check: README must not link Patreon or Buy Me a Coffee" >&2
  exit 1
fi

# Tip jar contract (Ko-fi)
[[ -f .github/FUNDING.yml ]] || { echo "ci-check: missing .github/FUNDING.yml" >&2; exit 1; }
grep -qE '^[[:space:]]*ko_fi:[[:space:]]*alkitect[[:space:]]*$' .github/FUNDING.yml \
  || { echo "ci-check: .github/FUNDING.yml must set ko_fi: alkitect" >&2; exit 1; }

grep -qF 'ko-fi.com/alkitect/?hidefeed=true&widget=true&embed=true' README.md \
  || { echo "ci-check: README must include Ko-fi tip-panel href (alkitect)" >&2; exit 1; }
grep -qF 'ko-fi.com/img/githubbutton_sm.svg' README.md \
  || { echo "ci-check: README must include Ko-fi GitHub button (githubbutton_sm.svg)" >&2; exit 1; }

# License contract
test -f LICENSE || { echo "ci-check: missing LICENSE" >&2; exit 1; }
grep -qF 'MIT — see [LICENSE](LICENSE).' README.md \
  || { echo "ci-check: README ## License must match LICENSE link" >&2; exit 1; }

# Versioning contract
grep -qF 'First public tag: v0.1.0' docs/PUBLISH.md \
  || { echo "ci-check: PUBLISH must record First public tag: v0.1.0" >&2; exit 1; }

REQUIRED_DOCS=(
  SECURITY.md
  CHANGELOG.md
  docs/README.md
  docs/product-comparison.md
  docs/getting-started.md
  docs/repo-layout.md
  docs/commit-gate.md
  docs/configuration.md
  docs/cli-reference.md
  docs/security.md
  docs/examples/README.md
  docs/architecture/README.md
  docs/decisions/README.md
  docs/PUBLISH.md
)
for f in "${REQUIRED_DOCS[@]}"; do
  test -f "${f}" || { echo "ci-check: missing required doc ${f}" >&2; exit 1; }
done

for f in scripts/install-to-local.sh scripts/uninstall-from-local.sh scripts/verify-pii-intake-pseudonymizer-sn.sh; do
  test -f "${f}" || { echo "ci-check: missing ${f}" >&2; exit 1; }
done

shopt -s nullglob
for f in scripts/*.sh; do
  mode="$(git ls-files -s "${f}" | awk '{print $1}')"
  if [[ "${mode}" != "100755" ]]; then
    echo "ci-check: ${f} must be executable in git (100755); run: git update-index --chmod=+x ${f}" >&2
    exit 1
  fi
  bash -n "${f}"
done
shopt -u nullglob

tmp="$(mktemp -d)"
cleanup() { rm -rf "${tmp}"; }
trap cleanup EXIT

export HOME="${tmp}"
export XDG_CONFIG_HOME="${tmp}/.config"
export XDG_STATE_HOME="${tmp}/.local/state"
export XDG_DATA_HOME="${tmp}/.local/share"

python -m venv "${tmp}/venv"
export PATH="${tmp}/venv/bin:${PATH}"
python -m pip install -q -r "${ROOT}/requirements-pii.txt" pytest

bash "${ROOT}/scripts/install-to-local.sh"
test -x "${HOME}/.local/bin/pii-intake-pseudonymizer-sn"
test -x "${HOME}/.local/bin/verify-pii-intake-pseudonymizer-sn"

"${HOME}/.local/bin/verify-pii-intake-pseudonymizer-sn"

bash "${ROOT}/scripts/uninstall-from-local.sh"
test ! -e "${HOME}/.local/bin/pii-intake-pseudonymizer-sn"
test ! -e "${HOME}/.local/bin/verify-pii-intake-pseudonymizer-sn"
test ! -d "${XDG_DATA_HOME}/pii-intake-pseudonymizer-sn"

# --- must-not-ship (public extract) ---
# Keepers under inbox/{raw,clean,instance-upload} are allowed; payloads are not.
fail_on() {
  echo "ci-check: FAIL must-not-ship: $1" >&2
  exit 1
}
if [[ -d .cursor/hooks ]]; then fail_on ".cursor/hooks present"; fi
if [[ -f .local/pii-map.json || -f .local/pii-map.json.bak ]]; then fail_on "pii-map present"; fi
# Indexed / worktree map + key artifacts
while IFS= read -r tracked; do
  case "${tracked}" in
    *.key|.local/pii-map.json|.local/pii-map.json.bak|*/pii-map.json|*/pii-map.json.bak)
      fail_on "tracked map/key path: ${tracked}"
      ;;
    .cursor/hooks/*)
      fail_on "tracked hooks path: ${tracked}"
      ;;
  esac
done < <(git ls-files)

python - <<'PY'
from pathlib import Path
import re
import subprocess
import sys

prefixes = [
    Path("inbox") / "raw",
    Path("inbox") / "instance-upload",
    Path("inbox") / "clean",
]
for d in prefixes:
    if not d.is_dir():
        continue
    for p in d.rglob("*"):
        if not p.is_file():
            continue
        if p.name == ".gitkeep":
            # Allow empty keepers (0 bytes) or whitespace-only leftovers
            if p.stat().st_size == 0 or not p.read_bytes().strip():
                continue
        print(f"payload: {p.as_posix()}", file=sys.stderr)
        sys.exit(1)

# Non-empty WORKDIR_SYNC SHA (no placeholder)
sync = Path("docs/WORKDIR_SYNC.md")
if sync.is_file():
    text = sync.read_text(encoding="utf-8", errors="ignore")
    if "WORKDIR_SHA=<fill" in text or "WORKDIR_SHA=TODO" in text:
        print("ci-check: WORKDIR_SYNC still has placeholder SHA", file=sys.stderr)
        sys.exit(1)
    if not re.search(r"WORKDIR_SHA=[0-9a-f]{7,40}", text):
        print("ci-check: WORKDIR_SYNC missing WORKDIR_SHA=<hex>", file=sys.stderr)
        sys.exit(1)

pat = re.compile(r"ESM-\d+")
# Fail on org story ids in tracked text files
tracked = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
for rel in tracked:
    p = Path(rel)
    if p.suffix.lower() not in {".md", ".py", ".sh", ".txt", ".yml", ".yaml"}:
        continue
    if "CHANGELOG" in p.name:
        continue
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        continue
    if pat.search(text):
        print(f"ci-check: org story id ESM-* in {p.as_posix()} (use STORY-*)", file=sys.stderr)
        sys.exit(1)
PY

# Unit tests (presence + execution)
python -m pytest -q tests/unit
# --- end must-not-ship ---

echo "ci-check: OK"

