#!/usr/bin/env bash
# Install PII scrubber wrappers + local data tree under XDG paths.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BIN="${HOME}/.local/bin"
DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/pii-intake-scrubber-servicenow"

mkdir -p "${BIN}"

rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"

mkdir -p "${DATA_DIR}/scripts" "${DATA_DIR}/config" "${DATA_DIR}/tests" "${DATA_DIR}/.cursor/hooks"

# Shell gate scripts + Python CLI (avoid __pycache__)
shopt -s nullglob
cp -a "${ROOT}/scripts/"*.py "${DATA_DIR}/scripts/" 2>/dev/null || true
cp -a "${ROOT}/scripts/"*.sh "${DATA_DIR}/scripts/" 2>/dev/null || true
shopt -u nullglob

cp -a "${ROOT}/config/"* "${DATA_DIR}/config/" 2>/dev/null || true
cp -a "${ROOT}/tests/." "${DATA_DIR}/tests/"
shopt -s nullglob
cp -a "${ROOT}/.cursor/hooks/"* "${DATA_DIR}/.cursor/hooks/"
shopt -u nullglob

cp -a "${ROOT}/requirements-pii"*.txt "${DATA_DIR}/" 2>/dev/null || true

# Minimal placeholders required for hook unit tests.
# (The tests reference in-repo paths that don't correspond to real tool input.)
mkdir -p "${DATA_DIR}/src/stories/STORY-1500/docs"
mkdir -p "${DATA_DIR}/src/stories/STORY-1000"
echo "<xml/>" >"${DATA_DIR}/src/stories/STORY-1500/docs/foo.xml"
echo "<xml/>" >"${DATA_DIR}/src/stories/STORY-1000/x.xml"
echo "# placeholder" >"${DATA_DIR}/AGENTS.md"

cat >"${BIN}/pii-intake-scrubber-servicenow" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec python "${DATA_DIR}/scripts/anonymize_intake.py" "\$@"
EOF

cat >"${BIN}/verify-pii-intake-scrubber-servicenow" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec python -m pytest -q "${ROOT}/tests/unit"
EOF

chmod 0755 "${BIN}/pii-intake-scrubber-servicenow" "${BIN}/verify-pii-intake-scrubber-servicenow"

echo ""
echo "Installed:"
echo "  ${BIN}/pii-intake-scrubber-servicenow"
echo "  ${BIN}/verify-pii-intake-scrubber-servicenow"
echo ""

