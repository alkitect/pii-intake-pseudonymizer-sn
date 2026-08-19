#!/usr/bin/env bash
# Install pii-intake-pseudonymizer-sn wrappers + local data tree under XDG paths.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BIN="${HOME}/.local/bin"
DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/pii-intake-pseudonymizer-sn"

mkdir -p "${BIN}"

rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"

mkdir -p "${DATA_DIR}/scripts" "${DATA_DIR}/config"

# Python CLI + config (avoid __pycache__)
shopt -s nullglob
cp -a "${ROOT}/scripts/"*.py "${DATA_DIR}/scripts/" 2>/dev/null || true
cp -a "${ROOT}/scripts/"*.sh "${DATA_DIR}/scripts/" 2>/dev/null || true
shopt -u nullglob

cp -a "${ROOT}/config/"* "${DATA_DIR}/config/" 2>/dev/null || true

cp -a "${ROOT}/requirements-pii"*.txt "${DATA_DIR}/" 2>/dev/null || true

cat >"${BIN}/pii-intake-pseudonymizer-sn" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec python "${DATA_DIR}/scripts/anonymize_intake.py" "\$@"
EOF

cat >"${BIN}/verify-pii-intake-pseudonymizer-sn" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec python -m pytest -q "${ROOT}/tests/unit"
EOF

chmod 0755 "${BIN}/pii-intake-pseudonymizer-sn" "${BIN}/verify-pii-intake-pseudonymizer-sn"

echo ""
echo "Installed:"
echo "  ${BIN}/pii-intake-pseudonymizer-sn"
echo "  ${BIN}/verify-pii-intake-pseudonymizer-sn"
echo ""
