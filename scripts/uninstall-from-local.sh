#!/usr/bin/env bash
# Remove installed wrappers + local data tree.
set -euo pipefail

BIN="${HOME}/.local/bin"
DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/pii-intake-pseudonymizer-sn"

rm -f "${BIN}/pii-intake-pseudonymizer-sn" "${BIN}/verify-pii-intake-pseudonymizer-sn"
rm -rf "${DATA_DIR}"

echo "Uninstalled pii-intake-pseudonymizer-sn wrappers."
