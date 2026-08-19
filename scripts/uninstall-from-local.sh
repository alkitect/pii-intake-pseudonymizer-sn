#!/usr/bin/env bash
# Remove installed wrappers + local data tree.
set -euo pipefail

BIN="${HOME}/.local/bin"
DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/pii-intake-scrubber-servicenow"

rm -f "${BIN}/pii-intake-scrubber-servicenow" "${BIN}/verify-pii-intake-scrubber-servicenow"
rm -rf "${DATA_DIR}"

echo "Uninstalled pii-intake-scrubber-servicenow wrappers."

