#!/usr/bin/env bash
# Verify installed pii-intake-pseudonymizer-sn in read-only mode.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== pii-intake-pseudonymizer-sn verify ==="

test -f "${ROOT}/scripts/anonymize_intake.py" || {
  echo "verify: missing scripts/anonymize_intake.py in ${ROOT}" >&2
  exit 1
}
test -d "${ROOT}/tests/unit" || {
  echo "verify: missing tests/unit in ${ROOT}" >&2
  exit 1
}

echo ""
echo "=== unit tests ==="
python -m pytest -q "${ROOT}/tests/unit"

echo "verify-pii-intake-pseudonymizer-sn: OK"
