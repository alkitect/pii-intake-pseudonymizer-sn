#!/usr/bin/env python3
"""Cursor beforeShellExecution: block PII-leaking shell patterns.

Denies:
- anonymize_intake.py with --report
- anonymize_intake.py with --summary on inbox/raw (commit gate, not intake)
- anonymize_intake.py with --irreversible or --map-prune-unused (human-only)
- Common file-read commands targeting inbox/raw or .local/
- Ad-hoc map decrypt/mutate: PiiMap.load, pii_map_crypto, py -c + pii-map.json
  (agents must use anonymize_intake.py CLI only — never open the reverse map)

Allows agent-safe scrub: anonymize_intake.py inbox/raw (no --report, no --summary).
Allows commit gate: anonymize_intake.py src/stories … --summary
Allows pytest / unit tests that name map paths without py -c map loads.
"""

from __future__ import annotations

import json
import re
import sys

# anonymize_intake … --report (anywhere in the argv string)
ANON_REPORT_RE = re.compile(
    r"anonymize_intake(?:\.py)?\b[\s\S]*?--report\b|--report\b[\s\S]*?anonymize_intake(?:\.py)?\b",
    re.IGNORECASE,
)

ANON_INTAKE_RE = re.compile(r"anonymize_intake(?:\.py)?\b", re.IGNORECASE)
SUMMARY_FLAG_RE = re.compile(r"--summary\b", re.IGNORECASE)
INBOX_RAW_RE = re.compile(r"inbox[/\\]+raw", re.IGNORECASE)
IRREVERSIBLE_RE = re.compile(r"--irreversible\b", re.IGNORECASE)
MAP_PRUNE_RE = re.compile(r"--map-prune-unused\b", re.IGNORECASE)

# Ad-hoc decrypt / mutate of the reverse map (bypasses Read hook)
PII_MAP_LOAD_RE = re.compile(r"\bPiiMap\s*\.\s*load\b", re.IGNORECASE)
PII_MAP_CRYPTO_RE = re.compile(r"\bpii_map_crypto\b", re.IGNORECASE)
PII_MAP_PATH_RE = re.compile(
    r"(?:\.local[/\\]+)?pii-map(?:\.json)?(?:\.bak)?\b",
    re.IGNORECASE,
)
# python / py -c one-liners (not `py -3 scripts/anonymize_intake.py`)
PY_DASH_C_RE = re.compile(
    r"(?:^|[\s;&|])(?:py(?:thon)?(?:\s+-3)?|python3)\s+-c\b",
    re.IGNORECASE,
)
# pytest / unittest runners — allow (tests may mention map paths in argv)
TEST_RUNNER_RE = re.compile(r"\b(?:pytest|py\.test|unittest)\b", re.IGNORECASE)

MSG_SUMMARY_NOT_INTAKE = (
    "Blocked: --summary on inbox/raw is the commit detect-only gate, not intake. "
    "To scrub: `py -3 scripts/anonymize_intake.py inbox/raw` (no --summary, no --report), "
    "then continue the user's task from inbox/clean/."
)

MSG_HUMAN_ONLY_FLAG = (
    "Blocked: --irreversible / --map-prune-unused are human-only (non-restorable or "
    "no-map). Use a VS Code **PII:** task outside the agent. "
    "Agent: `py -3 scripts/anonymize_intake.py inbox/raw` (default agent-safe)."
)

MSG_MAP_LOAD_DENY = (
    "Blocked: agents must not decrypt or mutate `.local/pii-map.json` via shell "
    "(PiiMap.load / pii_map_crypto / py -c). Use only "
    "`py -3 scripts/anonymize_intake.py …` (CLI loads the map). "
    "Map hygiene is human-only (VS Code **PII:** tasks / documented CLI)."
)

# Paths we must not dump via shell readers
SENSITIVE_PATH_RE = re.compile(
    r"(?:"
    r"inbox[/\\]+raw|/inbox[/\\]+raw|"
    r"inbox[/\\]+clean|/inbox[/\\]+clean|"
    r"\.local[/\\]+pii-map|\.local[/\\]|[/\\]\.local(?:[/\\]|$)"
    r")",
    re.IGNORECASE,
)

# Commands that stream file contents (best-effort; not a full sandbox)
READ_CMD_RE = re.compile(
    r"(?:"
    r"\bGet-Content\b|\bgc\b|\bcat\b|\btype\b|\bless\b|\bmore\b|"
    r"\bSelect-String\b|\bSelect-Content\b|\bGet-Content\b|"
    r"\brg\b|\bgrep\b|\bfindstr\b|\bml\b"
    r")",
    re.IGNORECASE,
)


def _is_allowlisted_cli(cmd: str) -> bool:
    """True when the command runs anonymize_intake.py as a script (not py -c)."""
    if not ANON_INTAKE_RE.search(cmd):
        return False
    if PY_DASH_C_RE.search(cmd):
        return False
    return True


def decide(command: str) -> tuple[str, str]:
    """Return (permission, message). permission is allow|deny."""
    cmd = command or ""
    if not cmd.strip():
        return "allow", ""

    if ANON_REPORT_RE.search(cmd):
        return (
            "deny",
            "Blocked: anonymize_intake with --report prints original PII into agent "
            "context. Human: use VS Code task **PII: anonymize inbox** (outside agent). "
            "Agent: `py -3 scripts/anonymize_intake.py inbox/raw` (default agent-safe, "
            "counts only), then analyze inbox/clean/.",
        )

    if ANON_INTAKE_RE.search(cmd) and (
        IRREVERSIBLE_RE.search(cmd) or MAP_PRUNE_RE.search(cmd)
    ):
        return ("deny", MSG_HUMAN_ONLY_FLAG)

    if (
        ANON_INTAKE_RE.search(cmd)
        and SUMMARY_FLAG_RE.search(cmd)
        and INBOX_RAW_RE.search(cmd)
    ):
        return ("deny", MSG_SUMMARY_NOT_INTAKE)

    # Map decrypt/mutate bypass — before generic path reads so messages are specific
    if not TEST_RUNNER_RE.search(cmd) and not _is_allowlisted_cli(cmd):
        if PII_MAP_LOAD_RE.search(cmd) or PII_MAP_CRYPTO_RE.search(cmd):
            return ("deny", MSG_MAP_LOAD_DENY)
        if PY_DASH_C_RE.search(cmd) and PII_MAP_PATH_RE.search(cmd):
            return ("deny", MSG_MAP_LOAD_DENY)

    if SENSITIVE_PATH_RE.search(cmd) and READ_CMD_RE.search(cmd):
        return (
            "deny",
            "Blocked: shell read of inbox/raw, inbox/clean, or .local/. "
            "Copy into inbox/raw without reading, run "
            "`py -3 scripts/anonymize_intake.py inbox/raw`, then Read inbox/clean "
            "via the file tool (checksum-gated). Do not Get-Content/cat clean files.",
        )

    return "allow", ""


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"permission": "allow"}))
        return 0
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print(json.dumps({"permission": "allow"}))
        return 0

    if not isinstance(payload, dict):
        print(json.dumps({"permission": "allow"}))
        return 0

    command = str(
        payload.get("command")
        or payload.get("cmd")
        or payload.get("shell_command")
        or ""
    )
    permission, message = decide(command)
    out: dict[str, str] = {"permission": permission}
    if message:
        out["user_message"] = message
        out["agent_message"] = message
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
