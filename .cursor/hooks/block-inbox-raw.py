#!/usr/bin/env python3
"""Cursor beforeReadFile: deny inbox/raw, .local, outside-workspace exports, unverified clean."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_HOOKS_DIR = Path(__file__).resolve().parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

import pii_detect  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]


def decide(path: str, repo_root: Path | None = None) -> tuple[str, str]:
    """Pure decide for tests: (permission, message)."""
    return pii_detect.decide_read(path, repo_root if repo_root is not None else REPO_ROOT)


def main() -> int:
    try:
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

        path = str(
            payload.get("file_path")
            or payload.get("path")
            or payload.get("filePath")
            or ""
        )
        permission, message = decide(path, REPO_ROOT)
        out: dict[str, str] = {"permission": permission}
        if message:
            out["user_message"] = message
        print(json.dumps(out))
        return 0
    except Exception:
        print(
            json.dumps(
                {
                    "permission": "deny",
                    "user_message": "PII read gate failed; deny file. " + pii_detect.MSG_DROP_RAW,
                }
            )
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
