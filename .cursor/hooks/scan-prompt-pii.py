#!/usr/bin/env python3
"""Cursor beforeSubmitPrompt: never block; inject copy→scrub→continue when needed."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_HOOKS_DIR = Path(__file__).resolve().parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

import pii_detect  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST_PATH = REPO_ROOT / "config" / "pii-allowlist.txt"


def load_allowlist() -> set[str]:
    items = {"example.test"}
    if not ALLOWLIST_PATH.is_file():
        return items
    for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        items.add(s.lower())
    return items


def decide(
    prompt: str,
    allowlist: set[str] | None = None,
    repo_root: Path | None = None,
) -> tuple[bool, str]:
    """Pure decide for tests: (continue, agent_message). Always continue=True."""
    return pii_detect.decide_prompt(
        prompt,
        allowlist if allowlist is not None else set(),
        repo_root if repo_root is not None else REPO_ROOT,
    )


def main() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            print(json.dumps({"continue": True}))
            return 0
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            print(json.dumps({"continue": True}))
            return 0

        if not isinstance(payload, dict):
            print(json.dumps({"continue": True}))
            return 0

        prompt = str(
            payload.get("prompt")
            or payload.get("content")
            or payload.get("text")
            or ""
        )
        _ok, message = decide(prompt, load_allowlist())
        out: dict[str, str | bool] = {"continue": True}
        if message:
            out["agent_message"] = message
        print(json.dumps(out))
        return 0
    except Exception:
        # Never block the user prompt; read hook still denies raw file contents.
        print(json.dumps({"continue": True}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
