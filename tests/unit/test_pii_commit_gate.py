"""Unit tests for scripts/pii_commit_gate.py helpers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import pii_commit_gate as gate  # noqa: E402


def test_is_story_path_skips_export() -> None:
    assert gate.is_story_path("src/stories/STORY-1000/README.md")
    assert not gate.is_story_path("src/stories/STORY-1000/source-export/foo.xml")
    assert not gate.is_story_path("scripts/foo.py")


def test_denied_staged_env_and_map() -> None:
    hits = gate.denied_staged(
        [".env", "src/stories/x.md", ".local/pii-map.json", "secrets.key"]
    )
    assert ".env" in hits
    assert ".local/pii-map.json" in hits
    assert "secrets.key" in hits
    assert "src/stories/x.md" not in hits


def test_hooks_path_ok_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(_args: list[str]) -> object:
        class R:
            returncode = 1
            stdout = ""
            stderr = ""

        return R()

    monkeypatch.setattr(gate, "_run_git", fake_run)
    assert gate.hooks_path_ok() is False
