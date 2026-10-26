"""Unit tests for scripts/pii_commit_gate.py helpers."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import pii_commit_gate as gate  # noqa: E402


def test_is_story_path_skips_export() -> None:
    assert gate.is_story_path("src/stories/STORY-1/README.md")
    assert not gate.is_story_path("src/stories/STORY-1/source-export/foo.xml")
    assert not gate.is_story_path("scripts/foo.py")


def test_denied_staged_env_and_map() -> None:
    hits = gate.denied_staged(
        [".env", "src/stories/x.md", ".local/pii-map.json", "secrets.key"]
    )
    assert ".env" in hits
    assert ".local/pii-map.json" in hits
    assert "secrets.key" in hits
    assert "src/stories/x.md" not in hits


def test_denied_staged_quarantine_payloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    raw_gk = tmp_path / "inbox" / "raw" / ".gitkeep"
    raw_gk.parent.mkdir(parents=True)
    raw_gk.write_text("", encoding="utf-8")
    (tmp_path / "inbox" / "raw" / "README.md").write_text("leak\n", encoding="utf-8")
    (tmp_path / "inbox" / "clean").mkdir(parents=True)
    (tmp_path / "inbox" / "clean" / "drop.md").write_text("x\n", encoding="utf-8")
    (tmp_path / "inbox" / "instance-upload").mkdir(parents=True)
    (tmp_path / "inbox" / "instance-upload" / "bundle.xml").write_text(
        "<u/>\n", encoding="utf-8"
    )
    story = "src/stories/STORY-1/intake-clean/drop.md"

    hits = gate.denied_staged(
        [
            "inbox/raw/README.md",
            "inbox/raw/.gitkeep",
            "inbox/clean/drop.md",
            "inbox/instance-upload/bundle.xml",
            story,
        ]
    )
    assert "inbox/raw/README.md" in hits
    assert "inbox/clean/drop.md" in hits
    assert "inbox/instance-upload/bundle.xml" in hits
    assert "inbox/raw/.gitkeep" not in hits
    assert story not in hits


def test_fail_on_hits_email_exits_nonzero(tmp_path: Path) -> None:
    """Personal email hits must fail --fail-on-hits (commit gate posture)."""
    sample = tmp_path / "story.md"
    sample.write_text("Contact jane.example@uva.nl please\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(gate.ANONYMIZE),
            str(sample),
            "--dry-run",
            "--fail-on-hits",
            "--force-path",
            "--summary",
        ],
        cwd=gate.REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def test_hooks_path_ok_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(_args: list[str]) -> object:
        class R:
            returncode = 1
            stdout = ""
            stderr = ""

        return R()

    monkeypatch.setattr(gate, "_run_git", fake_run)
    assert gate.hooks_path_ok() is False
