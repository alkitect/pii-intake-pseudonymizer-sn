"""Unit tests for scripts/intake_manifest.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import intake_manifest as manifest  # noqa: E402


def test_record_intake_write_creates_manifest(tmp_path: Path) -> None:
    clean = tmp_path / "inbox" / "clean"
    clean.mkdir(parents=True)
    f = clean / "drop.md"
    f.write_text("scrubbed\n", encoding="utf-8")
    local = tmp_path / ".local"
    manifest.record_intake_write(f, tmp_path, local_dir=local)
    mp = local / "intake-manifest.json"
    assert mp.is_file()
    data = json.loads(mp.read_text(encoding="utf-8"))
    assert "inbox/clean/drop.md" in data["files"]
    assert data["files"]["inbox/clean/drop.md"]["sha256"] == manifest.sha256_file(f)


def test_is_verified_intake_output(tmp_path: Path) -> None:
    clean = tmp_path / "inbox" / "clean"
    clean.mkdir(parents=True)
    f = clean / "x.md"
    f.write_text("ok\n", encoding="utf-8")
    manifest.record_intake_write(f, tmp_path, local_dir=tmp_path / ".local")
    assert manifest.is_verified_intake_output(str(f), tmp_path, local_dir=tmp_path / ".local")
    f.write_text("tampered\n", encoding="utf-8")
    assert not manifest.is_verified_intake_output(
        str(f), tmp_path, local_dir=tmp_path / ".local"
    )


def test_drop_inbox_clean_manifest_keys(tmp_path: Path) -> None:
    local = tmp_path / ".local"
    clean = tmp_path / "inbox" / "clean"
    clean.mkdir(parents=True)
    f = clean / "a.md"
    f.write_text("x\n", encoding="utf-8")
    manifest.record_intake_write(f, tmp_path, local_dir=local)
    promoted = tmp_path / "src" / "stories" / "STORY-1" / "intake-clean" / "a.md"
    promoted.parent.mkdir(parents=True)
    promoted.write_text("x\n", encoding="utf-8")
    manifest.record_intake_write(promoted, tmp_path, local_dir=local)
    dropped = manifest.drop_inbox_clean_manifest_keys(tmp_path, local_dir=local)
    assert dropped == 1
    data = manifest.load_intake_manifest(tmp_path, local_dir=local)
    assert "inbox/clean/a.md" not in data["files"]
    assert "src/stories/STORY-1/intake-clean/a.md" in data["files"]


def test_retain_inbox_clean_manifest_keys(tmp_path: Path) -> None:
    local = tmp_path / ".local"
    clean = tmp_path / "inbox" / "clean"
    clean.mkdir(parents=True)
    keep = clean / "keep.md"
    drop = clean / "drop.md"
    keep.write_text("k\n", encoding="utf-8")
    drop.write_text("d\n", encoding="utf-8")
    manifest.record_intake_write(keep, tmp_path, local_dir=local)
    manifest.record_intake_write(drop, tmp_path, local_dir=local)
    removed = manifest.retain_inbox_clean_manifest_keys(
        tmp_path, {"inbox/clean/keep.md"}, local_dir=local
    )
    assert removed == 1
    data = manifest.load_intake_manifest(tmp_path, local_dir=local)
    assert "inbox/clean/keep.md" in data["files"]
    assert "inbox/clean/drop.md" not in data["files"]
