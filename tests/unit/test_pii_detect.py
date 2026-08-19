"""Unit tests for .cursor/hooks/pii_detect.py and hook decide() wrappers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HOOKS = REPO / ".cursor" / "hooks"


def _load_module(name: str, path: Path):
    # Ensure sibling imports (pii_detect) resolve like Cursor runtime.
    hooks_dir = str(path.parent)
    if hooks_dir not in sys.path:
        sys.path.insert(0, hooks_dir)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def detect():
    return _load_module("pii_detect_under_test", HOOKS / "pii_detect.py")


@pytest.fixture(scope="module")
def prompt_hook():
    return _load_module("scan_prompt_pii_under_test", HOOKS / "scan-prompt-pii.py")


@pytest.fixture(scope="module")
def read_hook():
    return _load_module("block_inbox_raw_under_test", HOOKS / "block-inbox-raw.py")


def test_allowlisted_email_ok(detect):
    assert detect.find_non_allowlisted_emails(
        "mail noreply@example.invalid please", {"noreply@example.invalid"}
    ) == []


def test_personal_email_prompt_continues_with_intake_hint(detect, prompt_hook):
    ok, msg = prompt_hook.decide(
        "contact me at person.name@example.invalid thanks", set()
    )
    assert ok is True
    assert "person.name@example.invalid" not in msg
    assert "inbox/raw" in msg.lower()


def test_sn_unload_paste_continues_with_intake_hint(detect, prompt_hook):
    body = "<unload>\n" + ("display_value=\"Someone\"\n" * 3)
    assert detect.looks_like_raw_sn_export(body) is True
    ok, msg = prompt_hook.decide(body, set())
    assert ok is True
    assert "inbox/raw" in msg.lower()


def test_short_innocent_xml_allowed(detect, prompt_hook):
    snippet = "<sys_id>abc123</sys_id>\n<!-- tiny -->\n"
    assert detect.looks_like_raw_sn_export(snippet) is False
    ok, msg = prompt_hook.decide(snippet, set())
    assert ok is True
    assert msg == ""


def test_path_inbox_raw_deny(read_hook, detect):
    perm, msg = read_hook.decide(str(REPO / "inbox" / "raw" / "x.xml"), REPO)
    assert perm == "deny"
    assert "raw" in msg.lower() or "inbox" in msg.lower()


def test_path_inbox_clean_unverified_deny(read_hook, tmp_path):
    clean = tmp_path / "inbox" / "clean" / "drop.md"
    clean.parent.mkdir(parents=True)
    clean.write_text("not from pipeline\n", encoding="utf-8")
    perm, msg = read_hook.decide(str(clean), tmp_path)
    assert perm == "deny"
    assert "anonymize" in msg.lower() or "checksum" in msg.lower() or "inbox/clean" in msg.lower()


def test_outside_repo_csv_deny(read_hook, tmp_path):
    outside = tmp_path / "Downloads" / "sys_email.csv"
    outside.parent.mkdir(parents=True)
    outside.write_text("a\n", encoding="utf-8")
    perm, msg = read_hook.decide(str(outside), REPO)
    assert perm == "deny"
    assert "outside" in msg.lower() or "workspace" in msg.lower()


def test_outside_repo_json_deny(read_hook, tmp_path):
    outside = tmp_path / "Downloads" / "table.json"
    outside.parent.mkdir(parents=True)
    outside.write_text("{}\n", encoding="utf-8")
    perm, _ = read_hook.decide(str(outside), REPO)
    assert perm == "deny"


def test_in_repo_story_xml_allow(read_hook):
    # Path need not exist; resolve still under repo.
    path = REPO / "src" / "stories" / "STORY-1500" / "docs" / "foo.xml"
    perm, _ = read_hook.decide(str(path), REPO)
    assert perm == "allow"


def test_path_traversal_stays_under_repo_allow(read_hook):
    # .. segments that still resolve under repo should not trip outside deny.
    path = str(REPO / "src" / "stories" / ".." / "stories" / "STORY-1000" / "x.xml")
    perm, _ = read_hook.decide(path, REPO)
    assert perm == "allow"


def test_example_test_email_allowed(prompt_hook):
    ok, _ = prompt_hook.decide("use user_001@example.test in docs", set())
    assert ok is True


def test_read_outside_repo_md_deny(read_hook, tmp_path):
    outside = tmp_path / "Downloads" / "STORY-2500.md"
    outside.parent.mkdir(parents=True)
    outside.write_text("x\n", encoding="utf-8")
    perm, msg = read_hook.decide(str(outside), REPO)
    assert perm == "deny"
    assert "outside" in msg.lower() or "workspace" in msg.lower() or "copy" in msg.lower()


def test_read_outside_repo_xml_deny(read_hook, tmp_path):
    outside = tmp_path / "Downloads" / "sys_script_include.xml"
    outside.parent.mkdir(parents=True)
    outside.write_text("<xml/>\n", encoding="utf-8")
    perm, _ = read_hook.decide(str(outside), REPO)
    assert perm == "deny"


def test_read_in_repo_md_allow(read_hook):
    perm, _ = read_hook.decide(str(REPO / "AGENTS.md"), REPO)
    assert perm == "allow"


def test_read_outside_kit_md_allow(read_hook, tmp_path):
    kit_md = tmp_path / "cursor-starter-kit" / "README.md"
    kit_md.parent.mkdir(parents=True)
    kit_md.write_text("x\n", encoding="utf-8")
    perm, _ = read_hook.decide(str(kit_md), REPO)
    assert perm == "allow"


def test_prompt_outside_md_at_continues_with_intake_hint(prompt_hook, tmp_path):
    outside = tmp_path / "Downloads" / "STORY-2500.md"
    outside.parent.mkdir(parents=True)
    outside.write_text("x\n", encoding="utf-8")
    ok, msg = prompt_hook.decide(f"@{outside} PR the Proposed Design", set())
    assert ok is True
    assert "inbox/raw" in msg.lower()


def test_prompt_outside_xml_at_continues_with_intake_hint(prompt_hook, tmp_path):
    outside = tmp_path / "Downloads" / "sys_script_include.xml"
    outside.parent.mkdir(parents=True)
    outside.write_text("<xml/>\n", encoding="utf-8")
    ok, msg = prompt_hook.decide(f"@{outside} review this export", set())
    assert ok is True
    assert "inbox/raw" in msg.lower()


def test_prompt_in_repo_relative_md_allowed(prompt_hook):
    ok, msg = prompt_hook.decide("@src/stories/README.md summarize", set())
    assert ok is True
    assert msg == ""


def test_prompt_inbox_raw_at_continues_with_intake_hint(prompt_hook):
    ok, msg = prompt_hook.decide("@inbox/raw/sys_email.xml analyze this", set())
    assert ok is True
    assert "inbox/raw" in msg.lower()
    assert "do not read" in msg.lower() or "copy" in msg.lower()


def test_prompt_markdown_url_allowed(prompt_hook):
    ok, _ = prompt_hook.decide(
        "see https://example.com/docs/guide.md for setup", set()
    )
    assert ok is True


def test_path_inbox_clean_verified_allow(read_hook, detect, tmp_path):
    clean = tmp_path / "inbox" / "clean" / "drop.md"
    clean.parent.mkdir(parents=True)
    clean.write_text("scrubbed ok\n", encoding="utf-8")
    detect.record_intake_write(clean, tmp_path, local_dir=tmp_path / ".local")
    perm, _ = read_hook.decide(str(clean), tmp_path)
    assert perm == "allow"


def test_path_inbox_clean_stale_hash_deny(read_hook, detect, tmp_path):
    clean = tmp_path / "inbox" / "clean" / "drop.md"
    clean.parent.mkdir(parents=True)
    clean.write_text("scrubbed ok\n", encoding="utf-8")
    detect.record_intake_write(clean, tmp_path, local_dir=tmp_path / ".local")
    clean.write_text("tampered after scrub\n", encoding="utf-8")
    perm, msg = read_hook.decide(str(clean), tmp_path)
    assert perm == "deny"
    assert "checksum" in msg.lower() or "anonymize" in msg.lower()


def test_path_intake_clean_verified_allow(read_hook, detect, tmp_path):
    dest = tmp_path / "src" / "stories" / "STORY-1000" / "intake-clean" / "drop.md"
    dest.parent.mkdir(parents=True)
    dest.write_text("promoted\n", encoding="utf-8")
    detect.record_intake_write(dest, tmp_path, local_dir=tmp_path / ".local")
    perm, _ = read_hook.decide(str(dest), tmp_path)
    assert perm == "allow"


def test_retain_inbox_clean_drops_other_clean_keys(detect, tmp_path):
    local = tmp_path / ".local"
    clean = tmp_path / "inbox" / "clean"
    clean.mkdir(parents=True)
    keep = clean / "keep.md"
    drop = clean / "drop.md"
    keep.write_text("a\n", encoding="utf-8")
    drop.write_text("b\n", encoding="utf-8")
    story = tmp_path / "src" / "stories" / "STORY-1000" / "intake-clean" / "x.md"
    story.parent.mkdir(parents=True)
    story.write_text("c\n", encoding="utf-8")
    detect.record_intake_write(keep, tmp_path, local_dir=local)
    detect.record_intake_write(drop, tmp_path, local_dir=local)
    detect.record_intake_write(story, tmp_path, local_dir=local)
    dropped = detect.retain_inbox_clean_manifest_keys(
        tmp_path, {"inbox/clean/keep.md"}, local_dir=local
    )
    assert dropped == 1
    data = detect.load_intake_manifest(tmp_path, local_dir=local)
    files = data["files"]
    assert "inbox/clean/keep.md" in files
    assert "inbox/clean/drop.md" not in files
    assert "src/stories/STORY-1000/intake-clean/x.md" in files


def test_drop_inbox_clean_keeps_intake_clean_keys(detect, tmp_path):
    local = tmp_path / ".local"
    clean = tmp_path / "inbox" / "clean" / "drop.md"
    clean.parent.mkdir(parents=True)
    clean.write_text("a\n", encoding="utf-8")
    story = tmp_path / "src" / "stories" / "STORY-1000" / "intake-clean" / "x.md"
    story.parent.mkdir(parents=True)
    story.write_text("c\n", encoding="utf-8")
    detect.record_intake_write(clean, tmp_path, local_dir=local)
    detect.record_intake_write(story, tmp_path, local_dir=local)
    dropped = detect.drop_inbox_clean_manifest_keys(tmp_path, local_dir=local)
    assert dropped == 1
    data = detect.load_intake_manifest(tmp_path, local_dir=local)
    files = data["files"]
    assert "inbox/clean/drop.md" not in files
    assert "src/stories/STORY-1000/intake-clean/x.md" in files
