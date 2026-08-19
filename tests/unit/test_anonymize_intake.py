"""Unit tests for scripts/anonymize_intake.py (stdlib fixtures)."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "anonymize_intake.py"


def _load_mod():
    # Allow plaintext map saves in unit tests (no DPAPI key required).
    os.environ["PII_MAP_ALLOW_PLAINTEXT"] = "1"
    scripts = str(REPO / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    # Reload dependents if already imported
    for name in list(sys.modules):
        if name in {"anonymize_intake", "pii_map_crypto", "pii_detectors", "pii_ner", "intake_manifest"}:
            del sys.modules[name]
    spec = importlib.util.spec_from_file_location("anonymize_intake", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["anonymize_intake"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def mod():
    return _load_mod()


@pytest.fixture
def pii_map(tmp_path, mod):
    return mod.PiiMap.load(tmp_path / "pii-map.json")


@pytest.fixture
def allowlist(mod):
    return {"noreply@example.invalid", "system", "guest"}


def test_email_and_display_name(mod, pii_map, allowlist):
    text = "From: Jane Doe <jane.doe@example.invalid>\nCc: noreply@example.invalid\n"
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "jane.doe@example.invalid" not in result.text.lower()
    assert "noreply@example.invalid" in result.text
    assert "PERSON_" in result.text
    assert "@example.test" in result.text
    assert not result.residual_emails


def test_sys_created_by_username(mod, pii_map, allowlist):
    text = "<sys_created_by>jbregma1</sys_created_by><sys_updated_by>system</sys_updated_by>"
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "jbregma1" not in result.text
    assert "username_" in result.text
    assert "<sys_updated_by>system</sys_updated_by>" in result.text


def test_markdown_jira_paste(mod, pii_map, allowlist):
    text = (
        "## Bug\n"
        "- Sender test.user@example.invalid logged as Guest\n"
        "- Salutation used first name from Alex\n"
    )
    # Seed name so plain "Alex" is replaced
    pii_map.name_token("Alex")
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "test.user@example.invalid" not in result.text
    assert "Alex" not in result.text
    assert "PERSON_" in result.text


def test_harvest_reporter_slash_and_test_with(mod, pii_map, allowlist):
    text = (
        "| **REPORTER(S):** | - Jane Doe/Alex van Berg |\n"
        "| **DESCRIPTION** | - Import from ExampleOrgA and ExampleOrgB |\n"
        "| **TEST INSTRUCTIONS** | - Test with Jane Doe:<br>  - Run the import |\n"
    )
    result = mod.anonymize_text(
        text, pii_map=pii_map, allowlist=allowlist, also_ip=False, scrub_orgs=False
    )
    assert "Jane Doe" not in result.text
    assert "Alex van Berg" not in result.text
    assert "PERSON_" in result.text
    assert "ExampleOrgA" in result.text
    assert "ExampleOrgB" in result.text
    assert "Test with PERSON_" in result.text


def test_harvest_comma_and_bullet_lists(mod, pii_map, allowlist):
    text = (
        "**Stakeholders:**\n"
        "- Jane Doe\n"
        "- John Smith, Alex van Berg\n"
        "\n"
        "| **Reporter** | Jane Doe, John Smith |\n"
    )
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "Jane Doe" not in result.text
    assert "John Smith" not in result.text
    assert "Alex van Berg" not in result.text
    assert result.text.count("PERSON_") >= 3


def test_harvest_xml_display_value(mod, pii_map, allowlist):
    text = (
        '<opened_by display_value="Jane Doe">abc</opened_by>\n'
        '<assignment_group display_value="WPO IT on Site Support">x</assignment_group>\n'
    )
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "Jane Doe" not in result.text
    assert "WPO IT on Site Support" in result.text


def test_no_harvest_names_leaves_reporter(mod, pii_map, allowlist):
    text = "| **REPORTER(S):** | - Jane Doe |\n"
    result = mod.anonymize_text(
        text, pii_map=pii_map, allowlist=allowlist, also_ip=False, harvest_names=False
    )
    assert "Jane Doe" in result.text


def test_split_person_list_separators(mod):
    names = mod.split_person_list("- Jane Doe / John Smith\n- Alex van Berg")
    assert names == ["Jane Doe", "John Smith", "Alex van Berg"]
    names = mod.split_person_list("Jane Doe, John Smith; Alex van Berg")
    assert "Jane Doe" in names and "John Smith" in names and "Alex van Berg" in names


def test_looks_like_person_name_rejects_labels(mod):
    assert mod.looks_like_person_name("Jane Doe") is True
    assert mod.looks_like_person_name("Alex van Berg") is True
    assert mod.looks_like_person_name("Kostenplaats") is False
    assert mod.looks_like_person_name("ExampleOrgA") is False
    assert mod.looks_like_person_name("WPO") is False
    assert mod.looks_like_person_name("4 people") is False
    assert mod.looks_like_person_name("INC0871657") is False


def test_also_ip(mod, pii_map, allowlist):
    text = "Client 10.20.30.40 and peer fd12:3456:789a:1::1\n"
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=True)
    assert "10.20.30.40" not in result.text
    assert "203.0.113." in result.text
    assert "fd12:3456:789a:1::1" not in result.text.lower()
    assert "2001:db8::" in result.text.lower()


def test_map_stable_across_runs(mod, tmp_path, allowlist):
    map_path = tmp_path / "pii-map.json"
    m1 = mod.PiiMap.load(map_path)
    r1 = mod.anonymize_text(
        "a@example.invalid", pii_map=m1, allowlist=allowlist, also_ip=False
    )
    m1.save()
    m2 = mod.PiiMap.load(map_path)
    r2 = mod.anonymize_text(
        "a@example.invalid", pii_map=m2, allowlist=allowlist, also_ip=False
    )
    assert r1.text == r2.text
    data = json.loads(map_path.read_text(encoding="utf-8"))
    assert "a@example.invalid" in data["emails"]


def test_short_name_does_not_corrupt_serviceportal(mod, pii_map, allowlist):
    # Regression: short display fragments must not substring-replace inside emails/keys
    pii_map.names["or"] = "PERSON_999"
    text = (
        'sys_name": "serviceportal@example.invalid" order original core import\n'
    )
    allowlist = set(allowlist) | {"serviceportal@example.invalid"}
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "serviceportal@example.invalid" in result.text
    assert "PERSON_999" not in result.text
    assert "order" in result.text


def test_name_test_does_not_corrupt_example_test_emails(mod, pii_map, allowlist):
    # Regression: seeded \"test\" must not rewrite @example.test TLDs, and is deny-listed
    # for plain replace (docs/code collision).
    pii_map.names["test"] = "PERSON_001"
    text = (
        "Contact UHMASKEDADDR_user_001@example.test and user_002@example.test.\n"
        "Also keep standalone Test in prose.\n"
    )
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "UHMASKEDADDR_user_001@example.test" in result.text
    assert "user_002@example.test" in result.text
    assert "@example.PERSON" not in result.text
    assert "Test" in result.text  # deny-listed — not scrubbed
    assert result.residual is None or not result.residual.emails


def test_deny_listed_name_parts_not_plain_replaced(mod, pii_map, allowlist):
    pii_map.names["user"] = "PERSON_099"
    text = "The user opened a case for Sam Jansen.\n"
    pii_map.name_token("Sam Jansen")
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "user" in result.text.lower()
    assert "PERSON_099" not in result.text
    assert "Sam Jansen" not in result.text
    assert "PERSON_" in result.text


def test_already_scrubbed_person_tokens_not_retokenized(mod, pii_map, allowlist):
    # Re-scrub must not map PERSON_001 → PERSON_00N (cascade / hit inflation).
    text = "Caller PERSON_001 <user_001@example.test> and PERSON_002 in prose.\n"
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "PERSON_001" in result.text
    assert "PERSON_002" in result.text
    assert "user_001@example.test" in result.text
    assert not any(
        h.kind == "name" and str(h.original).upper().startswith("PERSON_")
        for h in result.hits
    )
    assert "PERSON_001" not in pii_map.names
    assert mod.is_pseudo_token("PERSON_001")
    assert not mod.looks_like_person_name("PERSON_001")


def test_json_sys_created_by(mod, pii_map, allowlist):
    text = '{"sys_created_by": "jbregma1", "sys_updated_by": "system"}'
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "jbregma1" not in result.text
    assert '"sys_created_by": "username_' in result.text
    assert '"sys_updated_by": "system"' in result.text


def test_cli_dry_run_inbox(mod, tmp_path, monkeypatch):
    raw = mod.DEFAULT_RAW
    raw.mkdir(parents=True, exist_ok=True)
    sample = raw / "_pytest_sample.md"
    sample.write_text("Contact alice@example.invalid please\n", encoding="utf-8")
    map_path = tmp_path / "map.json"
    try:
        code = mod.main(
            [
                str(sample),
                "--dry-run",
                "--report",
                "--map",
                str(map_path),
                "--allowlist",
                str(mod.DEFAULT_ALLOWLIST),
            ]
        )
        # residual may be 0 after dry-run anonymize in memory; exit 0 if no residual in result text
        assert code in (0, 1)
        assert not map_path.is_file()  # dry-run does not save
    finally:
        if sample.exists():
            sample.unlink()


def test_uhmaskedaddr_prefix_preserved(mod, pii_map, allowlist):
    text = "Masked `UHMASKEDADDR_masked.user@example.invalid` and bare icto-feb@example.invalid\n"
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "masked.user" not in result.text.lower()
    assert "icto-feb@example.invalid" not in result.text.lower()
    assert "UHMASKEDADDR_user_" in result.text
    assert "@example.test" in result.text
    assert not result.residual_emails


def test_allowlisted_noreply_unchanged(mod, pii_map, allowlist):
    text = "From noreply@example.invalid only\n"
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert result.text == text
    assert not result.hits


def test_cli_in_place_round_trip(mod, tmp_path):
    tree = tmp_path / "story" / "docs"
    tree.mkdir(parents=True)
    target = tree / "JIRA.md"
    target.write_text(
        "Sender bad.actor@example.invalid\nCc: noreply@example.invalid\n",
        encoding="utf-8",
    )
    map_path = tmp_path / "map.json"
    allow = tmp_path / "allow.txt"
    allow.write_text("noreply@example.invalid\n", encoding="utf-8")
    code = mod.main(
        [
            str(tree),
            "--in-place",
            "--report",
            "--map",
            str(map_path),
            "--allowlist",
            str(allow),
        ]
    )
    assert code == 0
    written = target.read_text(encoding="utf-8")
    assert "bad.actor@example.invalid" not in written
    assert "noreply@example.invalid" in written
    assert "@example.test" in written
    assert map_path.is_file()


def test_cli_in_place_refuses_out(mod, tmp_path):
    f = tmp_path / "a.md"
    f.write_text("x@y.com\n", encoding="utf-8")
    code = mod.main([str(f), "--in-place", "--out", str(tmp_path / "out.md")])
    assert code == 2


def _stories_fixture(tmp_path, monkeypatch, mod, rel: str = "STORY-1000/docs/JIRA.md"):
    stories_root = tmp_path / "src" / "stories"
    target = stories_root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(mod, "STORIES_ROOT", stories_root)
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    monkeypatch.setattr(mod, "DEFAULT_RAW", tmp_path / "inbox" / "raw")
    return target


def test_gate_multipath_personal_email_fails(mod, tmp_path, monkeypatch, capsys):
    f1 = _stories_fixture(tmp_path, monkeypatch, mod, "STORY-1000/docs/a.md")
    f2 = _stories_fixture(tmp_path, monkeypatch, mod, "STORY-2000/docs/b.md")
    f1.write_text("Contact bad.actor@example.invalid\n", encoding="utf-8")
    f2.write_text("ok text only\n", encoding="utf-8")
    map_path = tmp_path / "map.json"
    allow = tmp_path / "allow.txt"
    allow.write_text("noreply@example.invalid\n", encoding="utf-8")
    code = mod.main(
        [
            str(f1),
            str(f2),
            "--dry-run",
            "--fail-on-hits",
            "--force-path",
            "--summary",
            "--map",
            str(map_path),
            "--allowlist",
            str(allow),
        ]
    )
    out = capsys.readouterr().out
    assert code == 1
    assert "bad.actor@example.invalid" not in out
    assert '"mode": "gate"' in out or '"mode":"gate"' in out.replace(" ", "")
    assert not map_path.is_file()


def test_gate_allowlisted_only_ok(mod, tmp_path, monkeypatch, capsys):
    f = _stories_fixture(tmp_path, monkeypatch, mod)
    f.write_text("From noreply@example.invalid only\n", encoding="utf-8")
    allow = tmp_path / "allow.txt"
    allow.write_text("noreply@example.invalid\n", encoding="utf-8")
    code = mod.main(
        [
            str(f),
            "--dry-run",
            "--summary",
            "--map",
            str(tmp_path / "map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "noreply@example.invalid" not in out


def test_gate_summary_implies_fail_on_hits(mod, tmp_path, monkeypatch):
    f = _stories_fixture(tmp_path, monkeypatch, mod)
    f.write_text("leak person@example.invalid\n", encoding="utf-8")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    code = mod.main(
        [
            str(f),
            "--dry-run",
            "--summary",
            "--map",
            str(tmp_path / "map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    assert code == 1


def test_gate_rejects_report(mod, tmp_path, monkeypatch):
    f = _stories_fixture(tmp_path, monkeypatch, mod)
    f.write_text("x\n", encoding="utf-8")
    code = mod.main([str(f), "--dry-run", "--summary", "--report"])
    assert code == 2


def test_agent_safe_rejects_explicit_report(mod, tmp_path, monkeypatch, capsys):
    raw = tmp_path / "inbox" / "raw"
    raw.mkdir(parents=True)
    sample = raw / "drop.md"
    sample.write_text("From: a@example.invalid\n", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", tmp_path / "inbox" / "clean")
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    code = mod.main(
        [
            str(raw),
            "--agent-safe",
            "--report",
            "--map",
            str(tmp_path / "map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "agent-safe" in err.lower()
    assert "report" in err.lower()


def test_report_alone_opts_out_of_default_agent_safe(mod, tmp_path, monkeypatch, capsys):
    raw = tmp_path / "inbox" / "raw"
    clean = tmp_path / "inbox" / "clean"
    raw.mkdir(parents=True)
    sample = raw / "drop.md"
    sample.write_text("From: person@example.invalid\n", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", clean)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    code = mod.main(
        [
            str(raw),
            "--report",
            "--map",
            str(tmp_path / ".local" / "pii-map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "hits" in out
    assert "person@example.invalid" in out or "original" in out


def test_default_write_is_agent_safe_counts_only(mod, tmp_path, monkeypatch, capsys):
    raw = tmp_path / "inbox" / "raw"
    clean = tmp_path / "inbox" / "clean"
    raw.mkdir(parents=True)
    sample = raw / "drop.md"
    sample.write_text("From: person@example.invalid\n", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", clean)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    code = mod.main(
        [
            str(raw),
            "--map",
            str(tmp_path / ".local" / "pii-map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "person@example.invalid" not in out
    assert "original" not in out
    assert "processed=" in out
    assert "deleted_raw=1" in out
    assert "deleted_clean=0" in out
    assert (clean / "drop.md").is_file()
    assert not sample.exists()
    assert (
        "person@example.invalid"
        not in (clean / "drop.md").read_text(encoding="utf-8").lower()
    )
    manifest = tmp_path / ".local" / "intake-manifest.json"
    assert manifest.is_file()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert "inbox/clean/drop.md" in data.get("files", {})
    assert data["files"]["inbox/clean/drop.md"].get("sha256")


def test_write_keep_raw_retains_source(mod, tmp_path, monkeypatch, capsys):
    raw = tmp_path / "inbox" / "raw"
    clean = tmp_path / "inbox" / "clean"
    raw.mkdir(parents=True)
    sample = raw / "drop.md"
    sample.write_text("From: person@example.invalid\n", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", clean)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    code = mod.main(
        [
            str(raw),
            "--keep-raw",
            "--map",
            str(tmp_path / ".local" / "pii-map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "deleted_raw=0" in out
    assert sample.is_file()
    assert (clean / "drop.md").is_file()


def _patch_inbox(mod, tmp_path, monkeypatch):
    raw = tmp_path / "inbox" / "raw"
    clean = tmp_path / "inbox" / "clean"
    raw.mkdir(parents=True)
    clean.mkdir(parents=True)
    (clean / ".gitkeep").write_text("", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", clean)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    monkeypatch.setattr(mod, "STORIES_ROOT", tmp_path / "src" / "stories")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    return raw, clean, allow


def _write_argv(raw, tmp_path, allow, extra=None):
    argv = [
        str(raw),
        "--map",
        str(tmp_path / ".local" / "pii-map.json"),
        "--allowlist",
        str(allow),
    ]
    if extra:
        argv[1:1] = extra
    return argv


def test_next_write_prunes_leftover_clean(mod, tmp_path, monkeypatch, capsys):
    raw, clean, allow = _patch_inbox(mod, tmp_path, monkeypatch)
    (raw / "old.md").write_text("From: person@example.invalid\n", encoding="utf-8")
    code = mod.main(_write_argv(raw, tmp_path, allow))
    assert code in (0, 1)
    capsys.readouterr()
    assert (clean / "old.md").is_file()
    nested = clean / "nested" / "stale.md"
    nested.parent.mkdir()
    nested.write_text("stale\n", encoding="utf-8")
    (raw / "drop.md").write_text("From: person@example.invalid\n", encoding="utf-8")
    code = mod.main(_write_argv(raw, tmp_path, allow))
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "deleted_clean=2" in out
    assert (clean / "drop.md").is_file()
    assert (clean / ".gitkeep").is_file()
    assert not (clean / "old.md").exists()
    assert not nested.exists()
    data = json.loads((tmp_path / ".local" / "intake-manifest.json").read_text(encoding="utf-8"))
    files = data.get("files", {})
    assert "inbox/clean/drop.md" in files
    assert "inbox/clean/old.md" not in files
    assert "inbox/clean/nested/stale.md" not in files


def test_keep_clean_retains_leftover_staging(mod, tmp_path, monkeypatch, capsys):
    raw, clean, allow = _patch_inbox(mod, tmp_path, monkeypatch)
    leftover = clean / "old.md"
    leftover.write_text("previous run\n", encoding="utf-8")
    (raw / "drop.md").write_text("From: person@example.invalid\n", encoding="utf-8")
    code = mod.main(_write_argv(raw, tmp_path, allow, extra=["--keep-clean"]))
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "deleted_clean=0" in out
    assert leftover.is_file()
    assert (clean / "drop.md").is_file()
    assert (clean / ".gitkeep").is_file()


def test_promote_clears_staging_keeps_story(mod, tmp_path, monkeypatch, capsys):
    raw, clean, allow = _patch_inbox(mod, tmp_path, monkeypatch)
    leftover = clean / "old.md"
    leftover.write_text("previous run\n", encoding="utf-8")
    (raw / "drop.md").write_text("From: person@example.invalid\n", encoding="utf-8")
    story_doc = tmp_path / "src" / "stories" / "STORY-9900" / "docs" / "note.md"
    story_doc.parent.mkdir(parents=True)
    story_doc.write_text("keep me\n", encoding="utf-8")
    code = mod.main(
        _write_argv(raw, tmp_path, allow, extra=["--promote", "STORY-9900"])
    )
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "deleted_clean=2" in out
    promoted = tmp_path / "src" / "stories" / "STORY-9900" / "intake-clean" / "drop.md"
    assert promoted.is_file()
    assert (
        "person@example.invalid"
        not in promoted.read_text(encoding="utf-8").lower()
    )
    assert not (
        tmp_path / "src" / "stories" / "STORY-9900" / "intake-clean" / "old.md"
    ).exists()
    assert not leftover.exists()
    assert not (clean / "drop.md").exists()
    assert (clean / ".gitkeep").is_file()
    assert story_doc.is_file()
    assert story_doc.read_text(encoding="utf-8") == "keep me\n"
    data = json.loads((tmp_path / ".local" / "intake-manifest.json").read_text(encoding="utf-8"))
    files = data.get("files", {})
    assert "src/stories/STORY-9900/intake-clean/drop.md" in files
    assert not any(k.replace("\\", "/").startswith("inbox/clean/") for k in files)


def test_keep_clean_promote_leaves_staging(mod, tmp_path, monkeypatch, capsys):
    raw, clean, allow = _patch_inbox(mod, tmp_path, monkeypatch)
    leftover = clean / "old.md"
    leftover.write_text("previous run\n", encoding="utf-8")
    (raw / "drop.md").write_text("From: person@example.invalid\n", encoding="utf-8")
    code = mod.main(
        _write_argv(
            raw,
            tmp_path,
            allow,
            extra=["--keep-clean", "--promote", "STORY-9900"],
        )
    )
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "deleted_clean=0" in out
    assert leftover.is_file()
    assert (clean / "drop.md").is_file()
    assert (tmp_path / "src" / "stories" / "STORY-9900" / "intake-clean" / "drop.md").is_file()
    # keep-clean skips prune, so leftover is copied into the story as well
    assert (tmp_path / "src" / "stories" / "STORY-9900" / "intake-clean" / "old.md").is_file()


def test_dry_run_does_not_prune_clean(mod, tmp_path, monkeypatch, capsys):
    raw, clean, allow = _patch_inbox(mod, tmp_path, monkeypatch)
    leftover = clean / "old.md"
    leftover.write_text("previous run\n", encoding="utf-8")
    (raw / "drop.md").write_text("From: person@example.invalid\n", encoding="utf-8")
    code = mod.main(_write_argv(raw, tmp_path, allow, extra=["--dry-run"]))
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "wrote=0" in out
    assert leftover.is_file()
    assert not (clean / "drop.md").exists()
    assert (clean / ".gitkeep").is_file()


def test_prune_clean_not_kept_keeps_gitkeep(mod, tmp_path):
    clean = tmp_path / "inbox" / "clean"
    clean.mkdir(parents=True)
    gitkeep = clean / ".gitkeep"
    gitkeep.write_text("", encoding="utf-8")
    keep = clean / "keep.md"
    keep.write_text("this run\n", encoding="utf-8")
    stale = clean / "stale.md"
    stale.write_text("old\n", encoding="utf-8")
    deleted = mod.prune_clean_not_kept(clean, {keep})
    assert deleted == 1
    assert keep.is_file()
    assert gitkeep.is_file()
    assert not stale.exists()


def test_clear_clean_staging_keeps_gitkeep(mod, tmp_path):
    clean = tmp_path / "inbox" / "clean"
    nested = clean / "sub"
    nested.mkdir(parents=True)
    (clean / ".gitkeep").write_text("", encoding="utf-8")
    (nested / "a.md").write_text("x\n", encoding="utf-8")
    deleted = mod.clear_clean_staging(clean)
    assert deleted == 1
    assert (clean / ".gitkeep").is_file()
    assert not (nested / "a.md").exists()
    assert not nested.exists()


def test_dry_run_does_not_delete_raw(mod, tmp_path, monkeypatch, capsys):
    raw = tmp_path / "inbox" / "raw"
    clean = tmp_path / "inbox" / "clean"
    raw.mkdir(parents=True)
    sample = raw / "drop.md"
    sample.write_text("From: person@example.invalid\n", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", clean)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    code = mod.main(
        [
            str(raw),
            "--dry-run",
            "--map",
            str(tmp_path / "map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "wrote=0" in out
    assert "deleted_raw=0" in out
    assert sample.is_file()
    assert not (clean / "drop.md").exists()


def test_binary_skip_not_deleted_on_mixed_write(mod, tmp_path, monkeypatch, capsys):
    raw = tmp_path / "inbox" / "raw"
    clean = tmp_path / "inbox" / "clean"
    raw.mkdir(parents=True)
    xlsx = raw / "sheet.xlsx"
    xlsx.write_bytes(b"PK\x03\x04fake")
    note = raw / "note.csv"
    note.write_text("email,val\nperson@example.invalid,1\n", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", clean)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    code = mod.main(
        [
            str(raw),
            "--map",
            str(tmp_path / ".local" / "pii-map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "deleted_raw=1" in out
    assert "skipped_binary=1" in out
    assert xlsx.is_file()
    assert not note.exists()
    assert (clean / "note.csv").is_file()


def test_in_place_does_not_delete_source(mod, tmp_path, monkeypatch):
    stories = tmp_path / "src" / "stories" / "STORY-1000" / "docs"
    stories.mkdir(parents=True)
    doc = stories / "note.md"
    doc.write_text("Contact person@example.invalid\n", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "STORIES_ROOT", tmp_path / "src" / "stories")
    monkeypatch.setattr(mod, "DEFAULT_RAW", tmp_path / "inbox" / "raw")
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", tmp_path / "inbox" / "clean")
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    code = mod.main(
        [
            str(doc),
            "--in-place",
            "--force-path",
            "--map",
            str(tmp_path / ".local" / "pii-map.json"),
            "--allowlist",
            str(allow),
        ]
    )
    assert code in (0, 1)
    assert doc.is_file()
    assert (
        "person@example.invalid"
        not in doc.read_text(encoding="utf-8").lower()
    )


def test_gate_rejects_in_place(mod, tmp_path, monkeypatch):
    f = _stories_fixture(tmp_path, monkeypatch, mod)
    f.write_text("x\n", encoding="utf-8")
    code = mod.main([str(f), "--dry-run", "--summary", "--in-place"])
    assert code == 2


def test_gate_summary_implies_dry_run(mod, tmp_path, monkeypatch):
    f = _stories_fixture(tmp_path, monkeypatch, mod)
    f.write_text("x\n", encoding="utf-8")
    code = mod.main([str(f), "--summary", "--fail-on-hits"])
    assert code == 0


def test_gate_rejects_inbox_raw(mod, tmp_path, monkeypatch, capsys):
    stories = tmp_path / "src" / "stories"
    stories.mkdir(parents=True)
    raw = tmp_path / "inbox" / "raw"
    raw.mkdir(parents=True)
    sample = raw / "drop.md"
    sample.write_text("a@b.nl\n", encoding="utf-8")
    monkeypatch.setattr(mod, "STORIES_ROOT", stories)
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    code = mod.main([str(sample), "--summary"])
    err = capsys.readouterr().err
    assert code == 2
    assert "requires --dry-run" not in err
    assert "inbox/raw" in err.lower() or "not intake" in err.lower()
    assert "anonymize_intake.py inbox/raw" in err


def test_export_skip_directory_walk(mod, tmp_path, monkeypatch):
    root = _stories_fixture(
        tmp_path, monkeypatch, mod, "STORY-1000/docs/ok.md"
    ).parent.parent
    docs = root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "ok.md").write_text("clean\n", encoding="utf-8")
    export = root / "source-export"
    export.mkdir()
    (export / "secret.xml").write_text("<sys_created_by>leakuser1</sys_created_by>\n", encoding="utf-8")
    files, skipped_binary = mod.collect_files(root)
    assert skipped_binary == 0
    assert any(p.name == "ok.md" for p in files)
    assert not any("source-export" in str(p) for p in files)


def test_tsv_in_text_suffixes(mod):
    assert ".tsv" in mod.TEXT_SUFFIXES


def test_binary_skip_counted(mod, tmp_path):
    raw = tmp_path / "inbox" / "raw"
    raw.mkdir(parents=True)
    (raw / "sheet.xlsx").write_bytes(b"PK\x03\x04fake")
    (raw / "note.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    files, skipped_binary = mod.collect_files(raw)
    assert skipped_binary == 1
    assert len(files) == 1
    assert files[0].name == "note.csv"


def test_binary_only_agent_safe_message(mod, tmp_path, monkeypatch, capsys):
    raw = tmp_path / "inbox" / "raw"
    raw.mkdir(parents=True)
    (raw / "only.xlsx").write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", tmp_path / "inbox" / "clean")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    code = mod.main([str(raw), "--map", str(tmp_path / "m.json")])
    assert code == 0
    err = capsys.readouterr().err
    assert "skipped_binary=1" in err
    assert "NOT scrubbed" in err


def test_gate_all_export_paths_fail(mod, tmp_path, monkeypatch):
    stories = tmp_path / "src" / "stories" / "STORY-1000"
    export = stories / "source-export"
    export.mkdir(parents=True)
    xml = export / "rec.xml"
    xml.write_text("<a/>\n", encoding="utf-8")
    monkeypatch.setattr(mod, "STORIES_ROOT", tmp_path / "src" / "stories")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    code = mod.main([str(xml), "--dry-run", "--summary", "--map", str(tmp_path / "m.json")])
    assert code == 2


def test_gate_explicit_export_filtered_with_sibling(mod, tmp_path, monkeypatch, capsys):
    docs = _stories_fixture(
        tmp_path, monkeypatch, mod, "STORY-1000/docs/ok.md"
    )
    docs.write_text("From noreply@example.invalid\n", encoding="utf-8")
    export = docs.parent.parent / "source-export"
    export.mkdir(parents=True, exist_ok=True)
    xml = export / "rec.xml"
    xml.write_text("<sys_created_by>leakuser1</sys_created_by>\n", encoding="utf-8")
    allow = tmp_path / "allow.txt"
    allow.write_text("noreply@example.invalid\n", encoding="utf-8")
    code = mod.main(
        [
            str(docs),
            str(xml),
            "--dry-run",
            "--summary",
            "--map",
            str(tmp_path / "m.json"),
            "--allowlist",
            str(allow),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "leakuser1" not in out
    data = json.loads(out)
    assert data["skipped_export"] >= 1


def test_phone_and_iban_scrub(mod, pii_map, allowlist):
    # Valid IBAN (mod-97): NL91ABNA0417164300
    text = "Bel +31 6 12345678 of NL91 ABNA 0417 1643 00\n"
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "+31 6 12345678" not in result.text
    assert "NL91ABNA0417164300".lower() not in result.text.replace(" ", "").lower()
    assert "IBAN_" in result.text
    assert "PHONE_" in result.text



def test_residual_abort_before_write(mod, tmp_path, monkeypatch):
    """High-confidence residual must not write clean / save map / manifest."""
    raw = tmp_path / "inbox" / "raw"
    clean = tmp_path / "inbox" / "clean"
    local = tmp_path / ".local"
    raw.mkdir(parents=True)
    clean.mkdir(parents=True)
    local.mkdir(parents=True)
    src = raw / "x.md"
    src.write_text("hello\n", encoding="utf-8")
    allow = tmp_path / "empty.txt"
    allow.write_text("", encoding="utf-8")

    real_anon = mod.anonymize_text

    def fake_anon(text, **kwargs):
        r = real_anon(text, **kwargs)
        r.residual_emails = ["leak@example.invalid"]
        r.residual = mod._det.ResidualReport(emails=["leak@example.invalid"])
        return r

    monkeypatch.setattr(mod, "anonymize_text", fake_anon)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", clean)
    monkeypatch.setattr(mod, "LOCAL_DIR", local)
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    map_path = local / "pii-map.json"
    code = mod.main([str(src), "--map", str(map_path), "--allowlist", str(allow)])
    assert code == 1
    assert not (clean / "x.md").exists()
    assert not map_path.is_file()


def test_csv_person_header_harvest(mod, pii_map, allowlist):
    text = "naam,email\nJane Doe,jane@example.invalid\n"
    result = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "Jane Doe" not in result.text
    assert "jane@example.invalid" not in result.text.lower()
    assert "PERSON_" in result.text


def test_harvest_single_token_flag(mod, pii_map, allowlist):
    text = "| **Reporter** | ExampleOrgA |\n"
    off = mod.anonymize_text(text, pii_map=pii_map, allowlist=allowlist, also_ip=False)
    assert "ExampleOrgA" in off.text
    pii_map2 = mod.PiiMap.load(pii_map.path)
    on = mod.anonymize_text(
        text,
        pii_map=pii_map2,
        allowlist=allowlist,
        also_ip=False,
        harvest_single_token=True,
        scrub_orgs=False,
    )
    assert "ExampleOrgA" not in on.text
    assert "PERSON_" in on.text


def test_expand_name_parts_scrubs_residual_firstname(mod, pii_map, allowlist):
    text = (
        "| **Reporter** | Sam Jansen |\n"
        "| **DESCRIPTION** | Sam will provide the excels |\n"
    )
    result = mod.anonymize_text(
        text, pii_map=pii_map, allowlist=allowlist, also_ip=False, scrub_orgs=False
    )
    assert "Sam Jansen" not in result.text
    assert "Sam will" not in result.text
    assert "PERSON_" in result.text
    # Same token for full name and residual first name
    assert result.text.count("PERSON_") >= 2


def test_org_scrub_default_list(mod, pii_map, allowlist):
    text = (
        "| **DESCRIPTION** | Imports (ExampleOrgA and ExampleOrgB) fail |\n"
        "| **TEST** | Select the ExampleOrgA import sheet |\n"
    )
    result = mod.anonymize_text(
        text,
        pii_map=pii_map,
        allowlist=allowlist,
        also_ip=False,
        scrub_orgs=True,
        org_scrublist=["ExampleOrgA", "ExampleOrgB"],
    )
    assert "ExampleOrgA" not in result.text
    assert "ExampleOrgB" not in result.text
    assert "ORG_" in result.text


def test_no_scrub_orgs_leaves_import_names(mod, pii_map, allowlist):
    text = "| **DESCRIPTION** | ExampleOrgA and ExampleOrgB imports |\n"
    result = mod.anonymize_text(
        text, pii_map=pii_map, allowlist=allowlist, also_ip=False, scrub_orgs=False
    )
    assert "ExampleOrgA" in result.text
    assert "ExampleOrgB" in result.text


def test_irreversible_does_not_save_map(mod, tmp_path):
    raw = tmp_path / "inbox" / "raw"
    clean = tmp_path / "inbox" / "clean"
    raw.mkdir(parents=True)
    clean.mkdir(parents=True)
    src = raw / "a.md"
    src.write_text("Mail a@example.invalid\n", encoding="utf-8")
    map_path = tmp_path / "pii-map.json"
    # Point defaults via argv paths only
    code = mod.main(
        [
            str(src),
            "--irreversible",
            "--force-path",
            "--out",
            str(clean / "a.md"),
            "--map",
            str(map_path),
            "--allowlist",
            str(mod.DEFAULT_ALLOWLIST),
        ]
    )
    assert code == 0
    assert (clean / "a.md").is_file()
    assert (
        "a@example.invalid"
        not in (clean / "a.md").read_text(encoding="utf-8").lower()
    )
    assert not map_path.is_file()


def test_map_crypto_roundtrip(tmp_path, monkeypatch):
    import pii_map_crypto as crypto

    monkeypatch.delenv("PII_MAP_ALLOW_PLAINTEXT", raising=False)
    key = crypto.generate_key()
    monkeypatch.setenv("PII_MAP_KEY", key.decode("ascii"))
    path = tmp_path / "pii-map.json"
    payload = {"counters": {"email": 1}, "emails": {"a@x.nl": "user_001@example.test"}}
    crypto.save_map_dict(path, payload, repo_root=tmp_path, create_key=False)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw.get("format") == "fernet-v1"
    assert "emails" not in raw
    data, status = crypto.load_map_dict(path, repo_root=tmp_path, require_key=True)
    assert status == "ok"
    assert data["emails"]["a@x.nl"] == "user_001@example.test"


def test_detect_only_map_unavailable(mod, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PII_MAP_ALLOW_PLAINTEXT", raising=False)
    key = __import__("pii_map_crypto", fromlist=["x"]).generate_key()
    monkeypatch.setenv("PII_MAP_KEY", key.decode("ascii"))
    map_path = tmp_path / "enc-map.json"
    import pii_map_crypto as crypto

    crypto.save_map_dict(
        map_path,
        {"counters": {}, "emails": {}},
        repo_root=tmp_path,
        create_key=False,
    )
    monkeypatch.delenv("PII_MAP_KEY", raising=False)

    stories = tmp_path / "src" / "stories" / "STORY-1000"
    stories.mkdir(parents=True)
    f = stories / "x.md"
    f.write_text("From noreply@example.invalid\n", encoding="utf-8")
    monkeypatch.setattr(mod, "STORIES_ROOT", tmp_path / "src" / "stories")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "LOCAL_DIR", tmp_path / ".local")
    allow = tmp_path / "a.txt"
    allow.write_text("noreply@example.invalid\n", encoding="utf-8")
    code = mod.main(
        [
            str(f),
            "--summary",
            "--map",
            str(map_path),
            "--allowlist",
            str(allow),
        ]
    )
    out = capsys.readouterr().out
    data = json.loads(out)
    assert code == 0
    assert data.get("map") == "unavailable"


def test_ner_skipped_when_unavailable(mod, pii_map, allowlist):
    result = mod.anonymize_text(
        "Hello Jane Doe in free text only\n",
        pii_map=pii_map,
        allowlist=allowlist,
        also_ip=False,
        harvest_names=False,
        use_ner=True,
    )
    # Without Presidio installed, status is skipped; Jane Doe may remain
    assert result.ner_status in {"skipped", "ok"}
    if result.ner_status == "skipped":
        assert "Jane Doe" in result.text


def test_expand_does_not_seed_deny_stopwords(mod, pii_map, allowlist):
    """Regression: expand must not add function words like not/will into the map."""
    pii_map.names["Sam Not Jansen"] = "PERSON_050"
    added = mod.expand_person_name_parts(pii_map)
    keys_lower = {k.lower() for k in pii_map.names}
    assert "not" not in keys_lower
    assert "will" not in keys_lower  # not in the full name; ensure we didn't invent it
    # Capitalized name parts may still expand
    assert any(k.lower() == "sam" for k in pii_map.names) or added >= 0
    text = "This is not a valid walk. Sam Not Jansen opened a case.\n"
    result = mod.anonymize_text(
        text,
        pii_map=pii_map,
        allowlist=allowlist,
        also_ip=False,
        harvest_names=False,
        scrub_orgs=False,
        expand_name_parts=True,
    )
    assert "is not a valid" in result.text
    assert "Sam Not Jansen" not in result.text
    assert "PERSON_050" in result.text


def test_expand_skips_embedded_will_particle_style(mod, pii_map):
    """If a multi-token name somehow included a deny word, expand skips it."""
    pii_map.names["Alex Will Smith"] = "PERSON_051"
    mod.expand_person_name_parts(pii_map)
    assert not any(k.lower() == "will" for k in pii_map.names)


def test_cli_per_file_summary_counts_only(mod, tmp_path, monkeypatch, capsys):
    stories = tmp_path / "src" / "stories" / "STORY-TEST"
    stories.mkdir(parents=True)
    (stories / "README.md").write_text(
        "Contact someone@corp.example and PERSON_001 already scrubbed.\n",
        encoding="utf-8",
    )
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "STORIES_ROOT", tmp_path / "src" / "stories")
    monkeypatch.setattr(mod, "DEFAULT_RAW", tmp_path / "inbox" / "raw")
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", tmp_path / "inbox" / "clean")
    (tmp_path / "inbox" / "raw").mkdir(parents=True)
    (tmp_path / "inbox" / "clean").mkdir(parents=True)

    code = mod.main(
        [
            str(stories),
            "--per-file-summary",
            "--force-path",
            "--map",
            str(tmp_path / "m.json"),
            "--allowlist",
            str(allow),
        ]
    )
    out = capsys.readouterr().out
    data = json.loads(out)
    assert code in (0, 1)
    assert data["mode"] == "per_file_summary"
    assert "by_file" in data
    blob = json.dumps(data)
    assert "@corp.example" not in blob  # no originals
    assert "someone@" not in blob


def test_cli_fail_on_prose_damage_poison_map(mod, tmp_path, monkeypatch, capsys):
    raw = tmp_path / "inbox" / "raw"
    raw.mkdir(parents=True)
    (raw / "a.md").write_text("This is not a valid walk.\n", encoding="utf-8")
    allow = tmp_path / "allow.txt"
    allow.write_text("", encoding="utf-8")
    map_path = tmp_path / "m.json"
    # Poison: deny-listed key in map (would have over-scrubbed before deny wiring)
    map_path.write_text(
        json.dumps({"emails": {}, "names": {"not": "PERSON_016"}, "usernames": {}, "phones": {}, "ibans": {}, "orgs": {}, "counters": {"person": 16}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DEFAULT_RAW", raw)
    monkeypatch.setattr(mod, "DEFAULT_CLEAN", tmp_path / "inbox" / "clean")
    (tmp_path / "inbox" / "clean").mkdir(parents=True)

    code = mod.main(
        [
            str(raw),
            "--dry-run",
            "--fail-on-prose-damage",
            "--map",
            str(map_path),
            "--allowlist",
            str(allow),
        ]
    )
    err = capsys.readouterr().err
    assert code == 1
    assert "prose-damage" in err.lower()
    assert "map_poison" in err or "poison" in err.lower()


def test_prose_damage_counts_zero_when_clean(mod, pii_map, allowlist):
    text = "This is not a valid walk. Contact user_001@example.test.\n"
    result = mod.anonymize_text(
        text, pii_map=pii_map, allowlist=allowlist, also_ip=False, harvest_names=False
    )
    from pathlib import Path as P

    pending = [(P("x.md"), result)]
    counts = mod.prose_damage_counts(
        result.hits, pending, original_texts={"x.md": text}
    )
    assert counts["stopword_loss"] == 0
    assert counts["stopword_name_hits"] == 0
    assert counts["total"] == 0
