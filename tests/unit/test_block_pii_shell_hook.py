"""Unit tests for .cursor/hooks/block-pii-shell.py decide()."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / ".cursor" / "hooks" / "block-pii-shell.py"


def _load():
    spec = importlib.util.spec_from_file_location("block_pii_shell", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["block_pii_shell"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def hook():
    return _load()


def test_allow_default_anonymize(hook):
    perm, _ = hook.decide("py -3 scripts/anonymize_intake.py inbox/raw")
    assert perm == "allow"


def test_allow_explicit_agent_safe_anonymize(hook):
    perm, _ = hook.decide("py -3 scripts/anonymize_intake.py inbox/raw --agent-safe")
    assert perm == "allow"


def test_deny_anonymize_with_report(hook):
    perm, msg = hook.decide(
        "py -3 scripts/anonymize_intake.py inbox/raw --report --dry-run"
    )
    assert perm == "deny"
    assert "--report" in msg or "report" in msg.lower()


def test_deny_report_before_script_name(hook):
    perm, _ = hook.decide("py -3 scripts/anonymize_intake.py --report inbox/raw")
    assert perm == "deny"


def test_deny_get_content_raw(hook):
    perm, _ = hook.decide("Get-Content inbox\\raw\\sys_email.xml")
    assert perm == "deny"


def test_deny_get_content_clean(hook):
    perm, _ = hook.decide("Get-Content inbox\\clean\\drop.md")
    assert perm == "deny"


def test_deny_cat_pii_map(hook):
    perm, _ = hook.decide("cat .local/pii-map.json")
    assert perm == "deny"


def test_allow_list_raw_dir(hook):
    perm, _ = hook.decide("Get-ChildItem inbox/raw")
    assert perm == "allow"


def test_allow_list_clean_dir(hook):
    perm, _ = hook.decide("Get-ChildItem inbox/clean")
    assert perm == "allow"


def test_allow_unrelated(hook):
    perm, _ = hook.decide("pytest tests/unit/test_anonymize_intake.py")
    assert perm == "allow"


def test_allow_copy_item_into_raw(hook):
    perm, _ = hook.decide(
        "Copy-Item -LiteralPath 'C:\\Users\\x\\Downloads\\a.xml' -Destination inbox\\raw\\"
    )
    assert perm == "allow"


def test_deny_summary_on_inbox_raw(hook):
    perm, msg = hook.decide("py -3 scripts/anonymize_intake.py inbox/raw --summary")
    assert perm == "deny"
    assert "inbox/raw" in msg.lower() or "not intake" in msg.lower()
    assert "--summary" in msg.lower() or "scrub" in msg.lower()


def test_allow_summary_on_stories(hook):
    perm, _ = hook.decide(
        "py -3 scripts/anonymize_intake.py src/stories --dry-run --fail-on-hits "
        "--force-path --summary"
    )
    assert perm == "allow"


def test_deny_irreversible(hook):
    perm, msg = hook.decide(
        "py -3 scripts/anonymize_intake.py inbox/raw --irreversible"
    )
    assert perm == "deny"
    assert "irreversible" in msg.lower() or "human" in msg.lower()


def test_deny_map_prune(hook):
    perm, msg = hook.decide(
        "py -3 scripts/anonymize_intake.py inbox/raw --map-prune-unused"
    )
    assert perm == "deny"
    assert "prune" in msg.lower() or "human" in msg.lower()


def test_deny_piimap_load_in_py_c(hook):
    perm, msg = hook.decide(
        'py -3 -c "from anonymize_intake import PiiMap; PiiMap.load(\'.local/pii-map.json\')"'
    )
    assert perm == "deny"
    assert "pii-map" in msg.lower() or "PiiMap" in msg or "decrypt" in msg.lower()


def test_deny_pii_map_crypto_import(hook):
    perm, msg = hook.decide(
        'python -c "import pii_map_crypto as c; c.load_map_dict(path)"'
    )
    assert perm == "deny"
    assert "map" in msg.lower()


def test_deny_py_c_with_pii_map_path(hook):
    perm, _ = hook.decide(
        'py -3 -c "print(open(\'.local/pii-map.json\').read())"'
    )
    assert perm == "deny"


def test_allow_anonymize_cli_with_map_flag(hook):
    perm, _ = hook.decide(
        "py -3 scripts/anonymize_intake.py inbox/raw --map .local/pii-map.json"
    )
    assert perm == "allow"


def test_allow_pytest_mentioning_map(hook):
    perm, _ = hook.decide("pytest tests/unit/test_anonymize_intake.py -q")
    assert perm == "allow"