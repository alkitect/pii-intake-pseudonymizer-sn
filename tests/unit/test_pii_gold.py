"""Gold-set: always assert stdlib recall; NER runs if importable (skip ≠ pass)."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GOLD = REPO / "tests" / "fixtures" / "pii-gold" / "nl_synthetic.md"
GOLD_XML = REPO / "tests" / "fixtures" / "pii-gold" / "sn_display_value.xml"
GOLD_DIR = REPO / "tests" / "fixtures" / "pii-gold"
SCRIPT = REPO / "scripts" / "anonymize_intake.py"


def _load_mod():
    os.environ["PII_MAP_ALLOW_PLAINTEXT"] = "1"
    scripts = str(REPO / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    for name in list(sys.modules):
        if name in {"anonymize_intake", "pii_map_crypto", "pii_detectors", "pii_ner"}:
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


def test_gold_stdlib_email_phone_iban_reporter(mod, tmp_path):
    text = GOLD.read_text(encoding="utf-8")
    pii_map = mod.PiiMap.load(tmp_path / "map.json")
    result = mod.anonymize_text(
        text,
        pii_map=pii_map,
        allowlist=set(),
        also_ip=False,
        also_nl_id=True,
        also_p2=True,
    )
    assert "jane.doe@example.invalid" not in result.text.lower()
    assert "+31 6 12345678" not in result.text
    assert "NL91ABNA0417164300".lower() not in result.text.replace(" ", "").lower()
    assert "IBAN_" in result.text
    assert "Jane Doe" not in result.text
    assert result.residual is not None
    assert result.residual.high_confidence_count == 0


def test_gold_lock_lists_fixtures():
    lock = (GOLD_DIR / "LOCK.txt").read_text(encoding="utf-8")
    assert "nl_synthetic.md" in lock
    assert "sn_display_value.xml" in lock
    assert GOLD.is_file()
    assert GOLD_XML.is_file()


def test_gold_sn_display_value_email(mod, tmp_path):
    text = GOLD_XML.read_text(encoding="utf-8")
    pii_map = mod.PiiMap.load(tmp_path / "map.json")
    # Seed map so labeled display names scrub without NER
    pii_map.name_token("Alex Example")
    result = mod.anonymize_text(
        text,
        pii_map=pii_map,
        allowlist=set(),
        also_ip=False,
        harvest_names=True,
    )
    assert "alex.example@example.invalid" not in result.text.lower()
    assert "Alex Example" not in result.text
    assert "PERSON_" in result.text or "user_001@" in result.text.lower()


def test_gold_ner_if_available(mod, tmp_path):
    try:
        import pii_ner as ner
    except ImportError:
        pytest.skip("pii_ner import failed")
    if not ner.ner_available():
        pytest.skip(
            "Presidio not installed — human verify ladder; merge gate is stdlib-only"
        )
    text = "Hello Jane Doe, please review.\n"
    pii_map = mod.PiiMap.load(tmp_path / "map.json")
    result = mod.anonymize_text(
        text,
        pii_map=pii_map,
        allowlist=set(),
        also_ip=False,
        harvest_names=False,
        use_ner=True,
    )
    assert result.ner_status == "ok"
    assert "Jane Doe" not in result.text
    assert "PERSON_" in result.text
