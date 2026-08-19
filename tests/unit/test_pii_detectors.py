"""Stdlib detector unit tests (shared with CLI residual)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import pii_detectors as det  # noqa: E402


def test_iban_checksum():
    assert det.iban_checksum_valid("NL91ABNA0417164300")
    assert det.iban_checksum_valid("NL91 ABNA 0417 1643 00")
    assert not det.iban_checksum_valid("NL00ABNA0417164300")


def test_bsn_elfproef():
    assert det.bsn_elfproef_valid("000000000") is False
    assert det.bsn_elfproef_valid("123456789") is False
    # 123456782 is a commonly cited valid 11-proef example
    assert det.bsn_elfproef_valid("123456782") is True


def test_find_phones():
    text = "Bel +31 6 12345678 of 020-1234567"
    phones = det.find_phones(text)
    assert phones


def test_residual_high_confidence():
    r = det.scan_residuals(
        "mail leak@example.invalid and NL91ABNA0417164300 and +31612345678"
    )
    assert r.high_confidence_count >= 2
    assert r.warn_count >= 1
    assert r.counts_agent_safe()["residual_email"] >= 1
