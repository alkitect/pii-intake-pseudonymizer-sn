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


def test_find_labeled_machines():
    text = "hostname: host-a\nhost= box-b\n"
    machines = det.find_labeled_machines(text)
    assert "host-a" in machines
    assert "box-b" in machines


def test_find_absolute_paths():
    text = r"C:\Users\a\file.txt and /home/a/file.txt"
    paths = det.find_absolute_paths(text)
    assert any("C:\\Users" in p for p in paths)
    assert any("/home/a" in p for p in paths)


def test_find_command_lines():
    text = "py -3 scripts/foo.py\nplain line\n"
    cmds = det.find_command_lines(text)
    assert len(cmds) == 1
    assert "foo.py" in cmds[0]


def test_find_pem_blocks_whole_block():
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIB\n"
        "-----END CERTIFICATE-----\n"
    )
    blocks = det.find_pem_blocks(pem)
    assert len(blocks) == 1
    assert "BEGIN CERTIFICATE" in blocks[0]


def test_find_pem_blocks_skips_malformed():
    text = "-----BEGIN CERTIFICATE-----\nno end marker"
    assert det.find_pem_blocks(text) == []


def test_looks_like_sensitive_technical_paste():
    assert det.looks_like_sensitive_technical_paste("hostname: x\n") is True
    assert det.looks_like_sensitive_technical_paste("py -3 foo.py\n") is True
    assert det.looks_like_sensitive_technical_paste("-----BEGIN CERTIFICATE-----\n") is True
    assert det.looks_like_sensitive_technical_paste(r"C:\Users\a\file.txt") is True
    assert det.looks_like_sensitive_technical_paste("plain prose only") is False
