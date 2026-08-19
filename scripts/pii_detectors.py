#!/usr/bin/env python3
"""Stdlib PII detectors shared by anonymize CLI and hooks (no Presidio / NER).

Covers phones, IBAN (mod-97), optional BSN (11-proef), MAC, NL postcode,
labeled DOB, and high-confidence residual scanning after scrub.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- Phones (NL / EU-ish; low-confidence → warn, not fail-write) ---
PHONE_RE = re.compile(
    r"(?<!\w)(?:"
    r"\+31[\s\-.]?(?:\d[\s\-.]?){8,9}\d"
    r"|0\d[\s\-.]?(?:\d[\s\-.]?){7,8}\d"
    r"|\+(?:1|3[0-9]|4[0-9]|5[0-9])[\s\-.]?(?:\d[\s\-.]?){7,12}\d"
    r")(?!\w)"
)

# --- IBAN (capture candidates; validate with mod-97) ---
# Prefer compact OR space-grouped forms; do not let [\s] eat newlines/words.
IBAN_RE = re.compile(
    r"\b("
    r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}"
    r"|[A-Z]{2}\d{2}(?:[ ][A-Z0-9]{4}){2,7}(?:[ ][A-Z0-9]{1,4})?"
    r")\b",
    re.IGNORECASE,
)

# --- BSN (9 digits; 11-proef) — opt-in / labeled-field only ---
BSN_LABELED_RE = re.compile(
    r"(?i)\b(?:bsn|burgerservicen(?:ummer)?)\b\s*[:=]?\s*(\d{8,9})\b"
)
BSN_BARE_RE = re.compile(r"(?<!\d)(\d{9})(?!\d)")

# --- MAC ---
MAC_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
)

# --- NL postcode + optional street context ---
NL_POSTCODE_RE = re.compile(
    r"\b([1-9]\d{3}\s?[A-Za-z]{2})\b"
)
NL_STREET_POSTCODE_RE = re.compile(
    r"(?i)\b([A-Za-zÀ-ÿ][A-Za-zÀ-ÿ\s\-']{2,40}\s+\d{1,5}[a-zA-Z]?)\s*,?\s*"
    r"([1-9]\d{3}\s?[A-Za-z]{2})\b"
)

# --- DOB in labeled fields ---
DOB_LABELED_RE = re.compile(
    r"(?i)\b(?:dob|date\s*of\s*birth|geboortedatum|birth\s*date)\b\s*[:=]?\s*"
    r"("
    r"\d{4}-\d{2}-\d{2}"
    r"|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}"
    r")"
)

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    re.IGNORECASE,
)


def iban_checksum_valid(iban: str) -> bool:
    """ISO 13616 mod-97 check (spaces/dashes ignored)."""
    compact = re.sub(r"[\s\-]", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    digits = ""
    for ch in rearranged:
        if ch.isdigit():
            digits += ch
        else:
            digits += str(ord(ch) - 55)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def bsn_elfproef_valid(bsn: str) -> bool:
    """Dutch BSN 11-proef (elfproef). Rejects all-zero / too-short."""
    s = bsn.strip()
    if not re.fullmatch(r"\d{8,9}", s):
        return False
    s = s.zfill(9)
    if s == "000000000":
        return False
    total = 0
    for i, ch in enumerate(s):
        weight = 9 - i
        if weight == 1:
            weight = -1
        total += int(ch) * weight
    return total % 11 == 0


def find_phones(text: str) -> list[str]:
    found: list[str] = []
    for m in PHONE_RE.finditer(text or ""):
        val = m.group(0)
        # Skip tokens already scrubbed
        if val.upper().startswith("PHONE_"):
            continue
        found.append(val)
    return found


def find_valid_ibans(text: str) -> list[str]:
    found: list[str] = []
    for m in IBAN_RE.finditer(text or ""):
        cand = m.group(1)
        if cand.upper().startswith("IBAN_"):
            continue
        if iban_checksum_valid(cand):
            found.append(cand)
    return found


def find_bsns(text: str, *, bare: bool = False) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in BSN_LABELED_RE.finditer(text or ""):
        cand = m.group(1)
        if bsn_elfproef_valid(cand) and cand not in seen:
            seen.add(cand)
            found.append(cand)
    if bare:
        for m in BSN_BARE_RE.finditer(text or ""):
            cand = m.group(1)
            if bsn_elfproef_valid(cand) and cand not in seen:
                seen.add(cand)
                found.append(cand)
    return found


def find_macs(text: str) -> list[str]:
    return MAC_RE.findall(text or "")


def find_nl_postcodes(text: str) -> list[str]:
    """Return street+postcode spans only (bare postcodes are too noisy for replace)."""
    found: list[str] = []
    seen: set[str] = set()
    for m in NL_STREET_POSTCODE_RE.finditer(text or ""):
        span = m.group(0)
        key = span.lower()
        if key not in seen:
            seen.add(key)
            found.append(span)
    return found


def find_bare_nl_postcodes(text: str) -> list[str]:
    """Bare NL postcodes for residual warn counts (not fail-write)."""
    return [m.group(1) for m in NL_POSTCODE_RE.finditer(text or "")]


def find_labeled_dobs(text: str) -> list[str]:
    return [m.group(1) for m in DOB_LABELED_RE.finditer(text or "")]


def find_residual_emails(text: str, allowlist: set[str] | None = None) -> list[str]:
    allow = {a.lower() for a in (allowlist or set())}
    out: list[str] = []
    for m in EMAIL_RE.findall(text or ""):
        low = m.lower()
        if low.endswith("@example.test"):
            continue
        if low in allow:
            continue
        out.append(m)
    return out


@dataclass
class ResidualReport:
    emails: list[str] = field(default_factory=list)
    ibans: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    bsns: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    postcodes: list[str] = field(default_factory=list)
    dobs: list[str] = field(default_factory=list)

    @property
    def high_confidence_count(self) -> int:
        """Hits that must abort write (email + checksum IBAN)."""
        return len(self.emails) + len(self.ibans)

    @property
    def warn_count(self) -> int:
        return (
            len(self.phones)
            + len(self.bsns)
            + len(self.macs)
            + len(self.postcodes)
            + len(self.dobs)
        )

    def counts_agent_safe(self) -> dict[str, int]:
        return {
            "residual_email": len(self.emails),
            "residual_iban": len(self.ibans),
            "residual_phone": len(self.phones),
            "residual_bsn": len(self.bsns),
            "residual_mac": len(self.macs),
            "residual_postcode": len(self.postcodes),
            "residual_dob": len(self.dobs),
        }


def scan_residuals(
    text: str,
    *,
    allowlist: set[str] | None = None,
    also_nl_id: bool = False,
    also_p2: bool = True,
) -> ResidualReport:
    """Scan scrubbed text for residuals.

    High-confidence (fail-write): non-allowlisted email, checksum-valid IBAN.
    Low-confidence (warn only): phones, optional BSN, MAC/postcode/DOB.
    """
    report = ResidualReport(
        emails=find_residual_emails(text, allowlist),
        ibans=find_valid_ibans(text),
        phones=find_phones(text),
    )
    if also_nl_id:
        report.bsns = find_bsns(text, bare=False)
    if also_p2:
        report.macs = find_macs(text)
        report.postcodes = find_nl_postcodes(text) + find_bare_nl_postcodes(text)
        report.dobs = find_labeled_dobs(text)
    return report
