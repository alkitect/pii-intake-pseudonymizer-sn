#!/usr/bin/env python3
"""Local offline PII intake pseudonymizer for inbox intake.

Drop files in inbox/raw/, run this script, use inbox/clean/ or --promote.
Successful writes from inbox/raw delete scrubbed sources by default (--keep-raw to retain).
inbox/clean is this-run staging: leftovers are pruned after a successful write
(--keep-clean to retain). --promote copies then clears staging (never deletes src/stories).
Use --in-place to rewrite story docs under src/stories (path-preserving).
Detect-only gate: --summary --dry-run --fail-on-hits on src/stories paths
(redacted counts only; never use --report in gates).
Default mode is agent-safe (counts-only stdout). Opt into human hit lists with --report.
Harvests labeled Jira/SN person-field names (slash/comma/bullets) into the map.
Optional --ner (Presidio) is OFF by default. Map is encrypted at rest (key outside sync).
Never commit .local/pii-map.json. Mapped tokens are pseudonyms, not anonymous.

See README.md for install, inbox/raw intake, and src/stories commit-gate usage.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import hmac
import io
import ipaddress
import json
import re
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure scripts/ is importable when loaded as a file path from tests.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import intake_manifest as _manifest  # noqa: E402
import pii_detectors as _det  # noqa: E402
import pii_map_crypto as _crypto  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW = REPO_ROOT / "inbox" / "raw"
DEFAULT_CLEAN = REPO_ROOT / "inbox" / "clean"
DEFAULT_MAP = REPO_ROOT / ".local" / "pii-map.json"
DEFAULT_ALLOWLIST = REPO_ROOT / "config" / "pii-allowlist.txt"
DEFAULT_ORG_SCRUB = REPO_ROOT / "config" / "pii-org-scrub.txt"
DEFAULT_PERSON_FIELDS = REPO_ROOT / "config" / "pii-person-fields.json"
DEFAULT_NER_CONFIG = REPO_ROOT / "config" / "pii-ner.json"
DEFAULT_AUDIT = REPO_ROOT / ".local" / "pii-map-audit.jsonl"
STORIES_ROOT = REPO_ROOT / "src" / "stories"
LOCAL_DIR = REPO_ROOT / ".local"
EXPORT_DIR_NAMES = frozenset({"source-export", "source_export"})
INTAKE_WRITE_CMD = "py -3 scripts/anonymize_intake.py inbox/raw"
MSG_SUMMARY_NOT_INTAKE = (
    "--summary is the commit detect-only gate (src/stories only), not intake. "
    f"To scrub: {INTAKE_WRITE_CMD}"
)
MSG_SUMMARY_NOT_IN_PLACE = (
    "--summary never authorizes --in-place. Detect-only gate reports counts only; "
    "backfill is a separate deliberate --in-place run (prefer one subtree after dry-run)."
)

# High-risk stopwords for --fail-on-prose-damage before/after probes (counts only).
# Subset of _NAME_REPLACE_DENY — keep small for performance.
_PROSE_DAMAGE_PROBE = frozenset(
    {
        "not",
        "user",
        "test",
        "the",
        "and",
        "or",
        "for",
        "are",
        "was",
        "can",
        "has",
        "had",
        "but",
        "its",
        "our",
        "any",
        "all",
        "new",
        "old",
        "set",
        "get",
        "use",
        "run",
        "valid",
        "invalid",
        "niet",
        "voor",
        "met",
        "ook",
        "als",
    }
)

EMAIL_SIMPLE_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    re.IGNORECASE,
)
SYS_USER_TAG_RE = re.compile(
    r"(<(?:sys_created_by|sys_updated_by)>)([^<]+)(</(?:sys_created_by|sys_updated_by)>)",
    re.IGNORECASE,
)
JSON_USER_RE = re.compile(
    r'("(?:sys_created_by|sys_updated_by)"\s*:\s*")([^"]+)(")',
    re.IGNORECASE,
)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
# Rough IPv6 (full and compressed); validated with ipaddress
IPV6_CANDIDATE_RE = re.compile(
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:[0-9A-Fa-f]{0,4}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"
)

TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".xml",
    ".html",
    ".htm",
    ".json",
    ".js",
    ".eml",
    ".csv",
    ".tsv",
    ".log",
    ".yml",
    ".yaml",
}

# Binary intake — never treat as text; count skips (not scrubbed).
BINARY_INTAKE_SUFFIXES = {
    ".xlsx",
    ".xls",
    ".pdf",
}


_DEFAULT_COUNTERS = {
    "email": 0,
    "username": 0,
    "person": 0,
    "org": 0,
    "ip": 0,
    "phone": 0,
    "iban": 0,
    "bsn": 0,
    "mac": 0,
    "postcode": 0,
    "dob": 0,
}


@dataclass
class PiiMap:
    path: Path
    counters: dict[str, int] = field(default_factory=dict)
    emails: dict[str, str] = field(default_factory=dict)
    usernames: dict[str, str] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    orgs: dict[str, str] = field(default_factory=dict)
    ips: dict[str, str] = field(default_factory=dict)
    phones: dict[str, str] = field(default_factory=dict)
    ibans: dict[str, str] = field(default_factory=dict)
    bsns: dict[str, str] = field(default_factory=dict)
    macs: dict[str, str] = field(default_factory=dict)
    postcodes: dict[str, str] = field(default_factory=dict)
    dobs: dict[str, str] = field(default_factory=dict)
    status: str = "ok"  # ok | missing | unavailable | plaintext
    irreversible: bool = False
    _ephemeral_hmac_key: bytes = field(default_factory=lambda: b"", repr=False)

    @classmethod
    def empty(cls, path: Path, *, status: str = "missing", irreversible: bool = False) -> PiiMap:
        return cls(
            path=path,
            counters=dict(_DEFAULT_COUNTERS),
            status=status,
            irreversible=irreversible,
        )

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        require_key: bool = False,
        irreversible: bool = False,
    ) -> PiiMap:
        if irreversible:
            return cls.empty(path, status="irreversible", irreversible=True)

        data, status = _crypto.load_map_dict(path, repo_root=REPO_ROOT, require_key=require_key)
        if status in {"unavailable", "missing"} and not data:
            return cls.empty(path, status=status)

        counters = dict(_DEFAULT_COUNTERS)
        counters.update({k: int(v) for k, v in (data.get("counters") or {}).items()})
        # Drop legacy unused salt if present in plaintext migrate payloads
        return cls(
            path=path,
            counters=counters,
            emails={k.lower(): v for k, v in (data.get("emails") or {}).items()},
            usernames={k.lower(): v for k, v in (data.get("usernames") or {}).items()},
            names=dict(data.get("names") or {}),
            orgs={k: v for k, v in (data.get("orgs") or {}).items()},
            ips=dict(data.get("ips") or {}),
            phones={k.lower(): v for k, v in (data.get("phones") or {}).items()},
            ibans={k.upper().replace(" ", ""): v for k, v in (data.get("ibans") or {}).items()},
            bsns=dict(data.get("bsns") or {}),
            macs={k.lower(): v for k, v in (data.get("macs") or {}).items()},
            postcodes={k.lower(): v for k, v in (data.get("postcodes") or {}).items()},
            dobs=dict(data.get("dobs") or {}),
            status=status,
        )

    def to_payload(self) -> dict[str, Any]:
        # No salt field (removed after encrypt migrate — do not reserve fake crypto).
        return {
            "counters": self.counters,
            "emails": self.emails,
            "usernames": self.usernames,
            "names": self.names,
            "orgs": self.orgs,
            "ips": self.ips,
            "phones": self.phones,
            "ibans": self.ibans,
            "bsns": self.bsns,
            "macs": self.macs,
            "postcodes": self.postcodes,
            "dobs": self.dobs,
        }

    def save(self) -> None:
        if self.irreversible:
            return
        _crypto.save_map_dict(self.path, self.to_payload(), repo_root=REPO_ROOT, create_key=True)
        self.status = "ok"

    def prune_unused(self, used_tokens: set[str]) -> int:
        """Drop map entries whose token is not in used_tokens. Return removed count."""
        removed = 0

        def _prune(store: dict[str, str]) -> None:
            nonlocal removed
            drop = [k for k, v in store.items() if v not in used_tokens]
            for k in drop:
                del store[k]
                removed += 1

        _prune(self.emails)
        _prune(self.usernames)
        _prune(self.names)
        _prune(self.orgs)
        _prune(self.ips)
        _prune(self.phones)
        _prune(self.ibans)
        _prune(self.bsns)
        _prune(self.macs)
        _prune(self.postcodes)
        _prune(self.dobs)
        return removed

    def _next(self, kind: str) -> int:
        self.counters[kind] = int(self.counters.get(kind, 0)) + 1
        return self.counters[kind]

    def _irreversible_token(self, kind: str, value: str) -> str:
        if not self._ephemeral_hmac_key:
            self._ephemeral_hmac_key = hashlib.sha256(
                b"irreversible-ephemeral|" + str(self.path).encode()
            ).digest()
        digest = hmac.new(
            self._ephemeral_hmac_key, f"{kind}|{value}".encode(), hashlib.sha256
        ).hexdigest()[:10]
        return f"REDACTED_{kind.upper()}_{digest}"

    def email_token(self, email: str) -> str:
        key = email.lower()
        if key not in self.emails:
            if self.irreversible:
                self.emails[key] = self._irreversible_token("email", key)
            else:
                n = self._next("email")
                local = email.split("@", 1)[0]
                if local.lower().startswith("uhmaskedaddr_"):
                    self.emails[key] = f"UHMASKEDADDR_user_{n:03d}@example.test"
                else:
                    self.emails[key] = f"user_{n:03d}@example.test"
        return self.emails[key]

    def username_token(self, username: str) -> str:
        key = username.lower()
        if key not in self.usernames:
            if self.irreversible:
                self.usernames[key] = self._irreversible_token("username", key)
            else:
                n = self._next("username")
                self.usernames[key] = f"username_{n:03d}"
        return self.usernames[key]

    def name_token(self, name: str) -> str:
        if is_pseudo_token(name):
            return name.strip()
        if name.strip().lower() in _NAME_REPLACE_DENY:
            return name
        if name not in self.names:
            for existing, token in self.names.items():
                if existing.lower() == name.lower():
                    self.names[name] = token
                    return token
            if self.irreversible:
                self.names[name] = self._irreversible_token("person", name.lower())
            else:
                n = self._next("person")
                self.names[name] = f"PERSON_{n:03d}"
        return self.names[name]

    def org_token(self, org: str) -> str:
        """Stable ORG_NNN for company / import / product names."""
        if org not in self.orgs:
            for existing, token in self.orgs.items():
                if existing.lower() == org.lower():
                    self.orgs[org] = token
                    return token
            if self.irreversible:
                self.orgs[org] = self._irreversible_token("org", org.lower())
            else:
                n = self._next("org")
                self.orgs[org] = f"ORG_{n:03d}"
        return self.orgs[org]

    def ip_token(self, ip: str, version: int) -> str:
        if ip not in self.ips:
            if self.irreversible:
                self.ips[ip] = self._irreversible_token("ip", ip)
            elif version == 4:
                n = self._next("ip")
                self.ips[ip] = f"203.0.113.{(n % 254) + 1}"
            else:
                n = self._next("ip")
                self.ips[ip] = f"2001:db8::{n:x}"
        return self.ips[ip]

    def phone_token(self, phone: str) -> str:
        key = re.sub(r"\s+", "", phone.lower())
        if key not in self.phones:
            if self.irreversible:
                self.phones[key] = self._irreversible_token("phone", key)
            else:
                n = self._next("phone")
                self.phones[key] = f"PHONE_{n:03d}"
        return self.phones[key]

    def iban_token(self, iban: str) -> str:
        key = re.sub(r"[\s\-]", "", iban).upper()
        if key not in self.ibans:
            if self.irreversible:
                self.ibans[key] = self._irreversible_token("iban", key)
            else:
                n = self._next("iban")
                self.ibans[key] = f"IBAN_{n:03d}"
        return self.ibans[key]

    def bsn_token(self, bsn: str) -> str:
        key = bsn.strip()
        if key not in self.bsns:
            if self.irreversible:
                self.bsns[key] = self._irreversible_token("bsn", key)
            else:
                n = self._next("bsn")
                self.bsns[key] = f"0000000{n:02d}"
        return self.bsns[key]

    def mac_token(self, mac: str) -> str:
        key = mac.lower()
        if key not in self.macs:
            if self.irreversible:
                self.macs[key] = self._irreversible_token("mac", key)
            else:
                n = self._next("mac")
                self.macs[key] = f"00:00:5e:00:53:{n:02x}"
        return self.macs[key]

    def postcode_token(self, value: str) -> str:
        key = value.lower()
        if key not in self.postcodes:
            if self.irreversible:
                self.postcodes[key] = self._irreversible_token("postcode", key)
            else:
                n = self._next("postcode")
                self.postcodes[key] = (
                    f"9999 XX{n:02d}" if " " in value or len(value) > 6 else f"9999XX{n:02d}"
                )
        return self.postcodes[key]

    def dob_token(self, value: str) -> str:
        key = value.strip()
        if key not in self.dobs:
            if self.irreversible:
                self.dobs[key] = self._irreversible_token("dob", key)
            else:
                n = self._next("dob")
                self.dobs[key] = f"1900-01-{(n % 28) + 1:02d}"
        return self.dobs[key]


def load_allowlist(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    items: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        items.add(s.lower())
    return items


def is_allowlisted(value: str, allowlist: set[str]) -> bool:
    return value.lower() in allowlist


def load_org_scrublist(path: Path) -> list[str]:
    """Org/import/product names to scrub (preserve order; longest replaced first)."""
    if not path.is_file():
        return []
    items: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        items.append(s)
    return items


def load_person_fields_config(path: Path | None = None) -> dict[str, Any]:
    p = path or DEFAULT_PERSON_FIELDS
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _compile_person_xml_re(tags: list[str]) -> re.Pattern[str]:
    alt = "|".join(re.escape(t) for t in tags) or "opened_by"
    return re.compile(
        rf"<(?P<tag>{alt})\b[^>]*\bdisplay_value=(['\"])(?P<val>.*?)\2",
        re.IGNORECASE | re.DOTALL,
    )


def _compile_person_json_re(keys: list[str]) -> re.Pattern[str]:
    alt = "|".join(re.escape(k) for k in keys) or "opened_by"
    return re.compile(
        rf'"(?:{alt})"\s*:\s*\{{[^{{}}]*?"display_value"\s*:\s*"(?P<val>[^"]+)"',
        re.IGNORECASE | re.DOTALL,
    )


def _compile_person_label_re(labels: list[str]) -> re.Pattern[str]:
    parts: list[str] = []
    for lab in labels:
        parts.append(re.escape(lab).replace(r"\ ", r"\s+"))
    alt = "|".join(parts) or "reporter"
    return re.compile(rf"(?is)^\s*(?:{alt})(?:\s*\([^)]*\))?\s*:?\s*$")


_PERSON_FIELDS_CFG = load_person_fields_config()
_XML_TAGS = list(
    _PERSON_FIELDS_CFG.get("xml_display_tags")
    or [
        "opened_by",
        "requested_for",
        "caller_id",
        "assigned_to",
        "consumer",
        "closed_by",
        "contact",
        "watch_list",
    ]
)
_JSON_KEYS = list(
    _PERSON_FIELDS_CFG.get("json_display_keys")
    or [
        "opened_by",
        "requested_for",
        "caller_id",
        "assigned_to",
        "consumer",
        "closed_by",
        "contact",
        "watch_list",
    ]
)
_CSV_HEADERS = {
    h.lower()
    for h in (
        _PERSON_FIELDS_CFG.get("csv_person_headers")
        or [
            "naam",
            "name",
            "caller",
            "reporter",
            "assignee",
            "contact",
        ]
    )
}
_LABEL_LIST = list(
    _PERSON_FIELDS_CFG.get("person_field_labels")
    or [
        "reporter",
        "reporters",
        "stakeholder",
        "stakeholders",
        "assignee",
        "assignees",
        "assigned to",
        "opened by",
        "requested for",
        "caller",
        "caller id",
        "consumer",
        "contact",
        "submitted by",
        "watch list",
        "reported by",
    ]
)

MIN_PERSON_NAME_LEN = 4
# Parts expanded from a multi-token PERSON entry (e.g. Sam from "Sam Jansen").
MIN_PERSON_PART_LEN = 3

# Already-scrubbed tokens — never re-harvest / re-map / plain-replace these.
_PSEUDO_TOKEN_RE = re.compile(
    r"^(?:"
    r"PERSON_(?:SHORT|\d+)"
    r"|ORG_\d+"
    r"|username_\d+"
    r"|PHONE_\d+"
    r"|IBAN_\d+"
    r"|REDACTED_[A-Z]+_[0-9a-f]+"
    r"|(?:UHMASKEDADDR_)?user_\d+@example\.test"
    r")$",
    re.IGNORECASE,
)


def is_pseudo_token(value: str) -> bool:
    """True for stable scrub tokens (PERSON_001, user_001@example.test, …)."""
    s = (value or "").strip()
    return bool(s) and bool(_PSEUDO_TOKEN_RE.fullmatch(s))


# Particles kept inside harvested display names (NL/EN/DE).
_NAME_PARTICLES = frozenset(
    {
        "van",
        "de",
        "der",
        "den",
        "het",
        "ter",
        "ten",
        "te",
        "tot",
        "von",
        "da",
        "di",
        "dos",
        "das",
        "del",
        "la",
        "le",
        "el",
        "'t",
        "t",
    }
)

# Never plain-replace / expand these — collide with docs, emails, code identifiers.
_NAME_REPLACE_DENY = frozenset(
    {
        "test",
        "user",
        "users",
        "name",
        "names",
        "person",
        "people",
        "email",
        "mail",
        "admin",
        "system",
        "guest",
        "true",
        "false",
        "null",
        "none",
        "data",
        "file",
        "path",
        "type",
        "code",
        "case",
        "from",
        "with",
        "that",
        "this",
        "when",
        "what",
        "will",
        "have",
        "been",
        "were",
        "your",
        "into",
        "only",
        "also",
        "over",
        "such",
        "than",
        "then",
        "them",
        "they",
        "their",
        "there",
        "where",
        "which",
        "while",
        "about",
        "after",
        "before",
        "under",
        "above",
        "other",
        "value",
        "field",
        "label",
        "error",
        "event",
        "script",
        "action",
        "record",
        "table",
        "update",
        "create",
        "delete",
        "import",
        "export",
        "config",
        "default",
        "example",
        "sample",
        "string",
        "number",
        "object",
        "array",
        "boolean",
        "return",
        "class",
        "function",
        "method",
        "module",
        "package",
        "service",
        "client",
        "server",
        "request",
        "response",
        "status",
        "state",
        "order",
        "group",
        "role",
        "team",
        "core",
        "portal",
        "original",
        # Function words (EN/NL) — expand/plain-replace must never touch these
        "the",
        "and",
        "or",
        "not",
        "for",
        "are",
        "was",
        "can",
        "may",
        "has",
        "had",
        "does",
        "did",
        "but",
        "its",
        "his",
        "her",
        "our",
        "any",
        "all",
        "each",
        "both",
        "few",
        "more",
        "most",
        "some",
        "such",
        "no",
        "nor",
        "own",
        "same",
        "so",
        "too",
        "very",
        "just",
        "also",
        "how",
        "why",
        "who",
        "whom",
        "via",
        "per",
        "new",
        "old",
        "raw",
        "set",
        "get",
        "put",
        "add",
        "use",
        "used",
        "using",
        "run",
        "runs",
        "step",
        "flow",
        "form",
        "page",
        "link",
        "list",
        "item",
        "left",
        "right",
        "side",
        "open",
        "opened",
        "valid",
        "invalid",
        "dot",
        "walk",
        "see",
        "below",
        "above",
        "section",
        "summary",
        "fix",
        "fixes",
        "notes",
        "een",
        "van",
        "het",
        "een",
        "voor",
        "met",
        "niet",
        "ook",
        "nog",
        "als",
        "bij",
        "uit",
        "aan",
        "tot",
        "door",
        "naar",
        "deze",
        "die",
        "dat",
    }
)

_TICKET_OR_ID_RE = re.compile(
    r"^(?:INC|RITM|REQ|TASK|CS|ESM|STRY|PRB|KB|CHG)\d+$",
    re.IGNORECASE,
)
_SYS_ID_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

_PERSON_FIELD_LABEL_RE = _compile_person_label_re(_LABEL_LIST)

_TEST_WITH_RE = re.compile(
    r"(?i)\btest(?:ed)?\s+with\s+([^:<\n]+?)(?:\s*:|\s*$)",
)

_PERSON_XML_DISPLAY_RE = _compile_person_xml_re(_XML_TAGS)
_PERSON_JSON_DISPLAY_RE = _compile_person_json_re(_JSON_KEYS)

_MD_TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$", re.MULTILINE)

_HEADING_BULLETS_RE = re.compile(
    r"(?im)^[ \t]*(?:#{1,6}[ \t]+)?\*{0,2}[ \t]*(?P<label>[^\n|*]{2,80}?):\*{0,2}[ \t]*\n"
    r"(?P<body>(?:[ \t]*[-*•].+(?:\n|$))+)"
)

_LIST_SPLIT_RE = re.compile(
    r"\s*(?:[/;,]|&|\band\b|\ben\b)\s*",
    re.IGNORECASE,
)


def _strip_markup(blob: str) -> str:
    s = html.unescape(blob)
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.IGNORECASE)
    s = re.sub(r"</?p>", "\n", s, flags=re.IGNORECASE)
    s = re.sub(r"<li[^>]*>", "\n- ", s, flags=re.IGNORECASE)
    s = re.sub(r"<[^>]+>", " ", s)
    s = s.replace("**", "").replace("__", "")
    return s.strip()


def _normalize_field_label(label: str) -> str:
    s = _strip_markup(label)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def looks_like_person_name(value: str, *, allow_single_token: bool = False) -> bool:
    """True for display names (capitalized, optional NL/EN particles).

    Stdlib default requires ≥2 letter words. Single-token only when
    ``allow_single_token`` (CLI flag / NER path).
    """
    s = _strip_markup(value)
    s = re.sub(r"\s+", " ", s).strip(" \t.:;,-")
    min_len = MIN_PERSON_PART_LEN if allow_single_token else MIN_PERSON_NAME_LEN
    if len(s) < min_len or len(s) > 80:
        return False
    if is_pseudo_token(s):
        return False
    if s.lower() in _NAME_REPLACE_DENY:
        return False
    if _TICKET_OR_ID_RE.match(s.replace(" ", "")) or _SYS_ID_RE.match(s):
        return False
    if re.search(r"https?://|www\.", s, re.IGNORECASE):
        return False
    tokens = s.split()
    max_tokens = 5
    min_tokens = 1 if allow_single_token else 2
    if not min_tokens <= len(tokens) <= max_tokens:
        return False
    letter_words = 0
    for tok in tokens:
        raw = tok.strip(".,;:'\"()")
        if not raw:
            return False
        low = raw.lower()
        if low in _NAME_PARTICLES:
            continue
        if raw.isupper() and len(raw) <= 5:
            return False
        if not re.match(r"^[A-ZÀ-Ý]", raw):
            return False
        if re.search(r"\d", raw):
            return False
        letter_words += 1
    need = 1 if allow_single_token else 2
    return letter_words >= need


def split_person_list(blob: str, *, allow_single_token: bool = False) -> list[str]:
    """Split slash / comma / semicolon / bullet / 'and'/'en' lists into names."""
    text = _strip_markup(blob)
    found: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        line = re.sub(r"^[-*•]+\s*", "", line).strip()
        if not line:
            continue
        pieces = [p for p in _LIST_SPLIT_RE.split(line) if p.strip()]
        if not pieces:
            pieces = [line]
        for piece in pieces:
            cand = piece.strip().strip(".:;")
            key = cand.lower()
            if key in seen:
                continue
            if looks_like_person_name(cand, allow_single_token=allow_single_token):
                seen.add(key)
                found.append(cand)
    return found


def harvest_csv_person_headers(
    text: str,
    allowlist: set[str] | None = None,
    *,
    allow_single_token: bool = False,
) -> list[str]:
    """Harvest cells under person-like CSV/TSV headers (naam, caller, …)."""
    allow = allowlist or set()
    found: list[str] = []
    seen: set[str] = set()
    sample = text[:4096]
    if "," not in sample and "\t" not in sample:
        return found
    dialect = csv.excel_tab if sample.count("\t") > sample.count(",") else csv.excel
    try:
        reader = csv.reader(io.StringIO(text), dialect=dialect)
        rows = list(reader)
    except csv.Error:
        return found
    if not rows:
        return found
    headers = [h.strip().lower() for h in rows[0]]
    idxs = [i for i, h in enumerate(headers) if h in _CSV_HEADERS]
    if not idxs:
        return found
    for row in rows[1:]:
        for i in idxs:
            if i >= len(row):
                continue
            cell = row[i].strip()
            if not cell or is_allowlisted(cell, allow):
                continue
            for n in split_person_list(cell, allow_single_token=allow_single_token):
                key = n.lower()
                if key in seen:
                    continue
                seen.add(key)
                found.append(n)
            if looks_like_person_name(cell, allow_single_token=allow_single_token):
                key = cell.lower()
                if key not in seen:
                    seen.add(key)
                    found.append(cell)
    return found


def harvest_person_names(
    text: str,
    allowlist: set[str] | None = None,
    *,
    allow_single_token: bool = False,
) -> list[str]:
    """Pull display names from Jira/SN person fields — not from free-text DESCRIPTION.

    Covers markdown table cells, heading + bullets, Test with …, XML/JSON display_value,
    CSV/TSV person headers. Splitters: slash, comma, semicolon, bullets, and/en.
    """
    allow = allowlist or set()
    found: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        cand = _strip_markup(name)
        cand = re.sub(r"\s+", " ", cand).strip(" \t.:;")
        if not cand or is_allowlisted(cand, allow):
            return
        key = cand.lower()
        if key in seen:
            return
        if not looks_like_person_name(cand, allow_single_token=allow_single_token):
            return
        seen.add(key)
        found.append(cand)

    def _add_all(blob: str) -> None:
        for n in split_person_list(blob, allow_single_token=allow_single_token):
            _add(n)

    for row in _MD_TABLE_ROW_RE.finditer(text):
        raw = row.group(1)
        cols = [c.strip() for c in raw.split("|")]
        if len(cols) < 2:
            continue
        label = _normalize_field_label(cols[0])
        if _PERSON_FIELD_LABEL_RE.match(label):
            _add_all("|".join(cols[1:]))

    for m in _HEADING_BULLETS_RE.finditer(text):
        label = _normalize_field_label(m.group("label"))
        if _PERSON_FIELD_LABEL_RE.match(label):
            _add_all(m.group("body"))

    for m in _TEST_WITH_RE.finditer(text):
        _add_all(m.group(1))

    for m in _PERSON_XML_DISPLAY_RE.finditer(text):
        _add_all(m.group("val"))

    for m in _PERSON_JSON_DISPLAY_RE.finditer(text):
        _add_all(m.group("val"))

    for n in harvest_csv_person_headers(
        text, allow, allow_single_token=allow_single_token
    ):
        _add(n)

    return found


def expand_person_name_parts(pii_map: PiiMap) -> int:
    """From multi-token PERSON entries, seed first/last tokens to the same PERSON_NNN.

    Skips particles (van/de/…), digits, and tiny fragments. Enables residual
    \"Sam will…\" scrubbing after \"Sam Jansen\" was harvested as a full name.
    Does not invent new PERSON counters — parts reuse the full-name token.
    """
    added = 0
    multi = [(k, v) for k, v in list(pii_map.names.items()) if len(k.split()) >= 2]
    for full, token in multi:
        if token.startswith("PERSON_SHORT"):
            continue
        for tok in full.split():
            raw = tok.strip(".,;:'\"()")
            if not raw:
                continue
            low = raw.lower()
            if low in _NAME_PARTICLES:
                continue
            if low in _NAME_REPLACE_DENY:
                continue
            if len(raw) < MIN_PERSON_PART_LEN:
                continue
            if raw.isupper() and len(raw) <= 5:
                continue
            if re.search(r"\d", raw):
                continue
            if not re.match(r"^[A-Za-zÀ-ÿ]", raw):
                continue
            # Case-insensitive: keep first mapping if conflict across people
            existing_token: str | None = None
            for ek, ev in pii_map.names.items():
                if ek.lower() == low:
                    existing_token = ev
                    break
            if existing_token is None:
                pii_map.names[raw] = token
                added += 1
            elif existing_token == token and raw not in pii_map.names:
                pii_map.names[raw] = token
                added += 1
    return added


def _match_inside_email(m: re.Match[str]) -> bool:
    """True if the match is the local-part or a domain label of an email-like token.

    Prevents seeded/harvested names such as ``test`` from corrupting
    ``user_001@example.test`` into ``user_001@example.PERSON_001`` (which then
    fails residual email checks as ``…@example.PERSON``).
    """
    s = m.string
    start, end = m.start(), m.end()
    if end < len(s) and s[end] == "@":
        return True
    j = start - 1
    while j >= 0 and s[j] not in " \t\n\r<>,\"'()[]{}":
        if s[j] == "@":
            return True
        j -= 1
    return False


def _word_count(text: str, word: str) -> int:
    return len(re.findall(rf"\b{re.escape(word)}\b", text, flags=re.IGNORECASE))


def prose_damage_counts(
    hits: list[Hit],
    pending: list[tuple[Path, AnonymizeResult]] | None = None,
    *,
    original_texts: dict[str, str] | None = None,
) -> dict[str, int]:
    """Counts-only prose-damage signals (never includes originals).

    - stopword_name_hits / short_name_hits: name/org/username replacements of
      deny-listed or tiny tokens (should be zero when deny wiring is correct).
    - stopword_loss: probe words that disappeared from input→output (over-scrub).
    - map_poison_keys: unused here; callers may add via map_poison_key_count().
    """
    stopword_name_hits = 0
    short_name_hits = 0
    for h in hits:
        if h.kind not in ("name", "org", "username"):
            continue
        o = (h.original or "").strip()
        if not o:
            continue
        if o.lower() in _NAME_REPLACE_DENY:
            stopword_name_hits += 1
        elif len(o) <= 3:
            short_name_hits += 1

    stopword_loss = 0
    if pending is not None and original_texts is not None:
        for src, result in pending:
            key = str(src)
            before = original_texts.get(key, "")
            after = result.text
            if not before or before == after:
                continue
            for w in _PROSE_DAMAGE_PROBE:
                lost = _word_count(before, w) - _word_count(after, w)
                if lost > 0:
                    stopword_loss += lost

    total = stopword_name_hits + short_name_hits + stopword_loss
    return {
        "stopword_name_hits": stopword_name_hits,
        "short_name_hits": short_name_hits,
        "stopword_loss": stopword_loss,
        "total": total,
    }


def map_poison_key_count(pii_map: PiiMap) -> int:
    """Count map name keys that must never plain-replace (deny / tiny / pseudo)."""
    n = 0
    for k in pii_map.names:
        kl = k.lower()
        if is_pseudo_token(k) or kl in _NAME_REPLACE_DENY or len(k) <= 3:
            n += 1
    return n


def per_file_summary_rows(
    pending: list[tuple[Path, AnonymizeResult]],
) -> list[dict[str, Any]]:
    """Redacted per-file counts (no originals / no replacements)."""
    rows: list[dict[str, Any]] = []
    for src, result in pending:
        kinds: dict[str, int] = {}
        for h in result.hits:
            kinds[h.kind] = kinds.get(h.kind, 0) + 1
        residual = result.residual
        row: dict[str, Any] = {
            "file": _rel_to_repo(src),
            "hits": len(result.hits),
            "hits_by_kind": kinds,
        }
        if residual:
            res_counts = residual.counts_agent_safe()
            if any(res_counts.values()):
                row["residual"] = {k: v for k, v in res_counts.items() if v}
        if result.hits or row.get("residual"):
            rows.append(row)
    rows.sort(key=lambda r: (-int(r["hits"]), str(r["file"])))
    return rows


def resolve_repo_path(path: Path) -> Path:
    p = path.expanduser()
    if not p.is_absolute():
        p = (REPO_ROOT / p).resolve()
    else:
        p = p.resolve()
    return p


def under_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def under_raw(path: Path, raw_root: Path) -> bool:
    return under_root(path, raw_root)


def is_export_path(path: Path) -> bool:
    try:
        parts = path.resolve().parts
    except OSError:
        parts = path.parts
    return any(part in EXPORT_DIR_NAMES for part in parts)


def _rel_to_repo(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def collect_files(target: Path) -> tuple[list[Path], int]:
    """Collect text files under target; return (files, skipped_binary_count)."""
    skipped_binary = 0
    if target.is_file():
        if is_export_path(target):
            return [], 0
        suf = target.suffix.lower()
        if suf in BINARY_INTAKE_SUFFIXES:
            return [], 1
        return [target], 0
    files: list[Path] = []
    for p in sorted(target.rglob("*")):
        if not p.is_file() or p.name == ".gitkeep":
            continue
        if is_export_path(p):
            continue
        suf = p.suffix.lower()
        if suf in BINARY_INTAKE_SUFFIXES:
            skipped_binary += 1
            continue
        if suf in TEXT_SUFFIXES or suf == "":
            files.append(p)
    return files, skipped_binary


def collect_files_multi(targets: list[Path]) -> tuple[list[Path], int, int]:
    """Collect text files; return (files, skipped_export_count, skipped_binary_count)."""
    seen: set[Path] = set()
    files: list[Path] = []
    skipped_export = 0
    skipped_binary = 0
    for target in targets:
        if target.is_file() and is_export_path(target):
            skipped_export += 1
            continue
        batch, bin_skip = collect_files(target)
        skipped_binary += bin_skip
        for f in batch:
            key = f.resolve()
            if key in seen:
                continue
            seen.add(key)
            files.append(f)
    return files, skipped_export, skipped_binary


@dataclass
class Hit:
    kind: str
    original: str
    replacement: str
    path: str


@dataclass
class AnonymizeResult:
    text: str
    hits: list[Hit] = field(default_factory=list)
    residual_emails: list[str] = field(default_factory=list)
    residual: _det.ResidualReport | None = None
    ner_status: str = "off"  # off | ok | skipped


def anonymize_text(
    text: str,
    *,
    pii_map: PiiMap,
    allowlist: set[str],
    also_ip: bool,
    source: str = "",
    harvest_names: bool = True,
    harvest_single_token: bool = False,
    also_nl_id: bool = False,
    also_p2: bool = True,
    use_ner: bool = False,
    ner_config: Path | None = None,
    scrub_orgs: bool = True,
    org_scrublist: list[str] | None = None,
    expand_name_parts: bool = True,
) -> AnonymizeResult:
    hits: list[Hit] = []
    out = text
    ner_status = "off"

    # 1) Emails — Name <email> first, then bare addresses
    name_angle = re.compile(
        r"([A-Za-z][A-Za-z0-9 .'_-]{0,80}?)\s*<\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*>",
        re.IGNORECASE,
    )

    def name_angle_sub(m: re.Match[str]) -> str:
        display, email = m.group(1).strip(), m.group(2)
        if is_allowlisted(email, allowlist):
            return m.group(0)
        if email.lower().endswith("@example.test"):
            et = email
        else:
            et = pii_map.email_token(email)
            hits.append(Hit("email", email, et, source))
        if is_pseudo_token(display):
            return f"{display} <{et}>"
        if len(display) >= MIN_PERSON_NAME_LEN:
            nt = pii_map.name_token(display)
            hits.append(Hit("name", display, nt, source))
        else:
            nt = "PERSON_SHORT"
            hits.append(Hit("name", display, nt, source))
        return f"{nt} <{et}>"

    out = name_angle.sub(name_angle_sub, out)

    def bare_email_sub(m: re.Match[str]) -> str:
        email = m.group(0)
        if is_allowlisted(email, allowlist):
            return email
        if email.lower().endswith("@example.test"):
            return email
        token = pii_map.email_token(email)
        hits.append(Hit("email", email, token, source))
        return token

    out = EMAIL_SIMPLE_RE.sub(bare_email_sub, out)

    # 2) sys_created_by / sys_updated_by
    def sys_user_sub(m: re.Match[str]) -> str:
        open_t, user, close_t = m.group(1), m.group(2), m.group(3)
        if is_allowlisted(user, allowlist):
            return m.group(0)
        if user.lower().startswith("username_"):
            return m.group(0)
        token = pii_map.username_token(user)
        hits.append(Hit("username", user, token, source))
        return f"{open_t}{token}{close_t}"

    out = SYS_USER_TAG_RE.sub(sys_user_sub, out)

    # 2b) JSON metadata audit fields
    def json_user_sub(m: re.Match[str]) -> str:
        prefix, user, suffix = m.group(1), m.group(2), m.group(3)
        if is_allowlisted(user, allowlist):
            return m.group(0)
        if user.lower().startswith("username_"):
            return m.group(0)
        token = pii_map.username_token(user)
        hits.append(Hit("username", user, token, source))
        return f"{prefix}{token}{suffix}"

    out = JSON_USER_RE.sub(json_user_sub, out)

    # 2c) Harvest display names from labeled Jira/SN person fields
    if harvest_names:
        for harvested in harvest_person_names(
            text, allowlist, allow_single_token=harvest_single_token
        ):
            pii_map.name_token(harvested)

    # 2d) Opt-in NER (Presidio) — default off
    if use_ner:
        try:
            import pii_ner as _ner  # noqa: PLC0415

            names, ner_status = _ner.harvest_ner_names(
                text,
                config_path=ner_config or DEFAULT_NER_CONFIG,
                allowlist=allowlist,
            )
            for n in names:
                pii_map.name_token(n)
        except Exception:
            ner_status = "skipped"

    # 2e) Company / import / product names (default on)
    if scrub_orgs:
        for org in org_scrublist or []:
            if is_allowlisted(org, allowlist):
                continue
            pii_map.org_token(org)

    # 2f) Expand first/last tokens from multi-token PERSON entries (same PERSON_NNN)
    if expand_name_parts:
        expand_person_name_parts(pii_map)

    # 3) Seeded display names (longest first to avoid partial overlaps)
    # Parts may be MIN_PERSON_PART_LEN (3) after expansion — e.g. Sam from Sam Jansen.
    for real in sorted(pii_map.names.keys(), key=len, reverse=True):
        if len(real) < MIN_PERSON_PART_LEN:
            continue
        if is_pseudo_token(real) or real.lower() in _NAME_REPLACE_DENY:
            continue
        token = pii_map.names[real]
        if real == token:
            continue
        pattern = re.compile(rf"\b{re.escape(real)}\b", re.IGNORECASE)

        def name_plain_sub(m: re.Match[str], _tok: str = token, _real: str = real) -> str:
            if _match_inside_email(m) or is_pseudo_token(m.group(0)):
                return m.group(0)
            hits.append(Hit("name", m.group(0), _tok, source))
            return _tok

        out, _n = pattern.subn(name_plain_sub, out)

    # 3b) Org / company names (longest first)
    if scrub_orgs:
        for real in sorted(pii_map.orgs.keys(), key=len, reverse=True):
            if len(real) < MIN_PERSON_PART_LEN:
                continue
            token = pii_map.orgs[real]
            if real == token or is_allowlisted(real, allowlist):
                continue
            pattern = re.compile(rf"\b{re.escape(real)}\b", re.IGNORECASE)

            def org_plain_sub(m: re.Match[str], _tok: str = token) -> str:
                if _match_inside_email(m):
                    return m.group(0)
                hits.append(Hit("org", m.group(0), _tok, source))
                return _tok

            out = pattern.sub(org_plain_sub, out)

    # 4) Mapped usernames as whole words
    for real in sorted(pii_map.usernames.keys(), key=len, reverse=True):
        token = pii_map.usernames[real]
        pattern = re.compile(rf"\b{re.escape(real)}\b", re.IGNORECASE)

        def user_plain_sub(m: re.Match[str], _tok: str = token) -> str:
            if m.group(0).lower().startswith("username_"):
                return m.group(0)
            if _match_inside_email(m):
                return m.group(0)
            hits.append(Hit("username", m.group(0), _tok, source))
            return _tok

        out = pattern.sub(user_plain_sub, out)

    # 5) Optional IPs (default off — ADR-002)
    if also_ip:

        def ipv4_sub(m: re.Match[str]) -> str:
            ip = m.group(0)
            try:
                addr = ipaddress.IPv4Address(ip)
            except ValueError:
                return ip
            if addr.is_loopback or addr.is_unspecified:
                return ip
            if str(addr).startswith("203.0.113."):
                return ip
            token = pii_map.ip_token(ip, 4)
            hits.append(Hit("ip", ip, token, source))
            return token

        out = IPV4_RE.sub(ipv4_sub, out)

        def ipv6_sub(m: re.Match[str]) -> str:
            ip = m.group(0)
            try:
                addr = ipaddress.IPv6Address(ip)
            except ValueError:
                return ip
            if addr.is_loopback or addr.is_unspecified:
                return ip
            if ip.lower().startswith("2001:db8:"):
                return ip
            token = pii_map.ip_token(str(addr), 6)
            hits.append(Hit("ip", ip, token, source))
            return token

        out = IPV6_CANDIDATE_RE.sub(ipv6_sub, out)

    # 6) IBAN before phones (digit groups inside IBAN must not become phone hits)
    for iban in sorted(set(_det.find_valid_ibans(out)), key=len, reverse=True):
        token = pii_map.iban_token(iban)
        pattern = re.compile(re.escape(iban), re.IGNORECASE)

        def iban_sub(m: re.Match[str], _tok: str = token, _ib: str = iban) -> str:
            hits.append(Hit("iban", _ib, _tok, source))
            return _tok

        out = pattern.sub(iban_sub, out)

    for phone in sorted(set(_det.find_phones(out)), key=len, reverse=True):
        if is_allowlisted(phone, allowlist):
            continue
        if phone.upper().startswith("PHONE_"):
            continue
        token = pii_map.phone_token(phone)
        if phone == token:
            continue
        pattern = re.compile(re.escape(phone))

        def phone_sub(m: re.Match[str], _tok: str = token, _ph: str = phone) -> str:
            hits.append(Hit("phone", _ph, _tok, source))
            return _tok

        out = pattern.sub(phone_sub, out)

    if also_nl_id:
        for bsn in sorted(set(_det.find_bsns(out, bare=False)), key=len, reverse=True):
            token = pii_map.bsn_token(bsn)
            pattern = re.compile(rf"\b{re.escape(bsn)}\b")

            def bsn_sub(m: re.Match[str], _tok: str = token, _b: str = bsn) -> str:
                hits.append(Hit("bsn", _b, _tok, source))
                return _tok

            out = pattern.sub(bsn_sub, out)

    if also_p2:
        for mac in sorted(set(_det.find_macs(out)), key=len, reverse=True):
            if mac.lower().startswith("00:00:5e:00:53:"):
                continue
            token = pii_map.mac_token(mac)
            pattern = re.compile(re.escape(mac), re.IGNORECASE)

            def mac_sub(m: re.Match[str], _tok: str = token, _m: str = mac) -> str:
                hits.append(Hit("mac", _m, _tok, source))
                return _tok

            out = pattern.sub(mac_sub, out)

        for pc in sorted(set(_det.find_nl_postcodes(out)), key=len, reverse=True):
            if pc.upper().startswith("9999"):
                continue
            token = pii_map.postcode_token(pc)
            pattern = re.compile(re.escape(pc), re.IGNORECASE)

            def pc_sub(m: re.Match[str], _tok: str = token, _p: str = pc) -> str:
                hits.append(Hit("postcode", _p, _tok, source))
                return _tok

            out = pattern.sub(pc_sub, out)

        for dob in sorted(set(_det.find_labeled_dobs(out)), key=len, reverse=True):
            if dob.startswith("1900-01-"):
                continue
            token = pii_map.dob_token(dob)
            pattern = re.compile(re.escape(dob))

            def dob_sub(m: re.Match[str], _tok: str = token, _d: str = dob) -> str:
                hits.append(Hit("dob", _d, _tok, source))
                return _tok

            out = pattern.sub(dob_sub, out)

    residual = _det.scan_residuals(
        out, allowlist=allowlist, also_nl_id=also_nl_id, also_p2=also_p2
    )
    return AnonymizeResult(
        text=out,
        hits=hits,
        residual_emails=list(residual.emails),
        residual=residual,
        ner_status=ner_status,
    )


def mirror_out_path(src: Path, raw_root: Path, clean_root: Path) -> Path:
    rel = src.resolve().relative_to(raw_root.resolve())
    return clean_root / rel


def promote_clean(clean_root: Path, story_id: str) -> Path:
    m = re.fullmatch(r"(STORY-\d+|STRY\d+)", story_id, re.IGNORECASE)
    if not m:
        raise ValueError(f"Invalid story id for --promote: {story_id}")
    dest = REPO_ROOT / "src" / "stories" / m.group(1)
    dest.mkdir(parents=True, exist_ok=True)
    # Copy all clean files into dest/inbox-clean/ to avoid clobbering existing story layout
    target = dest / "intake-clean"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(clean_root, target, ignore=shutil.ignore_patterns(".gitkeep"))
    return target


def _record_intake_outputs(dests: list[Path]) -> None:
    """Record successful clean/promote writes in the intake manifest."""
    if not dests:
        return
    for dest in dests:
        if dest.is_dir():
            _manifest.record_intake_tree(dest, REPO_ROOT, local_dir=LOCAL_DIR)
        elif dest.is_file():
            _manifest.record_intake_write(dest, REPO_ROOT, local_dir=LOCAL_DIR)


def _under_dir(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def clear_clean_staging(clean_root: Path) -> int:
    """Delete inbox/clean files except .gitkeep. Return deleted file count."""
    if not clean_root.is_dir():
        return 0
    deleted = 0
    for p in sorted(clean_root.rglob("*"), reverse=True):
        if p == clean_root:
            continue
        if p.is_file():
            if p.name == ".gitkeep":
                continue
            p.unlink(missing_ok=True)
            deleted += 1
        elif p.is_dir():
            try:
                p.rmdir()
            except OSError:
                pass
    return deleted


def prune_clean_not_kept(clean_root: Path, keep: set[Path]) -> int:
    """Delete clean files not in this run. Keep .gitkeep. Return deleted count."""
    if not clean_root.is_dir():
        return 0
    keep_res = {p.resolve() for p in keep}
    deleted = 0
    for p in sorted(clean_root.rglob("*"), reverse=True):
        if p == clean_root:
            continue
        if p.is_file():
            if p.name == ".gitkeep" or p.resolve() in keep_res:
                continue
            p.unlink(missing_ok=True)
            deleted += 1
        elif p.is_dir():
            try:
                p.rmdir()
            except OSError:
                pass
    return deleted


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Anonymize PII in inbox/raw locally (offline).")
    p.add_argument(
        "paths",
        nargs="*",
        default=[],
        help="File(s) or directory(ies); default inbox/raw (non-gate). Gate mode: src/stories paths.",
    )
    p.add_argument("--out", type=str, default="", help="Output file or directory (default: inbox/clean mirror)")
    p.add_argument("--map", type=str, default=str(DEFAULT_MAP), help="Path to pii-map.json")
    p.add_argument("--allowlist", type=str, default=str(DEFAULT_ALLOWLIST), help="Allowlist file")
    p.add_argument("--dry-run", action="store_true", help="Do not write output or map")
    p.add_argument(
        "--report",
        action="store_true",
        help="Print hit report with originals (human interactive only; opts out of default agent-safe)",
    )
    p.add_argument(
        "--agent-safe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Counts-only stdout; cannot combine with --report (default: true). "
        "Use --no-agent-safe only if you must pair unusual flags; prefer --report alone for humans.",
    )
    p.add_argument(
        "--summary",
        action="store_true",
        help="Detect-only gate mode: redacted counts only; implies --dry-run and --fail-on-hits. "
        "Never authorizes --in-place (separate backfill).",
    )
    p.add_argument(
        "--per-file-summary",
        action="store_true",
        help="Agent-safe redacted per-file hit/residual counts (no originals); implies --dry-run. "
        "Use instead of ad-hoc py -c map/file inspection.",
    )
    p.add_argument(
        "--fail-on-prose-damage",
        action="store_true",
        help="Exit 1 if scrub would replace deny-listed/short name tokens or probe stopwords "
        "disappear from text (over-scrub guard). Counts only; safe with agent-safe.",
    )
    p.add_argument("--also-ip", action="store_true", help="Also anonymize IPv4/IPv6 addresses (default off)")
    p.add_argument(
        "--also-nl-id",
        action="store_true",
        help="Also scrub labeled BSN fields (11-proef); default off",
    )
    p.add_argument(
        "--also-p2",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Scrub MAC / NL postcode / labeled DOB (default: true)",
    )
    p.add_argument(
        "--ner",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Opt-in Presidio NER for free-text PERSON (default: off). ner=skipped if extras absent.",
    )
    p.add_argument(
        "--harvest-single-token",
        action="store_true",
        help="Allow single-token display names in harvest (conservative default: off)",
    )
    p.add_argument(
        "--expand-name-parts",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="From multi-token PERSON entries, also scrub matching first/last tokens "
        "(default: true). E.g. Sam Jansen → also replaces lone Sam / Jansen.",
    )
    p.add_argument(
        "--scrub-orgs",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Scrub company/import/product names from config/pii-org-scrub.txt (default: true)",
    )
    p.add_argument(
        "--org-list",
        type=str,
        default=str(DEFAULT_ORG_SCRUB),
        help="Org/import scrub list (one name per line)",
    )
    p.add_argument(
        "--irreversible",
        action="store_true",
        help="Human-only: redact with ephemeral tokens; do not write/update pii-map (ADR-004)",
    )
    p.add_argument(
        "--map-prune-unused",
        action="store_true",
        help="Human-only: drop map entries whose tokens were unused this run, then save",
    )
    p.add_argument(
        "--map-migrate",
        action="store_true",
        help="Encrypt a legacy plaintext map (keeps .bak); then exit",
    )
    p.add_argument(
        "--map-rollback",
        action="store_true",
        help="Restore pii-map.json from .bak; then exit",
    )
    p.add_argument(
        "--map-audit",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Append metadata-only audit line to .local/pii-map-audit.jsonl",
    )
    p.add_argument(
        "--fail-on-hits",
        action="store_true",
        help="Exit 1 if any replacements or residual emails were found (useful with --dry-run)",
    )
    p.add_argument(
        "--force-path",
        action="store_true",
        help="Allow paths outside inbox/raw",
    )
    p.add_argument(
        "--in-place",
        action="store_true",
        help="Write anonymized content back to source paths (allows outside inbox/raw; "
        "incompatible with --out / --promote)",
    )
    p.add_argument(
        "--promote",
        type=str,
        default="",
        help="After write, copy inbox/clean into src/stories/<id>/intake-clean/",
    )
    p.add_argument(
        "--keep-raw",
        action="store_true",
        help="Keep source files under inbox/raw after a successful write "
        "(default: delete scrubbed raw sources to reduce the local PII footprint). "
        "Dry-run, gate mode, --in-place, and skipped binaries never delete.",
    )
    p.add_argument(
        "--keep-clean",
        action="store_true",
        help="Keep leftover files under inbox/clean after a successful write "
        "(default: this run replaces staging; --promote then clears staging). "
        "Use while seeding the map / re-scrubbing. Never deletes src/stories.",
    )
    p.add_argument(
        "--harvest-names",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Auto-seed display names from Jira/SN person fields "
        "(slash/comma/bullet lists, Test with …, XML/JSON display_value, CSV headers). "
        "Default on. Not NER. Use --no-harvest-names to disable.",
    )
    return p


def append_map_audit(
    *,
    action: str,
    map_path: Path,
    counts: dict[str, int],
    audit_path: Path = DEFAULT_AUDIT,
) -> None:
    """Metadata-only audit (no originals). Exclude from OneDrive if possible."""
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    line = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": action,
        "map": str(map_path.name),
        "counts": counts,
    }
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, ensure_ascii=False) + "\n")


def _validate_gate_mode(args: argparse.Namespace) -> str | None:
    """Return error message if gate (--summary) argv is invalid."""
    if not args.summary:
        return None
    if args.report:
        return "gate mode (--summary) cannot be combined with --report (PII in logs)"
    if args.in_place:
        return f"gate mode (--summary) cannot be combined with --in-place. {MSG_SUMMARY_NOT_IN_PLACE}"
    if args.promote:
        return "gate mode (--summary) cannot be combined with --promote"
    if args.out:
        return "gate mode (--summary) cannot be combined with --out"
    return None


def _validate_per_file_summary(args: argparse.Namespace) -> str | None:
    if not getattr(args, "per_file_summary", False):
        return None
    if args.report:
        return "--per-file-summary cannot be combined with --report (PII in logs)"
    return None


def _apply_gate_defaults(args: argparse.Namespace) -> None:
    """--summary implies --dry-run and --fail-on-hits (matches --help)."""
    if args.summary:
        args.dry_run = True
        args.fail_on_hits = True
    if getattr(args, "per_file_summary", False):
        args.dry_run = True


def _validate_agent_safe(args: argparse.Namespace) -> str | None:
    """Return error message if agent-safe + --report conflict."""
    if args.agent_safe and args.report:
        return (
            "agent-safe (default) cannot be combined with --report (PII in logs); "
            "use --report alone for interactive human reports"
        )
    return None


def _apply_agent_safe_defaults(args: argparse.Namespace, argv: list[str] | None) -> None:
    """--report alone opts out of default agent-safe; explicit --agent-safe --report stays conflicting."""
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    explicit_agent_safe = "--agent-safe" in argv_list
    if args.report and args.agent_safe and not explicit_agent_safe:
        args.agent_safe = False


def _validate_gate_targets(targets: list[Path], raw_root: Path) -> str | None:
    for target in targets:
        if under_root(target, raw_root) or target == raw_root:
            return f"{MSG_SUMMARY_NOT_INTAKE} (refused inbox/raw: {_rel_to_repo(target)})"
        if under_root(target, LOCAL_DIR) or target == LOCAL_DIR.resolve():
            return f"gate mode refuses .local path: {_rel_to_repo(target)}"
        if not under_root(target, STORIES_ROOT) and target != STORIES_ROOT.resolve():
            return (
                f"gate mode only allows paths under src/stories: {_rel_to_repo(target)}"
            )
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _apply_agent_safe_defaults(args, argv)
    _apply_gate_defaults(args)
    raw_root = DEFAULT_RAW.resolve()
    clean_root = DEFAULT_CLEAN.resolve()
    map_path = resolve_repo_path(Path(args.map))

    if args.map_rollback:
        try:
            _crypto.rollback_map(map_path)
        except _crypto.MapCryptoError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"map_rollback=ok path={_rel_to_repo(map_path)}")
        return 0

    if args.map_migrate:
        try:
            status = _crypto.migrate_plaintext_to_encrypted(map_path, repo_root=REPO_ROOT)
        except _crypto.MapCryptoError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"map_migrate={status} path={_rel_to_repo(map_path)}")
        return 0

    gate_err = _validate_gate_mode(args)
    if gate_err:
        print(f"error: {gate_err}", file=sys.stderr)
        return 2

    pfs_err = _validate_per_file_summary(args)
    if pfs_err:
        print(f"error: {pfs_err}", file=sys.stderr)
        return 2

    agent_err = _validate_agent_safe(args)
    if agent_err:
        print(f"error: {agent_err}", file=sys.stderr)
        return 2

    if args.agent_safe:
        args.report = False

    if args.in_place and (args.out or args.promote):
        print("error: --in-place cannot be combined with --out or --promote", file=sys.stderr)
        return 2

    if args.irreversible and args.map_prune_unused:
        print("error: --irreversible cannot combine with --map-prune-unused", file=sys.stderr)
        return 2

    path_args = list(args.paths)
    if not path_args:
        if args.summary:
            print(
                "error: gate mode requires one or more src/stories paths. "
                + MSG_SUMMARY_NOT_INTAKE,
                file=sys.stderr,
            )
            return 2
        path_args = [str(DEFAULT_RAW)]

    targets = [resolve_repo_path(Path(p)) for p in path_args]
    for target in targets:
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

    if args.summary:
        scope_err = _validate_gate_targets(targets, raw_root)
        if scope_err:
            print(f"error: {scope_err}", file=sys.stderr)
            return 2

    allow_outside = (
        args.force_path or args.in_place or args.summary or args.per_file_summary
    )
    if not allow_outside:
        for target in targets:
            if target != raw_root and not under_raw(target, raw_root):
                print(
                    f"error: path must be under {raw_root} (use --force-path or --in-place)",
                    file=sys.stderr,
                )
                return 2

    allowlist = load_allowlist(resolve_repo_path(Path(args.allowlist)))
    org_scrublist = (
        load_org_scrublist(resolve_repo_path(Path(args.org_list)))
        if args.scrub_orgs
        else []
    )

    # Detect-only never fail-closed on missing key; mutate paths require key at save.
    require_key = not (
        args.dry_run or args.summary or args.per_file_summary or args.irreversible
    )
    try:
        pii_map = PiiMap.load(
            map_path,
            require_key=False,
            irreversible=bool(args.irreversible),
        )
    except _crypto.MapCryptoError as e:
        if require_key:
            print(f"error: {e}", file=sys.stderr)
            return 2
        pii_map = PiiMap.empty(map_path, status="unavailable")

    map_status = pii_map.status
    files, skipped_export, skipped_binary = collect_files_multi(targets)

    if not files:
        if skipped_export > 0 and skipped_binary == 0:
            print(
                f"error: all {skipped_export} path(s) were under source-export/source_export "
                "(nothing to scan)",
                file=sys.stderr,
            )
            return 2
        if skipped_binary > 0:
            print(
                f"processed=0 wrote=0 hits=0 residual=0 skipped_binary={skipped_binary} "
                f"skipped_export={skipped_export} dry_run={args.dry_run} "
                "NOTE: binary intake (.xlsx/.xls/.pdf) is NOT scrubbed — Save as CSV/TSV into inbox/raw",
                file=sys.stderr,
            )
            return 2 if args.summary else 0
        print("No text files to process.", file=sys.stderr)
        return 2 if args.summary else 0

    # Phase 1: scrub all in memory (no write / map.save / manifest yet).
    all_hits: list[Hit] = []
    residual_merged = _det.ResidualReport()
    ner_statuses: list[str] = []
    pending: list[tuple[Path, AnonymizeResult]] = []
    original_texts: dict[str, str] = {}

    for src in files:
        try:
            text = src.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = src.read_text(encoding="utf-8", errors="replace")

        original_texts[str(src)] = text
        result = anonymize_text(
            text,
            pii_map=pii_map,
            allowlist=allowlist,
            also_ip=args.also_ip,
            source=_rel_to_repo(src),
            harvest_names=args.harvest_names,
            harvest_single_token=args.harvest_single_token,
            also_nl_id=args.also_nl_id,
            also_p2=args.also_p2,
            use_ner=args.ner,
            ner_config=DEFAULT_NER_CONFIG,
            scrub_orgs=args.scrub_orgs,
            org_scrublist=org_scrublist,
            expand_name_parts=args.expand_name_parts,
        )
        all_hits.extend(result.hits)
        ner_statuses.append(result.ner_status)
        if result.residual:
            residual_merged.emails.extend(result.residual.emails)
            residual_merged.ibans.extend(result.residual.ibans)
            residual_merged.phones.extend(result.residual.phones)
            residual_merged.bsns.extend(result.residual.bsns)
            residual_merged.macs.extend(result.residual.macs)
            residual_merged.postcodes.extend(result.residual.postcodes)
            residual_merged.dobs.extend(result.residual.dobs)
        pending.append((src, result))

    # Deduplicate residual lists for counts
    residual_merged.emails = sorted(set(residual_merged.emails))
    residual_merged.ibans = sorted(set(residual_merged.ibans))
    residual_merged.phones = sorted(set(residual_merged.phones))
    residual_merged.bsns = sorted(set(residual_merged.bsns))
    residual_merged.macs = sorted(set(residual_merged.macs))
    residual_merged.postcodes = sorted(set(residual_merged.postcodes))
    residual_merged.dobs = sorted(set(residual_merged.dobs))
    residual_all = list(residual_merged.emails)

    high_conf = residual_merged.high_confidence_count
    abort_write = (
        high_conf > 0 and not args.dry_run and not args.summary and not args.per_file_summary
    )

    ner_status = "off"
    if args.ner:
        ner_status = "ok" if any(s == "ok" for s in ner_statuses) else "skipped"

    prose_damage = prose_damage_counts(
        all_hits, pending, original_texts=original_texts
    )
    poison_keys = map_poison_key_count(pii_map)
    if poison_keys:
        prose_damage = {
            **prose_damage,
            "map_poison_keys": poison_keys,
            "total": prose_damage["total"] + poison_keys,
        }

    if args.fail_on_prose_damage and prose_damage["total"] > 0:
        print(
            "error: prose-damage guard failed (counts only; no originals): "
            + " ".join(f"{k}={v}" for k, v in prose_damage.items() if v),
            file=sys.stderr,
        )
        print(
            "NOTE: fix deny/expand wiring or purge poison map keys before --in-place. "
            f"{MSG_SUMMARY_NOT_IN_PLACE}",
            file=sys.stderr,
        )
        return 1

    wrote = 0
    deleted_raw = 0
    delete_raw_failures = 0
    deleted_clean = 0
    delete_clean_failures = 0
    recorded_dests: list[Path] = []
    pruned_map = 0

    if abort_write:
        counts = residual_merged.counts_agent_safe()
        msg = (
            f"error: residual high-confidence hits abort write "
            f"(no clean write / map.save / manifest). "
            + " ".join(f"{k}={v}" for k, v in counts.items() if v)
            + f" ner={ner_status} map={map_status}"
        )
        print(msg, file=sys.stderr)
        print(
            "NOTE: residual=0 is not name-safe; PERSON false-negatives remain. "
            "Spot-check when ner=skipped.",
            file=sys.stderr,
        )
        return 1

    if not args.dry_run and not args.summary and not args.per_file_summary:
        for src, result in pending:
            if args.in_place:
                dest = src
            elif args.out:
                out_arg = resolve_repo_path(Path(args.out))
                if len(files) == 1 and (out_arg.suffix or not out_arg.exists() or out_arg.is_file()):
                    dest = out_arg
                else:
                    if under_raw(src, raw_root):
                        dest = out_arg / src.resolve().relative_to(raw_root)
                    else:
                        dest = out_arg / src.name
            else:
                if under_raw(src, raw_root):
                    dest = mirror_out_path(src, raw_root, clean_root)
                else:
                    dest = clean_root / src.name

            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(result.text, encoding="utf-8", newline="\n")
            wrote += 1
            if not args.in_place:
                recorded_dests.append(dest)

            if (
                not args.keep_raw
                and not args.in_place
                and under_raw(src, raw_root)
                and src.resolve() != dest.resolve()
            ):
                try:
                    src.unlink(missing_ok=True)
                    deleted_raw += 1
                except OSError as e:
                    delete_raw_failures += 1
                    print(
                        f"warning: could not delete raw source {_rel_to_repo(src)}: {e}",
                        file=sys.stderr,
                    )

        if args.map_prune_unused and not args.irreversible:
            used = {h.replacement for h in all_hits}
            pruned_map = pii_map.prune_unused(used)

        if not args.irreversible:
            try:
                # Migrate plaintext on first successful encrypt save
                if map_status == "plaintext" and map_path.is_file():
                    bak = map_path.with_suffix(map_path.suffix + ".bak")
                    if not bak.exists():
                        bak.write_bytes(map_path.read_bytes())
                pii_map.save()
                map_status = "ok"
            except _crypto.MapCryptoError as e:
                print(f"error: could not save encrypted PII map: {e}", file=sys.stderr)
                return 2

        if args.map_audit:
            try:
                append_map_audit(
                    action="save" if not args.irreversible else "irreversible",
                    map_path=map_path,
                    counts={
                        "hits": len(all_hits),
                        "wrote": wrote,
                        "pruned": pruned_map,
                    },
                )
            except OSError as e:
                print(f"warning: map audit write failed: {e}", file=sys.stderr)

        wrote_under_clean = [
            d for d in recorded_dests if d.is_file() and _under_dir(d, clean_root)
        ]
        manage_staging = not args.keep_clean and not args.in_place and wrote > 0

        if manage_staging and wrote_under_clean:
            try:
                deleted_clean = prune_clean_not_kept(
                    clean_root, {d.resolve() for d in wrote_under_clean}
                )
            except OSError as e:
                delete_clean_failures += 1
                print(
                    f"warning: could not prune inbox/clean staging: {e}",
                    file=sys.stderr,
                )

        if args.promote:
            try:
                dest = promote_clean(clean_root, args.promote)
                print(f"promoted clean tree -> {dest.relative_to(REPO_ROOT)}")
                recorded_dests.append(dest)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
        try:
            _record_intake_outputs(recorded_dests)
        except OSError as e:
            print(f"error: could not record intake manifest: {e}", file=sys.stderr)
            return 2

        if manage_staging:
            try:
                if args.promote:
                    deleted_clean += clear_clean_staging(clean_root)
                    _manifest.drop_inbox_clean_manifest_keys(REPO_ROOT, local_dir=LOCAL_DIR)
                elif wrote_under_clean:
                    keep_rels = {
                        _rel_to_repo(d).replace("\\", "/") for d in wrote_under_clean
                    }
                    _manifest.retain_inbox_clean_manifest_keys(
                        REPO_ROOT, keep_rels, local_dir=LOCAL_DIR
                    )
            except OSError as e:
                delete_clean_failures += 1
                print(
                    f"warning: could not prune inbox/clean staging: {e}",
                    file=sys.stderr,
                )

    residual_counts = residual_merged.counts_agent_safe()

    if args.report:
        report = {
            "files": len(files),
            "wrote": wrote,
            "deleted_raw": deleted_raw,
            "delete_raw_failures": delete_raw_failures,
            "deleted_clean": deleted_clean,
            "delete_clean_failures": delete_clean_failures,
            "keep_raw": args.keep_raw,
            "keep_clean": args.keep_clean,
            "dry_run": args.dry_run,
            "hits": [
                {"kind": h.kind, "original": h.original, "replacement": h.replacement, "path": h.path}
                for h in all_hits
            ],
            "residual_emails": sorted(set(residual_all)),
            "residual": residual_counts,
            "ner": ner_status,
            "map": str(pii_map.path),
            "map_status": map_status,
            "pruned_map": pruned_map,
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif args.per_file_summary:
        payload = {
            "mode": "per_file_summary",
            "files": len(files),
            "files_with_hits_or_residual": 0,
            "hits": len(all_hits),
            "residual": residual_counts,
            "skipped_export": skipped_export,
            "skipped_binary": skipped_binary,
            "dry_run": True,
            "ner": ner_status,
            "map": map_status if map_status != "unavailable" else "unavailable",
            "prose_damage": {k: v for k, v in prose_damage.items() if v},
            "by_file": per_file_summary_rows(pending),
        }
        payload["files_with_hits_or_residual"] = len(payload["by_file"])
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif args.summary:
        kind_counts: dict[str, int] = {}
        for h in all_hits:
            kind_counts[h.kind] = kind_counts.get(h.kind, 0) + 1
        summary = {
            "mode": "gate",
            "files": len(files),
            "hits": len(all_hits),
            "hits_by_kind": kind_counts,
            "residual_email_count": len(set(residual_all)),
            "residual": residual_counts,
            "skipped_export": skipped_export,
            "skipped_binary": skipped_binary,
            "dry_run": True,
            "ner": ner_status,
            "map": map_status if map_status != "ok" else "ok",
        }
        if map_status == "unavailable":
            summary["map"] = "unavailable"
        if args.fail_on_prose_damage or prose_damage["total"]:
            summary["prose_damage"] = {k: v for k, v in prose_damage.items() if v}
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        msg = (
            f"processed={len(files)} wrote={wrote} deleted_raw={deleted_raw} "
            f"deleted_clean={deleted_clean} "
            f"hits={len(all_hits)} residual={high_conf} "
            f"skipped_binary={skipped_binary} dry_run={args.dry_run} "
            f"ner={ner_status} map={map_status}"
        )
        for k, v in residual_counts.items():
            if v:
                msg += f" {k}={v}"
        if pruned_map:
            msg += f" pruned_map={pruned_map}"
        if delete_raw_failures > 0:
            msg += f" delete_raw_failures={delete_raw_failures}"
        if delete_clean_failures > 0:
            msg += f" delete_clean_failures={delete_clean_failures}"
        if residual_merged.warn_count and not high_conf:
            msg += " NOTE: low-confidence residuals are counts/warn only (not fail-write)"
        if skipped_binary > 0:
            msg += (
                " NOTE: skipped_binary files are NOT scrubbed — "
                "Save Excel as CSV into inbox/raw"
            )
        print(msg)

    if high_conf:
        return 1
    if args.fail_on_hits and all_hits:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
