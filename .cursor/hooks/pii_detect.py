"""Shared PII / raw-export detectors for Cursor hooks (pure helpers, no Cursor I/O)."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    re.IGNORECASE,
)

SYS_ID_RE = re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE)

# Keep in sync with scripts/anonymize_intake.py TEXT_SUFFIXES + BINARY_INTAKE_SUFFIXES.
HIGH_RISK_EXPORT_SUFFIXES = frozenset(
    {
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
        ".xlsx",
        ".xls",
        ".pdf",
    }
)

# Sibling kit / tooling trees are not intake; do not force inbox/raw.
OUTSIDE_READ_ALLOW_FRAGMENTS = frozenset({"cursor-starter-kit"})

# Prompt paste: SN unload / dense export heuristics (pinned for tests).
UNLOAD_MARKER = "<unload"
DISPLAY_VALUE_MIN = 3
SYS_ID_MIN_IN_LARGE_XML = 5
LARGE_XML_MIN_CHARS = 2000

_TRAILING_PATH_PUNCT = ".,;:)]}\"'"

MSG_DROP_RAW = (
    "Drop under inbox/raw/, scrub with "
    "`py -3 scripts/anonymize_intake.py inbox/raw` (agent-safe) or human `--report`, "
    "then use inbox/clean/ only. Do not re-paste raw content into chat "
    "(PII may already be in this turn if it passed the hook)."
)

MSG_ADOPT_THEN_CONTINUE = (
    "Do not Read outside-repo or inbox/raw files. Copy into inbox/raw/ without "
    "reading (Copy-Item -LiteralPath '<src>' -Destination inbox/raw/), then "
    "`py -3 scripts/anonymize_intake.py inbox/raw` (never --summary or --report), "
    "then continue the user's task from inbox/clean/ only. Do not refuse the request."
)

MSG_OUTSIDE_EXPORT = MSG_ADOPT_THEN_CONTINUE

MSG_UNVERIFIED_CLEAN = (
    "Blocked: this inbox/clean or intake-clean file was not recorded by a successful "
    "anonymize write (missing or stale checksum). "
    "Run `py -3 scripts/anonymize_intake.py inbox/raw`, then Read only the written clean file."
)

INTAKE_MANIFEST_NAME = "intake-manifest.json"

_AT_PATH_RE = re.compile(r"@(?P<p>[^\s]+)")
_WIN_ABS_RE = re.compile(r"(?<![@\w])(?P<p>[A-Za-z]:[\\/][^\s\"']+)")
_UNIX_ABS_RE = re.compile(
    r"(?<![@\w:])(?P<p>/(?:home|Users|tmp|opt|var|mnt)/[^\s\"']+)"
)
_QUOTED_ABS_RE = re.compile(
    r"""['"](?P<p>(?:[A-Za-z]:[^'"]+|/(?:home|Users|tmp|opt|var|mnt)[^'"]+))['"]"""
)

_DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


def intake_manifest_path(repo_root: Path, local_dir: Path | None = None) -> Path:
    base = local_dir if local_dir is not None else repo_root / ".local"
    return Path(base) / INTAKE_MANIFEST_NAME


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _posix_rel_to_repo(path: Path, repo_root: Path) -> str | None:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def is_under_intake_output(path: str, repo_root: Path) -> bool:
    """True for inbox/clean/** and **/intake-clean/** (not .gitkeep)."""
    rel = _posix_rel_to_repo(Path(path), repo_root)
    if not rel:
        return False
    low = rel.replace("\\", "/").lower()
    if low.rsplit("/", 1)[-1] == ".gitkeep":
        return False
    if low == "inbox/clean" or low.startswith("inbox/clean/"):
        return True
    return "/intake-clean/" in f"/{low}/" or low.endswith("/intake-clean")


def load_intake_manifest(
    repo_root: Path, local_dir: Path | None = None
) -> dict:
    p = intake_manifest_path(repo_root, local_dir=local_dir)
    if not p.is_file():
        return {"version": 1, "files": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "files": {}}
    if not isinstance(data, dict):
        return {"version": 1, "files": {}}
    files = data.get("files")
    if not isinstance(files, dict):
        data["files"] = {}
    return data


def _save_intake_manifest(
    data: dict, repo_root: Path, local_dir: Path | None = None
) -> None:
    data["version"] = 1
    data["written_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mp = intake_manifest_path(repo_root, local_dir=local_dir)
    mp.parent.mkdir(parents=True, exist_ok=True)
    mp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _is_inbox_clean_key(key: str) -> bool:
    low = key.replace("\\", "/").lower()
    return low == "inbox/clean" or low.startswith("inbox/clean/")


def drop_inbox_clean_manifest_keys(
    repo_root: Path, local_dir: Path | None = None
) -> int:
    """Remove inbox/clean keys after staging was copied (e.g. --promote)."""
    data = load_intake_manifest(repo_root, local_dir=local_dir)
    files = data.get("files") or {}
    kept = {k: v for k, v in files.items() if not _is_inbox_clean_key(str(k))}
    dropped = len(files) - len(kept)
    data["files"] = kept
    _save_intake_manifest(data, repo_root, local_dir=local_dir)
    return dropped


def retain_inbox_clean_manifest_keys(
    repo_root: Path,
    keep_rels: set[str],
    local_dir: Path | None = None,
) -> int:
    """Drop inbox/clean keys not in this run; leave intake-clean and other keys."""
    keep_norm = {k.replace("\\", "/") for k in keep_rels}
    data = load_intake_manifest(repo_root, local_dir=local_dir)
    files = data.get("files") or {}
    kept: dict = {}
    dropped = 0
    for key, val in files.items():
        kn = str(key).replace("\\", "/")
        if _is_inbox_clean_key(kn):
            if kn in keep_norm:
                kept[kn] = val
            else:
                dropped += 1
        else:
            kept[key] = val
    data["files"] = kept
    _save_intake_manifest(data, repo_root, local_dir=local_dir)
    return dropped


def record_intake_write(
    dest: Path,
    repo_root: Path,
    local_dir: Path | None = None,
) -> None:
    """Record a successful clean/promote write so the read hook can allow it."""
    if dest.name == ".gitkeep":
        return
    rel = _posix_rel_to_repo(dest, repo_root)
    if not rel:
        return
    data = load_intake_manifest(repo_root, local_dir=local_dir)
    files = data.setdefault("files", {})
    files[rel.replace("\\", "/")] = {"sha256": sha256_file(dest)}
    _save_intake_manifest(data, repo_root, local_dir=local_dir)


def record_intake_tree(
    root: Path,
    repo_root: Path,
    local_dir: Path | None = None,
) -> None:
    if not root.is_dir():
        return
    for p in root.rglob("*"):
        if p.is_file():
            record_intake_write(p, repo_root, local_dir=local_dir)


def is_verified_intake_output(
    path: str,
    repo_root: Path,
    local_dir: Path | None = None,
) -> bool:
    p = Path(path)
    if not p.is_file():
        return False
    rel = _posix_rel_to_repo(p, repo_root)
    if not rel:
        return False
    key = rel.replace("\\", "/")
    data = load_intake_manifest(repo_root, local_dir=local_dir)
    entry = data.get("files", {}).get(key)
    if not isinstance(entry, dict):
        return False
    expected = str(entry.get("sha256") or "")
    if not expected:
        return False
    try:
        return sha256_file(p) == expected
    except OSError:
        return False


def _norm(path: str) -> str:
    return path.replace("\\", "/").lower()


def find_non_allowlisted_emails(text: str, allowlist: set[str]) -> list[str]:
    suspects: list[str] = []
    for m in EMAIL_RE.findall(text or ""):
        low = m.lower()
        if low.endswith("@example.test"):
            continue
        if low in allowlist:
            continue
        suspects.append(m)
    return suspects


def looks_like_raw_sn_export(text: str) -> bool:
    """True when prompt body looks like a ServiceNow unload / dense export paste."""
    if not text:
        return False
    low = text.lower()
    if UNLOAD_MARKER in low:
        return True
    if low.count("display_value") >= DISPLAY_VALUE_MIN:
        return True
    if (
        len(text) >= LARGE_XML_MIN_CHARS
        and "<?xml" in low
        and len(SYS_ID_RE.findall(text)) >= SYS_ID_MIN_IN_LARGE_XML
    ):
        return True
    # Dense CSV-ish paste with many personal emails is handled by email finder;
    # also catch unload-less XML dumps with many sys_ids under large size.
    if (
        len(text) >= LARGE_XML_MIN_CHARS
        and ("sys_email" in low or "sc_req_item" in low or "sn_customerservice" in low)
        and len(SYS_ID_RE.findall(text)) >= SYS_ID_MIN_IN_LARGE_XML
    ):
        return True
    return False


def is_blocked_raw_path(path: str) -> bool:
    """Deny inbox/raw and .local (including pii-map)."""
    p = _norm(path)
    if not p:
        return False
    return (
        "inbox/raw/" in p
        or p.endswith("inbox/raw")
        or "/inbox/raw/" in p
        or p.endswith("/inbox/raw")
        or p.endswith(".local/pii-map.json")
        or "/.local/pii-map" in p
        or "/.local/" in p
        or p.endswith("/.local")
    )


def _suffix_of(path: str) -> str:
    name = _norm(path).rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def path_under_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def is_allowed_outside_workspace(path: str) -> bool:
    """True for known non-intake trees (e.g. sibling cursor-starter-kit)."""
    p = _norm(path)
    return any(frag in p for frag in OUTSIDE_READ_ALLOW_FRAGMENTS)


def _strip_path_token(token: str) -> str:
    t = (token or "").strip()
    if t.startswith("@"):
        t = t[1:]
    return t.rstrip(_TRAILING_PATH_PUNCT)


def iter_paths_in_prompt(text: str) -> list[str]:
    """Best-effort absolute / @-attached paths from a user prompt (not a sandbox)."""
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        p = _strip_path_token(raw)
        if not p or p in seen:
            return
        low = p.lower()
        if "://" in low or low.startswith("http"):
            return
        seen.add(p)
        found.append(p)

    for m in _AT_PATH_RE.finditer(text):
        add(m.group("p"))
    for m in _QUOTED_ABS_RE.finditer(text):
        add(m.group("p"))
    for m in _WIN_ABS_RE.finditer(text):
        add(m.group("p"))
    for m in _UNIX_ABS_RE.finditer(text):
        add(m.group("p"))
    return found


def is_blocked_outside_workspace_export(path: str, repo_root: Path) -> bool:
    """
    Deny high-risk export suffixes whose resolved path is outside the workspace.

    Fail closed: if resolve fails and the suffix is high-risk, deny.
    """
    suf = _suffix_of(path)
    if suf not in HIGH_RISK_EXPORT_SUFFIXES:
        return False
    if is_allowed_outside_workspace(path):
        return False
    try:
        raw_path = Path(path)
        if raw_path.is_absolute():
            resolved = raw_path.resolve()
        else:
            resolved = (repo_root / raw_path).resolve()
    except OSError:
        return True
    if is_allowed_outside_workspace(str(resolved)):
        return False
    try:
        repo = repo_root.resolve()
    except OSError:
        return True
    try:
        resolved.relative_to(repo)
        return False
    except ValueError:
        return True


def decide_prompt(
    prompt: str,
    allowlist: set[str],
    repo_root: Path | None = None,
) -> tuple[bool, str]:
    """Always continue (never block the user prompt).

    A non-empty message is an agent_message: copy→scrub→continue the task.
    Do not echo emails or paste bodies into the message.
    """
    root = repo_root if repo_root is not None else _DEFAULT_REPO_ROOT
    needs_intake = False
    if find_non_allowlisted_emails(prompt, allowlist):
        needs_intake = True
    if looks_like_raw_sn_export(prompt):
        needs_intake = True
    for p in iter_paths_in_prompt(prompt):
        if is_blocked_raw_path(p) or is_blocked_outside_workspace_export(p, root):
            needs_intake = True
            break
    if needs_intake:
        return True, MSG_ADOPT_THEN_CONTINUE
    return True, ""


def decide_read(path: str, repo_root: Path) -> tuple[str, str]:
    """Return (permission, user_message). permission is allow|deny."""
    if not (path or "").strip():
        return "allow", ""
    if is_blocked_raw_path(path):
        return (
            "deny",
            "Blocked: raw PII path (inbox/raw or .local/). " + MSG_DROP_RAW,
        )
    if is_blocked_outside_workspace_export(path, repo_root):
        return (
            "deny",
            MSG_OUTSIDE_EXPORT,
        )
    if is_under_intake_output(path, repo_root):
        if is_verified_intake_output(path, repo_root):
            return "allow", ""
        return "deny", MSG_UNVERIFIED_CLEAN
    return "allow", ""
