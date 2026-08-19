"""Intake manifest: record scrubbed outputs for inbox/clean and promote paths.

Tracks SHA-256 checksums under ``.local/intake-manifest.json`` so downstream
workflows can tell which clean files came from a successful anonymize run.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

INTAKE_MANIFEST_NAME = "intake-manifest.json"


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
    """Record a successful clean/promote write in the intake manifest."""
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
