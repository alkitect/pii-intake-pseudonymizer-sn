#!/usr/bin/env python3
"""PII commit gate: scan staged src/stories **index** blobs with --summary.

Fail-closed. Never --report / --in-place. Never requires PII_MAP_KEY.
Used by .githooks/pre-commit and scripts/verify-before-commit.py.
"""

from __future__ import annotations

import argparse
import fnmatch
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STORIES_PREFIX = "src/stories/"
EXPORT_DIR_NAMES = frozenset({"source-export", "source_export"})
GATE_TMP_NAME = ".commit-gate-index"
DENIED_PATTERNS = (
    ".env",
    ".env.*",
    ".local/pii-map*",
    "*.key",
    "**/pii-map.json",
    "**/pii-map.json.bak",
)

ANONYMIZE = REPO_ROOT / "scripts" / "anonymize_intake.py"


def _die(msg: str, code: int = 1) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return code


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def hooks_path_ok() -> bool:
    r = _run_git(["config", "--get", "core.hooksPath"])
    if r.returncode != 0:
        return False
    value = (r.stdout or "").strip().replace("\\", "/")
    return value in {".githooks", str(REPO_ROOT / ".githooks").replace("\\", "/")}


def warn_hooks_path() -> None:
    if not hooks_path_ok():
        print(
            "warning: core.hooksPath is not .githooks — run "
            "`py -3 scripts/install-git-hooks.py` (Phase 2 local hook). "
            "Skill/verify gate still applies; --no-verify does not waive it.",
            file=sys.stderr,
        )


def list_staged_paths() -> list[str]:
    r = _run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"])
    if r.returncode != 0:
        err = (r.stderr or "").strip() or "unknown git error"
        raise RuntimeError(err)
    raw = r.stdout or ""
    if not raw:
        return []
    return [p for p in raw.split("\0") if p]


def is_export_path(rel: str) -> bool:
    parts = Path(rel.replace("\\", "/")).parts
    return any(p in EXPORT_DIR_NAMES for p in parts)


def is_story_path(rel: str) -> bool:
    norm = rel.replace("\\", "/")
    return norm.startswith(STORIES_PREFIX) and not is_export_path(norm)


def denied_staged(paths: list[str]) -> list[str]:
    hits: list[str] = []
    for rel in paths:
        norm = rel.replace("\\", "/")
        base = Path(norm).name
        for pat in DENIED_PATTERNS:
            if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(base, pat):
                hits.append(norm)
                break
            if pat.startswith("**/") and fnmatch.fnmatch(norm, pat):
                hits.append(norm)
                break
    return hits


def materialize_index_blobs(story_paths: list[str], dest_root: Path) -> list[Path]:
    """Write `git show :path` into dest_root mirroring repo-relative paths."""
    out: list[Path] = []
    for rel in story_paths:
        norm = rel.replace("\\", "/")
        raw = subprocess.run(
            ["git", "show", f":{norm}"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
        )
        if raw.returncode != 0:
            err = (raw.stderr or b"").decode("utf-8", errors="replace").strip()
            raise RuntimeError(err or f"git show :{norm} failed")
        target = dest_root / norm
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw.stdout)
        out.append(target)
    return out


def run_summary_gate(materialized: list[Path]) -> int:
    if not ANONYMIZE.is_file():
        return _die(f"missing {ANONYMIZE}", 2)
    if not materialized:
        return 0
    cmd = [
        sys.executable,
        str(ANONYMIZE),
        *[str(p) for p in materialized],
        "--dry-run",
        "--fail-on-hits",
        "--force-path",
        "--summary",
    ]
    r = subprocess.run(cmd, cwd=REPO_ROOT, check=False)
    return int(r.returncode)


def gate_staged_stories(*, warn_hooks: bool = False) -> int:
    if warn_hooks:
        warn_hooks_path()
    try:
        staged = list_staged_paths()
    except RuntimeError as e:
        return _die(str(e), 2)

    denied = denied_staged(staged)
    if denied:
        return _die(
            "refusing to commit sensitive path(s): " + ", ".join(denied),
            1,
        )

    stories = [p for p in staged if is_story_path(p)]
    if not stories:
        return 0

    dest = REPO_ROOT / STORIES_PREFIX.rstrip("/") / GATE_TMP_NAME
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        try:
            materialized = materialize_index_blobs(stories, dest)
        except RuntimeError as e:
            return _die(str(e), 2)
        # Paths must remain under src/stories for gate validation
        return run_summary_gate(materialized)
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--warn-hooks-path",
        action="store_true",
        help="Warn if core.hooksPath is not .githooks",
    )
    args = parser.parse_args(argv)
    try:
        return gate_staged_stories(warn_hooks=args.warn_hooks_path)
    except OSError as e:
        return _die(f"PII commit gate failed: {e}", 2)


if __name__ == "__main__":
    # Fail closed if somehow imported wrong
    if not ANONYMIZE.is_file():
        sys.exit(_die(f"missing anonymize script at {ANONYMIZE}", 2))
    sys.exit(main())
