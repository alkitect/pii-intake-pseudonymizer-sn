#!/usr/bin/env python3
"""Opt-in Presidio NER for free-text PERSON (and optional LOCATION) spans.

Default OFF. Hooks must never import this module. When extras are absent,
callers report ``ner=skipped`` — never silent quality skew.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NER_CONFIG = REPO_ROOT / "config" / "pii-ner.json"


@dataclass
class NerSpan:
    text: str
    entity_type: str
    start: int
    end: int


def ner_available() -> bool:
    try:
        from presidio_analyzer import AnalyzerEngine  # noqa: F401

        return True
    except ImportError:
        return False


def load_ner_config(path: Path | None = None) -> dict[str, Any]:
    p = path or DEFAULT_NER_CONFIG
    if not p.is_file():
        return {
            "entities": ["PERSON"],
            "language": "en",
            "score_threshold": 0.5,
        }
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"entities": ["PERSON"], "language": "en", "score_threshold": 0.5}
    if not isinstance(data, dict):
        return {"entities": ["PERSON"], "language": "en", "score_threshold": 0.5}
    return data


_engine: Any | None = None


def _get_engine() -> Any:
    global _engine
    if _engine is not None:
        return _engine
    from presidio_analyzer import AnalyzerEngine

    _engine = AnalyzerEngine()
    return _engine


def extract_person_spans(
    text: str,
    *,
    config_path: Path | None = None,
    allowlist: set[str] | None = None,
) -> list[NerSpan]:
    """Return PERSON (and configured) entity spans. Raises ImportError if missing."""
    if not text:
        return []
    cfg = load_ner_config(config_path)
    entities = list(cfg.get("entities") or ["PERSON"])
    language = str(cfg.get("language") or "en")
    threshold = float(cfg.get("score_threshold") or 0.5)
    allow = {a.lower() for a in (allowlist or set())}

    engine = _get_engine()
    results = engine.analyze(
        text=text,
        language=language,
        entities=entities,
        score_threshold=threshold,
    )
    spans: list[NerSpan] = []
    seen: set[tuple[int, int, str]] = set()
    for r in results:
        start, end = int(r.start), int(r.end)
        chunk = text[start:end].strip()
        if len(chunk) < 2:
            continue
        if chunk.lower() in allow:
            continue
        # Skip Script Include-ish identifiers (CamelCase API tokens)
        if re.fullmatch(r"[A-Z][A-Za-z0-9]+(?:_[A-Za-z0-9]+)+", chunk):
            continue
        if chunk.startswith("UH_") or chunk.startswith("Glide"):
            continue
        key = (start, end, chunk.lower())
        if key in seen:
            continue
        seen.add(key)
        spans.append(
            NerSpan(
                text=chunk,
                entity_type=str(getattr(r, "entity_type", "PERSON")),
                start=start,
                end=end,
            )
        )
    return spans


def harvest_ner_names(
    text: str,
    *,
    config_path: Path | None = None,
    allowlist: set[str] | None = None,
) -> tuple[list[str], str]:
    """Return (names, status) where status is ``ok`` or ``skipped``."""
    if not ner_available():
        return [], "skipped"
    try:
        spans = extract_person_spans(
            text, config_path=config_path, allowlist=allowlist
        )
    except Exception:
        return [], "skipped"
    names: list[str] = []
    seen: set[str] = set()
    for span in spans:
        if span.entity_type.upper() not in {"PERSON", "LOCATION"}:
            continue
        if span.entity_type.upper() == "LOCATION":
            continue  # PERSON only into name map by default
        key = span.text.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(span.text)
    return names, "ok"
