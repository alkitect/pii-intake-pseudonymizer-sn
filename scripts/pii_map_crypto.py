#!/usr/bin/env python3
"""Encrypt / decrypt the local PII map (key outside OneDrive sync root).

Ciphertext may live under ``.local/pii-map.json``. The Fernet key must NOT sit
next to the map under the synced tree. Resolution order:

1. ``PII_MAP_KEY`` — raw Fernet key (url-safe base64)
2. ``PII_MAP_KEY_FILE`` — path to key file (must be outside repo / OneDrive root)
3. Platform default key file under ``%LOCALAPPDATA%/ServiceNow-PII/`` (Windows)
   or ``~/.config/servicenow-pii/`` (Unix), optionally DPAPI-wrapped on Windows

Detect-only / ``--summary`` callers should treat missing key as
``map=unavailable`` (empty map), never hard-fail. Mutating writes fail closed.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

FORMAT_FERNET_V1 = "fernet-v1"
ENV_KEY = "PII_MAP_KEY"
ENV_KEY_FILE = "PII_MAP_KEY_FILE"
ENV_ALLOW_PLAINTEXT = "PII_MAP_ALLOW_PLAINTEXT"


class MapCryptoError(Exception):
    """Map encryption / key resolution failure."""


def cryptography_available() -> bool:
    try:
        from cryptography.fernet import Fernet  # noqa: F401

        return True
    except ImportError:
        return False


def _default_key_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "ServiceNow-PII"
    return Path.home() / ".config" / "servicenow-pii"


def default_key_path() -> Path:
    return _default_key_dir() / "pii-map.key"


def is_under_path(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_key_outside_sync(key_path: Path, repo_root: Path | None = None) -> None:
    """Forbid storing the key next to the map under the synced repo tree."""
    root = (repo_root or REPO_ROOT).resolve()
    resolved = key_path.expanduser().resolve()
    if is_under_path(resolved, root):
        raise MapCryptoError(
            f"PII map key must not live under the repo/OneDrive sync root: {resolved}. "
            f"Use {ENV_KEY}, {ENV_KEY_FILE} outside the tree, or {default_key_path()}."
        )
    # Also forbid accidental .local sibling even if repo_root mis-detected
    if resolved.parent.name == ".local" and (resolved.parent / "pii-map.json").exists():
        raise MapCryptoError("PII map key must not sit next to pii-map.json under .local/")


def _dpapi_protect(data: bytes) -> bytes:
    if sys.platform != "win32":
        return data
    try:
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_blob = DATA_BLOB(
            len(data),
            ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_char)),
        )
        out_blob = DATA_BLOB()
        if not crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "ServiceNow-PII-map",
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        ):
            return data
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except Exception:
        return data


def _dpapi_unprotect(data: bytes) -> bytes:
    if sys.platform != "win32":
        return data
    try:
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_blob = DATA_BLOB(
            len(data),
            ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_char)),
        )
        out_blob = DATA_BLOB()
        if not crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        ):
            return data
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except Exception:
        return data


def generate_key() -> bytes:
    from cryptography.fernet import Fernet

    return Fernet.generate_key()


def write_key_file(path: Path, key: bytes | None = None, *, repo_root: Path | None = None) -> Path:
    """Create a key file outside the sync root (DPAPI-wrapped on Windows when possible)."""
    assert_key_outside_sync(path, repo_root=repo_root)
    if not cryptography_available():
        raise MapCryptoError(
            "cryptography package required for map encryption. "
            "Install: pip install -r requirements-pii.txt"
        )
    raw = key if key is not None else generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    protected = _dpapi_protect(raw)
    path.write_bytes(protected)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def _read_key_bytes(path: Path) -> bytes:
    raw = path.read_bytes().strip()
    if not raw:
        raise MapCryptoError(f"Could not read Fernet key from {path}")
    # Try DPAPI unwrap; if it was plaintext Fernet key, unwrap returns same / fails soft
    unwrapped = _dpapi_unprotect(raw)
    # Fernet keys are url-safe base64 ~44 bytes
    for candidate in (unwrapped, raw):
        try:
            text = candidate.decode("ascii").strip()
        except UnicodeDecodeError:
            continue
        if text:
            return text.encode("ascii")
        if len(candidate) >= 32:
            return candidate
    raise MapCryptoError(f"Could not read Fernet key from {path}")


def resolve_key(*, repo_root: Path | None = None, create_default: bool = False) -> bytes | None:
    """Return Fernet key bytes, or None if unavailable."""
    env_key = os.environ.get(ENV_KEY, "").strip()
    if env_key:
        return env_key.encode("ascii")

    env_file = os.environ.get(ENV_KEY_FILE, "").strip()
    if env_file:
        kp = Path(env_file).expanduser()
        assert_key_outside_sync(kp, repo_root=repo_root)
        if not kp.is_file():
            raise MapCryptoError(f"{ENV_KEY_FILE} does not exist: {kp}")
        return _read_key_bytes(kp)

    default = default_key_path()
    if default.is_file():
        assert_key_outside_sync(default, repo_root=repo_root)
        return _read_key_bytes(default)

    if create_default:
        write_key_file(default, repo_root=repo_root)
        return _read_key_bytes(default)

    return None


def is_encrypted_payload(data: dict[str, Any]) -> bool:
    return str(data.get("format") or "") == FORMAT_FERNET_V1 and bool(data.get("ciphertext"))


def encrypt_payload(plaintext: dict[str, Any], key: bytes) -> dict[str, Any]:
    if not cryptography_available():
        raise MapCryptoError(
            "cryptography package required. Install: pip install -r requirements-pii.txt"
        )
    from cryptography.fernet import Fernet

    raw = json.dumps(plaintext, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = Fernet(key).encrypt(raw)
    return {"format": FORMAT_FERNET_V1, "ciphertext": token.decode("ascii")}


def decrypt_payload(envelope: dict[str, Any], key: bytes) -> dict[str, Any]:
    if not cryptography_available():
        raise MapCryptoError(
            "cryptography package required. Install: pip install -r requirements-pii.txt"
        )
    from cryptography.fernet import Fernet, InvalidToken

    ct = str(envelope.get("ciphertext") or "").encode("ascii")
    try:
        raw = Fernet(key).decrypt(ct)
    except (InvalidToken, ValueError, TypeError) as e:
        raise MapCryptoError("Failed to decrypt PII map (wrong key or corrupt ciphertext)") from e
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise MapCryptoError("Decrypted PII map is not a JSON object")
    return data


def plaintext_allowed() -> bool:
    """Test / emergency escape hatch — never for production agent writes."""
    return os.environ.get(ENV_ALLOW_PLAINTEXT, "").strip().lower() in {"1", "true", "yes"}


def load_map_dict(
    path: Path,
    *,
    repo_root: Path | None = None,
    require_key: bool = False,
) -> tuple[dict[str, Any], str]:
    """Load map JSON.

    Returns (data, status) where status is one of:
    ``ok``, ``missing``, ``unavailable``, ``plaintext``, ``migrated_pending``.
    """
    if not path.is_file():
        return {}, "missing"

    try:
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except (OSError, json.JSONDecodeError) as e:
        if require_key:
            raise MapCryptoError(f"Cannot read PII map: {e}") from e
        return {}, "unavailable"

    if not isinstance(data, dict):
        if require_key:
            raise MapCryptoError("PII map root must be a JSON object")
        return {}, "unavailable"

    if is_encrypted_payload(data):
        try:
            key = resolve_key(repo_root=repo_root, create_default=False)
        except MapCryptoError:
            if require_key:
                raise
            return {}, "unavailable"
        if key is None:
            if require_key:
                raise MapCryptoError(
                    "Encrypted PII map requires a key "
                    f"({ENV_KEY} / {ENV_KEY_FILE} / {default_key_path()})"
                )
            return {}, "unavailable"
        return decrypt_payload(data, key), "ok"

    # Legacy plaintext
    return data, "plaintext"


def save_map_dict(
    path: Path,
    plaintext: dict[str, Any],
    *,
    repo_root: Path | None = None,
    create_key: bool = True,
) -> None:
    """Encrypt and atomically write the map (fail closed without key/crypto)."""
    if plaintext_allowed():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(plaintext, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return

    if not cryptography_available():
        raise MapCryptoError(
            "cryptography package required to save PII map. "
            "Install: pip install -r requirements-pii.txt"
        )

    key = resolve_key(repo_root=repo_root, create_default=create_key)
    if key is None:
        raise MapCryptoError(
            "Cannot save PII map without encryption key. "
            f"Set {ENV_KEY}, {ENV_KEY_FILE}, or allow creating {default_key_path()}."
        )

    envelope = encrypt_payload(plaintext, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def migrate_plaintext_to_encrypted(
    path: Path,
    *,
    repo_root: Path | None = None,
) -> str:
    """Encrypt a legacy plaintext map. Keeps ``.bak`` dual-read backup. Returns status."""
    if not path.is_file():
        return "missing"
    data, status = load_map_dict(path, repo_root=repo_root, require_key=False)
    if status == "ok":
        return "already_encrypted"
    if status == "unavailable":
        raise MapCryptoError("Cannot migrate: map unavailable (missing key for ciphertext?)")
    if status not in {"plaintext", "missing"}:
        raise MapCryptoError(f"Cannot migrate map in status={status}")

    bak = path.with_suffix(path.suffix + ".bak")
    if not bak.exists():
        bak.write_bytes(path.read_bytes())
    save_map_dict(path, data, repo_root=repo_root, create_key=True)
    return "migrated"


def rollback_map(path: Path) -> None:
    """Restore ``path.bak`` over ``path`` (map rollback — not ``--keep-raw``)."""
    bak = path.with_suffix(path.suffix + ".bak")
    if not bak.is_file():
        raise MapCryptoError(f"No backup map at {bak}")
    path.write_bytes(bak.read_bytes())
