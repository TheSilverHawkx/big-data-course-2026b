"""Deterministic hashing helpers for deduplication keys."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def dict_hash(d: dict[str, Any]) -> str:
    """Stable SHA-256 of a JSON-serializable dict with sorted keys."""
    canonical = json.dumps(d, sort_keys=True, ensure_ascii=False)
    return sha256_hex(canonical)
