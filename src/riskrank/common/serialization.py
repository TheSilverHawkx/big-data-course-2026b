"""JSON serialization helpers for Kafka messages and file sinks."""
from __future__ import annotations

import json
import uuid
from datetime import date, datetime
from typing import Any


class _ExtendedEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        return super().default(obj)


def to_json(obj: Any, *, indent: int | None = None) -> str:
    return json.dumps(obj, cls=_ExtendedEncoder, ensure_ascii=False, indent=indent)


def from_json(s: str | bytes) -> Any:
    return json.loads(s)


def kafka_serializer(obj: Any) -> bytes:
    """Encode a Python object to UTF-8 JSON bytes for confluent-kafka."""
    return to_json(obj).encode("utf-8")


def kafka_deserializer(data: bytes | None) -> Any:
    """Decode UTF-8 JSON bytes from confluent-kafka."""
    if data is None:
        return None
    return from_json(data)
