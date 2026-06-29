"""Common event envelope for all Kafka messages in the RiskRank pipeline."""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel

from riskrank.common.dates import utcnow
from riskrank.common.hashing import dict_hash, sha256_hex

SourceName = Literal["nvd", "epss", "kev"]


class EventEnvelope(BaseModel):
    event_id: str
    event_schema_version: str = "1.0.0"
    source: SourceName
    source_record_id: str
    event_type: str
    effective_date: date
    source_modified_at: datetime | None = None
    fetched_at: datetime
    ingestion_run_id: str
    payload_sha256: str
    payload: dict[str, Any]


def make_envelope(
    source: SourceName,
    source_record_id: str,
    effective_date: date,
    payload: dict[str, Any],
    ingestion_run_id: str,
    *,
    fetched_at: datetime | None = None,
    source_modified_at: datetime | None = None,
    event_type: str = "source.raw_record",
) -> EventEnvelope:
    """
    Build a deterministic EventEnvelope.

    The same source record fetched twice without payload changes produces the same
    event_id. ingestion_run_id and fetched_at do NOT affect event_id or payload_sha256.
    """
    if fetched_at is None:
        fetched_at = utcnow()
    payload_sha256 = dict_hash(payload)
    identity = f"{source}|{source_record_id}|{effective_date.isoformat()}|{payload_sha256}"
    event_id = sha256_hex(identity)
    return EventEnvelope(
        event_id=event_id,
        source=source,
        source_record_id=source_record_id,
        event_type=event_type,
        effective_date=effective_date,
        source_modified_at=source_modified_at,
        fetched_at=fetched_at,
        ingestion_run_id=ingestion_run_id,
        payload_sha256=payload_sha256,
        payload=payload,
    )
