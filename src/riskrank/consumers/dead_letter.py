"""Dead-letter queue (DLQ) contract and publisher."""
from __future__ import annotations

import base64
import logging
from datetime import datetime

from pydantic import BaseModel

from riskrank.common.dates import utcnow
from riskrank.common.serialization import kafka_serializer

log = logging.getLogger(__name__)


class DLQRecord(BaseModel):
    original_topic: str
    original_partition: int
    original_offset: int
    failed_at: datetime
    error_type: str
    error_message: str
    raw_value_base64: str


def publish_to_dlq(
    producer: object,
    dlq_topic: str,
    *,
    original_topic: str,
    original_partition: int,
    original_offset: int,
    error_type: str,
    error_message: str,
    raw_value: bytes | None,
) -> None:
    """
    Publish a failed message to the DLQ. Does not raise on producer errors.

    raw_value is base64-encoded so the DLQ record is always valid JSON.
    """
    record = DLQRecord(
        original_topic=original_topic,
        original_partition=original_partition,
        original_offset=original_offset,
        failed_at=utcnow(),
        error_type=error_type,
        error_message=error_message[:2000],
        raw_value_base64=base64.b64encode(raw_value or b"").decode("ascii"),
    )
    value = kafka_serializer(record.model_dump(mode="json"))
    try:
        producer.produce(dlq_topic, value=value)  # type: ignore[attr-defined]
        producer.poll(0)  # type: ignore[attr-defined]
        log.warning("message routed to DLQ: topic=%s error=%s", original_topic, error_type)
    except Exception:
        log.exception("failed to publish to DLQ — message dropped silently")
