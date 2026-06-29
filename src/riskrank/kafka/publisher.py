"""Kafka producer wrapper for publishing EventEnvelopes."""
from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from confluent_kafka import Message, Producer

from riskrank.common.serialization import kafka_serializer
from riskrank.config import Settings
from riskrank.contracts.envelope import EventEnvelope
from riskrank.kafka.settings import producer_conf

log = logging.getLogger(__name__)


@contextmanager
def build_producer(
    settings: Settings,
    *,
    flush_timeout: int = 30,
) -> Generator[Producer, None, None]:
    """Context manager: yields a Producer and flushes pending messages on exit."""
    producer = Producer(producer_conf(settings))
    try:
        yield producer
    finally:
        remaining = producer.flush(timeout=flush_timeout)
        if remaining > 0:
            log.warning("producer flush timed out; %d messages still in queue", remaining)


def _delivery_callback(err: Any, msg: Message) -> None:
    if err:
        log.error("delivery failed to %s: %s", msg.topic(), err)
    else:
        log.debug("delivered to %s [%d] @ %d", msg.topic(), msg.partition(), msg.offset())


def publish_envelope(
    producer: Producer,
    topic: str,
    key: str,
    envelope: EventEnvelope,
) -> None:
    """Serialize one envelope and produce it. Calls poll(0) to trigger callbacks."""
    value = kafka_serializer(envelope.model_dump(mode="json"))
    producer.produce(
        topic,
        key=key.encode("utf-8"),
        value=value,
        on_delivery=_delivery_callback,
    )
    producer.poll(0)
