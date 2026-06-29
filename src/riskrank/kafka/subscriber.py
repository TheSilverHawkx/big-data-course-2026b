"""Kafka consumer wrapper with manual offset commit."""
from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager

import confluent_kafka
from confluent_kafka import Consumer, KafkaError, KafkaException, Message, TopicPartition

from riskrank.config import Settings
from riskrank.kafka.settings import consumer_conf

log = logging.getLogger(__name__)


@contextmanager
def build_consumer(
    settings: Settings,
    topics: list[str],
    *,
    group_id: str | None = None,
    offset_reset: str | None = None,
) -> Generator[Consumer, None, None]:
    """
    Context manager: subscribes to topics and closes on exit.

    offset_reset: if "earliest" or "latest", seek all partitions on assignment
    (overrides stored offsets for the consumer group).
    """
    consumer = Consumer(consumer_conf(settings, group_id=group_id))

    if offset_reset is not None:
        _reset = offset_reset

        def _on_assign(c: Consumer, partitions: list[TopicPartition]) -> None:
            target = (
                confluent_kafka.OFFSET_BEGINNING
                if _reset == "earliest"
                else confluent_kafka.OFFSET_END
            )
            for tp in partitions:
                tp.offset = target
            c.assign(partitions)
            log.info("offset reset to %s on %d partition(s)", _reset, len(partitions))

        consumer.subscribe(topics, on_assign=_on_assign)
    else:
        consumer.subscribe(topics)

    try:
        yield consumer
    finally:
        consumer.close()


def poll_one(consumer: Consumer, timeout: float = 1.0) -> Message | None:
    """
    Poll for one message.

    Returns None on timeout or partition EOF. Raises KafkaException on real errors.
    """
    msg = consumer.poll(timeout=timeout)
    if msg is None:
        return None
    if msg.error():
        if msg.error().code() == KafkaError._PARTITION_EOF:
            return None
        raise KafkaException(msg.error())
    return msg


def commit_offsets(consumer: Consumer, messages: list[Message]) -> None:
    """Synchronously commit next-offset for each message (offset + 1)."""
    if not messages:
        return
    offsets = [
        TopicPartition(msg.topic(), msg.partition(), msg.offset() + 1) for msg in messages
    ]
    consumer.commit(offsets=offsets, asynchronous=False)
    log.debug("committed %d offsets", len(offsets))
