"""Kafka topic administration via confluent-kafka AdminClient.

Runnable: ``python -m riskrank.kafka.admin`` creates all required topics.
"""
from __future__ import annotations

import logging

from confluent_kafka import KafkaError, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic

from riskrank.config import Settings, get_settings
from riskrank.kafka.settings import admin_conf

log = logging.getLogger(__name__)


def _new_topics(settings: Settings) -> list[NewTopic]:
    topics = settings.kafka.topics
    partitions = settings.kafka.partitions
    replication = settings.kafka.replication_factor
    return [
        NewTopic(topics.nvd, num_partitions=partitions, replication_factor=replication),
        NewTopic(topics.epss, num_partitions=partitions, replication_factor=replication),
        NewTopic(topics.kev, num_partitions=partitions, replication_factor=replication),
        # DLQ uses a single partition — ordering matters for replay
        NewTopic(topics.dlq, num_partitions=1, replication_factor=replication),
    ]


def create_topics(settings: Settings) -> dict[str, str]:
    """Create all required Kafka topics. Idempotent — existing topics are not an error."""
    client = AdminClient(admin_conf(settings))
    futures = client.create_topics(_new_topics(settings))
    results: dict[str, str] = {}
    for topic, future in futures.items():
        try:
            future.result()
            results[topic] = "created"
            log.info("topic created: %s", topic)
        except KafkaException as exc:
            code = exc.args[0].code()
            if code == KafkaError.TOPIC_ALREADY_EXISTS:
                results[topic] = "already_exists"
                log.debug("topic already exists: %s", topic)
            else:
                results[topic] = f"error: {exc}"
                log.error("failed to create topic %s: %s", topic, exc)
    return results


def describe_topics(settings: Settings) -> list[dict]:
    """Return partition info for all managed topics."""
    client = AdminClient(admin_conf(settings))
    metadata = client.list_topics(timeout=10)
    managed = {
        settings.kafka.topics.nvd,
        settings.kafka.topics.epss,
        settings.kafka.topics.kev,
        settings.kafka.topics.dlq,
    }
    result = []
    for name, topic_meta in metadata.topics.items():
        if name not in managed:
            continue
        result.append(
            {
                "name": name,
                "partitions": len(topic_meta.partitions),
                "error": str(topic_meta.error) if topic_meta.error else None,
            }
        )
    return sorted(result, key=lambda t: t["name"])


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    results = create_topics(settings)
    for topic, status in sorted(results.items()):
        print(f"{topic}: {status}")


if __name__ == "__main__":
    main()
