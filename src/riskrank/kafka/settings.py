"""Build confluent-kafka config dicts from the application Settings."""
from __future__ import annotations

from typing import Any

from riskrank.config import Settings


def producer_conf(settings: Settings) -> dict[str, Any]:
    return {
        "bootstrap.servers": settings.kafka.bootstrap_servers,
        "client.id": settings.kafka.client_id,
        "enable.idempotence": True,
        "acks": "all",
        "retries": 10,
        "retry.backoff.ms": 250,
    }


def consumer_conf(settings: Settings, group_id: str | None = None) -> dict[str, Any]:
    return {
        "bootstrap.servers": settings.kafka.bootstrap_servers,
        "group.id": group_id or settings.kafka.consumer_group,
        "client.id": settings.kafka.client_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        "max.poll.interval.ms": 300_000,
    }


def admin_conf(settings: Settings) -> dict[str, Any]:
    return {
        "bootstrap.servers": settings.kafka.bootstrap_servers,
    }
