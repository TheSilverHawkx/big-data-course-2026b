"""
File-sink consumer: reads Kafka topics and writes Bronze .jsonl.gz files.

  Kafka topics -> poll_one() -> parse EventEnvelope -> BatchWriter -> atomic Bronze file
                                                    \\ parse error -> DLQ topic

Offsets are committed only after a file is atomically renamed into Bronze.

Runnable: ``python -m riskrank.consumers.file_sink --source all --until-idle 30``
"""
from __future__ import annotations

import argparse
import logging
import time
import uuid
from typing import Any

from pydantic import ValidationError

from riskrank.common.dates import utcnow
from riskrank.common.serialization import from_json
from riskrank.config import Settings, get_settings
from riskrank.consumers.batch_writer import BatchWriter
from riskrank.consumers.dead_letter import publish_to_dlq
from riskrank.contracts.envelope import EventEnvelope
from riskrank.kafka.publisher import build_producer
from riskrank.kafka.subscriber import build_consumer, commit_offsets, poll_one
from riskrank.paths import get_paths

log = logging.getLogger(__name__)

_SOURCE_MAP = ("nvd", "epss", "kev")


def _topics_for(settings: Settings, source_filter: str) -> list[str]:
    t = settings.kafka.topics
    all_topics = {"nvd": t.nvd, "epss": t.epss, "kev": t.kev}
    if source_filter == "all":
        return list(all_topics.values())
    return [all_topics[source_filter]]


def _source_from_topic(settings: Settings, topic: str) -> str:
    t = settings.kafka.topics
    mapping = {t.nvd: "nvd", t.epss: "epss", t.kev: "kev"}
    return mapping.get(topic, "unknown")


def run_file_sink(
    settings: Settings,
    *,
    source_filter: str = "all",
    until_idle_seconds: int | None = None,
    max_messages: int | None = None,
    offset_reset: str | None = None,
) -> dict[str, Any]:
    """Consume Kafka topics and write Bronze files. Returns summary dict."""
    idle_timeout = (
        until_idle_seconds
        if until_idle_seconds is not None
        else settings.consumer.idle_exit_seconds
    )
    cfg = settings.consumer
    paths = get_paths(settings)
    paths.ensure_dirs()

    run_id = str(uuid.uuid4())
    ingest_date = utcnow().date().isoformat()
    topics = _topics_for(settings, source_filter)
    sources = _SOURCE_MAP if source_filter == "all" else (source_filter,)

    writers: dict[str, BatchWriter] = {
        src: BatchWriter(src, run_id, paths, cfg, ingest_date=ingest_date) for src in sources
    }

    stats: dict[str, Any] = {"consumed": 0, "written": 0, "dlq": 0, "errors": 0}
    last_msg_mono = time.monotonic()

    with build_producer(settings) as producer:
        with build_consumer(settings, topics, offset_reset=offset_reset) as consumer:
            while True:
                for writer in writers.values():
                    if writer.should_flush_on_timer():
                        result = writer.flush()
                        if result:
                            stats["written"] += result.record_count
                            commit_offsets(consumer, result.offset_infos)

                if time.monotonic() - last_msg_mono >= idle_timeout:
                    log.info("idle timeout reached (%.1f s), shutting down", idle_timeout)
                    break

                if max_messages is not None and stats["consumed"] >= max_messages:
                    log.info("reached max_messages=%d", max_messages)
                    break

                msg = poll_one(consumer, timeout=1.0)
                if msg is None:
                    continue

                last_msg_mono = time.monotonic()
                stats["consumed"] += 1
                source = _source_from_topic(settings, msg.topic())
                raw_value: bytes = msg.value() or b""

                try:
                    data = from_json(raw_value)
                    envelope = EventEnvelope.model_validate(data)
                except (ValidationError, Exception) as exc:
                    stats["dlq"] += 1
                    publish_to_dlq(
                        producer,
                        settings.kafka.topics.dlq,
                        original_topic=msg.topic(),
                        original_partition=msg.partition(),
                        original_offset=msg.offset(),
                        error_type=type(exc).__name__,
                        error_message=str(exc),
                        raw_value=raw_value,
                    )
                    continue

                writer = writers.get(source)
                if writer is None:
                    log.warning("no writer for source=%s, skipping", source)
                    continue

                flush_result = writer.add(envelope, offset_info=msg)
                if flush_result:
                    stats["written"] += flush_result.record_count
                    commit_offsets(consumer, flush_result.offset_infos)

            for writer in writers.values():
                result = writer.close()
                if result:
                    stats["written"] += result.record_count
                    commit_offsets(consumer, result.offset_infos)

    log.info("file sink complete: %s", stats)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Kafka -> Bronze file-sink consumer")
    parser.add_argument("--source", choices=["all", "nvd", "epss", "kev"], default="all")
    parser.add_argument("--until-idle", type=int, default=None, dest="until_idle")
    parser.add_argument("--max-messages", type=int, default=None)
    parser.add_argument("--offset-reset", choices=["earliest", "latest"], default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    summary = run_file_sink(
        settings,
        source_filter=args.source,
        until_idle_seconds=args.until_idle,
        max_messages=args.max_messages,
        offset_reset=args.offset_reset,
    )
    print(summary)


if __name__ == "__main__":
    main()
