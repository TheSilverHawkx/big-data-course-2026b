"""
NVD CVE producer — fetches from NVD API 2.0 and publishes to risk.raw.nvd.

Modes:
  full       — page through all CVEs, no date filter
  published  — date-filtered by publication date (120-day chunks)
  modified   — date-filtered by last-modified date (120-day chunks)

Runnable: ``python -m riskrank.producers.nvd --mode modified --max-records 50``
"""
from __future__ import annotations

import argparse
import logging
import time
from datetime import UTC, date, datetime

from confluent_kafka import Producer

from riskrank.common.dates import utcnow
from riskrank.common.http import build_client, get_with_retry
from riskrank.config import Settings, get_settings
from riskrank.contracts.envelope import make_envelope
from riskrank.kafka.publisher import build_producer, publish_envelope
from riskrank.producers.base import (
    ProducerStats,
    chunk_date_range,
    new_run_id,
    parse_iso_date,
    resolve_date_range,
)

log = logging.getLogger(__name__)

_DATE_FMT = "%Y-%m-%dT00:00:00.000"


def _fmt(d: date) -> str:
    return d.strftime(_DATE_FMT)


def _request_params(
    mode: str,
    start: date | None,
    end: date | None,
    results_per_page: int,
    start_index: int,
) -> dict:
    params: dict = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "noRejected": "",
    }
    if mode == "published" and start and end:
        params["pubStartDate"] = _fmt(start)
        params["pubEndDate"] = _fmt(end)
    elif mode == "modified" and start and end:
        params["lastModStartDate"] = _fmt(start)
        params["lastModEndDate"] = _fmt(end)
    return params


def _parse_modified_at(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=UTC)
    except ValueError:
        return None


def _paginate_chunk(
    client,
    url: str,
    mode: str,
    chunk_start: date | None,
    chunk_end: date | None,
    results_per_page: int,
    delay: float,
    stats: ProducerStats,
    run_id: str,
    topic: str,
    kafka_producer: Producer | None,
    dry_run: bool,
    max_records: int | None,
    fetched_at,
) -> bool:
    """Page through one date chunk. Returns True if max_records was reached."""
    start_index = 0
    while True:
        params = _request_params(mode, chunk_start, chunk_end, results_per_page, start_index)
        resp = get_with_retry(
            client, url, params, delay_seconds=delay if start_index > 0 else 0.0
        )
        data = resp.json()
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        stats.fetched += len(vulns)

        for item in vulns:
            if max_records is not None and stats.published >= max_records:
                return True

            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                stats.invalid += 1
                continue

            pub_date = parse_iso_date(cve.get("published", "")) or utcnow().date()
            source_modified_at = _parse_modified_at(cve.get("lastModified", ""))

            try:
                envelope = make_envelope(
                    source="nvd",
                    source_record_id=cve_id,
                    effective_date=pub_date,
                    payload=cve,
                    ingestion_run_id=run_id,
                    fetched_at=fetched_at,
                    source_modified_at=source_modified_at,
                )
            except Exception:
                log.exception("failed to build envelope for %s", cve_id)
                stats.failed += 1
                continue

            if not dry_run and kafka_producer is not None:
                try:
                    publish_envelope(kafka_producer, topic, cve_id, envelope)
                    stats.published += 1
                except Exception:
                    log.exception("failed to publish %s", cve_id)
                    stats.failed += 1
            else:
                stats.published += 1

        start_index += len(vulns)
        if not vulns or start_index >= total:
            break
        time.sleep(delay)

    return False


def run_nvd_producer(
    settings: Settings,
    kafka_producer: Producer | None,
    *,
    mode: str = "full",
    start_date: date | None = None,
    end_date: date | None = None,
    lookback_days: int = 180,
    run_id: str | None = None,
    dry_run: bool = False,
    max_records: int | None = None,
) -> ProducerStats:
    """Fetch CVEs from NVD API 2.0 and publish to Kafka."""
    if run_id is None:
        run_id = new_run_id()
    stats = ProducerStats(source="nvd", run_id=run_id)
    nvd_cfg = settings.nvd
    topic = settings.kafka.topics.nvd
    delay = (
        nvd_cfg.request_delay_with_key_seconds
        if settings.nvd_api_key
        else nvd_cfg.request_delay_without_key_seconds
    )
    fetched_at = utcnow()

    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    if mode == "full":
        chunks: list[tuple[date | None, date | None]] = [(None, None)]
    else:
        start, end = resolve_date_range(start_date, end_date, lookback_days)
        chunks = chunk_date_range(start, end, nvd_cfg.request_window_days)

    with build_client(headers=headers) as client:
        for chunk_start, chunk_end in chunks:
            done = _paginate_chunk(
                client,
                nvd_cfg.base_url,
                mode,
                chunk_start,
                chunk_end,
                nvd_cfg.results_per_page,
                delay,
                stats,
                run_id,
                topic,
                kafka_producer,
                dry_run,
                max_records,
                fetched_at,
            )
            if done:
                break

    stats.log_summary()
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="NVD CVE producer")
    parser.add_argument("--mode", choices=["full", "published", "modified"], default="modified")
    parser.add_argument("--start-date", type=date.fromisoformat, default=None)
    parser.add_argument("--end-date", type=date.fromisoformat, default=None)
    parser.add_argument("--lookback-days", type=int, default=180)
    parser.add_argument("--max-records", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    with build_producer(settings) as producer:
        run_nvd_producer(
            settings,
            None if args.dry_run else producer,
            mode=args.mode,
            start_date=args.start_date,
            end_date=args.end_date,
            lookback_days=args.lookback_days,
            dry_run=args.dry_run,
            max_records=args.max_records,
        )


if __name__ == "__main__":
    main()
