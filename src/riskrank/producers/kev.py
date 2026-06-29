"""
CISA KEV catalog producer — fetches the full catalog and publishes to risk.raw.kev.

By default the entire catalog is emitted so the Gold builder can exclude CVEs that
were already in KEV before each observation date.

Runnable: ``python -m riskrank.producers.kev``
"""
from __future__ import annotations

import argparse
import logging
from datetime import UTC, date, datetime

from confluent_kafka import Producer

from riskrank.common.dates import utcnow
from riskrank.common.http import build_client, get_with_retry
from riskrank.config import Settings, get_settings
from riskrank.contracts.envelope import make_envelope
from riskrank.kafka.publisher import build_producer, publish_envelope
from riskrank.producers.base import ProducerStats, new_run_id, parse_iso_date

log = logging.getLogger(__name__)

_REQUIRED_FIELDS = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes",
)


def run_kev_producer(
    settings: Settings,
    kafka_producer: Producer | None,
    *,
    run_id: str | None = None,
    dry_run: bool = False,
    max_records: int | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
) -> ProducerStats:
    """Fetch the CISA KEV JSON catalog and publish one envelope per vulnerability."""
    if run_id is None:
        run_id = new_run_id()
    stats = ProducerStats(source="kev", run_id=run_id)
    topic = settings.kafka.topics.kev
    fetched_at = utcnow()

    with build_client() as client:
        try:
            resp = get_with_retry(client, settings.kev.catalog_url)
            catalog = resp.json()
        except Exception:
            log.exception("failed to fetch KEV catalog")
            stats.failed += 1
            stats.log_summary()
            return stats

    catalog_version = catalog.get("catalogVersion", "")
    catalog_date_released = catalog.get("dateReleased", "")
    vulnerabilities = catalog.get("vulnerabilities", [])
    log.info("fetched KEV catalog: %d entries (v%s)", len(vulnerabilities), catalog_version)

    for vuln in vulnerabilities:
        if max_records is not None and stats.published >= max_records:
            break

        cve_id = vuln.get("cveID", "")
        effective_date = parse_iso_date(vuln.get("dateAdded", ""))
        if not cve_id or effective_date is None:
            stats.invalid += 1
            continue

        if start_date and effective_date < start_date:
            stats.skipped += 1
            continue
        if end_date and effective_date > end_date:
            stats.skipped += 1
            continue

        source_modified_at = datetime(
            effective_date.year, effective_date.month, effective_date.day, tzinfo=UTC
        )

        payload = {field: vuln.get(field) for field in _REQUIRED_FIELDS}
        payload["catalog_version"] = catalog_version
        payload["catalog_date_released"] = catalog_date_released
        stats.fetched += 1

        try:
            envelope = make_envelope(
                source="kev",
                source_record_id=cve_id,
                effective_date=effective_date,
                payload=payload,
                ingestion_run_id=run_id,
                fetched_at=fetched_at,
                source_modified_at=source_modified_at,
            )
        except Exception:
            log.exception("failed to build envelope for KEV %s", cve_id)
            stats.failed += 1
            continue

        if not dry_run and kafka_producer is not None:
            try:
                publish_envelope(kafka_producer, topic, cve_id, envelope)
                stats.published += 1
            except Exception:
                log.exception("failed to publish KEV %s", cve_id)
                stats.failed += 1
        else:
            stats.published += 1
        stats.maybe_log_progress(500)

    stats.log_summary()
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="CISA KEV catalog producer")
    parser.add_argument("--start-date", type=date.fromisoformat, default=None)
    parser.add_argument("--end-date", type=date.fromisoformat, default=None)
    parser.add_argument("--max-records", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    with build_producer(settings) as producer:
        run_kev_producer(
            settings,
            None if args.dry_run else producer,
            dry_run=args.dry_run,
            max_records=args.max_records,
            start_date=args.start_date,
            end_date=args.end_date,
        )


if __name__ == "__main__":
    main()
