"""
CVE producer — reads the local OSV corpus and publishes to risk.raw.nvd.

The corpus is a directory of per-CVE OSV documents (``CVE-YYYY-NNNN.json``).
Each one is translated into the NVD API 2.0 ``cve`` payload shape by
``riskrank.producers.osv_adapter`` before being wrapped in an EventEnvelope, so
Bronze, Silver and Gold see exactly what the old NVD API producer emitted.

Runnable: ``python -m riskrank.producers.nvd --max-records 500 --dry-run``
"""
from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Iterator
from pathlib import Path

from confluent_kafka import Producer

from riskrank.common.dates import utcnow
from riskrank.config import Settings, get_settings
from riskrank.contracts.envelope import make_envelope
from riskrank.kafka.publisher import build_producer, publish_envelope
from riskrank.producers.base import ProducerStats, new_run_id, parse_iso_date
from riskrank.producers.osv_adapter import is_rejected, osv_to_nvd_cve, parse_osv_timestamp

log = logging.getLogger(__name__)


def iter_osv_files(input_dir: Path, file_glob: str) -> Iterator[Path]:
    """Yield corpus files in a stable order, one at a time (the corpus is ~80k files)."""
    yield from sorted(input_dir.glob(file_glob))


def run_nvd_producer(
    settings: Settings,
    kafka_producer: Producer | None,
    *,
    input_dir: str | Path | None = None,
    run_id: str | None = None,
    dry_run: bool = False,
    max_records: int | None = None,
) -> ProducerStats:
    """Read OSV CVE documents from disk and publish them to Kafka."""
    if run_id is None:
        run_id = new_run_id()
    stats = ProducerStats(source="nvd", run_id=run_id)

    nvd_cfg = settings.nvd
    root = Path(input_dir) if input_dir is not None else Path(nvd_cfg.input_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"NVD input directory not found: {root}")

    topic = settings.kafka.topics.nvd
    fetched_at = utcnow()
    log.info("reading OSV corpus from %s (glob %s)", root, nvd_cfg.file_glob)

    for path in iter_osv_files(root, nvd_cfg.file_glob):
        if max_records is not None and stats.published >= max_records:
            break

        try:
            with path.open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            log.exception("failed to read %s", path.name)
            stats.invalid += 1
            continue

        stats.fetched += 1

        if is_rejected(doc):
            stats.skipped += 1
            continue

        try:
            cve = osv_to_nvd_cve(doc)
        except Exception:
            log.exception("failed to adapt %s", path.name)
            stats.invalid += 1
            continue

        if cve is None or not cve.get("id"):
            stats.invalid += 1
            continue

        cve_id = cve["id"]
        pub_date = parse_iso_date(cve.get("published")) or utcnow().date()
        source_modified_at = parse_osv_timestamp(doc.get("modified"))

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
        stats.maybe_log_progress(2000)

    stats.log_summary()
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="CVE producer (local OSV corpus)")
    parser.add_argument(
        "--input-dir", default=None, help="Directory of OSV CVE JSON files (default: config nvd.input_dir)"
    )
    parser.add_argument("--max-records", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    if args.dry_run:
        run_nvd_producer(
            settings,
            None,
            input_dir=args.input_dir,
            dry_run=True,
            max_records=args.max_records,
        )
        return

    with build_producer(settings) as producer:
        run_nvd_producer(
            settings,
            producer,
            input_dir=args.input_dir,
            max_records=args.max_records,
        )


if __name__ == "__main__":
    main()
