"""
EPSS daily score producer — downloads compressed CSV files and publishes to risk.raw.epss.

File format (per date):
  Line 1: #model_version:v2024.01.01,score_date:2024-06-01T00:00:00+0000
  Line 2: cve,epss,percentile  (header)
  Line 3+: CVE-xxxx-xxxx,0.00432,0.73421

Runnable: ``python -m riskrank.producers.epss --start-date 2025-01-01 --end-date 2025-01-07``
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import logging
from datetime import date

from confluent_kafka import Producer

from riskrank.common.dates import sampled_date_range, utcnow
from riskrank.common.http import build_client, get_with_retry
from riskrank.config import Settings, get_settings
from riskrank.contracts.envelope import make_envelope
from riskrank.kafka.publisher import build_producer, publish_envelope
from riskrank.producers.base import ProducerStats, new_run_id, resolve_date_range

log = logging.getLogger(__name__)


def _parse_comment_metadata(line: str) -> dict[str, str]:
    """Parse the leading '#' comment line into a metadata dict."""
    meta: dict[str, str] = {}
    for part in line.lstrip("#").split(","):
        key, sep, value = part.strip().partition(":")
        if sep:
            meta[key.strip()] = value.strip()
    return meta


def parse_epss_file(content: bytes) -> tuple[str, str, list[dict[str, str]]]:
    """
    Decompress and parse an EPSS .csv.gz file.

    Returns (model_version, score_date_str, rows) where rows are dicts
    with keys: cve, epss, percentile.
    """
    with gzip.open(io.BytesIO(content), "rt", encoding="utf-8") as gz:
        lines = gz.readlines()

    model_version = ""
    score_date = ""
    data_lines: list[str] = []
    for line in lines:
        stripped = line.rstrip("\n")
        if stripped.startswith("#"):
            meta = _parse_comment_metadata(stripped)
            model_version = meta.get("model_version", "")
            score_date = meta.get("score_date", "")[:10]  # keep YYYY-MM-DD only
        elif stripped.lower().startswith("cve,"):
            continue  # skip header row
        elif stripped:
            data_lines.append(stripped)

    reader = csv.DictReader(data_lines, fieldnames=["cve", "epss", "percentile"])
    rows = list(reader)
    return model_version, score_date, rows


def run_epss_producer(
    settings: Settings,
    kafka_producer: Producer | None,
    *,
    start_date: date | None = None,
    end_date: date | None = None,
    lookback_days: int = 180,
    days_of_month: tuple[int, ...] | None = None,
    run_id: str | None = None,
    dry_run: bool = False,
    max_records: int | None = None,
    strict: bool = False,
) -> ProducerStats:
    """
    Iterate the dates in range, download the EPSS CSV, publish one message per CVE row.

    ``days_of_month`` thins a long span to selected days (e.g. ``(1, 15)``); see
    :func:`riskrank.common.dates.sampled_date_range`.
    """
    if run_id is None:
        run_id = new_run_id()
    stats = ProducerStats(source="epss", run_id=run_id)
    start, end = resolve_date_range(start_date, end_date, lookback_days)
    score_days = sampled_date_range(start, end, days_of_month)
    log.info(
        "EPSS range %s..%s -> %d score dates (days_of_month=%s)",
        start,
        end,
        len(score_days),
        days_of_month or "all",
    )
    topic = settings.kafka.topics.epss
    url_template = settings.epss.raw_url_template
    fetched_at = utcnow()

    with build_client() as client:
        for score_day in score_days:
            if max_records is not None and stats.published >= max_records:
                break

            url = url_template.format(year=score_day.year, date=score_day.isoformat())
            try:
                resp = get_with_retry(client, url)
                content = resp.content
            except Exception as exc:
                if strict:
                    raise
                log.warning("EPSS file missing or unavailable for %s: %s", score_day, exc)
                stats.skipped += 1
                continue

            try:
                model_version, score_date_str, rows = parse_epss_file(content)
            except Exception as exc:
                log.warning("failed to parse EPSS file for %s: %s", score_day, exc)
                stats.invalid += 1
                continue

            if not score_date_str:
                score_date_str = score_day.isoformat()
            try:
                score_date = date.fromisoformat(score_date_str)
            except ValueError:
                score_date = score_day

            for row in rows:
                if max_records is not None and stats.published >= max_records:
                    break

                cve_id = row.get("cve", "").strip()
                epss_str = row.get("epss", "").strip()
                pct_str = row.get("percentile", "").strip()
                if not cve_id or not epss_str:
                    stats.invalid += 1
                    continue

                try:
                    epss_val = float(epss_str)
                    pct_val = float(pct_str) if pct_str else 0.0
                except ValueError:
                    stats.invalid += 1
                    continue

                if not (0.0 <= epss_val <= 1.0) or not (0.0 <= pct_val <= 1.0):
                    stats.invalid += 1
                    continue

                payload = {
                    "cve": cve_id,
                    "epss": epss_val,
                    "percentile": pct_val,
                    "score_date": score_date.isoformat(),
                    "model_version": model_version,
                }
                source_record_id = f"{cve_id}|{score_date.isoformat()}"
                stats.fetched += 1

                try:
                    envelope = make_envelope(
                        source="epss",
                        source_record_id=source_record_id,
                        effective_date=score_date,
                        payload=payload,
                        ingestion_run_id=run_id,
                        fetched_at=fetched_at,
                    )
                except Exception:
                    log.exception("failed to build envelope for %s", source_record_id)
                    stats.failed += 1
                    continue

                if not dry_run and kafka_producer is not None:
                    try:
                        publish_envelope(kafka_producer, topic, source_record_id, envelope)
                        stats.published += 1
                    except Exception:
                        log.exception("failed to publish %s", source_record_id)
                        stats.failed += 1
                else:
                    stats.published += 1
                stats.maybe_log_progress(50000)

    stats.log_summary()
    return stats


def _parse_days_of_month(value: str | None) -> tuple[int, ...] | None:
    """Parse '1,15' into (1, 15). Empty/None means every day in range."""
    if not value:
        return None
    days = tuple(sorted({int(part) for part in value.split(",") if part.strip()}))
    if any(not 1 <= d <= 31 for d in days):
        raise argparse.ArgumentTypeError(f"days-of-month out of range: {value}")
    return days or None


def main() -> None:
    parser = argparse.ArgumentParser(description="EPSS daily score producer")
    parser.add_argument("--start-date", type=date.fromisoformat, default=None)
    parser.add_argument("--end-date", type=date.fromisoformat, default=None)
    parser.add_argument("--lookback-days", type=int, default=180)
    parser.add_argument(
        "--days-of-month",
        type=_parse_days_of_month,
        default=None,
        help="thin a long span to these days, e.g. '1,15' (default: every day in range)",
    )
    parser.add_argument("--max-records", type=int, default=None)
    parser.add_argument("--strict", action="store_true", help="fail on missing daily file")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    with build_producer(settings) as producer:
        run_epss_producer(
            settings,
            None if args.dry_run else producer,
            start_date=args.start_date,
            end_date=args.end_date,
            lookback_days=args.lookback_days,
            days_of_month=args.days_of_month,
            dry_run=args.dry_run,
            max_records=args.max_records,
            strict=args.strict,
        )


if __name__ == "__main__":
    main()
