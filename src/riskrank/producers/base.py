"""Shared types and helpers for all source producers."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import date, timedelta

from riskrank.common.dates import today_utc

log = logging.getLogger(__name__)


@dataclass
class ProducerStats:
    source: str
    run_id: str
    fetched: int = 0
    published: int = 0
    skipped: int = 0
    invalid: int = 0
    failed: int = 0

    def log_summary(self) -> None:
        log.info(
            "%s producer complete: fetched=%d published=%d skipped=%d invalid=%d failed=%d",
            self.source,
            self.fetched,
            self.published,
            self.skipped,
            self.invalid,
            self.failed,
        )


def new_run_id() -> str:
    return str(uuid.uuid4())


def resolve_date_range(
    start_date: date | None,
    end_date: date | None,
    lookback_days: int = 180,
) -> tuple[date, date]:
    """Return (start, end) resolved from explicit dates or lookback from today."""
    today = today_utc()
    if start_date is None:
        start_date = today - timedelta(days=lookback_days)
    if end_date is None:
        end_date = today
    if start_date > end_date:
        raise ValueError(f"start_date {start_date} is after end_date {end_date}")
    return start_date, end_date


def chunk_date_range(start: date, end: date, max_days: int = 120) -> list[tuple[date, date]]:
    """Split [start, end] into consecutive chunks of at most max_days each."""
    chunks: list[tuple[date, date]] = []
    current = start
    while current <= end:
        chunk_end = min(current + timedelta(days=max_days - 1), end)
        chunks.append((current, chunk_end))
        current = chunk_end + timedelta(days=1)
    return chunks


def parse_iso_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except (ValueError, TypeError):
        return None
