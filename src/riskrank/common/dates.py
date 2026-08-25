"""Date/time helpers used across the pipeline."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def today_utc() -> date:
    return utcnow().date()


def date_range(start: date, end: date) -> list[date]:
    """Return list of dates inclusive of both start and end."""
    days = (end - start).days + 1
    return [start + timedelta(days=i) for i in range(days)]


def iso_date(d: date) -> str:
    return d.isoformat()


def nvd_datetime(d: date) -> str:
    """Format date as an NVD API 2.0 datetime string."""
    return datetime(d.year, d.month, d.day, tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%S.000")


def sampled_date_range(
    start: date, end: date, days_of_month: tuple[int, ...] | None = None
) -> list[date]:
    """
    Dates in [start, end], optionally thinned to selected days of the month.

    EPSS snapshots are published daily, but adjacent days are near-identical: a
    three-year daily pull is ~1,100 files (~317M rows) that mostly restate each
    other. Sampling the 1st and 15th keeps the same span at ~6% of the volume
    while preserving the number of *distinct* KEV positives, which is what
    actually bounds the model.

    A day that does not exist in a given month (e.g. 31 in February) is skipped.
    """
    days = date_range(start, end)
    if not days_of_month:
        return days
    wanted = set(days_of_month)
    return [d for d in days if d.day in wanted]
