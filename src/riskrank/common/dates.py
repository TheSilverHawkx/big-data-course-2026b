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
