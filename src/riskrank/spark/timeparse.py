"""
Tolerant ISO-8601 timestamp parsing for Spark normalizers.

Spark 4.x runs with ANSI mode on, so ``to_timestamp`` *raises* on a non-matching
pattern instead of returning null — which breaks a ``coalesce`` of format variants.
``try_to_timestamp`` returns null on failure, so coalescing variants works again.

Patterns cover the formats actually emitted by the pipeline:
  - our own ``fetched_at`` (Python isoformat, microseconds + Z/offset)
  - NVD ``published`` / ``lastModified`` (milliseconds, no zone)
  - bare second precision
"""
from __future__ import annotations

from pyspark.sql import Column
from pyspark.sql.functions import coalesce, try_to_timestamp

_FORMATS = [
    "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX",
    "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
    "yyyy-MM-dd'T'HH:mm:ssXXX",
    "yyyy-MM-dd'T'HH:mm:ss.SSSSSS",
    "yyyy-MM-dd'T'HH:mm:ss.SSS",
    "yyyy-MM-dd'T'HH:mm:ss",
]


def parse_ts(c: Column) -> Column:
    """Parse an ISO-8601 timestamp string column, tolerating precision/zone variants."""
    from pyspark.sql.functions import lit

    return coalesce(*[try_to_timestamp(c, lit(fmt)) for fmt in _FORMATS])
