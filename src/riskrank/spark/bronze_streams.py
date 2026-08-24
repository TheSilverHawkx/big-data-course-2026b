"""
One Structured Streaming query per source: Bronze JSONL.gz -> Silver Parquet.

Uses foreachBatch so normalizer functions work on static micro-batch DataFrames,
routing valid rows to Silver tables and invalid rows to rejected paths.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.streaming import StreamingQuery

from riskrank.config import Settings
from riskrank.paths import ProjectPaths
from riskrank.spark.normalize_epss import normalize_epss
from riskrank.spark.normalize_kev import normalize_kev
from riskrank.spark.normalize_nvd import normalize_nvd
from riskrank.spark.schemas import (
    BRONZE_EPSS_SCHEMA,
    BRONZE_KEV_SCHEMA,
    BRONZE_NVD_SCHEMA,
)

log = logging.getLogger(__name__)

# The file sink writes a `<part>.jsonl.gz.manifest.json` beside every Bronze part.
# Spark's JSON source would otherwise read those sidecars as data: each is a
# pretty-printed object, so every line becomes a corrupt (all-null) record and
# lands in silver/rejected as `missing_event_id`.
_BRONZE_FILE_GLOB = "*.jsonl.gz"

# source -> (bronze read schema, normalizer function, silver table subdirectory)
_SOURCES: dict[str, tuple] = {
    "nvd": (BRONZE_NVD_SCHEMA, normalize_nvd, "nvd_vulnerabilities"),
    "epss": (BRONZE_EPSS_SCHEMA, normalize_epss, "epss_daily"),
    "kev": (BRONZE_KEV_SCHEMA, normalize_kev, "kev_catalog"),
}


def _make_batch_writer(
    normalizer: Callable[[DataFrame], tuple[DataFrame, dict[str, DataFrame]]],
    silver_path: str,
    rejected_base: Path,
) -> Callable[[DataFrame, int], None]:
    def _write_batch(batch_df: DataFrame, batch_id: int) -> None:
        if batch_df.isEmpty():
            return

        batch_df.cache()
        try:
            silver_df, rejected = normalizer(batch_df)

            if not silver_df.isEmpty():
                silver_df.write.mode("append").parquet(silver_path)
                log.info(
                    "batch %d: wrote %d Silver rows to %s",
                    batch_id,
                    silver_df.count(),
                    silver_path,
                )

            for reason, rej_df in rejected.items():
                if not rej_df.isEmpty():
                    rej_path = str(rejected_base / f"reason={reason}")
                    rej_df.write.mode("append").parquet(rej_path)
                    log.warning(
                        "batch %d: wrote %d rejected rows (%s)",
                        batch_id,
                        rej_df.count(),
                        reason,
                    )
        finally:
            batch_df.unpersist()

    return _write_batch


def start_bronze_to_silver(
    spark: SparkSession,
    settings: Settings,
    *,
    trigger_mode: str | None = None,
) -> list[StreamingQuery]:
    """Start one Structured Streaming query per source. Returns active queries."""
    mode = trigger_mode or settings.spark.streaming_trigger

    if mode == "availableNow":
        trigger_kwargs: dict = {"availableNow": True}
    else:
        secs = settings.spark.processing_time_seconds
        trigger_kwargs = {"processingTime": f"{secs} seconds"}

    paths = ProjectPaths(settings)
    paths.ensure_dirs()

    queries: list[StreamingQuery] = []

    for source, (schema, normalizer, silver_table) in _SOURCES.items():
        bronze_path = str(paths.bronze / f"source={source}")
        silver_path = str(paths.silver / silver_table)
        checkpoint_path = str(paths.checkpoints / f"{source}_to_silver")
        rejected_base = paths.silver / "rejected" / f"source={source}"

        Path(bronze_path).mkdir(parents=True, exist_ok=True)
        rejected_base.mkdir(parents=True, exist_ok=True)

        stream_df = (
            spark.readStream.schema(schema)
            .option("pathGlobFilter", _BRONZE_FILE_GLOB)
            .json(bronze_path)
        )

        batch_writer = _make_batch_writer(normalizer, silver_path, rejected_base)

        query = (
            stream_df.writeStream.foreachBatch(batch_writer)
            .option("checkpointLocation", checkpoint_path)
            .queryName(f"{source}_to_silver")
            .trigger(**trigger_kwargs)
            .start()
        )

        log.info("started streaming query %s -> %s (trigger=%s)", source, silver_path, mode)
        queries.append(query)

    return queries
