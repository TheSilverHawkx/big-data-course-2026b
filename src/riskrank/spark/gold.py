"""
Gold observation dataset builder.

Grain: one row per (cve_id, observation_date).
Spine: EPSS daily rows (each CVE/date with a contemporaneous EPSS value).

Runnable: ``python -m riskrank.spark.gold``
"""
from __future__ import annotations

import argparse
import logging
from datetime import date
from pathlib import Path

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import col, datediff, lit, month, row_number, to_date, year
from pyspark.sql.window import Window

from riskrank.config import Settings, get_settings
from riskrank.paths import ProjectPaths
from riskrank.spark.features import build_epss_features, build_nvd_features
from riskrank.spark.labels import add_kev_labels, apply_right_censoring, exclude_already_kev
from riskrank.spark.schemas import SILVER_EPSS_SCHEMA, SILVER_KEV_SCHEMA, SILVER_NVD_SCHEMA
from riskrank.spark.session import build_spark_session

log = logging.getLogger(__name__)

_GOLD_OBSERVATIONS = "observations"


def _read_parquet_or_empty(spark: SparkSession, path: str, schema=None) -> DataFrame:
    """Read Parquet if files exist, otherwise return an empty DataFrame."""
    p = Path(path)
    if p.exists() and list(p.rglob("*.parquet")):
        return spark.read.parquet(path)
    log.warning("No Parquet files found at %s — returning empty DataFrame", path)
    if schema is not None:
        return spark.createDataFrame([], schema)
    from pyspark.sql.types import StructType

    return spark.createDataFrame([], StructType([]))


def read_silver_nvd(spark: SparkSession, settings: Settings) -> DataFrame:
    """Latest NVD record per CVE (highest fetched_at)."""
    paths = ProjectPaths(settings)
    df = _read_parquet_or_empty(
        spark, str(paths.silver / "nvd_vulnerabilities"), SILVER_NVD_SCHEMA
    )
    if df.isEmpty():
        return df
    w = Window.partitionBy("cve_id").orderBy(col("fetched_at").desc())
    return df.withColumn("_rn", row_number().over(w)).filter(col("_rn") == 1).drop("_rn")


def read_silver_epss(spark: SparkSession, settings: Settings) -> DataFrame:
    """Canonical EPSS rows: one per (cve_id, observation_date) — latest fetched_at wins."""
    paths = ProjectPaths(settings)
    df = _read_parquet_or_empty(spark, str(paths.silver / "epss_daily"), SILVER_EPSS_SCHEMA)
    if df.isEmpty():
        return df
    w = Window.partitionBy("cve_id", "observation_date").orderBy(col("fetched_at").desc())
    return df.withColumn("_rn", row_number().over(w)).filter(col("_rn") == 1).drop("_rn")


def read_silver_kev(spark: SparkSession, settings: Settings) -> DataFrame:
    """Canonical KEV: earliest date_added per CVE (first known exploitation date)."""
    paths = ProjectPaths(settings)
    df = _read_parquet_or_empty(spark, str(paths.silver / "kev_catalog"), SILVER_KEV_SCHEMA)
    if df.isEmpty():
        return df
    w = Window.partitionBy("cve_id").orderBy(col("date_added").asc())
    return df.withColumn("_rn", row_number().over(w)).filter(col("_rn") == 1).drop("_rn")


def build_gold_observations(
    spark: SparkSession,
    settings: Settings,
    *,
    label_as_of_date: date | None = None,
    write: bool = True,
) -> DataFrame:
    """Build the Gold observation dataset and optionally write Parquet."""
    paths = ProjectPaths(settings)
    horizon = settings.model.kev_horizon_days

    nvd_df = read_silver_nvd(spark, settings)
    epss_df = read_silver_epss(spark, settings)
    kev_df = read_silver_kev(spark, settings)

    if epss_df.isEmpty():
        log.warning("EPSS Silver is empty — Gold dataset will be empty")
        from pyspark.sql.types import StructType

        return spark.createDataFrame([], StructType([]))

    if label_as_of_date is None:
        max_kev_row = kev_df.agg({"fetched_at": "max"}).collect() if not kev_df.isEmpty() else []
        if max_kev_row and max_kev_row[0][0]:
            label_as_of_date = max_kev_row[0][0].date()
        else:
            max_epss_row = epss_df.agg({"fetched_at": "max"}).collect()
            label_as_of_date = (
                max_epss_row[0][0].date() if max_epss_row and max_epss_row[0][0] else date.today()
            )
        log.info("derived label_as_of_date = %s", label_as_of_date)

    # ── 1. EPSS spine ───────────────────────────────────────────────────────────
    spine = epss_df.select("cve_id", "observation_date").distinct()

    # ── 2. Require valid NVD record ─────────────────────────────────────────────
    nvd_minimal = nvd_df.select(
        col("cve_id").alias("n_cve_id"),
        col("published_at").alias("nvd_published_at"),
    )
    spine = spine.join(
        nvd_minimal, spine.cve_id == nvd_minimal.n_cve_id, "inner"
    ).drop("n_cve_id")

    # ── 3. CVE published before observation_date ────────────────────────────────
    spine = spine.withColumn("published_date", to_date(col("nvd_published_at"))).filter(
        col("published_date") <= col("observation_date")
    )

    # ── 4. Exclude CVEs already in KEV on or before observation_date ─────────────
    if not kev_df.isEmpty():
        kev_minimal = kev_df.select(
            col("cve_id").alias("k_cve_id"),
            col("date_added").alias("kev_date_added_check"),
        )
        spine = (
            spine.join(kev_minimal, spine.cve_id == kev_minimal.k_cve_id, "left")
            .drop("k_cve_id")
            .filter(
                col("kev_date_added_check").isNull()
                | (col("kev_date_added_check") > col("observation_date"))
            )
            .drop("kev_date_added_check")
        )

    # ── 5. Right-censoring (90-day window) ──────────────────────────────────────
    spine = apply_right_censoring(spine, label_as_of_date, horizon_days=horizon)

    if spine.isEmpty():
        log.warning("Gold spine is empty after cohort filters")
        from pyspark.sql.types import StructType

        return spark.createDataFrame([], StructType([]))

    spine.cache()
    log.info("Gold spine: %d rows after cohort filters", spine.count())

    # ── 6. Features ─────────────────────────────────────────────────────────────
    obs = build_epss_features(spine, epss_df)
    obs = build_nvd_features(obs, nvd_df)

    # ── 7. Metadata ─────────────────────────────────────────────────────────────
    spine_meta = spine.select("cve_id", "observation_date", "published_date")
    obs = obs.join(spine_meta, ["cve_id", "observation_date"], "left")
    obs = (
        obs.withColumn(
            "vulnerability_age_days", datediff(col("observation_date"), col("published_date"))
        )
        .withColumn("observation_year", year(col("observation_date")))
        .withColumn("observation_month", month(col("observation_date")))
    )

    # ── 8. KEV labels (7/30/90-day), drop already-KEV rows ──────────────────────
    obs = add_kev_labels(obs, kev_df, label_as_of_date) if not kev_df.isEmpty() else obs
    if not kev_df.isEmpty():
        obs = exclude_already_kev(obs)

    spine.unpersist()

    if write:
        out_path = str(paths.gold / _GOLD_OBSERVATIONS)
        obs.repartition(settings.spark.shuffle_partitions).write.partitionBy(
            "observation_year", "observation_month"
        ).mode("overwrite").parquet(out_path)
        log.info("wrote Gold observations to %s", out_path)

    return obs


def read_gold_observations(spark: SparkSession, settings: Settings) -> DataFrame:
    """Read the Gold observation dataset from disk."""
    paths = ProjectPaths(settings)
    return spark.read.parquet(str(paths.gold / _GOLD_OBSERVATIONS))


def main() -> None:
    parser = argparse.ArgumentParser(description="Silver -> Gold observation dataset builder")
    parser.add_argument("--label-as-of-date", type=date.fromisoformat, default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    spark = build_spark_session(settings, app_name="riskrank-gold")
    spark.sparkContext.setLogLevel("WARN")
    try:
        obs = build_gold_observations(
            spark, settings, label_as_of_date=args.label_as_of_date, write=True
        )
        log.info("Gold observations rows: %d", obs.count())
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
