"""Bronze -> Silver normalizer for EPSS daily score records."""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql.functions import col, lit, to_date, when

from riskrank.spark.timeparse import parse_ts as _ts

_CVE_RE = r"^CVE-\d{4}-\d{4,}$"


def normalize_epss(df: DataFrame) -> tuple[DataFrame, dict[str, DataFrame]]:
    """Transform a Bronze EPSS envelope DataFrame into the Silver EPSS schema."""
    enriched = df.select(
        col("event_id"),
        col("payload.cve").alias("cve_id"),
        to_date(col("payload.score_date"), "yyyy-MM-dd").alias("observation_date"),
        col("payload.epss").cast("double").alias("epss_score"),
        col("payload.percentile").cast("double").alias("epss_percentile"),
        col("payload.model_version").alias("epss_model_version"),
        _ts(col("fetched_at")).alias("fetched_at"),
        col("ingestion_run_id"),
        col("payload_sha256"),
    )

    reject_reason = (
        when(col("event_id").isNull(), lit("missing_event_id"))
        .when(col("payload_sha256").isNull(), lit("missing_payload_sha256"))
        .when(col("cve_id").isNull() | ~col("cve_id").rlike(_CVE_RE), lit("invalid_cve_id"))
        .when(
            col("epss_score").isNotNull()
            & ((col("epss_score") < 0.0) | (col("epss_score") > 1.0)),
            lit("invalid_epss_value"),
        )
        .when(
            col("epss_percentile").isNotNull()
            & ((col("epss_percentile") < 0.0) | (col("epss_percentile") > 1.0)),
            lit("invalid_epss_value"),
        )
        .otherwise(lit(None).cast("string"))
    )

    annotated = enriched.withColumn("_reject_reason", reject_reason)
    annotated.cache()

    silver = annotated.filter(col("_reject_reason").isNull()).drop("_reject_reason")
    rejected_df = annotated.filter(col("_reject_reason").isNotNull())

    rejected: dict[str, DataFrame] = {}
    for reason in (
        "missing_event_id",
        "missing_payload_sha256",
        "invalid_cve_id",
        "invalid_epss_value",
    ):
        sub = rejected_df.filter(col("_reject_reason") == reason)
        if not sub.isEmpty():
            rejected[reason] = sub

    return silver, rejected
