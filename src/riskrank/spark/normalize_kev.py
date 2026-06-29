"""Bronze -> Silver normalizer for CISA KEV catalog records."""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql.functions import col, lit, to_date, when

from riskrank.spark.timeparse import parse_ts as _ts

_CVE_RE = r"^CVE-\d{4}-\d{4,}$"


def normalize_kev(df: DataFrame) -> tuple[DataFrame, dict[str, DataFrame]]:
    """Transform a Bronze KEV envelope DataFrame into the Silver KEV schema."""
    enriched = df.select(
        col("event_id"),
        col("payload.cveID").alias("cve_id"),
        col("payload.vendorProject").alias("vendor_project"),
        col("payload.product"),
        col("payload.vulnerabilityName").alias("vulnerability_name"),
        to_date(col("payload.dateAdded"), "yyyy-MM-dd").alias("date_added"),
        to_date(col("payload.dueDate"), "yyyy-MM-dd").alias("due_date"),
        col("payload.requiredAction").alias("required_action"),
        col("payload.knownRansomwareCampaignUse").alias("known_ransomware_campaign_use"),
        col("payload.shortDescription").alias("short_description"),
        col("payload.notes"),
        col("payload.cwes"),
        col("payload.catalog_version"),
        _ts(col("payload.catalog_date_released")).alias("catalog_date_released"),
        _ts(col("fetched_at")).alias("fetched_at"),
        col("ingestion_run_id"),
        col("payload_sha256"),
    )

    reject_reason = (
        when(col("event_id").isNull(), lit("missing_event_id"))
        .when(col("payload_sha256").isNull(), lit("missing_payload_sha256"))
        .when(col("date_added").isNull(), lit("missing_date_added"))
        .when(col("cve_id").isNull() | ~col("cve_id").rlike(_CVE_RE), lit("invalid_cve_id"))
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
        "missing_date_added",
        "invalid_cve_id",
    ):
        sub = rejected_df.filter(col("_reject_reason") == reason)
        if not sub.isEmpty():
            rejected[reason] = sub

    return silver, rejected
