"""
Bronze -> Silver normalizer for NVD CVE records.

Applies CVSS priority: Primary source > Secondary; v4.0 > v3.1 > v3.0 > v2.0.
The CVSS vector string is preserved and its components (AV/AC/PR/UI/S/C/I/A) are
decoded into individual columns for downstream feature engineering.
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql.functions import coalesce, col, expr, lit, size, when

from riskrank.spark.timeparse import parse_ts

_CVE_RE = r"^CVE-\d{4}-\d{4,}$"

# SQL fragment: select Primary metric first, else first element, else null
_BEST_METRIC = """
    CASE
      WHEN size(coalesce({arr}, array())) = 0 THEN null
      WHEN size(filter({arr}, m -> m.type = 'Primary')) > 0
        THEN filter({arr}, m -> m.type = 'Primary')[0]
      ELSE {arr}[0]
    END
"""


def normalize_nvd(df: DataFrame) -> tuple[DataFrame, dict[str, DataFrame]]:
    """
    Transform a Bronze NVD envelope DataFrame into the Silver NVD schema.

    Returns (silver_df, rejected) where rejected maps reason -> DataFrame.
    """
    with_metrics = (
        df.withColumn("_m40", expr(_BEST_METRIC.format(arr="payload.metrics.cvssMetricV40")))
        .withColumn("_m31", expr(_BEST_METRIC.format(arr="payload.metrics.cvssMetricV31")))
        .withColumn("_m30", expr(_BEST_METRIC.format(arr="payload.metrics.cvssMetricV30")))
        .withColumn("_m2", expr(_BEST_METRIC.format(arr="payload.metrics.cvssMetricV2")))
    )

    m40 = col("_m40")
    m31 = col("_m31")
    m30 = col("_m30")
    m2 = col("_m2")

    def _pick(v40, v31, v30, v2):
        return (
            when(m40.isNotNull(), v40)
            .when(m31.isNotNull(), v31)
            .when(m30.isNotNull(), v30)
            .when(m2.isNotNull(), v2)
            .otherwise(lit(None))
        )

    def _pick3(v40, v31, v30):
        return (
            when(m40.isNotNull(), v40)
            .when(m31.isNotNull(), v31)
            .when(m30.isNotNull(), v30)
            .otherwise(lit(None))
        )

    cwe_ids = expr("""
        array_distinct(
            flatten(
                transform(
                    coalesce(payload.weaknesses, array()),
                    w -> transform(
                        filter(coalesce(w.description, array()), d -> d.lang = 'en'),
                        d -> d.value
                    )
                )
            )
        )
    """)

    cpe_match_count = expr("""
        aggregate(
            coalesce(payload.configurations, array()),
            0,
            (total, cfg) -> total + aggregate(
                coalesce(cfg.nodes, array()),
                0,
                (node_total, node) -> node_total + size(coalesce(node.cpeMatch, array()))
            )
        )
    """)

    description_en = expr("""
        aggregate(
            filter(coalesce(payload.descriptions, array()), d -> d.lang = 'en'),
            cast(null as string),
            (acc, d) -> d.value
        )
    """)

    enriched = with_metrics.select(
        col("event_id"),
        col("payload.id").alias("cve_id"),
        parse_ts(col("fetched_at")).alias("fetched_at"),
        col("ingestion_run_id"),
        col("payload_sha256"),
        parse_ts(col("payload.published")).alias("published_at"),
        parse_ts(col("payload.lastModified")).alias("last_modified_at"),
        col("payload.vulnStatus").alias("vuln_status"),
        col("payload.sourceIdentifier").alias("source_identifier"),
        description_en.alias("description_en"),
        _pick(lit("4.0"), lit("3.1"), lit("3.0"), lit("2.0")).alias("cvss_version"),
        _pick(
            m40["cvssData"]["vectorString"],
            m31["cvssData"]["vectorString"],
            m30["cvssData"]["vectorString"],
            m2["cvssData"]["vectorString"],
        ).alias("cvss_vector"),
        _pick(
            m40["cvssData"]["baseScore"],
            m31["cvssData"]["baseScore"],
            m30["cvssData"]["baseScore"],
            m2["cvssData"]["baseScore"],
        ).cast("double").alias("cvss_base_score"),
        _pick(
            m40["cvssData"]["baseSeverity"],
            m31["cvssData"]["baseSeverity"],
            m30["cvssData"]["baseSeverity"],
            m2["baseSeverity"],
        ).alias("cvss_base_severity"),
        _pick(
            m40["cvssData"]["attackVector"],
            m31["cvssData"]["attackVector"],
            m30["cvssData"]["attackVector"],
            coalesce(m2["cvssData"]["attackVector"], m2["cvssData"]["accessVector"]),
        ).alias("attack_vector"),
        _pick(
            m40["cvssData"]["attackComplexity"],
            m31["cvssData"]["attackComplexity"],
            m30["cvssData"]["attackComplexity"],
            coalesce(m2["cvssData"]["attackComplexity"], m2["cvssData"]["accessComplexity"]),
        ).alias("attack_complexity"),
        _pick(
            m40["cvssData"]["privilegesRequired"],
            m31["cvssData"]["privilegesRequired"],
            m30["cvssData"]["privilegesRequired"],
            m2["cvssData"]["authentication"],
        ).alias("privileges_required"),
        _pick3(
            m40["cvssData"]["userInteraction"],
            m31["cvssData"]["userInteraction"],
            m30["cvssData"]["userInteraction"],
        ).alias("user_interaction"),
        _pick3(
            m40["cvssData"]["scope"],
            m31["cvssData"]["scope"],
            m30["cvssData"]["scope"],
        ).alias("scope"),
        _pick(
            m40["cvssData"]["confidentialityImpact"],
            m31["cvssData"]["confidentialityImpact"],
            m30["cvssData"]["confidentialityImpact"],
            m2["cvssData"]["confidentialityImpact"],
        ).alias("confidentiality_impact"),
        _pick(
            m40["cvssData"]["integrityImpact"],
            m31["cvssData"]["integrityImpact"],
            m30["cvssData"]["integrityImpact"],
            m2["cvssData"]["integrityImpact"],
        ).alias("integrity_impact"),
        _pick(
            m40["cvssData"]["availabilityImpact"],
            m31["cvssData"]["availabilityImpact"],
            m30["cvssData"]["availabilityImpact"],
            m2["cvssData"]["availabilityImpact"],
        ).alias("availability_impact"),
        _pick(
            m40["exploitabilityScore"],
            m31["exploitabilityScore"],
            m30["exploitabilityScore"],
            m2["exploitabilityScore"],
        ).cast("double").alias("exploitability_score"),
        _pick(
            m40["impactScore"],
            m31["impactScore"],
            m30["impactScore"],
            m2["impactScore"],
        ).cast("double").alias("impact_score"),
        cwe_ids.alias("cwe_ids"),
        expr("transform(coalesce(payload.references, array()), r -> r.url)").alias(
            "reference_urls"
        ),
        size(coalesce(col("payload.references"), expr("array()"))).alias("reference_count"),
        cpe_match_count.cast("int").alias("cpe_match_count"),
    )

    reject_reason = (
        when(col("event_id").isNull(), lit("missing_event_id"))
        .when(col("payload_sha256").isNull(), lit("missing_payload_sha256"))
        .when(col("cve_id").isNull() | ~col("cve_id").rlike(_CVE_RE), lit("invalid_cve_id"))
        .when(
            col("cvss_base_score").isNotNull()
            & ((col("cvss_base_score") < 0.0) | (col("cvss_base_score") > 10.0)),
            lit("invalid_cvss_score"),
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
        "invalid_cvss_score",
    ):
        sub = rejected_df.filter(col("_reject_reason") == reason)
        if not sub.isEmpty():
            rejected[reason] = sub

    return silver, rejected
