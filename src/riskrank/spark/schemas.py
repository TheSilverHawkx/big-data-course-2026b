"""
Explicit Spark StructType schemas for Bronze JSONL reads and Silver Parquet outputs.

Every readStream specifies an explicit schema; global schema inference is disabled.
"""
from __future__ import annotations

from pyspark.sql.types import (
    ArrayType,
    BooleanType,
    DateType,
    DoubleType,
    IntegerType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

# ── Shared envelope fields ─────────────────────────────────────────────────────

_ENVELOPE_BASE = [
    StructField("event_id", StringType(), True),
    StructField("event_schema_version", StringType(), True),
    StructField("source", StringType(), True),
    StructField("source_record_id", StringType(), True),
    StructField("event_type", StringType(), True),
    StructField("effective_date", StringType(), True),
    StructField("source_modified_at", StringType(), True),
    StructField("fetched_at", StringType(), True),
    StructField("ingestion_run_id", StringType(), True),
    StructField("payload_sha256", StringType(), True),
]


def _envelope(payload_schema: StructType) -> StructType:
    return StructType(_ENVELOPE_BASE + [StructField("payload", payload_schema, True)])


# ── NVD Bronze schema ──────────────────────────────────────────────────────────

_NVD_DESC_ITEM = StructType([
    StructField("lang", StringType(), True),
    StructField("value", StringType(), True),
])

_NVD_CVSS_DATA_V3 = StructType([
    StructField("version", StringType(), True),
    StructField("vectorString", StringType(), True),
    StructField("baseScore", DoubleType(), True),
    StructField("baseSeverity", StringType(), True),
    StructField("attackVector", StringType(), True),
    StructField("attackComplexity", StringType(), True),
    StructField("privilegesRequired", StringType(), True),
    StructField("userInteraction", StringType(), True),
    StructField("scope", StringType(), True),
    StructField("confidentialityImpact", StringType(), True),
    StructField("integrityImpact", StringType(), True),
    StructField("availabilityImpact", StringType(), True),
])

_NVD_CVSS_METRIC_V3_ITEM = StructType([
    StructField("source", StringType(), True),
    StructField("type", StringType(), True),
    StructField("cvssData", _NVD_CVSS_DATA_V3, True),
    StructField("exploitabilityScore", DoubleType(), True),
    StructField("impactScore", DoubleType(), True),
])

_NVD_CVSS_DATA_V2 = StructType([
    StructField("version", StringType(), True),
    StructField("vectorString", StringType(), True),
    StructField("baseScore", DoubleType(), True),
    StructField("attackVector", StringType(), True),
    StructField("accessVector", StringType(), True),
    StructField("attackComplexity", StringType(), True),
    StructField("accessComplexity", StringType(), True),
    StructField("authentication", StringType(), True),
    StructField("confidentialityImpact", StringType(), True),
    StructField("integrityImpact", StringType(), True),
    StructField("availabilityImpact", StringType(), True),
])

_NVD_CVSS_METRIC_V2_ITEM = StructType([
    StructField("source", StringType(), True),
    StructField("type", StringType(), True),
    StructField("cvssData", _NVD_CVSS_DATA_V2, True),
    StructField("baseSeverity", StringType(), True),
    StructField("exploitabilityScore", DoubleType(), True),
    StructField("impactScore", DoubleType(), True),
])

_NVD_METRICS = StructType([
    StructField("cvssMetricV40", ArrayType(_NVD_CVSS_METRIC_V3_ITEM), True),
    StructField("cvssMetricV31", ArrayType(_NVD_CVSS_METRIC_V3_ITEM), True),
    StructField("cvssMetricV30", ArrayType(_NVD_CVSS_METRIC_V3_ITEM), True),
    StructField("cvssMetricV2", ArrayType(_NVD_CVSS_METRIC_V2_ITEM), True),
])

_NVD_WEAKNESS_DESC = StructType([
    StructField("lang", StringType(), True),
    StructField("value", StringType(), True),
])

_NVD_WEAKNESS_ITEM = StructType([
    StructField("source", StringType(), True),
    StructField("type", StringType(), True),
    StructField("description", ArrayType(_NVD_WEAKNESS_DESC), True),
])

_NVD_REFERENCE_ITEM = StructType([
    StructField("url", StringType(), True),
    StructField("source", StringType(), True),
])

_NVD_CPEMATCH_ITEM = StructType([
    StructField("vulnerable", BooleanType(), True),
    StructField("criteria", StringType(), True),
])

_NVD_NODE_ITEM = StructType([
    StructField("cpeMatch", ArrayType(_NVD_CPEMATCH_ITEM), True),
])

_NVD_CONFIG_ITEM = StructType([
    StructField("nodes", ArrayType(_NVD_NODE_ITEM), True),
])

NVD_PAYLOAD_SCHEMA = StructType([
    StructField("id", StringType(), True),
    StructField("sourceIdentifier", StringType(), True),
    StructField("published", StringType(), True),
    StructField("lastModified", StringType(), True),
    StructField("vulnStatus", StringType(), True),
    StructField("descriptions", ArrayType(_NVD_DESC_ITEM), True),
    StructField("metrics", _NVD_METRICS, True),
    StructField("weaknesses", ArrayType(_NVD_WEAKNESS_ITEM), True),
    StructField("references", ArrayType(_NVD_REFERENCE_ITEM), True),
    StructField("configurations", ArrayType(_NVD_CONFIG_ITEM), True),
])

BRONZE_NVD_SCHEMA: StructType = _envelope(NVD_PAYLOAD_SCHEMA)

# ── EPSS Bronze schema ─────────────────────────────────────────────────────────

EPSS_PAYLOAD_SCHEMA = StructType([
    StructField("cve", StringType(), True),
    StructField("epss", DoubleType(), True),
    StructField("percentile", DoubleType(), True),
    StructField("score_date", StringType(), True),
    StructField("model_version", StringType(), True),
])

BRONZE_EPSS_SCHEMA: StructType = _envelope(EPSS_PAYLOAD_SCHEMA)

# ── KEV Bronze schema ──────────────────────────────────────────────────────────

KEV_PAYLOAD_SCHEMA = StructType([
    StructField("cveID", StringType(), True),
    StructField("vendorProject", StringType(), True),
    StructField("product", StringType(), True),
    StructField("vulnerabilityName", StringType(), True),
    StructField("dateAdded", StringType(), True),
    StructField("dueDate", StringType(), True),
    StructField("requiredAction", StringType(), True),
    StructField("knownRansomwareCampaignUse", StringType(), True),
    StructField("shortDescription", StringType(), True),
    StructField("notes", StringType(), True),
    StructField("cwes", ArrayType(StringType()), True),
    StructField("catalog_version", StringType(), True),
    StructField("catalog_date_released", StringType(), True),
])

BRONZE_KEV_SCHEMA: StructType = _envelope(KEV_PAYLOAD_SCHEMA)

# ── Silver output schemas (documented; used for schema validation) ─────────────

SILVER_NVD_SCHEMA = StructType([
    StructField("event_id", StringType(), False),
    StructField("cve_id", StringType(), False),
    StructField("published_at", TimestampType(), True),
    StructField("last_modified_at", TimestampType(), True),
    StructField("vuln_status", StringType(), True),
    StructField("source_identifier", StringType(), True),
    StructField("description_en", StringType(), True),
    StructField("cvss_version", StringType(), True),
    StructField("cvss_vector", StringType(), True),
    StructField("cvss_base_score", DoubleType(), True),
    StructField("cvss_base_severity", StringType(), True),
    StructField("attack_vector", StringType(), True),
    StructField("attack_complexity", StringType(), True),
    StructField("privileges_required", StringType(), True),
    StructField("user_interaction", StringType(), True),
    StructField("scope", StringType(), True),
    StructField("confidentiality_impact", StringType(), True),
    StructField("integrity_impact", StringType(), True),
    StructField("availability_impact", StringType(), True),
    StructField("exploitability_score", DoubleType(), True),
    StructField("impact_score", DoubleType(), True),
    StructField("cwe_ids", ArrayType(StringType()), True),
    StructField("reference_urls", ArrayType(StringType()), True),
    StructField("reference_count", IntegerType(), True),
    StructField("cpe_match_count", IntegerType(), True),
    StructField("fetched_at", TimestampType(), True),
    StructField("ingestion_run_id", StringType(), True),
    StructField("payload_sha256", StringType(), True),
])

SILVER_EPSS_SCHEMA = StructType([
    StructField("event_id", StringType(), False),
    StructField("cve_id", StringType(), False),
    StructField("observation_date", DateType(), True),
    StructField("epss_score", DoubleType(), True),
    StructField("epss_percentile", DoubleType(), True),
    StructField("epss_model_version", StringType(), True),
    StructField("fetched_at", TimestampType(), True),
    StructField("ingestion_run_id", StringType(), True),
    StructField("payload_sha256", StringType(), True),
])

SILVER_KEV_SCHEMA = StructType([
    StructField("event_id", StringType(), False),
    StructField("cve_id", StringType(), False),
    StructField("vendor_project", StringType(), True),
    StructField("product", StringType(), True),
    StructField("vulnerability_name", StringType(), True),
    StructField("date_added", DateType(), True),
    StructField("due_date", DateType(), True),
    StructField("required_action", StringType(), True),
    StructField("known_ransomware_campaign_use", StringType(), True),
    StructField("short_description", StringType(), True),
    StructField("notes", StringType(), True),
    StructField("cwes", ArrayType(StringType()), True),
    StructField("catalog_version", StringType(), True),
    StructField("catalog_date_released", TimestampType(), True),
    StructField("fetched_at", TimestampType(), True),
    StructField("ingestion_run_id", StringType(), True),
    StructField("payload_sha256", StringType(), True),
])
