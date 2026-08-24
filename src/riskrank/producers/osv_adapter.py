"""
OSV -> NVD payload adapter.

The Bronze corpus is a directory of per-CVE OSV documents, but every downstream
stage (``spark.schemas.NVD_PAYLOAD_SCHEMA``, ``spark.normalize_nvd``,
``spark.features``) is written against the raw NVD API 2.0 ``cve`` object. This
module translates one into the other so the rest of the pipeline is untouched.

OSV carries no numeric CVSS scores — only vector strings — so ``baseScore``,
``baseSeverity`` and the exploitability/impact sub-scores are recomputed via
``riskrank.common.cvss``.
"""
from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

from riskrank.common.cvss import (
    SILVER_TO_CVSS_DATA_KEY,
    decode_cvss_vector,
    score_vector,
)

log = logging.getLogger(__name__)

# NVD renders timestamps as millisecond-precision local-naive ISO-8601; the Spark
# patterns in riskrank.spark.timeparse are built for exactly that.
_NVD_TS_FMT = "%Y-%m-%dT%H:%M:%S.%f"

# OSV emits up to 9 fractional digits ("...:37.981222774Z"); datetime tops out at 6.
_FRACTION_RE = re.compile(r"\.(\d+)")

_REJECT_PREFIXES = ("** REJECT **", "Rejected reason:", "** RESERVED **")

# The eight Silver categoricals that _NVD_CVSS_DATA_V3 actually declares.
_CVSS_DATA_COLUMNS = (
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
)

# OSV severity.type -> the NVD metrics array the record belongs in.
_METRIC_ARRAY_BY_VERSION = {
    "4": "cvssMetricV40",
    "3": "cvssMetricV31",
    "2": "cvssMetricV2",
}


def parse_osv_timestamp(value: str | None) -> datetime | None:
    """Parse an OSV RFC-3339 timestamp, tolerating sub-microsecond precision."""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    def _truncate(match: re.Match[str]) -> str:
        return "." + match.group(1)[:6]

    text = _FRACTION_RE.sub(_truncate, text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def format_nvd_timestamp(moment: datetime | None) -> str | None:
    """Render a datetime the way the NVD API does (millisecond precision, no zone)."""
    if moment is None:
        return None
    return moment.astimezone(UTC).replace(tzinfo=None).strftime(_NVD_TS_FMT)[:-3]


def is_rejected(doc: dict) -> bool:
    """True for withdrawn or REJECT/RESERVED placeholder records (NVD's ``noRejected``)."""
    if doc.get("withdrawn"):
        return True
    details = (doc.get("details") or "").lstrip()
    return details.startswith(_REJECT_PREFIXES)


def _descriptions(doc: dict) -> list[dict]:
    summary = (doc.get("summary") or "").strip()
    details = (doc.get("details") or "").strip()
    value = f"{summary}\n\n{details}".strip() if summary and details else (summary or details)
    return [{"lang": "en", "value": value}] if value else []


def _metrics(doc: dict, cve_id: str) -> dict:
    """Build the NVD ``metrics`` object from OSV ``severity`` vector strings."""
    metrics: dict[str, list[dict]] = {}
    for entry in doc.get("severity") or []:
        vector = (entry.get("score") or "").strip()
        if not vector:
            continue
        scored = score_vector(vector)
        if scored is None:
            log.debug("%s: skipping unparseable vector %r", cve_id, vector)
            continue

        version = scored["version"]
        array_name = _METRIC_ARRAY_BY_VERSION.get(version[0])
        if array_name is None:
            continue

        decoded = decode_cvss_vector(vector)
        cvss_data = {
            "version": version,
            "vectorString": vector,
            "baseScore": scored["base_score"],
            "baseSeverity": scored["base_severity"],
        }
        for column in _CVSS_DATA_COLUMNS:
            cvss_data[SILVER_TO_CVSS_DATA_KEY[column]] = decoded.get(column)

        item = {
            "source": "osv.dev",
            "type": "Primary",
            "cvssData": cvss_data,
            "exploitabilityScore": scored["exploitability_score"],
            "impactScore": scored["impact_score"],
        }
        if array_name == "cvssMetricV2":
            # v2 keeps baseSeverity on the item, not inside cvssData (see schemas.py).
            item["baseSeverity"] = cvss_data.pop("baseSeverity")
            cvss_data["accessVector"] = cvss_data.get("attackVector")
            cvss_data["accessComplexity"] = cvss_data.get("attackComplexity")
            cvss_data["authentication"] = cvss_data.pop("privilegesRequired", None)
        metrics.setdefault(array_name, []).append(item)
    return metrics


def _weaknesses(doc: dict) -> list[dict]:
    cwe_ids = (doc.get("database_specific") or {}).get("cwe_ids") or []
    return [
        {
            "source": "osv.dev",
            "type": "Primary",
            "description": [{"lang": "en", "value": cwe}],
        }
        for cwe in cwe_ids
        if cwe
    ]


def _configurations(doc: dict) -> list[dict]:
    """Collect CPE strings from OSV so ``cpe_match_count`` keeps a real signal."""
    criteria: list[str] = []
    seen: set[str] = set()
    for entry in (doc.get("database_specific") or {}).get("unresolved_ranges") or []:
        for cpe in entry.get("cpes") or []:
            if cpe and cpe not in seen:
                seen.add(cpe)
                criteria.append(cpe)
    for affected in doc.get("affected") or []:
        for cpe in (affected.get("database_specific") or {}).get("cpes") or []:
            if cpe and cpe not in seen:
                seen.add(cpe)
                criteria.append(cpe)
    if not criteria:
        return []
    return [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": c} for c in criteria]}]}]


def osv_to_nvd_cve(doc: dict) -> dict | None:
    """
    Translate one OSV document into an NVD API 2.0 ``cve`` object.

    Returns None for records with no usable CVE id (rejected records are filtered
    separately via ``is_rejected`` so the producer can count them).
    """
    cve_id = (doc.get("id") or "").strip()
    if not cve_id:
        return None

    published = parse_osv_timestamp(doc.get("published"))
    modified = parse_osv_timestamp(doc.get("modified"))
    database_specific = doc.get("database_specific") or {}

    return {
        "id": cve_id,
        "sourceIdentifier": database_specific.get("cna_assigner") or "osv.dev",
        "published": format_nvd_timestamp(published),
        "lastModified": format_nvd_timestamp(modified),
        "vulnStatus": "Withdrawn" if doc.get("withdrawn") else "Published",
        "descriptions": _descriptions(doc),
        "metrics": _metrics(doc, cve_id),
        "weaknesses": _weaknesses(doc),
        "references": [
            {"url": ref.get("url"), "source": ref.get("type")}
            for ref in doc.get("references") or []
            if ref.get("url")
        ],
        "configurations": _configurations(doc),
    }
