"""
CVSS vector decoding and base-score computation.

The local OSV corpus ships only vector strings — no numeric scores — so Bronze has
to recompute what the NVD API used to hand us: ``baseScore``, ``baseSeverity`` and
the ``exploitabilityScore`` / ``impactScore`` sub-scores. The arithmetic is
delegated to the ``cvss`` package (the Red Hat reference implementation) rather
than transcribed here, so v3.x and v4.0 are both exact.

This module also owns the abbreviation -> full-word maps that turn a vector into
the eight Silver categorical columns; ``riskrank.models.scoring`` imports them.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# CVSS v3.x abbreviation -> NVD cvssData full-word value (Silver categorical domain).
VECTOR_DECODE_V3 = {
    "AV": ({"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}, "attack_vector"),
    "AC": ({"L": "LOW", "H": "HIGH"}, "attack_complexity"),
    "PR": ({"N": "NONE", "L": "LOW", "H": "HIGH"}, "privileges_required"),
    "UI": ({"N": "NONE", "R": "REQUIRED"}, "user_interaction"),
    "S": ({"U": "UNCHANGED", "C": "CHANGED"}, "scope"),
    "C": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "confidentiality_impact"),
    "I": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "integrity_impact"),
    "A": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "availability_impact"),
}

# CVSS v4.0 renames the impact metrics (VC/VI/VA) and drops Scope; UI gains PASSIVE/ACTIVE.
VECTOR_DECODE_V4 = {
    "AV": ({"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}, "attack_vector"),
    "AC": ({"L": "LOW", "H": "HIGH"}, "attack_complexity"),
    "AT": ({"N": "NONE", "P": "PRESENT"}, "attack_requirements"),
    "PR": ({"N": "NONE", "L": "LOW", "H": "HIGH"}, "privileges_required"),
    "UI": ({"N": "NONE", "P": "PASSIVE", "A": "ACTIVE"}, "user_interaction"),
    "VC": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "confidentiality_impact"),
    "VI": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "integrity_impact"),
    "VA": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "availability_impact"),
}

# Silver column -> NVD cvssData key, so the adapter can emit an NVD-shaped cvssData.
SILVER_TO_CVSS_DATA_KEY = {
    "attack_vector": "attackVector",
    "attack_complexity": "attackComplexity",
    "attack_requirements": "attackRequirements",
    "privileges_required": "privilegesRequired",
    "user_interaction": "userInteraction",
    "scope": "scope",
    "confidentiality_impact": "confidentialityImpact",
    "integrity_impact": "integrityImpact",
    "availability_impact": "availabilityImpact",
}


def vector_version(vector: str) -> str | None:
    """Return the CVSS version a vector string declares ('3.1', '4.0', ...)."""
    head = vector.strip().split("/", 1)[0]
    if head.upper().startswith("CVSS:"):
        return head.split(":", 1)[1]
    # v2.0 vectors carry no prefix at all (e.g. "AV:N/AC:L/Au:N/C:C/I:C/A:C").
    return "2.0" if vector.strip().startswith("AV:") else None


def decode_cvss_vector(vector: str) -> dict[str, str]:
    """Decode a CVSS vector string into the Silver categorical columns."""
    version = vector_version(vector) or ""
    table = VECTOR_DECODE_V4 if version.startswith("4") else VECTOR_DECODE_V3
    decoded: dict[str, str] = {}
    for token in vector.strip().split("/"):
        if ":" not in token:
            continue
        metric, _, value = token.partition(":")
        if metric in table:
            mapping, column = table[metric]
            decoded[column] = mapping.get(value.upper(), value.upper())
    return decoded


def severity_band(score: float) -> str:
    """Map a base score onto the standard qualitative band (NVD uppercase)."""
    if score <= 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


# CVSS v2.0 metric weights (spec section 3.2.1) — the library exposes only the
# base score, so the two sub-scores NVD publishes are computed here.
_V2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_V2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_V2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_V2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}


def _v2_sub_scores(metrics: dict) -> tuple[float | None, float | None]:
    """CVSS v2 (exploitability, impact) sub-scores, rounded the way NVD reports them."""
    try:
        exploitability = (
            20.0 * _V2_AV[metrics["AV"]] * _V2_AC[metrics["AC"]] * _V2_AU[metrics["Au"]]
        )
        impact = 10.41 * (
            1.0
            - (1.0 - _V2_CIA[metrics["C"]])
            * (1.0 - _V2_CIA[metrics["I"]])
            * (1.0 - _V2_CIA[metrics["A"]])
        )
    except KeyError:
        return None, None
    return round(exploitability, 1), round(impact, 1)


def score_vector(vector: str) -> dict | None:
    """
    Compute the numeric scores for a CVSS vector string.

    Returns ``{"version", "base_score", "base_severity", "exploitability_score",
    "impact_score"}``, or None if the vector is unparseable. CVSS 4.0 defines no
    exploitability/impact sub-scores, so those come back None for v4 vectors.
    """
    from cvss import CVSS2, CVSS3, CVSS4
    from cvss.exceptions import CVSSError

    version = vector_version(vector)
    if version is None:
        return None

    try:
        if version.startswith("4"):
            parsed = CVSS4(vector)
            base = float(parsed.base_score)
            exploitability = impact = None
        elif version.startswith("3"):
            parsed = CVSS3(vector)
            base = float(parsed.base_score)
            exploitability = round(float(parsed.esc), 1)
            impact = round(float(parsed.isc), 1)
        else:
            parsed = CVSS2(vector)
            base = float(parsed.base_score)
            exploitability, impact = _v2_sub_scores(parsed.metrics)
    except (CVSSError, ValueError, TypeError, ZeroDivisionError):
        log.debug("unparseable CVSS vector: %s", vector)
        return None

    # A zero-impact v3 vector scores 0.0; the sub-scores are still meaningful.
    return {
        "version": version,
        "base_score": base,
        "base_severity": severity_band(base),
        "exploitability_score": exploitability,
        "impact_score": impact,
    }
