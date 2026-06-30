"""
Shared feature definitions and Spark ML pipeline stages for the CVSS-vector models.

The CVSS vector is decoded in Silver into eight categorical components
(AV/AC/PR/UI/S/C/I/A) plus numeric CVSS sub-scores. Both Model A (EPSS regression)
and Model B (KEV classification) build their feature vector from these columns.
"""
from __future__ import annotations

from pyspark.ml import Transformer
from pyspark.ml.feature import OneHotEncoder, StringIndexer, VectorAssembler

# Eight decoded CVSS vector components (categorical).
CVSS_CATEGORICAL = [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]

# Numeric CVSS / NVD features (must NOT include EPSS or any KEV-derived column).
CVSS_NUMERIC = [
    "cvss_base_score",
    "exploitability_score",
    "impact_score",
    "cwe_count",
    "reference_count",
    "cpe_match_count",
]


def cvss_feature_stages(
    *,
    extra_numeric: list[str] | None = None,
    output_col: str = "features",
    prefix: str = "",
) -> tuple[list[Transformer], str]:
    """
    Build the StringIndexer + OneHotEncoder + VectorAssembler stages for CVSS features.

    extra_numeric: additional numeric columns to append (e.g. ["pred_epss"] for Model B).
    prefix: namespaces the intermediate index/one-hot columns so two pipelines applied
    to the same DataFrame (Model A then Model B) do not collide on column names.
    Returns (stages, output_col).
    """
    numeric = list(CVSS_NUMERIC) + list(extra_numeric or [])
    stages: list[Transformer] = []

    indexed_cols = []
    encoded_cols = []
    for c in CVSS_CATEGORICAL:
        idx = f"{prefix}{c}_idx"
        enc = f"{prefix}{c}_oh"
        stages.append(
            StringIndexer(inputCol=c, outputCol=idx, handleInvalid="keep")
        )
        indexed_cols.append(idx)
        encoded_cols.append(enc)
    stages.append(
        OneHotEncoder(inputCols=indexed_cols, outputCols=encoded_cols, handleInvalid="keep")
    )

    assembler = VectorAssembler(
        inputCols=encoded_cols + numeric, outputCol=output_col, handleInvalid="keep"
    )
    stages.append(assembler)
    return stages, output_col
