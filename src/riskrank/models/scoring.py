"""
Composite AdjustedRisk scoring and weight tuning.

    AdjustedRisk = 10 * [ w1 * (cvss_base_score / 10)
                          + w2 * P(exploit)          (Model A predicted EPSS)
                          + w3 * P(KEV <= 90 days) ] (Model B probability)

Weights (w1 + w2 + w3 = 1) are tuned on the validation split to maximise the
ranking quality (PR-AUC of the score against the 90-day KEV label), then frozen.

Also exposes a single-vector demo that reproduces the "Score a new CVSS vector"
screen: CVSS-only priority vs the model-adjusted priority.
"""
from __future__ import annotations

import logging

from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.sql import DataFrame
from pyspark.sql.functions import col, least, lit

from riskrank.models.model_a_epss import PRED_COL
from riskrank.models.model_b_kev import KEV_PROB_COL, LABEL

log = logging.getLogger(__name__)

ADJUSTED_RISK_COL = "adjusted_risk"

# CVSS vector abbreviation -> NVD cvssData full-word value (Silver categorical domain).
_VECTOR_DECODE = {
    "AV": ({"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}, "attack_vector"),
    "AC": ({"L": "LOW", "H": "HIGH"}, "attack_complexity"),
    "PR": ({"N": "NONE", "L": "LOW", "H": "HIGH"}, "privileges_required"),
    "UI": ({"N": "NONE", "R": "REQUIRED"}, "user_interaction"),
    "S": ({"U": "UNCHANGED", "C": "CHANGED"}, "scope"),
    "C": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "confidentiality_impact"),
    "I": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "integrity_impact"),
    "A": ({"H": "HIGH", "L": "LOW", "N": "NONE"}, "availability_impact"),
}


def decode_cvss_vector(vector: str) -> dict[str, str]:
    """Decode a CVSS vector string into the eight Silver categorical columns."""
    decoded: dict[str, str] = {}
    for token in vector.strip().split("/"):
        if ":" not in token:
            continue
        metric, _, value = token.partition(":")
        if metric in _VECTOR_DECODE:
            mapping, column = _VECTOR_DECODE[metric]
            decoded[column] = mapping.get(value.upper(), value.upper())
    return decoded


def add_adjusted_risk(
    df: DataFrame, w1: float, w2: float, w3: float, *, col_name: str = ADJUSTED_RISK_COL
) -> DataFrame:
    """Add the AdjustedRisk column (0..10) from the CVSS/EPSS/KEV terms."""
    cvss_term = least(col("cvss_base_score") / lit(10.0), lit(1.0))
    score = (
        lit(10.0)
        * (lit(w1) * cvss_term + lit(w2) * col(PRED_COL) + lit(w3) * col(KEV_PROB_COL))
    )
    return df.withColumn(col_name, score)


def _ranking_pr_auc(scored_df: DataFrame, score_col: str) -> float:
    """PR-AUC of a continuous score against the 90-day KEV label."""
    # BinaryClassificationEvaluator needs the raw score as a 2-element probability
    # vector [P(neg), P(score)]; wrap the scalar score accordingly.
    from pyspark.ml.functions import array_to_vector
    from pyspark.sql.functions import array

    wrapped = scored_df.filter(col(LABEL).isNotNull()).withColumn(
        "_score_vec", array_to_vector(array(lit(0.0), col(score_col)))
    )
    return float(
        BinaryClassificationEvaluator(
            labelCol=LABEL, rawPredictionCol="_score_vec", metricName="areaUnderPR"
        ).evaluate(wrapped)
    )


def tune_weights(
    val_scored: DataFrame, *, step: float = 0.05
) -> tuple[tuple[float, float, float], float]:
    """
    Grid-search w1+w2+w3 = 1 on the validation split, maximising ranking PR-AUC.

    Returns ((w1, w2, w3), best_pr_auc).
    """
    val_scored.cache()
    steps = int(round(1.0 / step))
    best_w = (0.2, 0.3, 0.5)
    best_auc = -1.0
    for i in range(steps + 1):
        for j in range(steps + 1 - i):
            w1 = i * step
            w2 = j * step
            w3 = 1.0 - w1 - w2
            if w3 < -1e-9:
                continue
            scored = add_adjusted_risk(val_scored, w1, w2, w3, col_name="_tune_score")
            auc = _ranking_pr_auc(scored, "_tune_score")
            if auc > best_auc:
                best_auc = auc
                best_w = (round(w1, 4), round(w2, 4), round(w3, 4))
    val_scored.unpersist()
    log.info("tuned weights w=%s val_pr_auc=%.4f", best_w, best_auc)
    return best_w, best_auc


def score_single_vector(
    spark,
    model_a,
    model_b,
    *,
    cvss_vector: str,
    cvss_base_score: float,
    weights: tuple[float, float, float],
    exploitability_score: float = 0.0,
    impact_score: float = 0.0,
    cwe_count: int = 0,
    reference_count: int = 0,
    cpe_match_count: int = 0,
) -> dict[str, float]:
    """Score one CVSS vector end-to-end (the screenshot demo)."""
    from riskrank.models.model_a_epss import apply_model_a
    from riskrank.models.model_b_kev import apply_model_b

    decoded = decode_cvss_vector(cvss_vector)
    row = {
        **{c: decoded.get(c) for _, (_, c) in _VECTOR_DECODE.items()},
        "cvss_base_score": float(cvss_base_score),
        "exploitability_score": float(exploitability_score),
        "impact_score": float(impact_score),
        "cwe_count": int(cwe_count),
        "reference_count": int(reference_count),
        "cpe_match_count": int(cpe_match_count),
    }
    df = spark.createDataFrame([row])
    df = apply_model_a(model_a, df)
    df = apply_model_b(model_b, df)
    w1, w2, w3 = weights
    df = add_adjusted_risk(df, w1, w2, w3)
    out = df.select(PRED_COL, KEV_PROB_COL, ADJUSTED_RISK_COL).collect()[0]
    return {
        "cvss_only_priority": float(cvss_base_score),
        "pred_exploit_epss": float(out[PRED_COL]),
        "pred_kev_prob_90d": float(out[KEV_PROB_COL]),
        "adjusted_risk": float(out[ADJUSTED_RISK_COL]),
        "weights": {"w1_cvss": w1, "w2_exploit": w2, "w3_kev": w3},
    }


def main() -> None:
    import argparse
    import json

    from pyspark.ml import PipelineModel

    from riskrank.config import get_settings
    from riskrank.paths import ProjectPaths
    from riskrank.spark.session import build_spark_session

    parser = argparse.ArgumentParser(description="Score one CVSS vector (RiskRank demo)")
    parser.add_argument("--vector", required=True, help="e.g. CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N")
    parser.add_argument("--base-score", type=float, required=True, help="CVSS base score 0..10")
    parser.add_argument("--exploitability-score", type=float, default=0.0)
    parser.add_argument("--impact-score", type=float, default=0.0)
    parser.add_argument("--cwe-count", type=int, default=0)
    parser.add_argument("--reference-count", type=int, default=0)
    parser.add_argument("--cpe-match-count", type=int, default=0)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    paths = ProjectPaths(settings)

    weights_path = paths.models / "weights.json"
    if weights_path.exists():
        w = json.loads(weights_path.read_text(encoding="utf-8"))
        weights = (w["w1_cvss"], w["w2_exploit"], w["w3_kev"])
    else:
        rs = settings.risk_score
        weights = (rs.cvss_weight, rs.exploit_weight, rs.kev_weight)

    spark = build_spark_session(settings, app_name="riskrank-score")
    spark.sparkContext.setLogLevel("WARN")
    try:
        model_a = PipelineModel.load(str(paths.models / "model_a_epss"))
        model_b = PipelineModel.load(str(paths.models / "model_b_kev"))
        result = score_single_vector(
            spark,
            model_a,
            model_b,
            cvss_vector=args.vector,
            cvss_base_score=args.base_score,
            weights=weights,
            exploitability_score=args.exploitability_score,
            impact_score=args.impact_score,
            cwe_count=args.cwe_count,
            reference_count=args.reference_count,
            cpe_match_count=args.cpe_match_count,
        )
    finally:
        spark.stop()

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
