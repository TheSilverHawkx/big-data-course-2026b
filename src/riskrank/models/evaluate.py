"""
Ranking evaluation helpers: PR-AUC for a continuous score and top-K hit rate.

Two flavours of each metric:

*Pooled* (``score_pr_auc``, ``top_k_hit_rate``) ranks every row in a split together.
This is misleading here. The Gold grain is (cve_id, observation_date), so one CVE
that goes into KEV contributes a positive row on *every* observation date inside the
90-day window — up to six correlated rows at the semi-monthly cadence. They land at
adjacent ranks, so a single vulnerability moving up or down swings the metric by 2x.

*Per-date* (``score_pr_auc_by_date``, ``top_k_hit_rate_by_date``) computes the metric
independently on each observation date — where every CVE appears exactly once — and
macro-averages. No CVE can be counted twice, and each date contributes equally.
Prefer these when comparing scores; the pooled versions are kept for continuity.
"""
from __future__ import annotations

from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.ml.functions import array_to_vector
from pyspark.sql import DataFrame
from pyspark.sql.functions import array, col, desc, lit

from riskrank.models.model_b_kev import LABEL

_DATE_COL = "observation_date"


def score_pr_auc(df: DataFrame, score_col: str) -> float:
    """PR-AUC of a continuous score column against the 90-day KEV label."""
    wrapped = df.filter(col(LABEL).isNotNull()).withColumn(
        "_score_vec", array_to_vector(array(lit(0.0), col(score_col).cast("double")))
    )
    return float(
        BinaryClassificationEvaluator(
            labelCol=LABEL, rawPredictionCol="_score_vec", metricName="areaUnderPR"
        ).evaluate(wrapped)
    )


def top_k_hit_rate(df: DataFrame, score_col: str, k: int) -> dict[str, float]:
    """
    Fraction of true future-KEV CVEs captured in the top-K by score.

    Returns precision@k and recall@k.
    """
    labeled = df.filter(col(LABEL).isNotNull())
    total_pos = labeled.filter(col(LABEL) == 1).count()
    top = labeled.orderBy(desc(score_col)).limit(k)
    hits = top.filter(col(LABEL) == 1).count()
    return {
        "k": k,
        "precision_at_k": hits / k if k else 0.0,
        "recall_at_k": hits / total_pos if total_pos else 0.0,
        "positives_total": total_pos,
    }


def _dates_with_positives(labeled: DataFrame) -> list:
    """Observation dates that carry at least one positive (others make PR-AUC undefined)."""
    rows = (
        labeled.filter(col(LABEL) == 1)
        .select(_DATE_COL)
        .distinct()
        .orderBy(_DATE_COL)
        .collect()
    )
    return [r[_DATE_COL] for r in rows]


def score_pr_auc_by_date(df: DataFrame, score_col: str) -> dict:
    """
    PR-AUC computed per observation date, then macro-averaged.

    Within one date each CVE appears exactly once, so no vulnerability is counted
    more than once. Dates with no positives are skipped and reported.
    """
    labeled = df.filter(col(LABEL).isNotNull()).cache()
    try:
        dates = _dates_with_positives(labeled)
        per_date: dict[str, float] = {}
        for d in dates:
            day = labeled.filter(col(_DATE_COL) == lit(d)).withColumn(
                "_score_vec", array_to_vector(array(lit(0.0), col(score_col).cast("double")))
            )
            per_date[str(d)] = float(
                BinaryClassificationEvaluator(
                    labelCol=LABEL, rawPredictionCol="_score_vec", metricName="areaUnderPR"
                ).evaluate(day)
            )
        total_dates = labeled.select(_DATE_COL).distinct().count()
    finally:
        labeled.unpersist()

    scored = list(per_date.values())
    return {
        "macro_pr_auc": sum(scored) / len(scored) if scored else 0.0,
        "dates_scored": len(scored),
        "dates_without_positives": total_dates - len(scored),
        "per_date_pr_auc": per_date,
    }


def top_k_hit_rate_by_date(df: DataFrame, score_col: str, k: int) -> dict:
    """Top-K precision/recall computed per observation date, then macro-averaged."""
    labeled = df.filter(col(LABEL).isNotNull()).cache()
    try:
        dates = _dates_with_positives(labeled)
        precisions: list[float] = []
        recalls: list[float] = []
        for d in dates:
            day = labeled.filter(col(_DATE_COL) == lit(d))
            total_pos = day.filter(col(LABEL) == 1).count()
            hits = day.orderBy(desc(score_col)).limit(k).filter(col(LABEL) == 1).count()
            precisions.append(hits / k if k else 0.0)
            recalls.append(hits / total_pos if total_pos else 0.0)
    finally:
        labeled.unpersist()

    n = len(precisions)
    return {
        "k": k,
        "mean_precision_at_k": sum(precisions) / n if n else 0.0,
        "mean_recall_at_k": sum(recalls) / n if n else 0.0,
        "dates_scored": n,
    }
