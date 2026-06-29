"""Ranking evaluation helpers: PR-AUC for a continuous score and top-K hit rate."""
from __future__ import annotations

from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.ml.functions import array_to_vector
from pyspark.sql import DataFrame
from pyspark.sql.functions import array, col, desc, lit

from riskrank.models.model_b_kev import LABEL


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
