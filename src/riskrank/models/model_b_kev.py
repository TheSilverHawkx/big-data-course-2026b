"""
Model B — classification: CVSS vector + predicted EPSS -> P(KEV <= 90 days).

Trains a GBT classifier whose features are the CVSS vector plus Model A's
`pred_epss`. The positive class probability is the project's P(KEV) term, used as
the w3 term in the AdjustedRisk blend. Class imbalance is handled with a per-row
weight column (balanced).
"""
from __future__ import annotations

import logging

from pyspark.ml import Pipeline, PipelineModel
from pyspark.ml.classification import GBTClassifier
from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.ml.functions import vector_to_array
from pyspark.sql import DataFrame
from pyspark.sql.functions import col, lit, when

from riskrank.models.ml_features import CVSS_NUMERIC, cvss_feature_stages
from riskrank.models.model_a_epss import PRED_COL

LABEL = "kev_within_90_days"
KEV_PROB_COL = "pred_kev_prob"
_WEIGHT_COL = "class_weight"


def _prep(df: DataFrame) -> DataFrame:
    return df.fillna(0.0, subset=[*CVSS_NUMERIC, PRED_COL])


def _add_balanced_weight(train_df: DataFrame) -> DataFrame:
    """Add a per-row weight so positives and negatives contribute equally."""
    counts = train_df.groupBy(LABEL).count().collect()
    by_label = {int(r[LABEL]): r["count"] for r in counts if r[LABEL] is not None}
    total = sum(by_label.values())
    n_pos = by_label.get(1, 0)
    n_neg = by_label.get(0, 0)
    # weight ~ total / (2 * class_count); guard against divide-by-zero
    w_pos = total / (2.0 * n_pos) if n_pos else 1.0
    w_neg = total / (2.0 * n_neg) if n_neg else 1.0
    return train_df.withColumn(
        _WEIGHT_COL, when(col(LABEL) == 1, lit(w_pos)).otherwise(lit(w_neg))
    )


def train_model_b(train_df: DataFrame, *, seed: int = 42, max_iter: int = 40) -> PipelineModel:
    """Fit Model B on rows with a non-null 90-day KEV label."""
    stages, features_col = cvss_feature_stages(
        extra_numeric=[PRED_COL], output_col="features_b", prefix="b_"
    )
    classifier = GBTClassifier(
        featuresCol=features_col,
        labelCol=LABEL,
        weightCol=_WEIGHT_COL,
        maxIter=max_iter,
        maxDepth=5,
        seed=seed,
    )
    pipeline = Pipeline(stages=[*stages, classifier])
    labeled = _add_balanced_weight(_prep(train_df).filter(col(LABEL).isNotNull()))
    log.info("training Model B on %d rows", labeled.count())
    return pipeline.fit(labeled)


def apply_model_b(model: PipelineModel, df: DataFrame) -> DataFrame:
    """Attach `pred_kev_prob` = P(positive class) to df."""
    scored = model.transform(_prep(df))
    return scored.withColumn(KEV_PROB_COL, vector_to_array(col("probability")).getItem(1))


def evaluate_model_b(model: PipelineModel, df: DataFrame) -> dict[str, float]:
    """Area under PR and ROC on a labeled split (primary metric = PR-AUC)."""
    scored = apply_model_b(model, df).filter(col(LABEL).isNotNull())
    metrics = {}
    for name, metric in (("area_under_pr", "areaUnderPR"), ("area_under_roc", "areaUnderROC")):
        ev = BinaryClassificationEvaluator(
            labelCol=LABEL, rawPredictionCol="probability", metricName=metric
        )
        metrics[name] = float(ev.evaluate(scored))
    return metrics


log = logging.getLogger(__name__)
