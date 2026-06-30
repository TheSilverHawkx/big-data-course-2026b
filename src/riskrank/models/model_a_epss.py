"""
Model A — regression: CVSS vector -> predicted EPSS (exploitation probability).

Trains a GBT regressor on the CVSS vector features to predict the observed EPSS
score. The prediction `pred_epss` is the project's P(exploit) term, used both as a
feature for Model B and as the w2 term in the AdjustedRisk blend.
"""
from __future__ import annotations

import logging

from pyspark.ml import Pipeline, PipelineModel
from pyspark.ml.evaluation import RegressionEvaluator
from pyspark.ml.regression import GBTRegressor
from pyspark.sql import DataFrame

from riskrank.models.ml_features import CVSS_NUMERIC, cvss_feature_stages

log = logging.getLogger(__name__)

TARGET = "epss_current"
PRED_COL = "pred_epss"


def _prep(df: DataFrame) -> DataFrame:
    """Fill numeric nulls with 0.0 so the VectorAssembler does not choke on nulls."""
    return df.fillna(0.0, subset=CVSS_NUMERIC)


def train_model_a(train_df: DataFrame, *, seed: int = 42, max_iter: int = 40) -> PipelineModel:
    """Fit Model A on rows that have an observed EPSS value."""
    stages, features_col = cvss_feature_stages(output_col="features_a", prefix="a_")
    regressor = GBTRegressor(
        featuresCol=features_col,
        labelCol=TARGET,
        predictionCol=PRED_COL,
        maxIter=max_iter,
        maxDepth=5,
        seed=seed,
    )
    pipeline = Pipeline(stages=[*stages, regressor])
    labeled = _prep(train_df).filter(
        (train_df[TARGET].isNotNull()) & (train_df[TARGET] >= 0.0)
    )
    log.info("training Model A on %d rows", labeled.count())
    return pipeline.fit(labeled)


def apply_model_a(model: PipelineModel, df: DataFrame) -> DataFrame:
    """Attach the `pred_epss` column to df, clamped to [0, 1]."""
    from pyspark.sql.functions import greatest, least, lit

    scored = model.transform(_prep(df))
    return scored.withColumn(
        PRED_COL, greatest(lit(0.0), least(lit(1.0), scored[PRED_COL]))
    )


def evaluate_model_a(model: PipelineModel, df: DataFrame) -> dict[str, float]:
    """RMSE and R2 of predicted vs observed EPSS on a labeled split."""
    scored = apply_model_a(model, df).filter(df[TARGET].isNotNull())
    metrics = {}
    for name, metric in (("rmse", "rmse"), ("mae", "mae"), ("r2", "r2")):
        ev = RegressionEvaluator(labelCol=TARGET, predictionCol=PRED_COL, metricName=metric)
        metrics[name] = float(ev.evaluate(scored))
    return metrics
