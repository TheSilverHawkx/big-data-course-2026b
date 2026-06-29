"""
End-to-end model training orchestrator.

Pipeline:
  1. Read Gold observations.
  2. Chronological train/val/test split.
  3. Train Model A (EPSS regression); attach pred_epss to every split.
  4. Train Model B (KEV classification) using CVSS vector + pred_epss.
  5. Tune AdjustedRisk weights (w1/w2/w3) on validation.
  6. Evaluate baseline (CVSS-only) vs adjusted score on the test split.
  7. Save fitted pipelines to data/models/ and metrics to data/reports/.

Runnable: ``python -m riskrank.models.train``
"""
from __future__ import annotations

import argparse
import json
import logging

from riskrank.config import get_settings
from riskrank.models.evaluate import score_pr_auc, top_k_hit_rate
from riskrank.models.model_a_epss import apply_model_a, evaluate_model_a, train_model_a
from riskrank.models.model_b_kev import apply_model_b, evaluate_model_b, train_model_b
from riskrank.models.scoring import add_adjusted_risk, tune_weights
from riskrank.paths import ProjectPaths
from riskrank.spark.gold import read_gold_observations
from riskrank.spark.session import build_spark_session
from riskrank.spark.splits import build_chronological_splits

log = logging.getLogger(__name__)


def run_training(settings, *, ranking_k: int | None = None) -> dict:
    paths = ProjectPaths(settings)
    paths.ensure_dirs()
    k = ranking_k or settings.model.ranking_k
    seed = settings.model.random_seed

    spark = build_spark_session(settings, app_name="riskrank-train")
    spark.sparkContext.setLogLevel("WARN")
    report: dict = {}
    try:
        obs = read_gold_observations(spark, settings)
        label_as_of = obs.select("label_as_of_date").first()[0]
        train_df, val_df, test_df, boundaries = build_chronological_splits(
            obs, settings, label_as_of
        )
        report["splits"] = boundaries

        # ── Model A: EPSS regression ────────────────────────────────────────────
        model_a = train_model_a(train_df, seed=seed)
        report["model_a"] = {
            "validation": evaluate_model_a(model_a, val_df),
            "test": evaluate_model_a(model_a, test_df),
        }
        train_a = apply_model_a(model_a, train_df)
        val_a = apply_model_a(model_a, val_df)
        test_a = apply_model_a(model_a, test_df)

        # ── Model B: KEV classification ─────────────────────────────────────────
        model_b = train_model_b(train_a, seed=seed)
        report["model_b"] = {
            "validation": evaluate_model_b(model_b, val_a),
            "test": evaluate_model_b(model_b, test_a),
        }
        val_b = apply_model_b(model_b, val_a)
        test_b = apply_model_b(model_b, test_a)

        # ── Weight tuning on validation ─────────────────────────────────────────
        (w1, w2, w3), val_auc = tune_weights(val_b)
        report["weights"] = {"w1_cvss": w1, "w2_exploit": w2, "w3_kev": w3}
        report["weight_tuning"] = {"validation_pr_auc": val_auc}

        # ── Baseline vs adjusted on test ────────────────────────────────────────
        test_scored = add_adjusted_risk(test_b, w1, w2, w3)
        baseline_pr = score_pr_auc(test_scored, "cvss_base_score")
        adjusted_pr = score_pr_auc(test_scored, "adjusted_risk")
        report["test_ranking"] = {
            "baseline_cvss_pr_auc": baseline_pr,
            "adjusted_pr_auc": adjusted_pr,
            "baseline_top_k": top_k_hit_rate(test_scored, "cvss_base_score", k),
            "adjusted_top_k": top_k_hit_rate(test_scored, "adjusted_risk", k),
        }

        # ── Persist models + reports ────────────────────────────────────────────
        model_a.write().overwrite().save(str(paths.models / "model_a_epss"))
        model_b.write().overwrite().save(str(paths.models / "model_b_kev"))
        (paths.models / "weights.json").write_text(
            json.dumps(report["weights"], indent=2), encoding="utf-8"
        )
        (paths.reports / "training_metrics.json").write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        log.info("training complete: %s", json.dumps(report["test_ranking"], default=str))
    finally:
        spark.stop()

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Train RiskRank models A + B and tune weights")
    parser.add_argument("--ranking-k", type=int, default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    report = run_training(get_settings(), ranking_k=args.ranking_k)
    print(json.dumps(report.get("test_ranking", {}), indent=2, default=str))


if __name__ == "__main__":
    main()
