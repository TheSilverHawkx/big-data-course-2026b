"""
Baseline 0 — CVSS score only.

    priority = cvss_base_score

A transparent reference ranking that treats every CVSS 7.0 as equally urgent.
The trained AdjustedRisk score is compared against this baseline on the test split.
"""
from __future__ import annotations

from pyspark.sql import DataFrame

from riskrank.models.evaluate import score_pr_auc, top_k_hit_rate

BASELINE_SCORE_COL = "cvss_base_score"


def evaluate_baseline(df: DataFrame, *, k: int = 100) -> dict:
    """PR-AUC and top-K hit rate of the CVSS-only ranking against the 90-day KEV label."""
    return {
        "pr_auc": score_pr_auc(df, BASELINE_SCORE_COL),
        "top_k": top_k_hit_rate(df, BASELINE_SCORE_COL, k),
    }
