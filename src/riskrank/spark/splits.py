"""
Chronological train/validation/test splits for the Gold observation dataset.

Never uses random row splits — all CVEs on one observation date go into the same
split, so the model is always trained on the past and evaluated on the future.
"""
from __future__ import annotations

import json
from datetime import date
from typing import Any

# Primary label horizon used for positive-count validation
_PRIMARY_LABEL = "kev_within_90_days"

# ── Pure Python helpers ───────────────────────────────────────────────────────


def compute_split_boundaries(
    dates: list[date],
    train_ratio: float = 0.60,
    val_ratio: float = 0.20,
) -> dict[str, Any]:
    """Compute chronological split boundary dates from distinct observation dates."""
    if not dates:
        raise ValueError("No observation dates provided; cannot compute splits.")

    sorted_dates = sorted(set(dates))
    n = len(sorted_dates)

    train_n = max(1, int(n * train_ratio))
    val_n = max(1, int(n * val_ratio))
    test_n = n - train_n - val_n

    if test_n < 1:
        raise ValueError(
            f"Not enough distinct dates ({n}) for train/val/test split "
            f"with ratios {train_ratio}/{val_ratio}/{1 - train_ratio - val_ratio}."
        )

    train_end_idx = train_n - 1
    val_end_idx = train_n + val_n - 1

    return {
        "train_start": str(sorted_dates[0]),
        "train_end": str(sorted_dates[train_end_idx]),
        "val_start": str(sorted_dates[train_end_idx + 1]),
        "val_end": str(sorted_dates[val_end_idx]),
        "test_start": str(sorted_dates[val_end_idx + 1]),
        "test_end": str(sorted_dates[-1]),
        "train_count": train_n,
        "val_count": val_n,
        "test_count": test_n,
        "total_count": n,
    }


def validate_split_positives(split_name: str, positive_count: int, minimum: int) -> None:
    if positive_count < minimum:
        raise ValueError(
            f"{split_name} split has only {positive_count} positive labels "
            f"(minimum {minimum}). Use a longer history range with --lookback-days."
        )


# ── Spark split implementation ─────────────────────────────────────────────────


def build_chronological_splits(obs_df, settings, label_as_of_date: date):
    """
    Split obs_df into (train_df, val_df, test_df) using chronological date boundaries.

    Saves split_boundaries.json to data/reports/. Raises ValueError if minimum positive
    counts are not met.
    """
    from pyspark.sql.functions import col, lit

    from riskrank.paths import ProjectPaths

    paths = ProjectPaths(settings)
    model_cfg = settings.model

    dates_rows = obs_df.select("observation_date").distinct().collect()
    dates = [r["observation_date"] for r in dates_rows]

    boundaries = compute_split_boundaries(dates, model_cfg.train_ratio, model_cfg.val_ratio)

    train_df = obs_df.filter(
        col("observation_date") <= lit(date.fromisoformat(boundaries["train_end"]))
    )
    val_df = obs_df.filter(
        (col("observation_date") > lit(date.fromisoformat(boundaries["train_end"])))
        & (col("observation_date") <= lit(date.fromisoformat(boundaries["val_end"])))
    )
    test_df = obs_df.filter(
        col("observation_date") > lit(date.fromisoformat(boundaries["val_end"]))
    )

    def _positive_count(df):
        return df.filter(col(_PRIMARY_LABEL) == 1).count()

    min_positives = {"training": 50, "validation": 15, "test": 15}
    for split_name, df in [("training", train_df), ("validation", val_df), ("test", test_df)]:
        pc = _positive_count(df)
        validate_split_positives(split_name, pc, min_positives[split_name])
        boundaries[f"{split_name}_positives"] = pc
        boundaries[f"{split_name}_rows"] = df.count()

    boundaries["label_as_of_date"] = str(label_as_of_date)

    paths.reports.mkdir(parents=True, exist_ok=True)
    report_path = paths.reports / "split_boundaries.json"
    report_path.write_text(json.dumps(boundaries, indent=2), encoding="utf-8")

    return train_df, val_df, test_df, boundaries
