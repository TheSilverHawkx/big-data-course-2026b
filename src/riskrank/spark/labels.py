"""
KEV label computation and right-censoring for the Gold observation dataset.

The primary prediction horizon for RiskRank is 90 days (7 and 30 are also computed).
Pure Python helpers are exposed for testing without a SparkSession.
"""
from __future__ import annotations

from datetime import date

# ── Pure Python helpers ───────────────────────────────────────────────────────


def kev_label_within_days(days_until_kev: int | None, horizon: int) -> int | None:
    """
    Compute the binary KEV label for a prediction horizon.

    Returns:
      1    — KEV was added within `horizon` days after observation_date (positive).
      0    — KEV not added within horizon days (confirmed negative).
      None — CVE was already in KEV on or before observation_date; must be excluded.
    """
    if days_until_kev is None:
        return 0  # never in KEV as of label_as_of_date -> confirmed negative
    if days_until_kev <= 0:
        return None  # already in KEV -> exclude from model training
    return 1 if days_until_kev <= horizon else 0


def is_right_censored(
    observation_date: date, label_as_of_date: date, horizon_days: int = 90
) -> bool:
    """
    Return True when the future label window is incomplete.

    A negative label is only reliable when:
        observation_date <= label_as_of_date - horizon_days
    """
    delta = (label_as_of_date - observation_date).days
    return delta < horizon_days


def derive_label_as_of_date(kev_fetched_at_dates: list[date]) -> date | None:
    """Return the maximum KEV catalog fetch date as the label_as_of_date."""
    if not kev_fetched_at_dates:
        return None
    return max(kev_fetched_at_dates)


# ── Spark label builders ───────────────────────────────────────────────────────


def add_kev_labels(obs_df, kev_df, label_as_of_date: date):
    """
    Join the observation spine with KEV Silver and compute all label columns.

    Returns obs_df annotated with:
        kev_date_added, days_until_kev,
        kev_within_7_days, kev_within_30_days, kev_within_90_days,
        ever_in_kev, label_as_of_date
    """
    from pyspark.sql.functions import col, datediff, lit, when

    kev_minimal = kev_df.select(
        col("cve_id").alias("k_cve_id"),
        col("date_added").alias("kev_date_added"),
    )

    joined = obs_df.join(
        kev_minimal, obs_df.cve_id == kev_minimal.k_cve_id, "left"
    ).drop("k_cve_id")

    days_until = datediff(col("kev_date_added"), col("observation_date"))

    def _within(horizon: int):
        return (
            when(
                col("days_until_kev").isNotNull()
                & (col("days_until_kev") > 0)
                & (col("days_until_kev") <= horizon),
                lit(1),
            )
            .when(col("days_until_kev").isNull(), lit(0))
            .when(col("days_until_kev") <= 0, lit(None).cast("int"))
            .otherwise(lit(0))
        )

    labeled = (
        joined.withColumn(
            "days_until_kev",
            when(col("kev_date_added").isNotNull(), days_until).otherwise(lit(None).cast("int")),
        )
        .withColumn("ever_in_kev", col("kev_date_added").isNotNull().cast("int"))
        .withColumn("kev_within_7_days", _within(7))
        .withColumn("kev_within_30_days", _within(30))
        .withColumn("kev_within_90_days", _within(90))
        .withColumn("label_as_of_date", lit(label_as_of_date))
    )

    return labeled


def apply_right_censoring(obs_df, label_as_of_date: date, horizon_days: int = 90):
    """
    Remove rows where the future label window is incomplete.

    Excludes rows where observation_date > label_as_of_date - horizon_days.
    """
    from pyspark.sql.functions import col, lit

    cutoff = date.fromordinal(label_as_of_date.toordinal() - horizon_days)
    return obs_df.filter(col("observation_date") <= lit(cutoff))


def exclude_already_kev(obs_df):
    """Remove rows where the CVE was already in KEV on the observation date."""
    from pyspark.sql.functions import col

    return obs_df.filter(col("days_until_kev").isNull() | (col("days_until_kev") > 0))
