"""
Feature engineering for the Gold observation dataset.

All window computations use only data with score_date <= observation_date
(strict no-future-leakage guarantee).
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql.functions import avg, col, count, datediff, lit, size, stddev, when
from pyspark.sql.functions import max as spark_max
from pyspark.sql.functions import min as spark_min
from pyspark.sql.functions import sum as spark_sum


def build_epss_features(spine_df: DataFrame, epss_df: DataFrame) -> DataFrame:
    """
    Compute temporal EPSS features for every (cve_id, observation_date) in spine_df.

    Uses only EPSS rows with score_date <= observation_date (no future leakage).
    Lookback window: 30 days.
    """
    epoch = lit("1970-01-01").cast("date")
    spine = spine_df.withColumn("obs_days", datediff(col("observation_date"), epoch))

    epss = epss_df.select(
        col("cve_id").alias("e_cve_id"),
        col("observation_date").alias("score_date"),
        col("epss_score"),
        col("epss_percentile"),
        col("epss_model_version"),
        datediff(col("observation_date"), epoch).alias("score_days"),
    )

    joined = spine.join(
        epss,
        (col("cve_id") == col("e_cve_id"))
        & (col("score_days") <= col("obs_days"))
        & (col("score_days") >= col("obs_days") - 30),
        "left",
    ).drop("e_cve_id")

    # Normalized day offset for numerically stable slope (range [-30, 0])
    x = (col("score_days") - col("obs_days")).cast("double")

    agg = joined.groupBy("cve_id", "observation_date", "obs_days").agg(
        spark_max(when(col("score_days") == col("obs_days"), col("epss_score"))).alias(
            "epss_current"
        ),
        spark_max(
            when(col("score_days") == col("obs_days"), col("epss_percentile"))
        ).alias("epss_percentile_current"),
        spark_max(
            when(col("score_days") == col("obs_days"), col("epss_model_version"))
        ).alias("epss_model_version"),
        spark_max(when(col("score_days") == col("obs_days") - 1, col("epss_score"))).alias(
            "epss_lag_1d"
        ),
        spark_max(when(col("score_days") == col("obs_days") - 7, col("epss_score"))).alias(
            "epss_lag_7d"
        ),
        spark_max(when(col("score_days") == col("obs_days") - 30, col("epss_score"))).alias(
            "epss_lag_30d"
        ),
        avg(when(col("score_days") >= col("obs_days") - 6, col("epss_score"))).alias(
            "epss_mean_7d"
        ),
        spark_max(when(col("score_days") >= col("obs_days") - 6, col("epss_score"))).alias(
            "epss_max_7d"
        ),
        spark_min(when(col("score_days") >= col("obs_days") - 6, col("epss_score"))).alias(
            "epss_min_7d"
        ),
        stddev(when(col("score_days") >= col("obs_days") - 6, col("epss_score"))).alias(
            "epss_stddev_7d"
        ),
        avg(when(col("score_days") >= col("obs_days") - 29, col("epss_score"))).alias(
            "epss_mean_30d"
        ),
        spark_max(when(col("score_days") >= col("obs_days") - 29, col("epss_score"))).alias(
            "epss_max_30d"
        ),
        spark_min(when(col("score_days") >= col("obs_days") - 29, col("epss_score"))).alias(
            "epss_min_30d"
        ),
        stddev(when(col("score_days") >= col("obs_days") - 29, col("epss_score"))).alias(
            "epss_stddev_30d"
        ),
        count(when(col("score_days") >= col("obs_days") - 29, lit(1))).alias(
            "epss_days_observed_30d"
        ),
        spark_sum(
            when(
                (col("score_days") >= col("obs_days") - 29) & (col("epss_score") > 0.1), lit(1)
            ).otherwise(lit(0))
        ).alias("epss_days_above_0_1_30d"),
        spark_sum(
            when(
                (col("score_days") >= col("obs_days") - 29) & (col("epss_score") > 0.5), lit(1)
            ).otherwise(lit(0))
        ).alias("epss_days_above_0_5_30d"),
        # OLS slope intermediates (7d)
        count(when(col("score_days") >= col("obs_days") - 6, lit(1))).alias("_n7"),
        spark_sum(when(col("score_days") >= col("obs_days") - 6, x)).alias("_sx7"),
        spark_sum(when(col("score_days") >= col("obs_days") - 6, col("epss_score"))).alias("_sy7"),
        spark_sum(when(col("score_days") >= col("obs_days") - 6, x * col("epss_score"))).alias(
            "_sxy7"
        ),
        spark_sum(when(col("score_days") >= col("obs_days") - 6, x * x)).alias("_sx27"),
        # OLS slope intermediates (30d)
        count(when(col("score_days") >= col("obs_days") - 29, lit(1))).alias("_n30"),
        spark_sum(when(col("score_days") >= col("obs_days") - 29, x)).alias("_sx30"),
        spark_sum(when(col("score_days") >= col("obs_days") - 29, col("epss_score"))).alias(
            "_sy30"
        ),
        spark_sum(when(col("score_days") >= col("obs_days") - 29, x * col("epss_score"))).alias(
            "_sxy30"
        ),
        spark_sum(when(col("score_days") >= col("obs_days") - 29, x * x)).alias("_sx230"),
    )

    denom7 = col("_n7") * col("_sx27") - col("_sx7") ** 2
    denom30 = col("_n30") * col("_sx230") - col("_sx30") ** 2

    result = (
        agg.withColumn("epss_delta_1d", col("epss_current") - col("epss_lag_1d"))
        .withColumn("epss_delta_7d", col("epss_current") - col("epss_lag_7d"))
        .withColumn("epss_delta_30d", col("epss_current") - col("epss_lag_30d"))
        .withColumn(
            "epss_slope_7d",
            when(denom7 == 0, lit(0.0)).otherwise(
                (col("_n7") * col("_sxy7") - col("_sx7") * col("_sy7")) / denom7
            ),
        )
        .withColumn(
            "epss_slope_30d",
            when(denom30 == 0, lit(0.0)).otherwise(
                (col("_n30") * col("_sxy30") - col("_sx30") * col("_sy30")) / denom30
            ),
        )
        .drop(
            "obs_days",
            "_n7", "_sx7", "_sy7", "_sxy7", "_sx27",
            "_n30", "_sx30", "_sy30", "_sxy30", "_sx230",
        )
    )

    return result


def build_nvd_features(spine_df: DataFrame, nvd_df: DataFrame) -> DataFrame:
    """Join NVD Silver (latest per CVE) into the spine and add CVSS/NVD feature columns."""
    nvd_cols = nvd_df.select(
        col("cve_id").alias("n_cve_id"),
        "cvss_base_score",
        "cvss_version",
        "cvss_base_severity",
        "cvss_vector",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction",
        "scope",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
        "exploitability_score",
        "impact_score",
        col("cwe_ids"),
        col("reference_count"),
        col("cpe_match_count"),
        col("published_at").alias("nvd_published_at"),
        col("fetched_at").alias("nvd_fetched_at"),
    )

    joined = spine_df.join(nvd_cols, col("cve_id") == col("n_cve_id"), "left").drop("n_cve_id")

    return joined.withColumn("cwe_count", size(col("cwe_ids"))).withColumn(
        "has_cvss", col("cvss_base_score").isNotNull().cast("int")
    )
