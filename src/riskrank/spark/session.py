"""Shared SparkSession builder configured from Settings."""
from __future__ import annotations

from pyspark.sql import SparkSession

from riskrank.config import Settings, get_settings


def build_spark_session(
    settings: Settings | None = None, *, app_name: str = "riskrank"
) -> SparkSession:
    """Create or reuse a SparkSession configured from Settings."""
    cfg = (settings or get_settings()).spark
    return (
        SparkSession.builder.master(cfg.master)
        .appName(app_name)
        .config("spark.driver.memory", cfg.driver_memory)
        .config("spark.sql.shuffle.partitions", str(cfg.shuffle_partitions))
        .config("spark.default.parallelism", str(cfg.default_parallelism))
        .config("spark.sql.streaming.schemaInference", "false")
        .getOrCreate()
    )
