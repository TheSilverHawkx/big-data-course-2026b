"""
Bronze -> Silver pipeline entry point.

Runnable: ``python -m riskrank.spark.silver`` (trigger=availableNow processes all
currently available Bronze files, then exits).
"""
from __future__ import annotations

import argparse
import logging

from riskrank.config import Settings, get_settings
from riskrank.spark.bronze_streams import start_bronze_to_silver
from riskrank.spark.session import build_spark_session

log = logging.getLogger(__name__)


def run_silver(settings: Settings | None = None, *, trigger_mode: str | None = None) -> None:
    """Build a SparkSession, start Bronze-to-Silver queries, block until they finish."""
    cfg = settings or get_settings()
    spark = build_spark_session(cfg, app_name="riskrank-silver")
    spark.sparkContext.setLogLevel("WARN")

    log.info(
        "starting Bronze-to-Silver (trigger=%s)",
        trigger_mode or cfg.spark.streaming_trigger,
    )
    queries = start_bronze_to_silver(spark, cfg, trigger_mode=trigger_mode)

    try:
        for q in queries:
            q.awaitTermination()
    finally:
        spark.stop()

    log.info("all Bronze-to-Silver queries finished")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bronze -> Silver Spark pipeline")
    parser.add_argument("--trigger", default=None, help="availableNow (default) or processingTime")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    run_silver(trigger_mode=args.trigger)


if __name__ == "__main__":
    main()
