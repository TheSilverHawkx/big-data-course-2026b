"""
Application configuration loaded from YAML + environment variables.

Precedence (highest to lowest):
    environment variables  >  YAML file  >  code defaults

The YAML file path is read from the RISKRANK_CONFIG env var, defaulting to
``config/default.yaml`` at the repository root. Nested env vars use the ``__``
delimiter, e.g. ``KAFKA__BOOTSTRAP_SERVERS=localhost:9092``.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

# ── Sub-models (one per YAML section) ─────────────────────────────────────────


class ProjectConfig(BaseModel):
    name: str = "riskrank"
    timezone: str = "UTC"


class HistoryConfig(BaseModel):
    default_lookback_days: int = 180
    prediction_horizon_days: int = 90


class KafkaTopicsConfig(BaseModel):
    nvd: str = "risk.raw.nvd"
    epss: str = "risk.raw.epss"
    kev: str = "risk.raw.kev"
    dlq: str = "risk.dlq"


class KafkaConfig(BaseModel):
    bootstrap_servers: str = "kafka:9092"
    client_id: str = "riskrank"
    consumer_group: str = "riskrank-file-sink-v1"
    topics: KafkaTopicsConfig = Field(default_factory=KafkaTopicsConfig)
    partitions: int = 3
    replication_factor: int = 1


class ConsumerConfig(BaseModel):
    max_records_per_file: int = 10_000
    max_uncompressed_bytes_per_file: int = 67_108_864  # 64 MiB
    flush_interval_seconds: int = 30
    idle_exit_seconds: int = 30


class StorageConfig(BaseModel):
    root: str = "/app/data"
    bronze: str = "/app/data/bronze"
    silver: str = "/app/data/silver"
    gold: str = "/app/data/gold"
    checkpoints: str = "/app/data/checkpoints"
    models: str = "/app/data/models"
    reports: str = "/app/data/reports"
    temp: str = "/app/data/tmp"


class SparkConfig(BaseModel):
    master: str = "local[8]"
    driver_memory: str = "8g"
    shuffle_partitions: int = 32
    default_parallelism: int = 16
    streaming_trigger: str = "availableNow"
    processing_time_seconds: int = 10


class NvdConfig(BaseModel):
    """CVE input. The corpus is read from disk (OSV format), not the NVD API."""

    input_dir: str = "/app/data/raw_osv"
    file_glob: str = "*.json"


class KevConfig(BaseModel):
    catalog_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    ingest_full_catalog: bool = True


class EpssConfig(BaseModel):
    raw_url_template: str = (
        "https://raw.githubusercontent.com/empiricalsec/epss_scores/main"
        "/{year}/epss_scores-{date}.csv.gz"
    )


class ModelConfig(BaseModel):
    primary_metric: str = "area_under_pr"
    ranking_k: int = 100
    train_ratio: float = 0.60
    validation_ratio: float = 0.20
    test_ratio: float = 0.20
    class_weighting: str = "balanced"
    random_seed: int = 42
    kev_horizon_days: int = 90


class RiskThresholdsConfig(BaseModel):
    low_max: int = 25
    medium_max: int = 50
    high_max: int = 75


class RiskScoreConfig(BaseModel):
    """Default / fallback weights for the AdjustedRisk blend; tuned on validation."""

    cvss_weight: float = 0.20      # w1, applied to cvss_base_score / 10
    exploit_weight: float = 0.30   # w2, applied to Model A predicted EPSS
    kev_weight: float = 0.50       # w3, applied to Model B P(KEV<=90d)
    thresholds: RiskThresholdsConfig = Field(default_factory=RiskThresholdsConfig)


# ── Custom YAML settings source ────────────────────────────────────────────────


class YamlConfigSettingsSource(PydanticBaseSettingsSource):
    """Reads config from the YAML file at the RISKRANK_CONFIG env var."""

    def __call__(self) -> dict[str, Any]:
        config_path = os.environ.get("RISKRANK_CONFIG")
        if config_path is None:
            project_root = Path(__file__).parent.parent.parent
            config_path = str(project_root / "config" / "default.yaml")
        path = Path(config_path)
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    def field_is_required(self) -> bool:  # type: ignore[override]
        return False

    def get_field_value(self, field: Any, field_name: str) -> Any:  # type: ignore[override]
        return None


# ── Root settings ──────────────────────────────────────────────────────────────


class Settings(BaseSettings):
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    kafka: KafkaConfig = Field(default_factory=KafkaConfig)
    consumer: ConsumerConfig = Field(default_factory=ConsumerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    spark: SparkConfig = Field(default_factory=SparkConfig)
    nvd: NvdConfig = Field(default_factory=NvdConfig)
    kev: KevConfig = Field(default_factory=KevConfig)
    epss: EpssConfig = Field(default_factory=EpssConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    risk_score: RiskScoreConfig = Field(default_factory=RiskScoreConfig)

    # Top-level env vars (not nested in YAML)
    kafka_bootstrap_servers: str | None = Field(default=None, alias="KAFKA_BOOTSTRAP_SERVERS")

    model_config = {  # type: ignore[misc]
        "env_nested_delimiter": "__",
        "case_sensitive": False,
        "populate_by_name": True,
    }

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            YamlConfigSettingsSource(settings_cls),
        )


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
        if _settings.kafka_bootstrap_servers:
            _settings.kafka.bootstrap_servers = _settings.kafka_bootstrap_servers
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
