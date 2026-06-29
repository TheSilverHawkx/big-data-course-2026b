"""Resolve and ensure all project storage paths from config."""
from __future__ import annotations

from pathlib import Path

from riskrank.config import Settings, get_settings


class ProjectPaths:
    """Resolves StorageConfig string paths to Path objects."""

    def __init__(self, settings: Settings | None = None) -> None:
        cfg = settings or get_settings()
        s = cfg.storage
        self.root = Path(s.root)
        self.bronze = Path(s.bronze)
        self.silver = Path(s.silver)
        self.gold = Path(s.gold)
        self.checkpoints = Path(s.checkpoints)
        self.models = Path(s.models)
        self.reports = Path(s.reports)
        self.temp = Path(s.temp)

    @property
    def all_paths(self) -> list[Path]:
        return [
            self.root,
            self.bronze,
            self.silver,
            self.gold,
            self.checkpoints,
            self.models,
            self.reports,
            self.temp,
        ]

    def ensure_dirs(self) -> None:
        for path in self.all_paths:
            path.mkdir(parents=True, exist_ok=True)

    def bronze_for(self, source: str) -> Path:
        p = self.bronze / f"source={source}"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def silver_for(self, table: str) -> Path:
        p = self.silver / table
        p.mkdir(parents=True, exist_ok=True)
        return p


def get_paths(settings: Settings | None = None) -> ProjectPaths:
    return ProjectPaths(settings)
