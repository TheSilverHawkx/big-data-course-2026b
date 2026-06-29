"""
Atomic-rename batch writer for Bronze .jsonl.gz files.

Write flow:
  1. Accumulate EventEnvelope records in memory.
  2. When a flush condition is met, write a gzip JSONL file to data/tmp/.
  3. Rename atomically into the Bronze partition path.
  4. Write a manifest JSON alongside the Bronze file.
  5. Return FlushResult so the caller can commit Kafka offsets.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from riskrank.common.dates import utcnow
from riskrank.config import ConsumerConfig
from riskrank.contracts.envelope import EventEnvelope
from riskrank.paths import ProjectPaths

log = logging.getLogger(__name__)


@dataclass
class FlushResult:
    path: Path
    manifest_path: Path
    source: str
    record_count: int
    sha256: str
    created_at: str
    offset_infos: list[Any] = field(default_factory=list)


class BatchWriter:
    """
    Accumulates EventEnvelopes and flushes them to gzip JSONL Bronze files.

    Flush is triggered automatically when:
    - record count >= max_records_per_file
    - uncompressed byte estimate >= max_uncompressed_bytes_per_file
    - should_flush_on_timer() is True and the caller calls flush()
    - close() is called (final flush)
    """

    def __init__(
        self,
        source: str,
        run_id: str,
        paths: ProjectPaths,
        config: ConsumerConfig,
        *,
        ingest_date: str | None = None,
    ) -> None:
        self._source = source
        self._run_id = run_id
        self._paths = paths
        self._config = config
        self._ingest_date = ingest_date or utcnow().date().isoformat()
        self._lines: list[bytes] = []
        self._offset_infos: list[Any] = []
        self._uncompressed_bytes = 0
        self._last_flush_mono = time.monotonic()
        self._seq = 0

    @property
    def record_count(self) -> int:
        return len(self._lines)

    def add(self, envelope: EventEnvelope, offset_info: Any = None) -> FlushResult | None:
        """Buffer one envelope. Returns FlushResult if this triggered a flush, else None."""
        line = (envelope.model_dump_json() + "\n").encode("utf-8")
        self._lines.append(line)
        self._offset_infos.append(offset_info)
        self._uncompressed_bytes += len(line)

        if (
            len(self._lines) >= self._config.max_records_per_file
            or self._uncompressed_bytes >= self._config.max_uncompressed_bytes_per_file
        ):
            return self.flush()
        return None

    def should_flush_on_timer(self) -> bool:
        """True when there is buffered data and the flush interval has elapsed."""
        return bool(self._lines) and (
            time.monotonic() - self._last_flush_mono >= self._config.flush_interval_seconds
        )

    def flush(self) -> FlushResult | None:
        """Flush the current buffer to a Bronze file. Returns None if the buffer is empty."""
        if not self._lines:
            self._last_flush_mono = time.monotonic()
            return None
        lines, offsets = self._lines, self._offset_infos
        self._lines = []
        self._offset_infos = []
        self._uncompressed_bytes = 0
        self._last_flush_mono = time.monotonic()
        self._seq += 1
        return self._write_atomic(lines, offsets)

    def close(self) -> FlushResult | None:
        """Final flush. Idempotent when the buffer is already empty."""
        return self.flush()

    # ── internal ────────────────────────────────────────────────────────────────

    def _write_atomic(self, lines: list[bytes], offset_infos: list[Any]) -> FlushResult:
        timestamp_ms = int(time.time() * 1000)
        filename = f"part-{timestamp_ms}-{self._seq:04d}.jsonl.gz"

        tmp_dir = self._paths.temp
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = tmp_dir / (filename + ".tmp")

        with gzip.open(tmp_path, "wb") as gz:
            for line in lines:
                gz.write(line)

        bronze_dir = (
            self._paths.bronze_for(self._source)
            / f"ingest_date={self._ingest_date}"
            / f"run_id={self._run_id}"
        )
        bronze_dir.mkdir(parents=True, exist_ok=True)
        target = bronze_dir / filename
        tmp_path.replace(target)

        sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
        created_at = utcnow().isoformat()

        kafka_offsets = []
        for oi in offset_infos:
            if oi is not None and hasattr(oi, "offset") and callable(oi.offset):
                try:
                    kafka_offsets.append(oi.offset())
                except Exception:
                    pass
        first_offset = min(kafka_offsets) if kafka_offsets else None
        last_offset = max(kafka_offsets) if kafka_offsets else None

        manifest_path = target.parent / (target.name + ".manifest.json")
        manifest_path.write_text(
            json.dumps(
                {
                    "path": str(target),
                    "source": self._source,
                    "first_offset": first_offset,
                    "last_offset": last_offset,
                    "record_count": len(lines),
                    "sha256": sha256,
                    "created_at": created_at,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        log.info("bronze file finalized: %s (%d records)", target.name, len(lines))
        return FlushResult(
            path=target,
            manifest_path=manifest_path,
            source=self._source,
            record_count=len(lines),
            sha256=sha256,
            created_at=created_at,
            offset_infos=offset_infos,
        )
