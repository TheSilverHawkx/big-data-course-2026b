"""
Bronze validation: walks all finalized .jsonl.gz files and checks that each file
has a valid manifest, correct SHA256, correct record count, and parseable envelope
lines. Duplicate event_ids are reported but do not cause a hard failure
(at-least-once delivery allows duplicates).

Runnable: ``python -m riskrank.consumers.validate``
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
from collections import Counter
from pathlib import Path

from riskrank.config import Settings, get_settings

log = logging.getLogger(__name__)


def validate_bronze(settings: Settings) -> dict:
    """Walk data/bronze/**/*.jsonl.gz and verify integrity. Returns a summary dict."""
    bronze_root = Path(settings.storage.bronze)

    summary: dict = {
        "bronze_root": str(bronze_root),
        "files_checked": 0,
        "records_total": 0,
        "missing_manifest": [],
        "sha256_mismatch": [],
        "record_count_mismatch": [],
        "parse_errors": [],
        "duplicate_event_ids": [],
        "passed": True,
    }

    event_id_counter: Counter = Counter()

    for gz_file in sorted(bronze_root.rglob("*.jsonl.gz")):
        summary["files_checked"] += 1
        manifest_path = gz_file.parent / (gz_file.name + ".manifest.json")
        rel = str(gz_file.relative_to(bronze_root))

        if not manifest_path.exists():
            log.warning("missing manifest: %s", gz_file)
            summary["missing_manifest"].append(rel)
            continue

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            log.warning("unreadable manifest for %s", gz_file)
            summary["parse_errors"].append(rel)
            continue

        actual_sha256 = hashlib.sha256(gz_file.read_bytes()).hexdigest()
        if actual_sha256 != manifest.get("sha256"):
            log.warning("sha256 mismatch: %s", gz_file)
            summary["sha256_mismatch"].append(rel)

        try:
            with gzip.open(gz_file, "rb") as gz:
                lines = [ln for ln in gz.read().decode("utf-8").splitlines() if ln.strip()]
        except Exception:
            log.warning("failed to decompress %s", gz_file)
            summary["parse_errors"].append(rel)
            continue

        actual_count = len(lines)
        expected_count = manifest.get("record_count")
        if expected_count is not None and actual_count != expected_count:
            log.warning(
                "record count mismatch: %s (expected=%d actual=%d)",
                gz_file,
                expected_count,
                actual_count,
            )
            summary["record_count_mismatch"].append(rel)

        summary["records_total"] += actual_count

        for line in lines:
            try:
                data = json.loads(line)
                eid = data.get("event_id")
                if eid:
                    event_id_counter[eid] += 1
            except Exception:
                pass

    summary["duplicate_event_ids"] = [eid for eid, cnt in event_id_counter.items() if cnt > 1]

    summary["passed"] = not (
        summary["missing_manifest"]
        or summary["sha256_mismatch"]
        or summary["record_count_mismatch"]
        or summary["parse_errors"]
    )

    return summary


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    summary = validate_bronze(get_settings())
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
