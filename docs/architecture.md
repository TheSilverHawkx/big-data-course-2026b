# Architecture

## Data flow

```
Local OSV corpus ─┐   OSV→NVD adapter
(data/raw_osv/)   │
EPSS daily CSV   ─┼─▶ producers ─▶ Kafka (KRaft) ─▶ file-sink ─▶ Bronze (.jsonl.gz)
CISA KEV JSON    ─┘    make_envelope    risk.raw.*     consumer     source/ingest_date/run_id
```

- **CVE source**: a directory of per-CVE OSV documents on disk (`nvd.input_dir`), not
  the NVD REST API. `producers/osv_adapter.py` reshapes each document into the NVD API
  2.0 `cve` object and `common/cvss.py` recomputes the base/exploitability/impact scores
  from the vector string, so the Bronze payload contract is unchanged and the source
  name stays `nvd` throughout Kafka, Bronze and Silver.

- **Kafka**: single-node KRaft broker (`apache/kafka:4.1.2`), no ZooKeeper.
  Topics: `risk.raw.nvd`, `risk.raw.epss`, `risk.raw.kev` (3 partitions each),
  `risk.dlq` (1 partition).
- **Envelope**: every message is a deterministic `EventEnvelope`. The `event_id`
  is `sha256("{source}|{source_record_id}|{effective_date}|{payload_sha256}")`, so
  re-fetching unchanged data is idempotent.
- **Bronze**: append-only gzip JSONL, one envelope per line, partitioned by
  `source=/ingest_date=/run_id=`, each file with a `.manifest.json` (record count + sha256).

## Bronze → Silver (PySpark Structured Streaming)

`foreachBatch` applies one normalizer per source. Schemas are **explicit** (inference
disabled). The NVD normalizer selects the best CVSS metric (Primary > Secondary;
v4.0 > v3.1 > v3.0 > v2.0), preserves the `cvss_vector` string, and decodes the eight
components (AV/AC/PR/UI/S/C/I/A) plus base/exploitability/impact scores into columns.

Silver tables: `nvd_vulnerabilities`, `epss_daily`, `kev_catalog`.

## Silver → Gold (time-aware learning dataset)

Grain: one row per `(cve_id, observation_date)`.

1. Spine = distinct `(cve_id, observation_date)` from EPSS daily.
2. Inner-join NVD (require `published_at ≤ observation_date`).
3. Exclude CVEs already in KEV on/before the observation date.
4. Right-censor: drop `observation_date > label_as_of_date − 90` (incomplete window).
5. Features: NVD CVSS columns + EPSS temporal features (lags 1/7/30d, rolling
   mean/max/min/std over 7d & 30d, OLS slope) using only `score_date ≤ observation_date`.
6. Labels: `kev_within_{7,30,90}_days` (90 is primary). Tri-state — already-KEV → excluded.

## Models (Spark MLlib)

- **Model A** `GBTRegressor`: CVSS vector → predicted EPSS (`P(exploit)`).
- **Model B** `GBTClassifier` (balanced weights): CVSS vector + predicted EPSS →
  `P(KEV ≤ 90d)`. Model A scores the val/test splits so Model B never sees observed
  EPSS leakage on evaluation data.
- **AdjustedRisk** = `10 × [w1·CVSS/10 + w2·P(exploit) + w3·P(KEV)]`. Weights are grid
  searched on validation (sum = 1) to maximise PR-AUC against the 90-day KEV label,
  then reported on test against the CVSS-only baseline.
