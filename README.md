# RiskRank

A big-data pipeline that predicts a **risk score** for software vulnerabilities by
combining the **CVSS** vector, the **EPSS** exploitation-probability score, and the
**CISA KEV** known-exploited catalog.

```
Python producers ──▶ Kafka topics ──▶ File-sink consumer ──▶ Bronze (.jsonl.gz)
  CVE / EPSS / KEV     risk.raw.*          validate envelope        append-only
  (local OSV corpus)

Bronze ──▶ PySpark Structured Streaming ──▶ Silver (Parquet)
                normalize + decode CVSS         nvd / epss_daily / kev_catalog

Silver ──▶ Gold (one row per CVE per date) ──▶ Spark MLlib
            time-aware features + 90d KEV label   Model A + Model B + AdjustedRisk
```

## Models

- **Baseline 0** — CVSS only: `priority = cvss_base_score`.
- **Model A (regression)** — CVSS vector → predicted EPSS = `P(exploit)`.
- **Model B (classification)** — CVSS vector + predicted EPSS → `P(KEV ≤ 90 days)`.
- **AdjustedRisk** — `10 × [w1·CVSS/10 + w2·P(exploit) + w3·P(KEV)]`, with
  `w1/w2/w3` tuned on the validation split.

Splits are **chronological** (train on older dates, validate/test on newer) to
avoid leakage; EPSS temporal features use only data with `score_date ≤ observation_date`.

## Quickstart

```bash
# 1. Install (local dev)
uv sync --all-extras

# 2. Bring up Kafka + UI + service containers, then create topics
make up
make topics                       # http://localhost:8080  (Kafka UI)

# 3. Ingest — CVE records come from the local OSV corpus in data/raw_osv/
#    (~81k CVE-YYYY-NNNN.json files; see "CVE input" below). EPSS/KEV are fetched.
make produce-nvd
make produce-epss
make produce-kev
make consume                      # Kafka -> Bronze
make validate

# 4. Transform + train
make silver                       # Bronze -> Silver
make gold                         # Silver -> Gold (time-aware dataset)
make train                        # Model A + Model B + weight tuning

# 5. Score a single CVSS vector (the demo)
make score VECTOR="CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N" BASE=7.0
```

All commands are plain entrypoints, e.g. `python -m riskrank.producers.nvd --help`.

## CVE input

CVE records are **read from disk, not the NVD API**. Drop a directory of per-CVE
[OSV](https://ossf.github.io/osv-schema/) documents (`CVE-YYYY-NNNN.json`, one JSON
object per file) at `data/raw_osv/` — the path is `nvd.input_dir` in
`config/default.yaml`, overridable with `NVD__INPUT_DIR`.

`riskrank.producers.osv_adapter` translates each document into the NVD API 2.0 `cve`
payload shape, so Bronze/Silver/Gold are unchanged. OSV ships CVSS **vector strings
only**, so `riskrank.common.cvss` recomputes `baseScore`, `baseSeverity` and the
exploitability/impact sub-scores (exact for CVSS 2.0/3.x/4.0, via the `cvss` library).
Withdrawn and `** REJECT **` records are dropped, matching the old API's `noRejected`.

## Layout

| Path | Purpose |
|------|---------|
| `src/riskrank/producers/` | CVE (local OSV) / EPSS / KEV producers → Kafka |
| `src/riskrank/consumers/` | File-sink consumer → Bronze `.jsonl.gz` |
| `src/riskrank/spark/`     | Bronze→Silver normalizers, Silver→Gold features/labels |
| `src/riskrank/models/`    | Model A, Model B, AdjustedRisk scoring, evaluation |
| `config/default.yaml`     | All settings (Kafka, Spark, sources, model, risk weights) |
| `data/raw_osv/`           | Input corpus: per-CVE OSV JSON files (gitignored) |
| `data/`                   | Bronze/Silver/Gold/models/reports (gitignored) |

See `docs/architecture.md` for details and `docs/limitations.md` for caveats.
