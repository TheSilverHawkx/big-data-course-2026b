# RiskRank

A big-data pipeline that predicts a **risk score** for software vulnerabilities by
combining the **CVSS** vector, the **EPSS** exploitation-probability score, and the
**CISA KEV** known-exploited catalog.

```
Python producers ──▶ Kafka topics ──▶ File-sink consumer ──▶ Bronze (.jsonl.gz)
  NVD / EPSS / KEV     risk.raw.*          validate envelope        append-only

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

# 3. Ingest (NVD key already read from .env)
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

## Layout

| Path | Purpose |
|------|---------|
| `src/riskrank/producers/` | NVD / EPSS / KEV producers → Kafka |
| `src/riskrank/consumers/` | File-sink consumer → Bronze `.jsonl.gz` |
| `src/riskrank/spark/`     | Bronze→Silver normalizers, Silver→Gold features/labels |
| `src/riskrank/models/`    | Model A, Model B, AdjustedRisk scoring, evaluation |
| `config/default.yaml`     | All settings (Kafka, Spark, sources, model, risk weights) |
| `data/`                   | Bronze/Silver/Gold/models/reports (gitignored) |

See `docs/architecture.md` for details and `docs/limitations.md` for caveats.
