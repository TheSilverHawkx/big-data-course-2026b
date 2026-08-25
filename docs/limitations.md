# Limitations & caveats

- **AdjustedRisk is a project-defined prioritisation score**, not an absolute measure
  of organisational risk. It blends three signals on a 0–10 scale; the weights are
  fit on a validation set and will drift as the data window changes.
- **Historical approximation**: NVD Silver keeps the *latest* record per CVE, so CVSS
  features for a past observation date use today's CVSS vector, not the vector as it
  was on that date. EPSS features are point-in-time correct (`score_date ≤ observation_date`).
- **KEV is rare**: positive `kev_within_90_days` labels are a small fraction of rows.
  Use a wide enough history (`--lookback-days`) for EPSS so each split has enough
  positives (the split builder enforces a minimum and will error otherwise). The
  ceiling is the KEV catalog itself — 1,630 entries total, ~190-250 added per year —
  so the number of *distinct* positive CVEs is set by the span of the window, not by
  how densely it is sampled.
- **EPSS is sampled, not daily.** `make produce-epss` pulls three years on the 1st and
  15th of each month (~72 score dates). The upstream mirror publishes daily, but
  adjacent days are near-identical: the same span at daily cadence is ~1,100 files and
  ~317M rows (~76 GB through Silver) for no additional distinct positives. Consequence:
  `days_since_*` and EPSS delta features have a resolution of ~15 days, and a CVE whose
  score spikes and decays between the 1st and the 15th is invisible. Override with
  `--days-of-month` (omit it for every day in range).
- **Right-censoring is anchored to the last KEV fetch.** `label_as_of_date` is the max
  `fetched_at` in KEV Silver, and observations after `label_as_of_date - 90d` are
  dropped. A stale KEV partition therefore silently discards the most recent ~3 months
  of otherwise-usable observations — re-run `make produce-kev` before `make gold`.
- **Missing EPSS files are skipped silently.** The producer runs with `strict=False`, so
  an unavailable daily file increments `skipped` and logs a warning rather than failing.
  A wrong date range degrades the dataset quietly; check `skipped` in the run summary.
- **CVSS scores are recomputed, not sourced.** The OSV corpus carries vector strings
  only, so `riskrank.common.cvss` derives `baseScore`/`baseSeverity` (exact, via the
  `cvss` reference library) at ingest time. Two consequences: CVSS **4.0** defines no
  exploitability/impact sub-scores, so those columns are null for the ~14% of CVEs
  scored with v4.0; and `cpe_match_count` now counts CPEs from OSV
  `database_specific.unresolved_ranges` rather than NVD `configurations`, so it is
  present for only ~10% of CVEs and is **not comparable to pre-OSV runs**. `cwe_ids`
  is likewise sparser (~40% of CVEs).
- **AdjustedRisk is a ranking score, not a severity.** It is a weighted average of two
  probabilities that are tiny for almost every CVE (median `P(KEV<=90d)` ~0.03), so the
  raw 0–10 number sits near zero even for a CVSS 9.8 vector — and the tuner regularly
  sets `w1_cvss = 0`, at which point it stops tracking CVSS magnitude entirely. Compare
  AdjustedRisk values *against each other*, never against a CVSS base score. The scorer
  therefore also reports `adjusted_risk_percentile` (and `priority_0_10 = percentile/10`)
  against a reference distribution built on the validation split and stored in
  `data/models/score_percentiles.json`. That percentile is the number to show a reader.
- **`w1_cvss = 0` is expected, not a bug.** `cvss_base_score` is already an input feature
  to *both* GBTs (`models/ml_features.py`), so the w1 term re-adds a variable the models
  have already fit non-linearly. Measured on the 3-year window, forcing w1 up costs
  validation PR-AUC monotonically (−7.6% at w1=0.05, −9.5% at 0.1, −30% at 0.2).
  Normalising the three terms to equal dynamic range does *not* rescue it (0.0048 vs
  0.0061). CVSS still drives the score — through the models, not through w1.
- **Prefer the per-date metrics.** The Gold grain is (cve_id, observation_date), so one
  CVE entering KEV produces a positive row on every observation date in the 90-day
  window — up to six correlated rows at semi-monthly cadence, landing at adjacent ranks.
  Pooled ranking therefore lets a single vulnerability swing PR-AUC by 2x. `evaluate.py`
  exposes `score_pr_auc_by_date` / `top_k_hit_rate_by_date`, which score each observation
  date independently (every CVE appears once) and macro-average; `training_metrics.json`
  reports these under `test_ranking_by_date`. The pooled `test_ranking` block is kept for
  continuity only.
- **Single-vector demo** still takes the base score as an input argument; other numeric
  features default to 0, so demo numbers are illustrative.
- **Right-censoring** removes the most recent ~90 days of observations because their
  future KEV outcome is not yet known.
