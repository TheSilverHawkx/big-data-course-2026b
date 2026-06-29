# Limitations & caveats

- **AdjustedRisk is a project-defined prioritisation score**, not an absolute measure
  of organisational risk. It blends three signals on a 0–10 scale; the weights are
  fit on a validation set and will drift as the data window changes.
- **Historical approximation**: NVD Silver keeps the *latest* record per CVE, so CVSS
  features for a past observation date use today's CVSS vector, not the vector as it
  was on that date. EPSS features are point-in-time correct (`score_date ≤ observation_date`).
- **KEV is rare**: positive `kev_within_90_days` labels are a small fraction of rows.
  Use a wide enough history (`--lookback-days`) for EPSS so each split has enough
  positives (the split builder enforces a minimum and will error otherwise).
- **Single-vector demo** requires a CVSS base score input; RiskRank does not recompute
  the base score from the vector string. Other numeric features default to 0, so demo
  numbers are illustrative.
- **Right-censoring** removes the most recent ~90 days of observations because their
  future KEV outcome is not yet known.
