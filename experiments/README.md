# Finding-correlation research lab

This isolated experiment compares the rule baseline, a train-split-only
gradient-boosted classifier, and optionally configured General LLM and
TypeSafe Jev APIs. It never fills in unavailable results: missing API keys or
failed API calls are recorded as `NOT RUN`.

## Install and run

From the repository root:

```powershell
python -m pip install -r experiments/requirements.txt
python -m experiments.run --config experiments/config.yaml
```

The dashboard automatically writes SQLite findings to
`experiments/data/real_findings.csv` after each completed or imported scan and
generates `experiments/data/real_candidate_pairs.csv`. Review those candidate
pairs in the Research Lab page, assign labels and asset-grouped train/test
splits, and save them; the reviewed rows are written to
`experiments/data/real_labeled_pairs.csv`. The command validates both files
first and refuses to run until they are complete. Do not change the validation
rules to accommodate bad input.

Results are written only below `experiments/results/`:

- `validation.json` — validation errors, warnings, and provenance.
- `metrics.json` — test-only metrics, bootstrap intervals, confusion matrices,
  class-count warnings, and McNemar p-values.
- `results.csv` — per-pair predictions and latency.
- `run_manifest.json` — SHA-256 input hashes, seed, config, versions, and time.
- `raw_runs/*.jsonl` — one raw response record per method/pair.

Configure API endpoints and model names in `experiments/config.yaml`; API keys
are read only from the configured environment variable names. The dashboard
route is the existing **Research Lab** navigation item (`/research`) when the
backend and frontend are running. Its **Run comparison** button invokes the
same configured command and shows validation, `RUN`/`NOT RUN` status, metrics,
matrices, errors, provenance, and exports.

The older `synthetic_findings.csv` and `synthetic_labeled_pairs.csv` files are
kept as fixtures for tests and demonstrations. They are marked
`SYNTHETIC_EXAMPLE_NOT_EMPIRICAL`; the UI displays a `SYNTHETIC / MIXED
PROVENANCE` banner when they are used. The app-generated research dataset uses
`REAL_SCAN` provenance for scan-derived rows, but labels still require human
review before a run.

## Tests

```powershell
python -m pytest experiments/tests -q
```
