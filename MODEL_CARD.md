# BaitDetector Model Card

## Intended Use
BaitDetector is a phishing-first URL risk scorer for triage, demonstrations, and lightweight analyst support. It is designed to explain suspicious URL patterns and combine them with local feed context.

## Inputs
- One HTTP or HTTPS URL

## Outputs
- Phishing probability
- Verdict: `benign`, `suspicious`, or `phishing`
- Risk band: `low`, `medium`, or `high`
- Top feature contributions
- Local intel hits

## Training Data
- Positive class: Phishing.Database and PhishTank
- Benign class: Tranco
- Bundled repo artifact: synthetic demo dataset in `data/demo/demo_training.csv`

## Model Shape
- FeatureUnion of:
  - lexical URL features
  - character-level TF-IDF n-grams
- Fixed linear challenger set:
  - baseline logistic regression
  - sparse L1 logistic regression
  - SGD log-loss classifier
- Optional sigmoid calibration when the validation set is large enough

## Strengths
- Transparent feature-level explanations
- Lightweight runtime footprint
- Open-data-friendly pipeline
- Safe default behavior that does not fetch URLs during normal scans
- Shared benchmark comparison against the currently promoted model

## Limitations
- URL-only features miss page-content and infrastructure signals because external enrichment is not part of the current version
- Brand-new campaigns may score as uncertain instead of clearly malicious
- Benign URLs with words like `login` or `verify` can still create false positives
- The repo-shipped model is for bootstrap/demo use, not production-grade enterprise detection
- Bootstrap fallback mode trains from a single dataset but intentionally skips automatic promotion

## Evaluation Gates
- Challenger selection uses a temporal validation + benchmark split when at least 3 historical snapshots exist
- Candidate PR-AUC must not regress on the shared benchmark
- Candidate ROC-AUC must not regress on the shared benchmark
- Benign false-positive rate must not worsen on the shared benchmark
- Runtime phishing and suspicious thresholds are stored in metadata and reused unchanged by the API

## Privacy
- Standard scans remain local
- Raw submitted URLs are not stored in the metrics table
