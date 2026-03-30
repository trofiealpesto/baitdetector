from __future__ import annotations

from pathlib import Path

import pandas as pd

from baitdetector.features import FEATURE_SET_VERSION, build_lookup_context
from baitdetector.ingest import normalize_rows
from baitdetector.modeling import fit_bundle, save_model_bundle
from baitdetector.settings import Settings
from baitdetector.train import frame_window, split_frame


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_test_settings(tmp_path, rate_limit_requests: int = 10) -> Settings:
    data_dir = tmp_path / "data"
    model_dir = data_dir / "models" / "promoted"
    candidate_model_dir = data_dir / "models" / "candidate"
    data_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        project_root=PROJECT_ROOT,
        data_dir=data_dir,
        model_dir=model_dir,
        candidate_model_dir=candidate_model_dir,
        demo_data_path=PROJECT_ROOT / "data" / "demo" / "demo_training.csv",
        database_url=f"sqlite:///{(data_dir / 'baitdetector.db').resolve()}",
        rate_limit_requests=rate_limit_requests,
        rate_limit_window_seconds=60,
        phishstats_api_url=None,
        phishstats_api_key=None,
        urlscan_api_url="https://urlscan.io/api/v1/scan/",
        urlscan_api_key=None,
        phishtank_app_key=None,
        templates_dir=PROJECT_ROOT / "src" / "baitdetector" / "templates",
        source_user_agent="baitdetector-tests",
        request_timeout_seconds=5,
    )


def normalized_demo_frame() -> pd.DataFrame:
    frame = pd.read_csv(PROJECT_ROOT / "data" / "demo" / "demo_training.csv")
    frame = normalize_rows(frame.to_dict(orient="records"))
    frame["observed_at"] = pd.to_datetime(frame["observed_at"], utc=True)
    return frame.sort_values("observed_at").reset_index(drop=True)


def seed_promoted_bundle(
    settings: Settings,
    *,
    runtime_thresholds: dict[str, float] | None = None,
    evaluation_overrides: dict[str, float] | None = None,
    metadata_overrides: dict[str, object] | None = None,
) -> None:
    runtime_thresholds = runtime_thresholds or {"suspicious": 0.02, "phishing": 0.08}
    evaluation_overrides = evaluation_overrides or {}
    metadata_overrides = metadata_overrides or {}

    frame = normalized_demo_frame()
    train_frame, validation_frame = split_frame(frame)
    tranco_ranks, malicious_last_seen = build_lookup_context(train_frame.to_dict(orient="records"))

    metadata = {
        "model_version": "test-model",
        "model_id": "logistic_baseline",
        "model_family": "logistic_regression",
        "training_window": frame_window(train_frame),
        "validation_window": frame_window(validation_frame),
        "benchmark_window": {},
        "feature_set_version": FEATURE_SET_VERSION,
        "evaluation_mode": "bootstrap_fallback",
        "evaluation": {
            "pr_auc": 0.9,
            "roc_auc": 0.9,
            "false_positive_rate": 0.1,
            "decision_threshold": runtime_thresholds["phishing"],
            "runtime_thresholds": runtime_thresholds,
        },
        "runtime_thresholds": runtime_thresholds,
        "source_freshness": {"demo": frame["observed_at"].max().isoformat()},
    }
    metadata["evaluation"].update(evaluation_overrides)
    metadata.update(metadata_overrides)

    bundle = fit_bundle(
        train_urls=train_frame["normalized_url"].tolist(),
        train_labels=train_frame["label"].astype(int).tolist(),
        tranco_ranks=tranco_ranks,
        malicious_last_seen=malicious_last_seen,
        metadata=metadata,
    )
    save_model_bundle(bundle, settings.model_dir)


def write_demo_snapshots(settings: Settings) -> list[Path]:
    frame = normalized_demo_frame()
    chunks = [frame.iloc[:18].copy(), frame.iloc[18:36].copy(), frame.iloc[36:].copy()]
    normalized_dir = settings.data_dir / "normalized"
    normalized_dir.mkdir(parents=True, exist_ok=True)
    run_ids = ["20260115T000000Z", "20260215T000000Z", "20260315T000000Z"]
    paths: list[Path] = []
    for run_id, chunk in zip(run_ids, chunks, strict=True):
        path = normalized_dir / f"urls-{run_id}.parquet"
        chunk.to_parquet(path, index=False)
        paths.append(path)
    chunks[-1].to_parquet(normalized_dir / "latest.parquet", index=False)
    return paths
