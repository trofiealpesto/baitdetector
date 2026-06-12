from __future__ import annotations

import json

import pandas as pd
from fastapi.testclient import TestClient

from baitdetector.app import create_app
from baitdetector import promote as promote_module
from baitdetector import train as train_module

from tests.support import build_test_settings, normalized_demo_frame, seed_promoted_bundle, write_demo_snapshots


def test_build_temporal_dataset_uses_snapshot_history_and_excludes_holdout_duplicates(tmp_path, monkeypatch) -> None:
    settings = build_test_settings(tmp_path)
    paths = write_demo_snapshots(settings)

    earliest_frame = pd.read_parquet(paths[0])
    benchmark_frame = pd.read_parquet(paths[-1])
    duplicated_url = str(benchmark_frame.iloc[0]["normalized_url"])
    earliest_frame = pd.concat([earliest_frame, benchmark_frame.iloc[[0]]], ignore_index=True)
    earliest_frame.to_parquet(paths[0], index=False)

    monkeypatch.setattr(train_module, "get_settings", lambda: settings)
    dataset = train_module.build_training_dataset()

    assert dataset.evaluation_mode == "temporal_benchmark"
    assert len(dataset.validation_frame) == 18
    assert len(dataset.benchmark_frame) == 18
    assert duplicated_url not in set(dataset.train_frame["normalized_url"])
    assert not dataset.benchmark_unseen_frame.empty
    assert set(dataset.benchmark_unseen_frame["registrable_domain"]).isdisjoint(set(dataset.train_frame["registrable_domain"]))


def test_train_model_temporal_generates_leaderboard_and_shared_benchmark(tmp_path, monkeypatch) -> None:
    settings = build_test_settings(tmp_path)
    write_demo_snapshots(settings)
    seed_promoted_bundle(settings)

    monkeypatch.setattr(train_module, "get_settings", lambda: settings)
    metadata = train_module.train_model()

    leaderboard = json.loads((settings.candidate_model_dir / "leaderboard.json").read_text(encoding="utf-8"))
    summary = json.loads((settings.candidate_model_dir / "training_summary.json").read_text(encoding="utf-8"))

    assert metadata["evaluation_mode"] == "temporal_benchmark"
    assert metadata["validation_window"]["rows"] == 18
    assert metadata["benchmark_window"]["rows"] == 18
    assert len(leaderboard) == 3
    assert summary["feature_correlation"]["rows"] == metadata["training_window"]["rows"]
    assert summary["feature_correlation"]["features"]
    assert summary["feature_correlation"]["matrix"]
    assert all(entry["benchmark_metrics"]["rows"] == metadata["benchmark_window"]["rows"] for entry in leaderboard)
    assert summary["current_promoted_benchmark"]["evaluation"]["rows"] == metadata["benchmark_window"]["rows"]
    assert {entry["model_id"] for entry in leaderboard} == {
        "logistic_baseline",
        "logistic_sparse_l1",
        "sgd_log_loss",
    }


def test_train_model_bootstrap_fallback_with_two_snapshots(tmp_path, monkeypatch) -> None:
    settings = build_test_settings(tmp_path)
    frame = normalized_demo_frame()
    normalized_dir = settings.data_dir / "normalized"
    normalized_dir.mkdir(parents=True, exist_ok=True)

    first = frame.iloc[:27].copy()
    second = frame.iloc[27:].copy()
    first.to_parquet(normalized_dir / "urls-20260115T000000Z.parquet", index=False)
    second.to_parquet(normalized_dir / "urls-20260215T000000Z.parquet", index=False)
    second.to_parquet(normalized_dir / "latest.parquet", index=False)

    monkeypatch.setattr(train_module, "get_settings", lambda: settings)
    metadata = train_module.train_model()

    leaderboard = json.loads((settings.candidate_model_dir / "leaderboard.json").read_text(encoding="utf-8"))
    summary = json.loads((settings.candidate_model_dir / "training_summary.json").read_text(encoding="utf-8"))

    assert metadata["evaluation_mode"] == "bootstrap_fallback"
    assert metadata["benchmark_window"]["rows"] == 0
    assert len(leaderboard) == 1
    assert summary["feature_correlation"]["rows"] == metadata["training_window"]["rows"]
    assert summary["feature_correlation"]["features"]
    assert leaderboard[0]["promotion_outcome"] == "bootstrap_fallback_requires_manual_review"
    assert summary["promotion"]["recommended"] is False


def test_passes_shared_benchmark_gates_allows_small_regression() -> None:
    current = {"pr_auc": 0.94, "roc_auc": 0.73, "false_positive_rate": 0.25}
    near_candidate = {"pr_auc": 0.935, "roc_auc": 0.725, "false_positive_rate": 0.255}
    far_candidate = {"pr_auc": 0.92, "roc_auc": 0.73, "false_positive_rate": 0.25}

    assert train_module.passes_shared_benchmark_gates(near_candidate, current) is True
    assert train_module.passes_shared_benchmark_gates(far_candidate, current) is False


def test_temporal_training_promote_and_api_scan_end_to_end(tmp_path, monkeypatch) -> None:
    settings = build_test_settings(tmp_path)
    write_demo_snapshots(settings)

    monkeypatch.setattr(train_module, "get_settings", lambda: settings)
    monkeypatch.setattr(promote_module, "get_settings", lambda: settings)

    train_module.train_model()
    assert promote_module.promote() is True
    assert (settings.model_dir / "leaderboard.json").exists()
    assert (settings.model_dir / "training_summary.json").exists()

    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post("/api/scan", json={"url": "https://secure-paypa1-alert.xyz/login", "deep_scan": False})
        assert response.status_code == 200
        payload = response.json()
        assert {
            "normalized_url",
            "verdict",
            "phishing_probability",
            "risk_band",
            "reasons",
            "intel_hits",
            "model_version",
            "scanned_at",
            "deep_scan_status",
        }.issubset(payload.keys())
