from __future__ import annotations

import json
import re

from fastapi.testclient import TestClient

from baitdetector.app import create_app

from .support import build_test_settings, seed_promoted_bundle, write_demo_snapshots


def test_api_scan_and_model_info(tmp_path) -> None:
    settings = build_test_settings(tmp_path)
    seed_promoted_bundle(settings)
    app = create_app(settings)

    with TestClient(app) as client:
        model_info = client.get("/api/model-info")
        scan = client.post("/api/scan", json={"url": "https://secure-paypa1-alert.xyz/login", "deep_scan": False})

        assert model_info.status_code == 200
        assert scan.status_code == 200

        model_payload = model_info.json()
        assert model_payload["model_id"] == "logistic_baseline"
        assert model_payload["model_family"] == "logistic_regression"
        assert model_payload["evaluation_mode"] == "bootstrap_fallback"
        assert model_payload["runtime_thresholds"] == {"suspicious": 0.02, "phishing": 0.08}

        payload = scan.json()
        assert payload["verdict"] in {"phishing", "suspicious"}
        assert payload["reasons"]


def test_model_details_exposes_signal_maps_and_optional_leaderboard(tmp_path) -> None:
    settings = build_test_settings(tmp_path)
    seed_promoted_bundle(settings)
    (settings.model_dir / "leaderboard.json").write_text(
        json.dumps(
            [
                {
                    "model_id": "logistic_baseline",
                    "model_family": "logistic_regression",
                    "rank": 1,
                    "promotion_outcome": "promoted_candidate",
                    "benchmark_metrics": {"pr_auc": 0.91, "roc_auc": 0.95, "false_positive_rate": 0.04},
                }
            ]
        ),
        encoding="utf-8",
    )
    (settings.model_dir / "training_summary.json").write_text(
        json.dumps(
            {
                "promotion": {"recommended": True, "reason": "shared_benchmark_win"},
                "feature_correlation": {
                    "rows": 24,
                    "source": "training_corpus",
                    "features": [
                        {"key": "lexical__url_length", "name": "url_length", "label": "Unusually long URL"},
                        {"key": "lexical__num_digits", "name": "num_digits", "label": "Heavy use of digits"},
                    ],
                    "matrix": [[1.0, 0.42], [0.42, 1.0]],
                },
            }
        ),
        encoding="utf-8",
    )
    app = create_app(settings)

    with TestClient(app) as client:
        response = client.get("/api/model-details")

        assert response.status_code == 200
        payload = response.json()
        assert payload["feature_correlation"]["rows"] == 24
        assert payload["feature_correlation"]["matrix"][0][1] == 0.42
        assert payload["top_phishing_signals"]
        assert payload["top_protective_signals"]
        assert payload["signal_map"]
        assert payload["leaderboard"][0]["model_id"] == "logistic_baseline"
        assert payload["promotion"]["reason"] == "shared_benchmark_win"


def test_model_details_falls_back_to_latest_snapshot_when_promoted_summary_is_missing(tmp_path) -> None:
    settings = build_test_settings(tmp_path)
    seed_promoted_bundle(settings)
    write_demo_snapshots(settings)
    app = create_app(settings)

    with TestClient(app) as client:
        response = client.get("/api/model-details")

        assert response.status_code == 200
        payload = response.json()
        assert payload["feature_correlation"]["source"] == "latest_snapshot_fallback"
        assert payload["feature_correlation"]["rows"] > 0
        assert payload["leaderboard"] == []
        assert payload["promotion"] is None


def test_home_renders_idle_stitch_stage(tmp_path) -> None:
    settings = build_test_settings(tmp_path)
    seed_promoted_bundle(settings)
    app = create_app(settings)

    with TestClient(app) as client:
        response = client.get("/")
        video = client.get("/media/background-loop.webm")
        assert response.status_code == 200
        assert video.status_code == 200
        assert '<div id="root"></div>' in response.text
        assert "/assets/" in response.text


def test_api_rejects_invalid_url_and_rate_limits(tmp_path) -> None:
    settings = build_test_settings(tmp_path, rate_limit_requests=3)
    seed_promoted_bundle(settings)
    app = create_app(settings)

    with TestClient(app) as client:
        invalid = client.post("/api/scan", json={"url": "ftp://example.com"})
        malformed = client.post("/api/scan", json={"url": "https//www.google.com"})
        first = client.post("/api/scan", json={"url": "https://github.com"})
        second = client.post("/api/scan", json={"url": "https://openai.com"})

        assert invalid.status_code == 422
        assert malformed.status_code == 422
        assert first.status_code == 200
        assert second.status_code == 429


def test_home_serves_built_asset_and_client_routes(tmp_path) -> None:
    settings = build_test_settings(tmp_path)
    seed_promoted_bundle(settings)
    app = create_app(settings)

    with TestClient(app) as client:
        response = client.get("/")
        asset_match = re.search(r'/(assets/[^"\']+\.(?:js|css))', response.text)
        asset_path = asset_match.group(1) if asset_match else None
        nested = client.get("/analysis/session")

        assert asset_path is not None
        asset = client.get(asset_path)
        assert asset.status_code == 200
        assert nested.status_code == 200
        assert '<div id="root"></div>' in nested.text


def test_missing_spa_asset_returns_not_found(tmp_path) -> None:
    settings = build_test_settings(tmp_path)
    seed_promoted_bundle(settings)
    app = create_app(settings)

    with TestClient(app) as client:
        response = client.get("/assets/does-not-exist.js")

        assert response.status_code == 404
