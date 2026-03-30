from __future__ import annotations

import json

from baitdetector import promote as promote_module

from tests.support import build_test_settings


def _write_candidate_artifacts(settings, metadata: dict, *, include_current: bool = False) -> None:
    settings.candidate_model_dir.mkdir(parents=True, exist_ok=True)
    (settings.candidate_model_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (settings.candidate_model_dir / "training_summary.json").write_text(
        json.dumps({"promotion": metadata.get("promotion", {})}, indent=2),
        encoding="utf-8",
    )
    (settings.candidate_model_dir / "leaderboard.json").write_text(json.dumps([], indent=2), encoding="utf-8")
    (settings.candidate_model_dir / "model_bundle.joblib").write_bytes(b"candidate-bundle")

    if include_current:
        settings.model_dir.mkdir(parents=True, exist_ok=True)
        (settings.model_dir / "metadata.json").write_text(
            json.dumps({"model_version": "current-model", "evaluation": {"pr_auc": 0.8, "roc_auc": 0.8, "false_positive_rate": 0.1}}, indent=2),
            encoding="utf-8",
        )
        (settings.model_dir / "model_bundle.joblib").write_bytes(b"current-bundle")


def test_promote_when_no_current_model(tmp_path, monkeypatch) -> None:
    settings = build_test_settings(tmp_path)
    _write_candidate_artifacts(
        settings,
        {
            "model_version": "candidate-model",
            "evaluation_mode": "temporal_benchmark",
            "promotion": {"recommended": True, "reason": "no_current_promoted_model"},
        },
    )

    monkeypatch.setattr(promote_module, "get_settings", lambda: settings)
    assert promote_module.promote() is True
    assert (settings.model_dir / "metadata.json").exists()
    assert (settings.model_dir / "leaderboard.json").exists()


def test_promote_when_shared_benchmark_passes(tmp_path, monkeypatch) -> None:
    settings = build_test_settings(tmp_path)
    _write_candidate_artifacts(
        settings,
        {
            "model_version": "candidate-model",
            "evaluation_mode": "temporal_benchmark",
            "promotion": {"recommended": True, "reason": "shared_benchmark_win"},
        },
        include_current=True,
    )

    monkeypatch.setattr(promote_module, "get_settings", lambda: settings)
    assert promote_module.promote() is True


def test_promote_skips_shared_benchmark_regression(tmp_path, monkeypatch) -> None:
    settings = build_test_settings(tmp_path)
    _write_candidate_artifacts(
        settings,
        {
            "model_version": "candidate-model",
            "evaluation_mode": "temporal_benchmark",
            "promotion": {"recommended": False, "reason": "shared_benchmark_regression"},
        },
        include_current=True,
    )

    monkeypatch.setattr(promote_module, "get_settings", lambda: settings)
    assert promote_module.promote() is False


def test_promote_skips_bootstrap_fallback_candidate(tmp_path, monkeypatch) -> None:
    settings = build_test_settings(tmp_path)
    _write_candidate_artifacts(
        settings,
        {
            "model_version": "candidate-model",
            "evaluation_mode": "bootstrap_fallback",
            "promotion": {"recommended": False, "reason": "bootstrap_fallback_requires_manual_review"},
        },
        include_current=True,
    )

    monkeypatch.setattr(promote_module, "get_settings", lambda: settings)
    assert promote_module.promote() is False
