from __future__ import annotations

import pytest

from baitdetector.features import FEATURE_SET_VERSION, build_lookup_context
from baitdetector.modeling import CHALLENGER_SPECS, fit_bundle, resolve_runtime_thresholds
from baitdetector.train import frame_window, split_frame
from baitdetector.url_utils import redact_url_secrets

from .support import normalized_demo_frame


def _build_bundle():
    frame = normalized_demo_frame()
    train_frame, validation_frame = split_frame(frame)
    tranco_ranks, malicious_last_seen = build_lookup_context(train_frame.to_dict(orient="records"))
    spec = CHALLENGER_SPECS[0]

    return fit_bundle(
        train_urls=train_frame["normalized_url"].tolist(),
        train_labels=train_frame["label"].astype(int).tolist(),
        tranco_ranks=tranco_ranks,
        malicious_last_seen=malicious_last_seen,
        metadata={
            "model_version": "test-model",
            "model_id": spec.model_id,
            "model_family": spec.model_family,
            "training_window": frame_window(train_frame),
            "validation_window": frame_window(validation_frame),
            "benchmark_window": {},
            "feature_set_version": FEATURE_SET_VERSION,
            "evaluation_mode": "bootstrap_fallback",
            "runtime_thresholds": {"suspicious": 0.02, "phishing": 0.08},
            "source_freshness": {},
            "evaluation": {},
        },
    )


def test_bundle_scores_obvious_phish_above_benign() -> None:
    bundle = _build_bundle()

    suspicious = bundle.predict_proba_one("https://account-recovery-paypal-secure.xyz/login")
    benign = bundle.predict_proba_one("https://github.com/login")
    reasons = bundle.explain("https://account-recovery-paypal-secure.xyz/login")

    assert suspicious > benign
    assert reasons


def test_explain_surfaces_shortener_signal_for_suspicious_focus() -> None:
    bundle = _build_bundle()

    reasons = bundle.explain("https://bit.ly/reset-account", focus="suspicious")
    labels = {reason["label"] for reason in reasons}

    assert "Uses URL shortener domain" in labels


def test_explain_uses_human_labels_for_summary_features() -> None:
    bundle = _build_bundle()

    reasons = bundle.explain("https://secure-paypa1-alert.xyz/login", focus="suspicious", top_n=8)

    assert all("lexical" not in str(reason["label"]).lower() for reason in reasons)


def test_model_info_exposes_runtime_thresholds() -> None:
    bundle = _build_bundle()
    info = bundle.model_info()

    assert info["model_id"] == "logistic_baseline"
    assert info["evaluation_mode"] == "bootstrap_fallback"
    assert info["latest_ingestion_sources"] == {}
    assert info["runtime_thresholds"] == {"suspicious": 0.02, "phishing": 0.08}
    assert resolve_runtime_thresholds(bundle.metadata) == {"suspicious": 0.02, "phishing": 0.08}


def test_fit_bundle_applies_calibration_with_enough_rows() -> None:
    frame = normalized_demo_frame()
    train_frame, validation_frame = split_frame(frame)
    tranco_ranks, malicious_last_seen = build_lookup_context(train_frame.to_dict(orient="records"))
    spec = CHALLENGER_SPECS[0]

    calibration_urls = (validation_frame["normalized_url"].tolist() * 5)[:60]
    calibration_labels = (validation_frame["label"].astype(int).tolist() * 5)[:60]

    bundle = fit_bundle(
        train_urls=train_frame["normalized_url"].tolist(),
        train_labels=train_frame["label"].astype(int).tolist(),
        tranco_ranks=tranco_ranks,
        malicious_last_seen=malicious_last_seen,
        metadata={"model_version": "test-calibrated", "training_window": frame_window(train_frame)},
        classifier=spec.build_classifier(),
        calibration_urls=calibration_urls,
        calibration_labels=calibration_labels,
    )

    assert bundle.metadata["calibration"]["status"] == "applied"
    probability = bundle.predict_proba_one("https://example.com/login")
    assert 0.0 <= probability <= 1.0


def test_bundle_scores_secret_like_inputs_consistently() -> None:
    bundle = _build_bundle()
    fake_google_api_key = "AIza" + "FAKE" * 8 + "000"
    raw_url = f"https://compact.link/reset?mode=resetPassword&oobCode=UlNWwoLW0Nt5KimkaIVmA5WYa5gENFl3n2aBkBwEomsAAAGY5NMkHQ&apiKey={fake_google_api_key}"
    sanitized_url = redact_url_secrets(raw_url)

    assert bundle.predict_proba_one(raw_url) == pytest.approx(bundle.predict_proba_one(sanitized_url))
