from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve, precision_score, recall_score, roc_auc_score

from .features import FEATURE_LABELS, FEATURE_SET_VERSION, LexicalFeatureExtractor, build_lookup_context
from .ingest import normalize_rows
from .modeling import (
    CHALLENGER_SPECS,
    ChallengerSpec,
    default_runtime_thresholds,
    fit_bundle,
    load_model_bundle,
    resolve_runtime_thresholds,
    save_model_bundle,
)
from .settings import get_settings


@dataclass
class TrainingDataset:
    evaluation_mode: str
    full_frame: pd.DataFrame
    train_frame: pd.DataFrame
    validation_frame: pd.DataFrame
    benchmark_frame: pd.DataFrame
    benchmark_unseen_frame: pd.DataFrame
    snapshot_paths: list[str]


def load_training_frame(path: str | None = None) -> pd.DataFrame:
    settings = get_settings()
    training_path = path or str(settings.data_dir / "normalized" / "latest.parquet")
    frame = pd.read_parquet(training_path) if training_path.endswith(".parquet") else pd.read_csv(training_path)
    if "normalized_url" not in frame.columns:
        frame = normalize_rows(frame.to_dict(orient="records"))
    frame["observed_at"] = pd.to_datetime(frame["observed_at"], utc=True)
    frame = frame.sort_values("observed_at").reset_index(drop=True)
    return frame


def split_frame(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    if len(frame) < 10:
        raise ValueError("Not enough rows to train.")
    cutoff_index = max(1, int(len(frame) * 0.8))
    train_frame = frame.iloc[:cutoff_index].copy()
    test_frame = frame.iloc[cutoff_index:].copy()
    if test_frame["label"].nunique() < 2:
        midpoint = len(frame) // 2
        train_frame = frame.iloc[:midpoint].copy()
        test_frame = frame.iloc[midpoint:].copy()
    return train_frame, test_frame


def source_freshness(frame: pd.DataFrame) -> dict[str, str]:
    values = {}
    for source, group in frame.groupby("source"):
        values[source] = group["observed_at"].max().isoformat()
    return values


def frame_window(frame: pd.DataFrame, *, snapshot_count: int = 1, snapshot_paths: list[str] | None = None) -> dict[str, Any]:
    if frame.empty:
        return {"rows": 0, "snapshot_count": snapshot_count, "snapshot_paths": snapshot_paths or []}
    return {
        "start": frame["observed_at"].min().isoformat(),
        "end": frame["observed_at"].max().isoformat(),
        "rows": int(len(frame)),
        "snapshot_count": snapshot_count,
        "snapshot_paths": snapshot_paths or [],
    }


def build_feature_correlation_summary(
    frame: pd.DataFrame,
    *,
    tranco_ranks: dict[str, int] | None = None,
    malicious_last_seen: dict[str, str] | None = None,
    source: str = "training_corpus",
) -> dict[str, Any]:
    if frame.empty:
        return {"rows": 0, "source": source, "features": [], "matrix": []}

    extractor = LexicalFeatureExtractor(
        tranco_ranks=tranco_ranks,
        malicious_last_seen=malicious_last_seen,
    )
    feature_names = [str(name) for name in extractor.get_feature_names_out()]
    values = extractor.transform(frame["normalized_url"].astype(str).tolist())
    correlation_frame = pd.DataFrame(values, columns=feature_names)
    correlation_matrix = correlation_frame.corr(numeric_only=True).fillna(0.0)

    for index in range(len(feature_names)):
        correlation_matrix.iat[index, index] = 1.0

    features = [
        {
            "key": f"lexical__{name}",
            "name": name,
            "label": FEATURE_LABELS.get(f"lexical__{name}", name.replace("_", " ")),
        }
        for name in feature_names
    ]

    return {
        "rows": int(len(frame)),
        "source": source,
        "features": features,
        "matrix": [
            [round(float(value), 4) for value in row]
            for row in correlation_matrix.to_numpy().tolist()
        ],
    }


def snapshot_history_paths() -> list[Path]:
    settings = get_settings()
    normalized_dir = settings.data_dir / "normalized"
    return sorted(normalized_dir.glob("urls-*.parquet"))


def _default_bootstrap_path(snapshot_paths: list[Path]) -> str | None:
    settings = get_settings()
    latest_path = settings.data_dir / "normalized" / "latest.parquet"
    if latest_path.exists():
        return str(latest_path)
    if snapshot_paths:
        return str(snapshot_paths[-1])
    return None


def build_training_dataset(training_path: str | None = None) -> TrainingDataset:
    paths = snapshot_history_paths()
    if training_path or len(paths) < 3:
        bootstrap_path = training_path or _default_bootstrap_path(paths)
        if bootstrap_path is None:
            raise FileNotFoundError("No training dataset found. Run python -m baitdetector.ingest first.")
        return build_bootstrap_dataset(bootstrap_path, paths)
    return build_temporal_dataset(paths)


def build_bootstrap_dataset(training_path: str, snapshot_paths: list[Path] | None = None) -> TrainingDataset:
    frame = load_training_frame(training_path)
    train_frame, validation_frame = split_frame(frame)
    snapshot_refs = [str(path) for path in snapshot_paths or []]
    return TrainingDataset(
        evaluation_mode="bootstrap_fallback",
        full_frame=frame,
        train_frame=train_frame.reset_index(drop=True),
        validation_frame=validation_frame.reset_index(drop=True),
        benchmark_frame=pd.DataFrame(columns=frame.columns),
        benchmark_unseen_frame=pd.DataFrame(columns=frame.columns),
        snapshot_paths=snapshot_refs,
    )


def build_temporal_dataset(paths: list[Path]) -> TrainingDataset:
    training_paths = paths[:-2]
    validation_path = paths[-2]
    benchmark_path = paths[-1]

    train_frames = [load_training_frame(str(path)) for path in training_paths]
    train_frame = pd.concat(train_frames, ignore_index=True)
    validation_frame = load_training_frame(str(validation_path))
    benchmark_frame = load_training_frame(str(benchmark_path))

    holdout_urls = set(validation_frame["normalized_url"].astype(str)) | set(benchmark_frame["normalized_url"].astype(str))
    train_frame = train_frame.loc[~train_frame["normalized_url"].astype(str).isin(holdout_urls)].copy()
    train_frame = (
        train_frame.sort_values("observed_at")
        .drop_duplicates(subset=["normalized_url", "label"], keep="last")
        .reset_index(drop=True)
    )

    train_domains = set(train_frame["registrable_domain"].astype(str).str.lower())
    benchmark_unseen_frame = benchmark_frame.loc[
        ~benchmark_frame["registrable_domain"].astype(str).str.lower().isin(train_domains)
    ].copy()

    full_frame = pd.concat([train_frame, validation_frame, benchmark_frame], ignore_index=True)
    return TrainingDataset(
        evaluation_mode="temporal_benchmark",
        full_frame=full_frame.reset_index(drop=True),
        train_frame=train_frame,
        validation_frame=validation_frame.reset_index(drop=True),
        benchmark_frame=benchmark_frame.reset_index(drop=True),
        benchmark_unseen_frame=benchmark_unseen_frame.reset_index(drop=True),
        snapshot_paths=[str(path) for path in paths],
    )


def select_decision_threshold(y_true: list[int], y_prob: list[float]) -> float:
    if not y_true or len(set(y_true)) < 2:
        return default_runtime_thresholds()["phishing"]
    precision, recall, thresholds = precision_recall_curve(y_true, y_prob)
    best_threshold = 0.5
    best_score = -1.0
    for idx, threshold in enumerate(thresholds):
        p = precision[idx]
        r = recall[idx]
        score = (2 * p * r) / (p + r) if (p + r) else 0.0
        if score > best_score:
            best_score = score
            best_threshold = float(threshold)
    return round(best_threshold, 4)


def select_suspicious_threshold(y_true: list[int], y_prob: list[float], phishing_threshold: float) -> float:
    if not y_true or len(set(y_true)) < 2:
        return round(max(0.0, phishing_threshold * 0.5), 4)

    candidate_thresholds = sorted({float(value) for value in y_prob if float(value) < phishing_threshold}, reverse=True)
    for threshold in candidate_thresholds:
        y_pred = [1 if value >= threshold else 0 for value in y_prob]
        recall = recall_score(y_true, y_pred, zero_division=0)
        if recall >= 0.95:
            return round(threshold, 4)
    return round(max(0.0, phishing_threshold * 0.5), 4)


def select_runtime_thresholds(y_true: list[int], y_prob: list[float]) -> dict[str, float]:
    if not y_true or len(set(y_true)) < 2:
        return default_runtime_thresholds()

    phishing_threshold = select_decision_threshold(y_true, y_prob)
    suspicious_threshold = select_suspicious_threshold(y_true, y_prob, phishing_threshold)
    if suspicious_threshold > phishing_threshold:
        suspicious_threshold = round(max(0.0, phishing_threshold * 0.5), 4)
    return {"suspicious": round(suspicious_threshold, 4), "phishing": round(phishing_threshold, 4)}


def evaluation_summary(y_true: list[int], y_prob: list[float], threshold: float) -> dict[str, Any]:
    if not y_true:
        return {
            "rows": 0,
            "positives": 0,
            "negatives": 0,
            "roc_auc": None,
            "pr_auc": None,
            "precision": None,
            "recall": None,
            "false_positive_rate": None,
            "decision_threshold": round(threshold, 4),
        }

    y_pred = [1 if value >= threshold else 0 for value in y_prob]
    negatives = sum(1 for label in y_true if label == 0)
    positives = sum(1 for label in y_true if label == 1)
    false_positives = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 1)

    try:
        pr_auc = round(float(average_precision_score(y_true, y_prob)), 4)
    except ValueError:
        pr_auc = None

    roc_auc = round(float(roc_auc_score(y_true, y_prob)), 4) if len(set(y_true)) > 1 else None
    precision = round(float(precision_score(y_true, y_pred, zero_division=0)), 4)
    recall = round(float(recall_score(y_true, y_pred, zero_division=0)), 4)
    false_positive_rate = round(false_positives / negatives, 4) if negatives else None
    return {
        "rows": int(len(y_true)),
        "positives": int(positives),
        "negatives": int(negatives),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "decision_threshold": round(threshold, 4),
    }


def _evaluate_frame(frame: pd.DataFrame, probabilities: list[float], thresholds: dict[str, float]) -> dict[str, Any]:
    metrics = evaluation_summary(frame["label"].astype(int).tolist(), probabilities, threshold=thresholds["phishing"])
    metrics["runtime_thresholds"] = thresholds
    return metrics


def _score_bundle(bundle, frame: pd.DataFrame) -> list[float]:
    if frame.empty:
        return []
    return bundle.predict_proba(frame["normalized_url"].tolist()).tolist()


def evaluate_candidate_bundle(bundle, dataset: TrainingDataset) -> dict[str, Any]:
    validation_probabilities = _score_bundle(bundle, dataset.validation_frame)
    thresholds = select_runtime_thresholds(dataset.validation_frame["label"].astype(int).tolist(), validation_probabilities)

    validation_metrics = _evaluate_frame(dataset.validation_frame, validation_probabilities, thresholds)
    benchmark_probabilities = _score_bundle(bundle, dataset.benchmark_frame)
    benchmark_metrics = _evaluate_frame(dataset.benchmark_frame, benchmark_probabilities, thresholds)
    unseen_probabilities = _score_bundle(bundle, dataset.benchmark_unseen_frame)
    unseen_metrics = _evaluate_frame(dataset.benchmark_unseen_frame, unseen_probabilities, thresholds)
    return {
        "runtime_thresholds": thresholds,
        "validation_evaluation": validation_metrics,
        "benchmark_evaluation": benchmark_metrics,
        "benchmark_unseen_domain_evaluation": unseen_metrics,
    }


def evaluate_current_bundle(bundle, dataset: TrainingDataset) -> dict[str, Any]:
    thresholds = resolve_runtime_thresholds(bundle.metadata)
    benchmark_probabilities = _score_bundle(bundle, dataset.benchmark_frame)
    unseen_probabilities = _score_bundle(bundle, dataset.benchmark_unseen_frame)
    return {
        "model_version": bundle.metadata.get("model_version", "current-promoted"),
        "model_id": bundle.metadata.get("model_id", "current_promoted"),
        "model_family": bundle.metadata.get("model_family", "unknown"),
        "evaluation": _evaluate_frame(dataset.benchmark_frame, benchmark_probabilities, thresholds),
        "benchmark_unseen_domain_evaluation": _evaluate_frame(dataset.benchmark_unseen_frame, unseen_probabilities, thresholds),
    }


def _metric_value(metrics: dict[str, Any], key: str, default: float) -> float:
    value = metrics.get(key)
    if value is None:
        return default
    return float(value)


def leaderboard_sort_key(entry: dict[str, Any]) -> tuple[float, float, float]:
    benchmark = entry["benchmark_metrics"]
    return (
        _metric_value(benchmark, "pr_auc", -1.0),
        -_metric_value(benchmark, "false_positive_rate", 1.0),
        _metric_value(benchmark, "roc_auc", -1.0),
    )


def passes_shared_benchmark_gates(candidate_metrics: dict[str, Any], current_metrics: dict[str, Any]) -> bool:
    required = ("pr_auc", "roc_auc", "false_positive_rate")
    if any(candidate_metrics.get(metric) is None or current_metrics.get(metric) is None for metric in required):
        return False
    return (
        float(candidate_metrics["pr_auc"]) >= float(current_metrics["pr_auc"])
        and float(candidate_metrics["roc_auc"]) >= float(current_metrics["roc_auc"])
        and float(candidate_metrics["false_positive_rate"]) <= float(current_metrics["false_positive_rate"])
    )


def outranks(candidate_metrics: dict[str, Any], current_metrics: dict[str, Any]) -> bool:
    return leaderboard_sort_key({"benchmark_metrics": candidate_metrics}) > leaderboard_sort_key({"benchmark_metrics": current_metrics})


def _base_metadata(
    dataset: TrainingDataset,
    *,
    model_version: str,
    model_id: str,
    model_family: str,
    hyperparameters: dict[str, Any],
) -> dict[str, Any]:
    train_snapshot_paths = dataset.snapshot_paths[:-2] if dataset.evaluation_mode == "temporal_benchmark" else []
    validation_snapshot_paths = dataset.snapshot_paths[-2:-1] if dataset.evaluation_mode == "temporal_benchmark" else []
    benchmark_snapshot_paths = dataset.snapshot_paths[-1:] if dataset.evaluation_mode == "temporal_benchmark" else []
    return {
        "model_version": model_version,
        "model_id": model_id,
        "model_family": model_family,
        "training_window": frame_window(
            dataset.train_frame,
            snapshot_count=max(1, len(train_snapshot_paths)),
            snapshot_paths=train_snapshot_paths,
        ),
        "validation_window": frame_window(
            dataset.validation_frame,
            snapshot_count=max(1, len(validation_snapshot_paths) or 1),
            snapshot_paths=validation_snapshot_paths,
        ),
        "benchmark_window": frame_window(
            dataset.benchmark_frame,
            snapshot_count=len(benchmark_snapshot_paths),
            snapshot_paths=benchmark_snapshot_paths,
        ),
        "feature_set_version": FEATURE_SET_VERSION,
        "evaluation_mode": dataset.evaluation_mode,
        "runtime_thresholds": {},
        "source_freshness": source_freshness(dataset.full_frame),
        "hyperparameters": hyperparameters,
        "evaluation": {},
    }


def _write_json(path: Path, payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _load_current_promoted_summary(dataset: TrainingDataset) -> dict[str, Any] | None:
    settings = get_settings()
    try:
        bundle = load_model_bundle(settings.model_dir)
    except FileNotFoundError:
        return None
    return evaluate_current_bundle(bundle, dataset)


def _build_leaderboard_entry(spec: ChallengerSpec, bundle, evaluation: dict[str, Any]) -> dict[str, Any]:
    return {
        "model_version": bundle.metadata["model_version"],
        "model_id": spec.model_id,
        "model_family": spec.model_family,
        "hyperparameters": spec.hyperparameters,
        "calibration": bundle.metadata.get("calibration", {}),
        "thresholds": evaluation["runtime_thresholds"],
        "validation_metrics": evaluation["validation_evaluation"],
        "benchmark_metrics": evaluation["benchmark_evaluation"],
        "unseen_domain_metrics": evaluation["benchmark_unseen_domain_evaluation"],
        "promotion_outcome": "not_selected",
    }


def _finalize_leaderboard(
    leaderboard: list[dict[str, Any]],
    *,
    champion_model_id: str,
    promotion_reason: str,
    recommended: bool,
) -> list[dict[str, Any]]:
    ordered = sorted(leaderboard, key=leaderboard_sort_key, reverse=True)
    for rank, entry in enumerate(ordered, start=1):
        entry["rank"] = rank
        if entry["model_id"] != champion_model_id:
            continue
        entry["promotion_outcome"] = "promoted_candidate" if recommended else promotion_reason
    return ordered


def train_bootstrap_candidate(dataset: TrainingDataset, training_path: str | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    tranco_ranks, malicious_last_seen = build_lookup_context(dataset.train_frame.to_dict(orient="records"))
    spec = CHALLENGER_SPECS[0]
    model_version = datetime.now(timezone.utc).strftime("baitdetector-%Y%m%dT%H%M%SZ")
    metadata = _base_metadata(
        dataset,
        model_version=model_version,
        model_id=spec.model_id,
        model_family=spec.model_family,
        hyperparameters=spec.hyperparameters,
    )

    bundle = fit_bundle(
        train_urls=dataset.train_frame["normalized_url"].tolist(),
        train_labels=dataset.train_frame["label"].astype(int).tolist(),
        tranco_ranks=tranco_ranks,
        malicious_last_seen=malicious_last_seen,
        metadata=metadata,
        classifier=spec.build_classifier(),
        calibration_urls=dataset.validation_frame["normalized_url"].tolist(),
        calibration_labels=dataset.validation_frame["label"].astype(int).tolist(),
    )

    evaluation = evaluate_candidate_bundle(bundle, dataset)
    bundle.metadata["runtime_thresholds"] = evaluation["runtime_thresholds"]
    bundle.metadata["evaluation"] = evaluation["validation_evaluation"]
    bundle.metadata["evaluation"]["runtime_thresholds"] = evaluation["runtime_thresholds"]
    bundle.metadata["validation_evaluation"] = evaluation["validation_evaluation"]
    bundle.metadata["benchmark_unseen_domain_evaluation"] = evaluation["benchmark_unseen_domain_evaluation"]
    bundle.metadata["promotion"] = {
        "recommended": False,
        "reason": "bootstrap_fallback_requires_manual_review",
    }
    if training_path:
        bundle.metadata["training_input_path"] = training_path

    save_model_bundle(bundle, get_settings().candidate_model_dir)

    leaderboard = [
        {
            **_build_leaderboard_entry(spec, bundle, evaluation),
            "promotion_outcome": "bootstrap_fallback_requires_manual_review",
            "rank": 1,
        }
    ]
    summary = {
        "evaluation_mode": dataset.evaluation_mode,
        "snapshot_history": dataset.snapshot_paths,
        "selected_candidate": bundle.metadata,
        "current_promoted_benchmark": None,
        "promotion": bundle.metadata["promotion"],
        "feature_correlation": build_feature_correlation_summary(
            dataset.train_frame,
            tranco_ranks=tranco_ranks,
            malicious_last_seen=malicious_last_seen,
        ),
    }
    return summary, leaderboard


def train_temporal_candidates(dataset: TrainingDataset) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run_version = datetime.now(timezone.utc).strftime("baitdetector-%Y%m%dT%H%M%SZ")
    tranco_ranks, malicious_last_seen = build_lookup_context(dataset.train_frame.to_dict(orient="records"))

    candidate_results: list[dict[str, Any]] = []
    leaderboard: list[dict[str, Any]] = []
    for spec in CHALLENGER_SPECS:
        metadata = _base_metadata(
            dataset,
            model_version=f"{run_version}-{spec.model_id}",
            model_id=spec.model_id,
            model_family=spec.model_family,
            hyperparameters=spec.hyperparameters,
        )
        bundle = fit_bundle(
            train_urls=dataset.train_frame["normalized_url"].tolist(),
            train_labels=dataset.train_frame["label"].astype(int).tolist(),
            tranco_ranks=tranco_ranks,
            malicious_last_seen=malicious_last_seen,
            metadata=metadata,
            classifier=spec.build_classifier(),
            calibration_urls=dataset.validation_frame["normalized_url"].tolist(),
            calibration_labels=dataset.validation_frame["label"].astype(int).tolist(),
        )
        evaluation = evaluate_candidate_bundle(bundle, dataset)
        bundle.metadata["runtime_thresholds"] = evaluation["runtime_thresholds"]
        bundle.metadata["evaluation"] = evaluation["benchmark_evaluation"]
        bundle.metadata["evaluation"]["runtime_thresholds"] = evaluation["runtime_thresholds"]
        bundle.metadata["validation_evaluation"] = evaluation["validation_evaluation"]
        bundle.metadata["benchmark_unseen_domain_evaluation"] = evaluation["benchmark_unseen_domain_evaluation"]
        candidate_results.append({"spec": spec, "bundle": bundle, "evaluation": evaluation})
        leaderboard.append(_build_leaderboard_entry(spec, bundle, evaluation))

    champion = max(candidate_results, key=lambda item: leaderboard_sort_key({"benchmark_metrics": item["evaluation"]["benchmark_evaluation"]}))
    current_summary = _load_current_promoted_summary(dataset)
    promotion = {
        "recommended": False,
        "reason": "shared_benchmark_regression",
    }
    if current_summary is None:
        promotion = {
            "recommended": True,
            "reason": "no_current_promoted_model",
        }
    else:
        champion_metrics = champion["evaluation"]["benchmark_evaluation"]
        current_metrics = current_summary["evaluation"]
        if passes_shared_benchmark_gates(champion_metrics, current_metrics):
            if outranks(champion_metrics, current_metrics):
                promotion = {
                    "recommended": True,
                    "reason": "shared_benchmark_win",
                }
            else:
                promotion = {
                    "recommended": False,
                    "reason": "shared_benchmark_tie_keeps_current",
                }

    champion_bundle = champion["bundle"]
    champion_bundle.metadata["promotion"] = {
        **promotion,
        "current_promoted_benchmark": current_summary,
    }
    save_model_bundle(champion_bundle, get_settings().candidate_model_dir)

    finalized_leaderboard = _finalize_leaderboard(
        leaderboard,
        champion_model_id=champion["spec"].model_id,
        promotion_reason=promotion["reason"],
        recommended=promotion["recommended"],
    )
    summary = {
        "evaluation_mode": dataset.evaluation_mode,
        "snapshot_history": dataset.snapshot_paths,
        "selected_candidate": champion_bundle.metadata,
        "current_promoted_benchmark": current_summary,
        "promotion": promotion,
        "feature_correlation": build_feature_correlation_summary(
            dataset.train_frame,
            tranco_ranks=tranco_ranks,
            malicious_last_seen=malicious_last_seen,
        ),
    }
    return summary, finalized_leaderboard


def train_model(training_path: str | None = None) -> dict[str, object]:
    settings = get_settings()
    dataset = build_training_dataset(training_path=training_path)

    if dataset.evaluation_mode == "bootstrap_fallback":
        summary, leaderboard = train_bootstrap_candidate(dataset, training_path=training_path)
    else:
        summary, leaderboard = train_temporal_candidates(dataset)

    _write_json(settings.candidate_model_dir / "training_summary.json", summary)
    _write_json(settings.candidate_model_dir / "leaderboard.json", leaderboard)
    return summary["selected_candidate"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the BaitDetector model.")
    parser.add_argument("--training-path", help="Path to a parquet or CSV training file.", default=None)
    args = parser.parse_args()
    metadata = train_model(training_path=args.training_path)
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
