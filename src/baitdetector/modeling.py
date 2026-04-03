from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
from scipy import sparse
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.pipeline import FeatureUnion, Pipeline

from .features import FEATURE_LABELS, FEATURE_SET_VERSION, LexicalFeatureExtractor
from .url_utils import redact_url_secrets

SUSPICIOUS_SIGNAL_BONUSES = {
    "lexical__known_phishing_hit": 4.0,
    "lexical__known_phishing_freshness": 3.2,
    "lexical__has_ip_host": 2.8,
    "lexical__is_shortener": 2.4,
    "lexical__has_punycode": 2.4,
    "lexical__has_at_symbol": 2.0,
    "lexical__has_redirect_param": 1.8,
    "lexical__tld_is_high_risk": 1.6,
    "lexical__has_login_token": 1.3,
    "lexical__has_verify_token": 1.3,
    "lexical__has_secure_token": 1.3,
    "lexical__has_update_token": 1.1,
    "lexical__has_account_token": 1.1,
    "lexical__tranco_rank_bucket": 1.0,
    "lexical__subdomain_depth": 0.8,
    "lexical__num_digits": 0.7,
    "lexical__num_hyphens": 0.7,
    "lexical__num_query_params": 0.7,
}

MIN_CALIBRATION_ROWS = 50
SIGNAL_MAP_METRICS: tuple[str, str, str] = ("phishing_pull", "protective_pull", "feature_density")
SIGNAL_GROUP_ORDER: tuple[str, str, str, str, str] = ("structure", "tokens", "host", "routing", "trust")
SIGNAL_GROUP_LABELS = {
    "structure": "Structure",
    "tokens": "Tokens",
    "host": "Host",
    "routing": "Routing",
    "trust": "Trust",
}


def _tfidf_preprocessor(value: str) -> str:
    return redact_url_secrets(value).lower()


@dataclass(frozen=True)
class ChallengerSpec:
    model_id: str
    model_family: str
    classifier_name: str
    hyperparameters: dict[str, Any]

    def build_classifier(self) -> Any:
        if self.classifier_name == "logistic_regression":
            return LogisticRegression(**self.hyperparameters)
        if self.classifier_name == "sgd_classifier":
            return SGDClassifier(**self.hyperparameters)
        raise ValueError(f"Unsupported classifier: {self.classifier_name}")


CHALLENGER_SPECS: tuple[ChallengerSpec, ...] = (
    ChallengerSpec(
        model_id="logistic_baseline",
        model_family="logistic_regression",
        classifier_name="logistic_regression",
        hyperparameters={
            "max_iter": 2_000,
            "class_weight": "balanced",
            "solver": "liblinear",
            "C": 2.0,
        },
    ),
    ChallengerSpec(
        model_id="logistic_sparse_l1",
        model_family="logistic_regression",
        classifier_name="logistic_regression",
        hyperparameters={
            "max_iter": 2_000,
            "class_weight": "balanced",
            "solver": "liblinear",
            "penalty": "l1",
            "C": 1.0,
        },
    ),
    ChallengerSpec(
        model_id="sgd_log_loss",
        model_family="sgd_classifier",
        classifier_name="sgd_classifier",
        hyperparameters={
            "loss": "log_loss",
            "alpha": 1e-5,
            "class_weight": "balanced",
            "max_iter": 2_000,
            "random_state": 42,
            "tol": 1e-3,
        },
    ),
)


def default_runtime_thresholds() -> dict[str, float]:
    return {"suspicious": 0.25, "phishing": 0.5}


def resolve_runtime_thresholds(metadata: dict[str, Any]) -> dict[str, float]:
    candidate = metadata.get("runtime_thresholds") or metadata.get("evaluation", {}).get("runtime_thresholds") or {}
    phishing = float(candidate.get("phishing", metadata.get("evaluation", {}).get("decision_threshold", 0.5)))
    suspicious = float(candidate.get("suspicious", max(0.02, round(phishing * 0.65, 4))))
    if suspicious > phishing:
        suspicious = max(0.0, round(phishing * 0.5, 4))
    return {"suspicious": round(suspicious, 4), "phishing": round(phishing, 4)}


def build_pipeline(
    classifier: Any,
    tranco_ranks: dict[str, int] | None = None,
    malicious_last_seen: dict[str, str] | None = None,
) -> Pipeline:
    return Pipeline(
        steps=[
            (
                "features",
                FeatureUnion(
                    transformer_list=[
                        (
                            "lexical",
                            LexicalFeatureExtractor(
                                tranco_ranks=tranco_ranks,
                                malicious_last_seen=malicious_last_seen,
                            ),
                        ),
                        (
                            "char_tfidf",
                            TfidfVectorizer(
                                analyzer="char",
                                ngram_range=(3, 5),
                                max_features=700,
                                lowercase=False,
                                preprocessor=_tfidf_preprocessor,
                            ),
                        ),
                    ]
                ),
            ),
            ("classifier", clone(classifier)),
        ]
    )


def build_base_pipeline(
    tranco_ranks: dict[str, int] | None = None,
    malicious_last_seen: dict[str, str] | None = None,
) -> Pipeline:
    return build_pipeline(
        classifier=CHALLENGER_SPECS[0].build_classifier(),
        tranco_ranks=tranco_ranks,
        malicious_last_seen=malicious_last_seen,
    )


@dataclass
class ModelBundle:
    calibrated_model: Any
    explainer_model: Pipeline
    metadata: dict[str, Any]
    feature_labels: dict[str, str] = field(default_factory=lambda: dict(FEATURE_LABELS))

    def predict_proba(self, urls: list[str]) -> np.ndarray:
        if hasattr(self.calibrated_model, "predict_proba"):
            return np.asarray(self.calibrated_model.predict_proba(urls))[:, 1]
        return np.asarray(self.explainer_model.predict_proba(urls))[:, 1]

    def predict_proba_one(self, url: str) -> float:
        return float(self.predict_proba([url])[0])

    def get_lookup_context(self) -> tuple[dict[str, int], dict[str, str]]:
        lexical = self.explainer_model.named_steps["features"].transformer_list[0][1]
        return dict(lexical.tranco_ranks or {}), dict(lexical.malicious_last_seen or {})

    def explain(
        self,
        url: str,
        top_n: int = 5,
        focus: Literal["balanced", "suspicious", "benign"] = "balanced",
    ) -> list[dict[str, str | float]]:
        feature_union = self.explainer_model.named_steps["features"]
        classifier = self.explainer_model.named_steps["classifier"]
        transformed = feature_union.transform([url])
        vector = transformed.toarray()[0] if sparse.issparse(transformed) else np.asarray(transformed)[0]
        contributions = vector * classifier.coef_[0]
        feature_names = feature_union.get_feature_names_out()

        ranked: list[dict[str, str | float | bool]] = sorted(
            [
                {
                    "feature": str(name),
                    "label": self._label_for_feature(str(name)),
                    "raw_value": float(vector[idx]),
                    "value": self._format_value(float(vector[idx]), str(name)),
                    "impact": float(contributions[idx]),
                    "is_lexical": str(name).startswith("lexical__"),
                }
                for idx, name in enumerate(feature_names)
                if abs(contributions[idx]) > 1e-6
            ],
            key=lambda item: abs(float(item["impact"])),
            reverse=True,
        )

        selected = self._select_summary_records(ranked, top_n=top_n, focus=focus)

        reasons: list[dict[str, str | float]] = []
        for item in selected:
            reasons.append(
                {
                    "feature": str(item["feature"]),
                    "label": str(item["label"]),
                    "value": str(item["value"]),
                    "impact": float(item["impact"]),
                }
            )

        if not reasons:
            reasons.append(
                {
                    "feature": "model__baseline",
                    "label": "No dominant phishing indicators fired",
                    "value": "baseline",
                    "impact": 0.0,
                }
            )
        return reasons

    def model_info(self) -> dict[str, Any]:
        runtime_thresholds = resolve_runtime_thresholds(self.metadata)
        return {
            "model_version": self.metadata["model_version"],
            "model_id": self.metadata.get("model_id", "logistic_baseline"),
            "model_family": self.metadata.get("model_family", "logistic_regression"),
            "training_window": self.metadata["training_window"],
            "validation_window": self.metadata.get("validation_window", {}),
            "benchmark_window": self.metadata.get("benchmark_window", {}),
            "feature_set_version": self.metadata.get("feature_set_version", FEATURE_SET_VERSION),
            "latest_ingestion_sources": {},
            "evaluation_mode": self.metadata.get("evaluation_mode", "bootstrap_fallback"),
            "evaluation": self.metadata.get("evaluation", {}),
            "runtime_thresholds": runtime_thresholds,
        }

    def model_details(self, top_n: int = 6) -> dict[str, Any]:
        feature_union = self.explainer_model.named_steps["features"]
        classifier = self.explainer_model.named_steps["classifier"]
        feature_names = feature_union.get_feature_names_out()
        coefficients = classifier.coef_[0]

        lexical_entries: list[dict[str, Any]] = []
        for feature_name, coefficient in zip(feature_names, coefficients, strict=True):
            name = str(feature_name)
            if not name.startswith("lexical__"):
                continue
            label = self._label_for_feature(name)
            lexical_entries.append(
                {
                    "feature": name,
                    "label": label,
                    "weight": round(float(coefficient), 4),
                    "category": self._feature_group(name, label),
                }
            )

        top_phishing = sorted(
            [entry for entry in lexical_entries if float(entry["weight"]) > 0],
            key=lambda entry: abs(float(entry["weight"])),
            reverse=True,
        )[:top_n]
        top_protective = sorted(
            [entry for entry in lexical_entries if float(entry["weight"]) < 0],
            key=lambda entry: abs(float(entry["weight"])),
            reverse=True,
        )[:top_n]

        grouped: dict[str, list[dict[str, Any]]] = {group: [] for group in SIGNAL_GROUP_ORDER}
        for entry in lexical_entries:
            grouped.setdefault(str(entry["category"]), []).append(entry)

        group_metrics: dict[str, dict[str, float]] = {}
        max_positive = 0.0
        max_negative = 0.0
        max_density = 0.0
        for group, entries in grouped.items():
            positive = sum(max(float(entry["weight"]), 0.0) for entry in entries)
            negative = sum(abs(min(float(entry["weight"]), 0.0)) for entry in entries)
            density = float(len(entries))
            group_metrics[group] = {
                "phishing_pull": positive,
                "protective_pull": negative,
                "feature_density": density,
            }
            max_positive = max(max_positive, positive)
            max_negative = max(max_negative, negative)
            max_density = max(max_density, density)

        signal_map: list[dict[str, Any]] = []
        for group in SIGNAL_GROUP_ORDER:
            metrics = group_metrics.get(group, {})
            signal_map.append(
                {
                    "category": SIGNAL_GROUP_LABELS[group],
                    "metric": "phishing_pull",
                    "value": round(metrics.get("phishing_pull", 0.0) / max_positive, 4) if max_positive else 0.0,
                }
            )
            signal_map.append(
                {
                    "category": SIGNAL_GROUP_LABELS[group],
                    "metric": "protective_pull",
                    "value": round(metrics.get("protective_pull", 0.0) / max_negative, 4) if max_negative else 0.0,
                }
            )
            signal_map.append(
                {
                    "category": SIGNAL_GROUP_LABELS[group],
                    "metric": "feature_density",
                    "value": round(metrics.get("feature_density", 0.0) / max_density, 4) if max_density else 0.0,
                }
            )

        return {
            "top_phishing_signals": top_phishing,
            "top_protective_signals": top_protective,
            "signal_map": signal_map,
            "calibration": self.metadata.get("calibration", {}),
        }

    def _label_for_feature(self, feature_name: str) -> str:
        normalized_name = feature_name.replace(" ", "_")
        if feature_name in FEATURE_LABELS:
            return FEATURE_LABELS[feature_name]
        if normalized_name in FEATURE_LABELS:
            return FEATURE_LABELS[normalized_name]
        if feature_name in self.feature_labels:
            return self.feature_labels[feature_name]
        if normalized_name in self.feature_labels:
            return self.feature_labels[normalized_name]
        if feature_name.startswith("char_tfidf__"):
            ngram = feature_name.split("__", 1)[1]
            return f"Character pattern '{ngram}'"
        return feature_name.replace("_", " ")

    @staticmethod
    def _feature_group(feature_name: str, label: str) -> str:
        text = f"{feature_name} {label}".lower()
        if any(token in text for token in ("length", "entropy", "digits", "hyphens")):
            return "structure"
        if any(token in text for token in ("token", "login", "verify", "secure", "update", "account", "password", "suspicious")):
            return "tokens"
        if any(token in text for token in ("domain", "host", "subdomain", "tld", "ip", "punycode", "shortener")):
            return "host"
        if any(token in text for token in ("redirect", "query", "path", "url")):
            return "routing"
        return "trust"

    @staticmethod
    def _format_value(value: float, feature_name: str) -> str:
        if feature_name.startswith("char_tfidf__"):
            return feature_name.split("__", 1)[1]
        if value in {0.0, 1.0}:
            return "yes" if value == 1.0 else "no"
        if float(value).is_integer():
            return str(int(value))
        return f"{value:.2f}"

    def _select_summary_records(
        self,
        ranked: list[dict[str, str | float | bool]],
        top_n: int,
        focus: Literal["balanced", "suspicious", "benign"],
    ) -> list[dict[str, str | float | bool]]:
        lexical = [item for item in ranked if bool(item["is_lexical"])]
        if not lexical:
            return ranked[:top_n]

        if focus == "suspicious":
            selected = self._select_suspicious_records(lexical, top_n)
            if selected:
                return selected

        if focus == "benign":
            selected = self._select_benign_records(lexical, top_n)
            if selected:
                return selected

        return lexical[:top_n]

    def _select_suspicious_records(
        self,
        lexical: list[dict[str, str | float | bool]],
        top_n: int,
    ) -> list[dict[str, str | float | bool]]:
        positive = [item for item in lexical if float(item["impact"]) > 0]
        if not positive:
            return []

        ordered = sorted(
            positive,
            key=lambda item: (
                float(item["impact"]) + SUSPICIOUS_SIGNAL_BONUSES.get(str(item["feature"]), 0.0),
                float(item["impact"]),
            ),
            reverse=True,
        )
        return ordered[:top_n]

    def _select_benign_records(
        self,
        lexical: list[dict[str, str | float | bool]],
        top_n: int,
    ) -> list[dict[str, str | float | bool]]:
        protective_features = {"lexical__has_https", "lexical__tld_is_common"}
        protective = [
            item
            for item in lexical
            if float(item["impact"]) < 0 and str(item["feature"]) in protective_features
        ]
        if protective:
            protective.sort(key=lambda item: abs(float(item["impact"])), reverse=True)
            return protective[:top_n]
        return []


def save_model_bundle(bundle: ModelBundle, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, target_dir / "model_bundle.joblib")
    (target_dir / "metadata.json").write_text(json.dumps(bundle.metadata, indent=2), encoding="utf-8")


def load_model_bundle(target_dir: Path) -> ModelBundle:
    return joblib.load(target_dir / "model_bundle.joblib")


def fit_bundle(
    train_urls: list[str],
    train_labels: list[int],
    tranco_ranks: dict[str, int],
    malicious_last_seen: dict[str, str],
    metadata: dict[str, Any],
    classifier: Any | None = None,
    calibration_urls: list[str] | None = None,
    calibration_labels: list[int] | None = None,
) -> ModelBundle:
    explainer_model = build_pipeline(
        classifier=classifier or CHALLENGER_SPECS[0].build_classifier(),
        tranco_ranks=tranco_ranks,
        malicious_last_seen=malicious_last_seen,
    )
    explainer_model.fit(train_urls, train_labels)

    calibrated_estimator: Any = explainer_model
    metadata["calibration"] = {
        "status": "skipped",
        "reason": "missing_validation_data",
        "rows": int(len(calibration_urls or [])),
    }

    if calibration_urls and calibration_labels and len(calibration_urls) >= MIN_CALIBRATION_ROWS and len(set(calibration_labels)) > 1:
        try:
            calibrated_estimator = CalibratedClassifierCV(
                estimator=explainer_model,
                method="sigmoid",
                cv="prefit",
            )
            calibrated_estimator.fit(calibration_urls, calibration_labels)
            metadata["calibration"] = {
                "status": "applied",
                "method": "sigmoid",
                "rows": int(len(calibration_urls)),
            }
        except ValueError as exc:
            metadata["calibration"] = {
                "status": "skipped",
                "reason": str(exc),
                "rows": int(len(calibration_urls)),
            }
    elif calibration_urls and calibration_labels:
        metadata["calibration"] = {
            "status": "skipped",
            "reason": "insufficient_validation_rows",
            "rows": int(len(calibration_urls)),
        }

    return ModelBundle(calibrated_model=calibrated_estimator, explainer_model=explainer_model, metadata=metadata)
