from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import json
from threading import Lock

from fastapi import HTTPException

from .database import record_scan
from .intel import IntelService
from .modeling import ModelBundle, load_model_bundle, resolve_runtime_thresholds
from .schemas import IntelHit, ModelInfoResponse, Reason, ScanResponse
from .settings import Settings
from .train import build_feature_correlation_summary, load_training_frame
from .url_utils import normalize_url


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def enforce(self, key: str) -> None:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] > self.window_seconds:
                events.popleft()
            if len(events) >= self.max_requests:
                raise HTTPException(status_code=429, detail="Rate limit exceeded. Please wait and try again.")
            events.append(now)


class AnalyzerService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.bundle: ModelBundle = load_model_bundle(settings.model_dir)
        self.intel_service = IntelService(settings)

    def model_info(self) -> ModelInfoResponse:
        payload = self.bundle.model_info()
        payload["last_ingestion_at"] = self._last_ingestion_at()
        return ModelInfoResponse(**payload)

    def model_details(self) -> dict[str, object]:
        details = self.bundle.model_details()
        leaderboard_path = self.settings.model_dir / "leaderboard.json"
        training_summary_path = self.settings.model_dir / "training_summary.json"
        feature_correlation = None

        leaderboard_preview: list[dict[str, object]] = []
        if leaderboard_path.exists():
            leaderboard_payload = json.loads(leaderboard_path.read_text(encoding="utf-8"))
            leaderboard_preview = [
                {
                    "model_id": str(entry.get("model_id", "unknown")),
                    "model_family": str(entry.get("model_family", "unknown")),
                    "rank": entry.get("rank"),
                    "promotion_outcome": entry.get("promotion_outcome"),
                    "benchmark_metrics": entry.get("benchmark_metrics", {}),
                }
                for entry in leaderboard_payload[:3]
            ]

        promotion = None
        if training_summary_path.exists():
            summary_payload = json.loads(training_summary_path.read_text(encoding="utf-8"))
            promotion = summary_payload.get("promotion")
            feature_correlation = summary_payload.get("feature_correlation")

        if feature_correlation is None:
            latest_snapshot_path = self.settings.data_dir / "normalized" / "latest.parquet"
            if latest_snapshot_path.exists():
                try:
                    frame = load_training_frame(str(latest_snapshot_path))
                    tranco_ranks, malicious_last_seen = self.bundle.get_lookup_context()
                    feature_correlation = build_feature_correlation_summary(
                        frame,
                        tranco_ranks=tranco_ranks,
                        malicious_last_seen=malicious_last_seen,
                        source="latest_snapshot_fallback",
                    )
                except (FileNotFoundError, ValueError, OSError):
                    feature_correlation = None

        return {
            **details,
            "feature_correlation": feature_correlation,
            "leaderboard": leaderboard_preview,
            "promotion": promotion,
        }

    def scan(self, url: str, deep_scan: bool = False) -> ScanResponse:
        normalized = normalize_url(url)
        intel_hits_raw, deep_scan_status = self.intel_service.gather(normalized, self.bundle, deep_scan=deep_scan)
        probability = self.bundle.predict_proba_one(normalized.normalized_url)
        verdict, risk_band = self._verdict_for(probability, intel_hits_raw)

        explanation_focus = "suspicious" if risk_band in {"high", "medium"} else "balanced"
        reasons = [Reason(**item) for item in self.bundle.explain(normalized.normalized_url, focus=explanation_focus)]
        intel_hits = [IntelHit(**item) for item in intel_hits_raw]
        scanned_at = datetime.now(timezone.utc)

        record_scan(
            self.settings,
            verdict=verdict,
            risk_band=risk_band,
            deep_scan_requested=deep_scan,
            model_version=self.bundle.metadata["model_version"],
        )

        return ScanResponse(
            normalized_url=normalized.normalized_url,
            verdict=verdict,
            phishing_probability=round(probability, 4),
            risk_band=risk_band,
            reasons=reasons,
            intel_hits=intel_hits,
            model_version=self.bundle.metadata["model_version"],
            scanned_at=scanned_at,
            deep_scan_status=deep_scan_status,
        )

    def _verdict_for(self, probability: float, intel_hits: list[dict[str, str | None]]) -> tuple[str, str]:
        malicious_match = any(hit.get("status") == "match" and hit.get("source") == "local-phishing-feeds" for hit in intel_hits)
        thresholds = resolve_runtime_thresholds(self.bundle.metadata)
        high_threshold = float(thresholds.get("phishing", 0.5))
        medium_threshold = float(thresholds.get("suspicious", max(0.02, round(high_threshold * 0.65, 4))))
        if malicious_match or probability >= high_threshold:
            return "phishing", "high"
        if probability >= medium_threshold:
            return "suspicious", "medium"
        return "benign", "low"

    def _last_ingestion_at(self) -> str | None:
        manifest_path = self.settings.data_dir / "normalized" / "latest_manifest.json"
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                manifest = None
            if isinstance(manifest, dict):
                fetched_at = manifest.get("fetched_at")
                if fetched_at:
                    return str(fetched_at)

        latest_snapshot_path = self.settings.data_dir / "normalized" / "latest.parquet"
        if latest_snapshot_path.exists():
            return datetime.fromtimestamp(latest_snapshot_path.stat().st_mtime, timezone.utc).isoformat()
        return None
