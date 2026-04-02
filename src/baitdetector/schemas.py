from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Reason(BaseModel):
    feature: str
    label: str
    value: str
    impact: float


class IntelHit(BaseModel):
    source: str
    status: str
    detail: str
    url: str | None = None
    last_seen: str | None = None


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    deep_scan: bool = False


class ScanResponse(BaseModel):
    normalized_url: str
    verdict: str
    phishing_probability: float
    risk_band: str
    reasons: list[Reason]
    intel_hits: list[IntelHit]
    model_version: str
    scanned_at: datetime
    deep_scan_status: str


class ModelInfoResponse(BaseModel):
    model_version: str
    model_id: str
    model_family: str
    training_window: dict[str, Any]
    validation_window: dict[str, Any]
    benchmark_window: dict[str, Any]
    feature_set_version: str
    latest_ingestion_sources: dict[str, Any]
    evaluation_mode: str
    evaluation: dict[str, Any]
    runtime_thresholds: dict[str, Any]


class ModelSignalWeight(BaseModel):
    feature: str
    label: str
    weight: float
    category: str


class ModelHeatCell(BaseModel):
    category: str
    metric: str
    value: float


class CorrelationFeature(BaseModel):
    key: str
    name: str
    label: str


class FeatureCorrelation(BaseModel):
    rows: int
    source: str | None = None
    features: list[CorrelationFeature] = Field(default_factory=list)
    matrix: list[list[float]] = Field(default_factory=list)


class ModelLeaderboardPreview(BaseModel):
    model_id: str
    model_family: str
    rank: int | None = None
    promotion_outcome: str | None = None
    benchmark_metrics: dict[str, Any]


class ModelDetailResponse(BaseModel):
    feature_correlation: FeatureCorrelation | None = None
    top_phishing_signals: list[ModelSignalWeight]
    top_protective_signals: list[ModelSignalWeight]
    signal_map: list[ModelHeatCell]
    leaderboard: list[ModelLeaderboardPreview] = Field(default_factory=list)
    promotion: dict[str, Any] | None = None
    calibration: dict[str, Any] | None = None
