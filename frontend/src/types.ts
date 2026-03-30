export interface Reason {
  feature: string;
  label: string;
  value: string;
  impact: number;
}

export interface IntelHit {
  source: string;
  status: string;
  detail: string;
  url?: string | null;
  last_seen?: string | null;
}

export interface ScanResponse {
  normalized_url: string;
  verdict: string;
  phishing_probability: number;
  risk_band: "low" | "medium" | "high";
  reasons: Reason[];
  intel_hits: IntelHit[];
  model_version: string;
  scanned_at: string;
  deep_scan_status: string;
}

export interface ModelInfoResponse {
  model_version: string;
  model_id: string;
  model_family: string;
  training_window: Record<string, unknown>;
  validation_window: Record<string, unknown>;
  benchmark_window: Record<string, unknown>;
  feature_set_version: string;
  evaluation_mode: string;
  evaluation: Record<string, unknown>;
  runtime_thresholds: Record<string, unknown>;
  source_freshness: Record<string, unknown>;
}

export interface ModelSignalWeight {
  feature: string;
  label: string;
  weight: number;
  category: string;
}

export interface ModelHeatCell {
  category: string;
  metric: string;
  value: number;
}

export interface CorrelationFeature {
  key: string;
  name: string;
  label: string;
}

export interface FeatureCorrelation {
  rows: number;
  source?: string | null;
  features: CorrelationFeature[];
  matrix: number[][];
}

export interface ModelLeaderboardPreview {
  model_id: string;
  model_family: string;
  rank?: number | null;
  promotion_outcome?: string | null;
  benchmark_metrics: Record<string, unknown>;
}

export interface ModelDetailResponse {
  feature_correlation?: FeatureCorrelation | null;
  top_phishing_signals: ModelSignalWeight[];
  top_protective_signals: ModelSignalWeight[];
  signal_map: ModelHeatCell[];
  leaderboard: ModelLeaderboardPreview[];
  promotion?: Record<string, unknown> | null;
  calibration?: Record<string, unknown> | null;
}
