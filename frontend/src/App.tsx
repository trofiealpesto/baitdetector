import { AnimatePresence, motion } from "framer-motion";
import { Fragment, startTransition, useEffect, useLayoutEffect, useRef, useState, type CSSProperties } from "react";

import type { FeatureCorrelation, ModelDetailResponse, ModelInfoResponse, ScanResponse } from "./types";

type UiStage = "idle" | "results";
type VisualState = "idle" | "benign" | "suspicious" | "phishing";

const VISUAL_COPY: Record<VisualState, { title: string; caption: string }> = {
  idle: {
    title: "local model ready",
    caption: "paste a url above to score it without fetching the destination.",
  },
  benign: {
    title: "low-risk pattern",
    caption: "this looks closer to benign traffic than active phishing behavior.",
  },
  suspicious: {
    title: "needs review",
    caption: "several phishing indicators are present. review the destination before interacting with it.",
  },
  phishing: {
    title: "phishing likely",
    caption: "multiple signals stack toward a phishing verdict in the local model and feed context.",
  },
};

function toVisualState(riskBand?: ScanResponse["risk_band"]): VisualState {
  if (riskBand === "high") {
    return "phishing";
  }
  if (riskBand === "medium") {
    return "suspicious";
  }
  if (riskBand === "low") {
    return "benign";
  }
  return "idle";
}

function reasonIconKind(feature: string, label: string): "length" | "token" | "domain" | "redirect" | "signal" {
  const text = `${feature} ${label}`.toLowerCase();

  if (text.includes("length") || text.includes("entropy")) {
    return "length";
  }
  if (text.includes("token") || text.includes("login") || text.includes("verify") || text.includes("password")) {
    return "token";
  }
  if (text.includes("domain") || text.includes("host") || text.includes("subdomain") || text.includes("tld") || text.includes("ip")) {
    return "domain";
  }
  if (text.includes("redirect") || text.includes("query") || text.includes("path") || text.includes("url")) {
    return "redirect";
  }
  return "signal";
}

function ReasonIcon({ kind }: { kind: "length" | "token" | "domain" | "redirect" | "signal" }) {
  if (kind === "length") {
    return (
      <svg className="signal-icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4 12H20M7 9V15M12 8V16M17 9V15" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      </svg>
    );
  }
  if (kind === "token") {
    return (
      <svg className="signal-icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 3L20 7V12C20 17 16.5 20 12 21C7.5 20 4 17 4 12V7L12 3Z" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
        <path d="M12 8V12M12 15H12.01" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      </svg>
    );
  }
  if (kind === "domain") {
    return (
      <svg className="signal-icon" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" strokeWidth="1.7" />
        <path d="M4 12H20M12 4C14.5 6.2 16 9 16 12C16 15 14.5 17.8 12 20M12 4C9.5 6.2 8 9 8 12C8 15 9.5 17.8 12 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    );
  }
  if (kind === "redirect") {
    return (
      <svg className="signal-icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M7 8H17V14M17 8L7 18" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  return (
    <svg className="signal-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 4L13.8 9.2L19 11L13.8 12.8L12 18L10.2 12.8L5 11L10.2 9.2L12 4Z" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
    </svg>
  );
}

function RepoIcon() {
  return (
    <svg className="repo-icon" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M8 0C3.58 0 0 3.58 0 8C0 11.54 2.29 14.53 5.47 15.59C5.87 15.66 6.02 15.42 6.02 15.21C6.02 15.02 6.01 14.39 6.01 13.72C4 14.09 3.48 13.23 3.32 12.78C3.23 12.55 2.84 11.84 2.5 11.65C2.22 11.5 1.82 11.12 2.49 11.11C3.12 11.1 3.57 11.69 3.72 11.93C4.44 13.14 5.59 12.8 6.06 12.59C6.13 12.07 6.34 11.72 6.57 11.52C4.79 11.32 2.93 10.63 2.93 7.56C2.93 6.69 3.24 5.97 3.75 5.41C3.67 5.21 3.39 4.39 3.83 3.29C3.83 3.29 4.5 3.08 6.03 4.12C6.67 3.94 7.35 3.85 8.03 3.85C8.71 3.85 9.39 3.94 10.03 4.12C11.56 3.07 12.23 3.29 12.23 3.29C12.67 4.39 12.39 5.21 12.31 5.41C12.82 5.97 13.13 6.68 13.13 7.56C13.13 10.64 11.26 11.32 9.48 11.52C9.77 11.77 10.02 12.25 10.02 13C10.02 14.07 10.01 14.93 10.01 15.2C10.01 15.41 10.16 15.66 10.56 15.58C13.71 14.52 16 11.53 16 8C16 3.58 12.42 0 8 0Z"
        fill="currentColor"
      />
    </svg>
  );
}

function SignalDriverHelp({ impact, value, label }: { impact: number; value: string; label: string }) {
  const [open, setOpen] = useState(false);

  return (
    <span
      className="signal-help"
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
          setOpen(false);
        }
      }}
    >
      <button
        type="button"
        className="signal-help-button"
        aria-label={`Explain signal details for ${label}`}
        aria-expanded={open ? "true" : "false"}
        onClick={() => setOpen((current) => !current)}
      >
        i
      </button>
      {open ? (
        <span className="signal-help-popup" role="tooltip">
          <strong>Impact {impact >= 0 ? " +" : " "}{impact.toFixed(2)}</strong> shows how strongly this signal pushed the
          model score.
          {" "}
          {impact >= 0 ? "Positive values push toward phishing." : "Negative values pull away from phishing."}
          {" "}
          <strong>Value {value}</strong> is the raw URL trait that fired for this driver.
        </span>
      ) : null}
    </span>
  );
}

function formatImpact(impact: number): string {
  return `${impact >= 0 ? "+" : ""}${impact.toFixed(2)}`;
}

async function readErrorMessage(response: Response): Promise<string> {
  const fallback = response.status === 429 ? "rate limit exceeded. please wait and try again." : "analysis failed. try again.";
  try {
    const payload = (await response.json()) as { detail?: string };
    return payload.detail ?? fallback;
  } catch {
    return fallback;
  }
}

const STAGE_VARIANTS = {
  enter: (direction: number) => ({
    opacity: 0,
    x: direction >= 0 ? 20 : -20,
  }),
  center: {
    opacity: 1,
    x: 0,
    transition: {
      opacity: { duration: 0.14, ease: "easeOut" },
      x: { duration: 0.24, ease: [0.22, 1, 0.36, 1] },
    },
  },
  exit: (direction: number) => ({
    opacity: 0,
    x: direction >= 0 ? -20 : 20,
    transition: {
      opacity: { duration: 0.1, ease: "easeOut" },
      x: { duration: 0.18, ease: [0.4, 0, 0.2, 1] },
    },
  }),
};

const MODEL_LAB_VARIANTS = {
  enter: (direction: number) => ({
    opacity: 0,
    x: direction >= 0 ? 16 : -16,
  }),
  center: {
    opacity: 1,
    x: 0,
    transition: {
      opacity: { duration: 0.14, ease: "easeOut" },
      x: { duration: 0.22, ease: [0.22, 1, 0.36, 1] },
    },
  },
  exit: (direction: number) => ({
    opacity: 0,
    x: direction >= 0 ? -16 : 16,
    transition: {
      opacity: { duration: 0.1, ease: "easeOut" },
      x: { duration: 0.16, ease: [0.4, 0, 0.2, 1] },
    },
  }),
};

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return null;
}

function formatPercent(value: unknown, digits = 0): string {
  const numeric = asNumber(value);
  if (numeric === null) {
    return "n/a";
  }
  return `${(numeric * 100).toFixed(digits).replace(/\.0+$/, "")}%`;
}

function formatShortDate(value: unknown): string {
  if (!value) {
    return "n/a";
  }

  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) {
    return String(value);
  }

  return parsed.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

function correlationCellStyle(value: number): CSSProperties {
  const clamped = Math.min(Math.max(value, -1), 1);
  const strength = Math.abs(clamped);
  const tone = clamped >= 0 ? "191, 46, 31" : "49, 98, 214";
  return {
    backgroundColor: `rgba(${tone}, ${0.08 + strength * 0.78})`,
    color: strength > 0.58 ? "#ffffff" : "var(--ink)",
  };
}

type CorrelationFeatureItem = FeatureCorrelation["features"][number];

function shortFeatureLabel(name: string): string {
  return name
    .replace(/^num_/, "")
    .replace(/^has_/, "")
    .replace(/^is_/, "")
    .replace(/^tld_is_/, "tld ")
    .replaceAll("_", " ");
}

function buildCorrelationFocus(correlation: FeatureCorrelation, limit = 8, pairLimit = 4) {
  const features = correlation.features;
  const matrix = correlation.matrix;
  if (features.length === 0 || matrix.length === 0) {
    return null;
  }

  const ranked = features
    .map((feature, index) => {
      const row = matrix[index] ?? [];
      const total = row.reduce((sum, value, columnIndex) => {
        if (columnIndex === index) {
          return sum;
        }
        return sum + Math.abs(value ?? 0);
      }, 0);
      const average = features.length > 1 ? total / (features.length - 1) : 0;
      return { feature, index, score: average };
    })
    .sort((left, right) => right.score - left.score)
    .slice(0, Math.min(limit, features.length));

  const selectedIndexes = ranked.map((item) => item.index);
  const selectedFeatures = ranked.map((item) => item.feature);
  const selectedMatrix = selectedIndexes.map((rowIndex) =>
    selectedIndexes.map((columnIndex) => matrix[rowIndex]?.[columnIndex] ?? 0),
  );

  const strongestPairs: Array<{
    left: CorrelationFeatureItem;
    right: CorrelationFeatureItem;
    value: number;
  }> = [];

  for (let rowIndex = 0; rowIndex < selectedFeatures.length; rowIndex += 1) {
    for (let columnIndex = rowIndex + 1; columnIndex < selectedFeatures.length; columnIndex += 1) {
      strongestPairs.push({
        left: selectedFeatures[rowIndex],
        right: selectedFeatures[columnIndex],
        value: selectedMatrix[rowIndex]?.[columnIndex] ?? 0,
      });
    }
  }

  strongestPairs.sort((left, right) => Math.abs(right.value) - Math.abs(left.value));

  return {
    features: selectedFeatures,
    matrix: selectedMatrix,
    strongestPairs: strongestPairs.slice(0, pairLimit),
  };
}

export default function App() {
  const [uiStage, setUiStage] = useState<UiStage>("idle");
  const [stageDirection, setStageDirection] = useState(1);
  const [draftUrl, setDraftUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [fieldError, setFieldError] = useState("");
  const [modelInfo, setModelInfo] = useState<ModelInfoResponse | null>(null);
  const [modelInfoError, setModelInfoError] = useState("");
  const [modelDetails, setModelDetails] = useState<ModelDetailResponse | null>(null);
  const [modelDetailsError, setModelDetailsError] = useState("");
  const [modelDetailsOpen, setModelDetailsOpen] = useState(false);
  const [mobileUnderHoodOpen, setMobileUnderHoodOpen] = useState(false);
  const [modelLabDirection, setModelLabDirection] = useState(1);
  const [loadingModelDetails, setLoadingModelDetails] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [heightLockActive, setHeightLockActive] = useState(false);
  const [shellHeight, setShellHeight] = useState<number | null>(null);
  const [isNarrowViewport, setIsNarrowViewport] = useState(() =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia("(max-width: 640px)").matches
      : false,
  );
  const measureRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let active = true;

    async function loadModelInfo() {
      try {
        const response = await fetch("/api/model-info");
        if (!response.ok) {
          throw new Error("Unable to load model metadata.");
        }
        const payload = (await response.json()) as ModelInfoResponse;
        if (!active) {
          return;
        }
        setModelInfo(payload);
      } catch (error) {
        if (!active) {
          return;
        }
        setModelInfoError(error instanceof Error ? error.message : "Unable to load model metadata.");
      }
    }

    void loadModelInfo();

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }

    const mediaQuery = window.matchMedia("(max-width: 640px)");
    const updateViewport = () => {
      setIsNarrowViewport(mediaQuery.matches);
    };

    updateViewport();

    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", updateViewport);
      return () => {
        mediaQuery.removeEventListener("change", updateViewport);
      };
    }

    mediaQuery.addListener(updateViewport);
    return () => {
      mediaQuery.removeListener(updateViewport);
    };
  }, []);

  useEffect(() => {
    if (isNarrowViewport) {
      setModelDetailsOpen(false);
      setMobileUnderHoodOpen(false);
    }
  }, [isNarrowViewport]);

  useLayoutEffect(() => {
    const element = measureRef.current;
    if (!element) {
      return;
    }

    let cancelled = false;

    const updateHeight = () => {
      if (cancelled) {
        return;
      }
      const nextHeight = Math.ceil(element.getBoundingClientRect().height);
      if (nextHeight > 0) {
        setShellHeight((current) => (current === nextHeight ? current : nextHeight));
      }
    };

    updateHeight();
    const frameOne = window.requestAnimationFrame(() => {
      const frameTwo = window.requestAnimationFrame(updateHeight);
      if (cancelled) {
        window.cancelAnimationFrame(frameTwo);
      }
    });

    const handleResize = () => {
      updateHeight();
    };
    window.addEventListener("resize", handleResize);

    const fonts = "fonts" in document ? document.fonts : undefined;
    void fonts?.ready.then(() => {
      updateHeight();
    });
    const observer =
      typeof ResizeObserver === "undefined"
        ? null
        : new ResizeObserver(() => {
            updateHeight();
          });
    observer?.observe(element);

    return () => {
      cancelled = true;
      window.cancelAnimationFrame(frameOne);
      window.removeEventListener("resize", handleResize);
      observer?.disconnect();
    };
  }, [uiStage, result, modelInfo, modelInfoError, fieldError, modelDetailsOpen, mobileUnderHoodOpen, modelDetails, modelDetailsError, loadingModelDetails, isNarrowViewport]);
  const visualState = toVisualState(result?.risk_band);
  const stageCopy = VISUAL_COPY[visualState];
  const reasons = result?.reasons.slice(0, 3) ?? [];
  const intelHits = result?.intel_hits.slice(0, 2) ?? [];
  const score = result ? Math.round(result.phishing_probability * 100) : 0;
  const evaluation = asRecord(modelInfo?.evaluation) ?? {};
  const runtimeThresholds = asRecord(modelInfo?.runtime_thresholds) ?? asRecord(evaluation["runtime_thresholds"]) ?? {};
  const featureCorrelation = modelDetails?.feature_correlation ?? null;
  const isMobileIdleCollapsed = isNarrowViewport && uiStage === "idle" && !mobileUnderHoodOpen;
  const suspiciousThreshold = asNumber(runtimeThresholds["suspicious"]) ?? 0.25;
  const phishingThreshold = asNumber(runtimeThresholds["phishing"]) ?? 0.45;
  const pipelineRows = [
    {
      label: "last ingestion",
      value: modelInfo ? formatShortDate(modelInfo.last_ingestion_at) : modelInfoError || "loading...",
    },
    {
      label: "last training",
      value: modelInfo ? formatShortDate(modelInfo.last_training_at) : modelInfoError || "loading...",
    },
  ];
  function renderUnderTheHood() {
    return (
      <div className="underhood-grid">
        <section className="model-card">
          <div className="section-header">
            <p className="panel-label">model snapshot</p>
          </div>
          <div className="info-list">
            <div className="info-row">
              <span className="info-key">version</span>
              <span className="info-value">{modelInfo ? modelInfo.model_version : "loading..."}</span>
            </div>
            <div className="info-row">
              <span className="info-key">feature set</span>
              <span className="info-value">{modelInfo ? modelInfo.feature_set_version : "loading..."}</span>
            </div>
          </div>
          <div className="section-header">
            <p className="panel-label">latest pipeline</p>
          </div>
          <div className="info-list">
            {pipelineRows.map((row) => (
              <div className="info-row" key={row.label}>
                <span className="info-key">{row.label}</span>
                <span className="info-value">{row.value}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="model-card">
          <div className="section-header">
            <p className="panel-label">decision bands</p>
          </div>
          <div className="threshold-viz" aria-label="runtime thresholds">
            <div className="threshold-track">
              <span className="threshold-zone threshold-zone--low" style={{ width: `${suspiciousThreshold * 100}%` }} />
              <span
                className="threshold-zone threshold-zone--mid"
                style={{ width: `${Math.max((phishingThreshold - suspiciousThreshold) * 100, 0)}%` }}
              />
              <span
                className="threshold-zone threshold-zone--high"
                style={{ width: `${Math.max((1 - phishingThreshold) * 100, 0)}%` }}
              />
              <span className="threshold-marker" style={{ left: `${suspiciousThreshold * 100}%` }} />
              <span className="threshold-marker threshold-marker--high" style={{ left: `${phishingThreshold * 100}%` }} />
            </div>
            <div className="threshold-meta">
              <span>{`review ${formatPercent(suspiciousThreshold)}`}</span>
              <span>{`phishing ${formatPercent(phishingThreshold)}`}</span>
            </div>
          </div>
        </section>
      </div>
    );
  }

  async function loadModelDetails() {
    if (loadingModelDetails || modelDetails) {
      return;
    }

    setLoadingModelDetails(true);
    setModelDetailsError("");
    try {
      const response = await fetch("/api/model-details");
      if (!response.ok) {
        throw new Error("Unable to load model lab details.");
      }
      const payload = (await response.json()) as ModelDetailResponse;
      setModelDetails(payload);
    } catch (error) {
      setModelDetailsError(error instanceof Error ? error.message : "Unable to load model lab details.");
    } finally {
      setLoadingModelDetails(false);
    }
  }

  function toggleModelDetails() {
    const currentHeight = measureRef.current
      ? Math.ceil(measureRef.current.getBoundingClientRect().height)
      : shellHeight;
    const nextOpen = !modelDetailsOpen;
    setHeightLockActive(true);
    setShellHeight(currentHeight);
    setModelLabDirection(nextOpen ? 1 : -1);
    setModelDetailsOpen(nextOpen);
    if (nextOpen) {
      void loadModelDetails();
    }
  }

  function toggleMobileUnderHood() {
    const currentHeight = measureRef.current
      ? Math.ceil(measureRef.current.getBoundingClientRect().height)
      : shellHeight;
    const nextOpen = !mobileUnderHoodOpen;
    setHeightLockActive(true);
    setShellHeight(currentHeight);
    setModelLabDirection(nextOpen ? 1 : -1);
    setMobileUnderHoodOpen(nextOpen);
  }

  function renderModelLab() {
    const heatmap = featureCorrelation as FeatureCorrelation | null;
    const compactHeatmap = heatmap ? buildCorrelationFocus(heatmap, isNarrowViewport ? 5 : 8, isNarrowViewport ? 2 : 4) : null;
    const heatmapColumns = compactHeatmap?.features.length ?? 0;
    const heatmapLabelWidth = isNarrowViewport ? 60 : 108;
    const heatmapCellSize = isNarrowViewport ? 20 : 32;
    const heatmapGridStyle =
      heatmapColumns > 0
        ? { gridTemplateColumns: `minmax(${heatmapLabelWidth}px, ${heatmapLabelWidth}px) repeat(${heatmapColumns}, minmax(${heatmapCellSize}px, ${heatmapCellSize}px))` }
        : undefined;

    return (
      <section className="model-lab-panel">
        <div className="section-header">
          <p className="panel-label">correlation focus</p>
          <p className="model-lab-copy">
            A compact read on the most interrelated lexical signals in the current training corpus.
          </p>
        </div>

        {loadingModelDetails && !modelDetails ? (
          <p className="empty-state">loading model details...</p>
        ) : null}

        {modelDetailsError ? <p className="field-error">{modelDetailsError}</p> : null}

        {heatmap && compactHeatmap ? (
          <div className="lab-compact-layout">
            <section className="lab-compact-card lab-compact-card--matrix">
              <div className="compact-correlation-grid" style={heatmapGridStyle} role="img" aria-label="Compact feature correlation heatmap">
                <div className="compact-correlation-corner">
                  <div className="correlation-legend" aria-hidden="true">
                    <span>-1</span>
                    <span className="correlation-legend-bar" />
                    <span>+1</span>
                  </div>
                </div>
                {compactHeatmap.features.map((feature) => (
                  <div
                    className="compact-correlation-col"
                    key={`column-${feature.key}`}
                    title={`${feature.label}`}
                  >
                    {shortFeatureLabel(feature.name)}
                  </div>
                ))}
                {compactHeatmap.features.map((rowFeature, rowIndex) => (
                  <Fragment key={rowFeature.key}>
                    <div className="compact-correlation-row" title={rowFeature.label}>
                      {shortFeatureLabel(rowFeature.name)}
                    </div>
                    {compactHeatmap.features.map((columnFeature, columnIndex) => {
                      const value = compactHeatmap.matrix[rowIndex]?.[columnIndex] ?? 0;
                      return (
                        <div
                          className={`compact-correlation-cell${rowIndex === columnIndex ? " compact-correlation-cell--diagonal" : ""}`}
                          key={`${rowFeature.key}-${columnFeature.key}`}
                          style={correlationCellStyle(value)}
                          title={`${rowFeature.name} x ${columnFeature.name}: ${value.toFixed(2)}`}
                        >
                          {value.toFixed(2)}
                        </div>
                      );
                    })}
                  </Fragment>
                ))}
              </div>
            </section>

            <aside className="lab-compact-card lab-compact-card--aside">
              <div className="section-header">
                <p className="panel-label">strongest links</p>
              </div>
              <div className="lab-stat-list">
                <div className="lab-stat-item">
                  <span className="lab-stat-key">rows</span>
                  <span className="lab-stat-value">{heatmap.rows}</span>
                </div>
                <div className="lab-stat-item">
                  <span className="lab-stat-key">source</span>
                  <span className="lab-stat-value">{heatmap.source === "training_corpus" ? "training corpus" : "latest snapshot"}</span>
                </div>
              </div>
              <div className="lab-pair-list">
                {compactHeatmap.strongestPairs.map((pair) => (
                  <div className="lab-pair-item" key={`${pair.left.key}-${pair.right.key}`}>
                    <div className="lab-pair-copy">
                      <span className="lab-pair-title">{`${shortFeatureLabel(pair.left.name)} x ${shortFeatureLabel(pair.right.name)}`}</span>
                      <span className="lab-pair-caption">
                        {pair.value >= 0 ? "move together strongly" : "pull in opposite directions"}
                      </span>
                    </div>
                    <span className="lab-pair-value">{`${pair.value >= 0 ? "+" : ""}${pair.value.toFixed(2)}`}</span>
                  </div>
                ))}
              </div>
            </aside>
          </div>
        ) : modelDetails ? (
          <p className="empty-state">correlation details are not available for the current promoted bundle.</p>
        ) : null}
      </section>
    );
  }

  async function runScan(url: string) {
    const trimmedUrl = url.trim();
    if (!trimmedUrl) {
      setFieldError("enter a url to inspect.");
      startTransition(() => setUiStage("idle"));
      return;
    }

    setSubmitting(true);
    setFieldError("");

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: trimmedUrl,
        }),
      });

      if (!response.ok) {
        const message = await readErrorMessage(response);
        startTransition(() => {
          setFieldError(message);
          setUiStage("idle");
        });
        return;
      }

      const payload = (await response.json()) as ScanResponse;
      const currentHeight = measureRef.current
        ? Math.ceil(measureRef.current.getBoundingClientRect().height)
        : shellHeight;
      startTransition(() => {
        setHeightLockActive(true);
        setShellHeight(currentHeight);
        setStageDirection(1);
        setResult(payload);
        setDraftUrl(trimmedUrl);
        setFieldError("");
        setUiStage("results");
      });
    } catch {
      startTransition(() => {
        setFieldError("network error. try again.");
        setUiStage("idle");
      });
    } finally {
      setSubmitting(false);
    }
  }

  function handleIdleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runScan(draftUrl);
  }

  function handleReturnToIdle() {
    const currentHeight = measureRef.current
      ? Math.ceil(measureRef.current.getBoundingClientRect().height)
      : shellHeight;
    startTransition(() => {
      setHeightLockActive(true);
      setShellHeight(currentHeight);
      setStageDirection(-1);
      setUiStage("idle");
      setResult(null);
      setDraftUrl("");
      setFieldError("");
      setMobileUnderHoodOpen(false);
    });
  }

  return (
    <main className="app-shell">
      <div className="background-video" aria-hidden="true">
        <video autoPlay muted loop playsInline preload="auto">
          <source src="/media/background-loop.webm" type="video/webm" />
        </video>
      </div>

      <div className={`app-grid${isMobileIdleCollapsed ? " app-grid--mobile-centered" : ""}`}>
        <motion.section className={`left-column${isMobileIdleCollapsed ? " left-column--mobile-centered" : ""}`}>
          <motion.div className="title-row">
            <h1 className="brand-title">baitdetector</h1>
            <a
              className="repo-link"
              href="https://github.com/trofiealpesto/baitdetector"
              target="_blank"
              rel="noreferrer"
              aria-label="Open the BaitDetector GitHub repository"
            >
              <RepoIcon />
              <span className="sr-only">GitHub repository</span>
            </a>
          </motion.div>

          <motion.section className="ui-shell" data-ui-stage={uiStage}>
            <motion.div
              className="stage-shell"
              initial={false}
              style={shellHeight !== null ? { height: shellHeight } : undefined}
              animate={heightLockActive && shellHeight !== null ? { height: shellHeight } : undefined}
              transition={{ height: { duration: 0.26, ease: [0.22, 1, 0.36, 1] } }}
            >
              <div className="stage-measure" ref={measureRef}>
                <AnimatePresence mode="wait" initial={false} custom={stageDirection}>
                  {uiStage === "idle" ? (
                    <motion.section
                      key="idle"
                      className="stage-panel stage-panel--idle"
                      custom={stageDirection}
                      variants={STAGE_VARIANTS}
                      initial="enter"
                      animate="center"
                      exit="exit"
                    >
                    <div className="idle-top">
                      <form className="scan-form" onSubmit={handleIdleSubmit} noValidate>
                        <div className="scan-bar">
                          <input
                            id="url"
                            name="url"
                            type="text"
                            className="scan-input"
                            placeholder="paste a url to inspect"
                            value={draftUrl}
                            autoComplete="off"
                            spellCheck={false}
                            aria-invalid={fieldError ? "true" : "false"}
                            onChange={(event) => setDraftUrl(event.target.value)}
                            disabled={submitting}
                          />
                          <motion.button
                            type="submit"
                            className="submit-button"
                            whileTap={{ scale: 0.98 }}
                            disabled={submitting}
                          >
                            {submitting ? "working..." : "inspect"}
                          </motion.button>
                        </div>

                        <div className="field-error" aria-live="polite">
                          {fieldError}
                        </div>
                      </form>
                    </div>

                    <div
                      className={`idle-info${isNarrowViewport ? " idle-info--mobile" : ""}${isNarrowViewport && !mobileUnderHoodOpen ? " idle-info--collapsed" : ""}`}
                    >
                      {isNarrowViewport ? (
                        <div className="idle-info-head idle-info-head--mobile">
                          <button
                            type="button"
                            className="mobile-underhood-toggle"
                            aria-expanded={mobileUnderHoodOpen ? "true" : "false"}
                            onClick={toggleMobileUnderHood}
                          >
                            <span className="panel-label">under the hood</span>
                            <span className="mobile-underhood-toggle-copy">
                              {mobileUnderHoodOpen ? "hide details" : "show details"}
                            </span>
                          </button>
                        </div>
                      ) : (
                        <div className="idle-info-head idle-info-head--split">
                          <p className="panel-label">{modelDetailsOpen ? "model lab" : "under the hood"}</p>
                          <button type="button" className="model-lab-toggle" onClick={toggleModelDetails}>
                            {modelDetailsOpen ? "back to summary" : "open model lab"}
                          </button>
                        </div>
                      )}
                      <AnimatePresence mode="wait" initial={false} custom={modelLabDirection}>
                        {isNarrowViewport ? (
                          mobileUnderHoodOpen ? (
                            <motion.div
                              key="mobile-under-the-hood"
                              className="idle-detail-panel"
                              custom={modelLabDirection}
                              variants={MODEL_LAB_VARIANTS}
                              initial="enter"
                              animate="center"
                              exit="exit"
                            >
                              {renderUnderTheHood()}
                            </motion.div>
                          ) : null
                        ) : modelDetailsOpen ? (
                          <motion.div
                            key="model-lab"
                            className="idle-detail-panel"
                            custom={modelLabDirection}
                            variants={MODEL_LAB_VARIANTS}
                            initial="enter"
                            animate="center"
                            exit="exit"
                          >
                            {renderModelLab()}
                          </motion.div>
                        ) : (
                          <motion.div
                            key="under-the-hood"
                            className="idle-detail-panel"
                            custom={modelLabDirection}
                            variants={MODEL_LAB_VARIANTS}
                            initial="enter"
                            animate="center"
                            exit="exit"
                          >
                            {renderUnderTheHood()}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                    </motion.section>
                  ) : (
                    <motion.section
                      key={result?.scanned_at ?? "results-empty"}
                      className="stage-panel"
                      custom={stageDirection}
                      variants={STAGE_VARIANTS}
                      initial="enter"
                      animate="center"
                      exit="exit"
                    >
                    {result ? (
                      <section className="result-shell" data-visual-state={visualState}>
                        <div className="result-hero">
                          <div className="score-block">
                            <span className="score-value">{score}%</span>
                            <span className="score-label">phishing probability</span>
                          </div>
                        </div>

                        <h2 className="panel-title result-title">{stageCopy.title}</h2>
                        <p className="panel-copy">{stageCopy.caption}</p>
                        <div className="result-url">{result.normalized_url}</div>

                        <div className="section-block">
                          <div className="section-header">
                            <p className="panel-label">signal drivers</p>
                          </div>
                          <div className="signal-list">
                            {reasons.map((reason) => (
                              <div className="signal-item" key={`${reason.feature}-${reason.label}`}>
                                <span className="signal-main">
                                  <ReasonIcon kind={reasonIconKind(reason.feature, reason.label)} />
                                  <span className="signal-name">{reason.label}</span>
                                </span>
                                <span className="signal-meta">
                                  <span className="signal-value">
                                    <span className="signal-stat">
                                      <span className="signal-stat-label">impact</span>
                                      <span>{formatImpact(reason.impact)}</span>
                                    </span>
                                    <span className="signal-stat-separator" aria-hidden="true">
                                      ·
                                    </span>
                                    <span className="signal-stat">
                                      <span className="signal-stat-label">value</span>
                                      <span>{reason.value}</span>
                                    </span>
                                  </span>
                                  <SignalDriverHelp impact={reason.impact} value={reason.value} label={reason.label} />
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>

                        <div className="section-block">
                          <div className="section-header">
                            <p className="panel-label">context</p>
                          </div>
                          <div className="context-list">
                            {intelHits.length > 0 ? (
                              intelHits.map((hit) => (
                                <div className="context-item" key={`${hit.source}-${hit.status}-${hit.detail}`}>
                                  <span className="context-copy">{`${hit.source} · ${hit.detail}`}</span>
                                  <span className="context-meta">{hit.status}</span>
                                </div>
                              ))
                            ) : (
                              <p className="empty-state">no additional local context hits were returned for this url.</p>
                            )}
                          </div>
                        </div>

                        <div className="rerun-form">
                          <motion.button
                            type="button"
                            className="rerun-button"
                            whileTap={{ scale: 0.98 }}
                            onClick={handleReturnToIdle}
                          >
                            <svg className="button-icon" viewBox="0 0 24 24" aria-hidden="true">
                              <path
                                d="M10 6L4 12L10 18M5 12H20"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="1.8"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                              />
                            </svg>
                            <span>run another analysis</span>
                          </motion.button>
                        </div>
                      </section>
                    ) : (
                      <div className="empty-results">
                        <p className="panel-label">results</p>
                        <h2 className="panel-title">analysis will appear here</h2>
                        <p className="panel-copy">submit a url from the idle stage to inspect it.</p>
                      </div>
                    )}
                    </motion.section>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          </motion.section>
        </motion.section>
      </div>
    </main>
  );
}
