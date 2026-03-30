import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

function buildModelInfo() {
  return {
    model_version: "test-model",
    model_id: "logistic_baseline",
    model_family: "logistic_regression",
    training_window: {
      start: "2026-03-01T00:00:00+00:00",
      end: "2026-03-23T00:00:00+00:00",
      train_rows: 48,
      test_rows: 12,
    },
    validation_window: {
      start: "2026-03-16T00:00:00+00:00",
      end: "2026-03-19T00:00:00+00:00",
      rows: 12,
    },
    benchmark_window: {
      start: "2026-03-20T00:00:00+00:00",
      end: "2026-03-23T00:00:00+00:00",
      rows: 12,
    },
    feature_set_version: "features-v1",
    evaluation_mode: "temporal_benchmark",
    evaluation: {
      pr_auc: 0.92,
      roc_auc: 0.96,
      false_positive_rate: 0.03,
      decision_threshold: 0.41,
      runtime_thresholds: {
        suspicious: 0.19,
        phishing: 0.41,
      },
    },
    runtime_thresholds: {
      suspicious: 0.19,
      phishing: 0.41,
    },
    source_freshness: {
      demo: "2026-03-23T00:00:00+00:00",
    },
  };
}

function buildScanResponse() {
  return {
    normalized_url: "https://secure-paypa1-alert.xyz/login",
    verdict: "phishing",
    phishing_probability: 0.93,
    risk_band: "high",
    reasons: [
      { feature: "a", label: "reason one", value: "x", impact: 3.2 },
      { feature: "b", label: "reason two", value: "y", impact: 1.9 },
      { feature: "c", label: "reason three", value: "z", impact: 1.1 },
      { feature: "d", label: "reason four", value: "overflow", impact: 0.8 },
    ],
    intel_hits: [
      { source: "feed one", status: "match", detail: "hit one" },
      { source: "feed two", status: "review", detail: "hit two" },
      { source: "feed three", status: "review", detail: "hit three" },
    ],
    model_version: "test-model",
    scanned_at: "2026-03-23T12:00:00+00:00",
    deep_scan_status: "skipped",
  };
}

function buildModelDetails() {
  return {
    feature_correlation: {
      rows: 48,
      source: "training_corpus",
      features: [
        { key: "lexical__url_length", name: "url_length", label: "Unusually long URL" },
        { key: "lexical__num_digits", name: "num_digits", label: "Heavy use of digits" },
        { key: "lexical__num_hyphens", name: "num_hyphens", label: "Hyphen-heavy URL" },
      ],
      matrix: [
        [1, 0.61, 0.34],
        [0.61, 1, 0.19],
        [0.34, 0.19, 1],
      ],
    },
    top_phishing_signals: [
      { feature: "lexical__path_length", label: "Long path segment", weight: 2.4, category: "routing" },
      { feature: "lexical__has_verify_token", label: "Contains 'verify' token", weight: 1.6, category: "tokens" },
    ],
    top_protective_signals: [
      { feature: "lexical__has_https", label: "Uses HTTPS", weight: -0.9, category: "trust" },
    ],
    signal_map: [
      { category: "Structure", metric: "phishing_pull", value: 0.42 },
      { category: "Structure", metric: "protective_pull", value: 0.15 },
      { category: "Structure", metric: "feature_density", value: 0.6 },
      { category: "Tokens", metric: "phishing_pull", value: 0.81 },
      { category: "Tokens", metric: "protective_pull", value: 0.08 },
      { category: "Tokens", metric: "feature_density", value: 0.5 },
    ],
    leaderboard: [
      {
        model_id: "logistic_baseline",
        model_family: "logistic_regression",
        rank: 1,
        promotion_outcome: "promoted_candidate",
        benchmark_metrics: {
          pr_auc: 0.92,
          roc_auc: 0.96,
          false_positive_rate: 0.03,
        },
      },
    ],
    promotion: {
      recommended: true,
      reason: "shared_benchmark_win",
    },
    calibration: {
      status: "sigmoid",
    },
  };
}

describe("App", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the idle stage with the info block embedded in the card", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(buildModelInfo()));

    render(<App />);

    expect(await screen.findByRole("heading", { name: "baitdetector" })).toBeInTheDocument();
    expect(document.querySelector('[data-ui-stage="idle"]')).toBeInTheDocument();
    expect(screen.getByText("under the hood")).toBeInTheDocument();
    expect(screen.getByText("decision bands")).toBeInTheDocument();
    expect(screen.getByText("source freshness")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "open info" })).not.toBeInTheDocument();
  });

  it("shows results and caps visible reasons and intel hits", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse(buildModelInfo()))
      .mockResolvedValueOnce(jsonResponse(buildScanResponse()));

    render(<App />);

    const input = await screen.findByPlaceholderText("paste a url to inspect");
    await userEvent.type(input, "https://secure-paypa1-alert.xyz/login");
    await userEvent.click(screen.getByRole("button", { name: "inspect" }));

    expect(await screen.findByText("phishing likely")).toBeInTheDocument();
    expect(document.querySelector('[data-ui-stage="results"]')).toBeInTheDocument();
    expect(document.querySelector('[data-visual-state="phishing"]')).toBeInTheDocument();
    expect(screen.getByText("reason one")).toBeInTheDocument();
    expect(screen.getByText("reason two")).toBeInTheDocument();
    expect(screen.getByText("reason three")).toBeInTheDocument();
    expect(screen.queryByText("reason four")).not.toBeInTheDocument();
    expect(screen.getAllByText("impact").length).toBeGreaterThan(0);
    expect(screen.getAllByText("value").length).toBeGreaterThan(0);
    expect(screen.getByText("feed one · hit one")).toBeInTheDocument();
    expect(screen.getByText("feed two · hit two")).toBeInTheDocument();
    expect(screen.queryByText("feed three · hit three")).not.toBeInTheDocument();
  });

  it("opens the slide-up model lab and renders the compact correlation focus", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse(buildModelInfo()))
      .mockResolvedValueOnce(jsonResponse(buildModelDetails()));

    render(<App />);

    await screen.findByText("under the hood");
    await userEvent.click(screen.getByRole("button", { name: "open model lab" }));

    expect(await screen.findByText("correlation focus")).toBeInTheDocument();
    expect(await screen.findByText("strongest links")).toBeInTheDocument();
    expect(await screen.findByText("rows")).toBeInTheDocument();
    expect(await screen.findByText("source")).toBeInTheDocument();
    expect(await screen.findByText("48")).toBeInTheDocument();
    expect(await screen.findByText("training corpus")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Compact feature correlation heatmap" })).toBeInTheDocument();
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
  });

  it("explains signal driver numbers in a popup", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse(buildModelInfo()))
      .mockResolvedValueOnce(jsonResponse(buildScanResponse()));

    render(<App />);

    const input = await screen.findByPlaceholderText("paste a url to inspect");
    await userEvent.type(input, "https://secure-paypa1-alert.xyz/login");
    await userEvent.click(screen.getByRole("button", { name: "inspect" }));
    await screen.findByText("phishing likely");

    await userEvent.click(screen.getByRole("button", { name: "Explain signal details for reason one" }));

    expect(await screen.findByRole("tooltip")).toHaveTextContent("shows how strongly this signal pushed the model score");
    expect(screen.getByRole("tooltip")).toHaveTextContent("Value x");
  });

  it("keeps the interface in idle and shows inline validation on API errors", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse(buildModelInfo()))
      .mockResolvedValueOnce(jsonResponse({ detail: "Only http and https URLs are allowed." }, 422));

    render(<App />);

    const input = await screen.findByPlaceholderText("paste a url to inspect");
    await userEvent.type(input, "ftp://example.com");
    await userEvent.click(screen.getByRole("button", { name: "inspect" }));

    expect(await screen.findByText("Only http and https URLs are allowed.")).toBeInTheDocument();
    expect(document.querySelector('[data-ui-stage="idle"]')).toBeInTheDocument();
  });

  it("shows the inline red validation message for empty submissions", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(buildModelInfo()));

    render(<App />);

    await screen.findByPlaceholderText("paste a url to inspect");
    await userEvent.click(screen.getByRole("button", { name: "inspect" }));

    expect(await screen.findByText("enter a url to inspect.")).toBeInTheDocument();
    expect(document.querySelector('[data-ui-stage="idle"]')).toBeInTheDocument();
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it("returns to idle when the user chooses to run another analysis", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse(buildModelInfo()))
      .mockResolvedValueOnce(jsonResponse(buildScanResponse()));

    render(<App />);

    const input = await screen.findByPlaceholderText("paste a url to inspect");
    await userEvent.type(input, "https://secure-paypa1-alert.xyz/login");
    await userEvent.click(screen.getByRole("button", { name: "inspect" }));
    await screen.findByText("phishing likely");

    await userEvent.click(screen.getByRole("button", { name: "run another analysis" }));

    await waitFor(() => expect(document.querySelector('[data-ui-stage="idle"]')).toBeInTheDocument());
    expect(await screen.findByPlaceholderText("paste a url to inspect")).toHaveValue("");
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
  });
});
