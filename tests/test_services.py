from __future__ import annotations

from baitdetector.modeling import resolve_runtime_thresholds
from baitdetector.services import AnalyzerService


def test_verdict_uses_runtime_thresholds_from_metadata() -> None:
    runtime_thresholds = {"suspicious": 0.2, "phishing": 0.4}
    service = AnalyzerService.__new__(AnalyzerService)
    service.bundle = type("Bundle", (), {"metadata": {"runtime_thresholds": runtime_thresholds, "evaluation": {}}})()

    assert resolve_runtime_thresholds(service.bundle.metadata) == runtime_thresholds
    assert service._verdict_for(0.3, []) == ("suspicious", "medium")
    assert service._verdict_for(0.45, []) == ("phishing", "high")
