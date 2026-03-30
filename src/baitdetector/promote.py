from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from .settings import get_settings


def load_metadata(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def should_promote(candidate: dict[str, Any], current: dict[str, Any] | None) -> bool:
    if candidate.get("evaluation_mode") == "bootstrap_fallback":
        return False

    promotion = candidate.get("promotion", {})
    if "recommended" in promotion:
        return bool(promotion["recommended"])

    if current is None:
        return True

    current_eval = current.get("evaluation", {})
    candidate_eval = candidate.get("evaluation", {})
    return (
        candidate_eval.get("pr_auc", 0.0) >= current_eval.get("pr_auc", 0.0)
        and candidate_eval.get("roc_auc", 0.0) >= current_eval.get("roc_auc", 0.0)
        and candidate_eval.get("false_positive_rate", 1.0) <= current_eval.get("false_positive_rate", 1.0)
    )


def _copy_if_exists(source: Path, target: Path) -> None:
    if source.exists():
        shutil.copy2(source, target)


def promote(force: bool = False) -> bool:
    settings = get_settings()
    candidate_metadata_path = settings.candidate_model_dir / "metadata.json"
    promoted_metadata_path = settings.model_dir / "metadata.json"

    candidate = load_metadata(candidate_metadata_path)
    if candidate is None:
        raise FileNotFoundError("No candidate model found. Run python -m baitdetector.train first.")

    current = load_metadata(promoted_metadata_path)
    if not force and not should_promote(candidate, current):
        return False

    settings.model_dir.mkdir(parents=True, exist_ok=True)
    _copy_if_exists(settings.candidate_model_dir / "model_bundle.joblib", settings.model_dir / "model_bundle.joblib")
    _copy_if_exists(candidate_metadata_path, promoted_metadata_path)
    _copy_if_exists(settings.candidate_model_dir / "training_summary.json", settings.model_dir / "training_summary.json")
    _copy_if_exists(settings.candidate_model_dir / "leaderboard.json", settings.model_dir / "leaderboard.json")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Promote a candidate model when metric gates pass.")
    parser.add_argument("--force", action="store_true", help="Promote even if metric gates would skip the candidate.")
    args = parser.parse_args()
    promoted = promote(force=args.force)
    print("promoted" if promoted else "skipped")


if __name__ == "__main__":
    main()
