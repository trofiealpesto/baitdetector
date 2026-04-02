from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    project_root: Path
    data_dir: Path
    model_dir: Path
    candidate_model_dir: Path
    demo_data_path: Path
    database_url: str
    rate_limit_requests: int
    rate_limit_window_seconds: int
    phishstats_api_url: str | None
    phishstats_api_key: str | None
    urlscan_api_url: str
    urlscan_api_key: str | None
    phishtank_app_key: str | None
    templates_dir: Path
    source_user_agent: str
    request_timeout_seconds: int


def _read_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


def _resolve_project_root() -> Path:
    configured = os.getenv("BAITDETECTOR_PROJECT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _resolve_path(name: str, default: Path) -> Path:
    configured = os.getenv(name)
    if configured:
        return Path(configured).expanduser().resolve()
    return default.resolve()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    project_root = _resolve_project_root()
    data_dir = _resolve_path("BAITDETECTOR_DATA_DIR", project_root / "data")
    model_dir = _resolve_path("BAITDETECTOR_MODEL_DIR", data_dir / "models" / "promoted")
    candidate_model_dir = data_dir / "models" / "candidate"
    database_url = _normalize_database_url(
        os.getenv("DATABASE_URL", f"sqlite:///{(data_dir / 'baitdetector.db').resolve()}")
    )
    demo_data_path = data_dir / "demo" / "demo_training.csv"
    if not demo_data_path.exists():
        demo_data_path = project_root / "data" / "demo" / "demo_training.csv"

    return Settings(
        project_root=project_root,
        data_dir=data_dir,
        model_dir=model_dir,
        candidate_model_dir=candidate_model_dir,
        demo_data_path=demo_data_path,
        database_url=database_url,
        rate_limit_requests=_read_int("RATE_LIMIT_REQUESTS", 15),
        rate_limit_window_seconds=_read_int("RATE_LIMIT_WINDOW_SECONDS", 60),
        phishstats_api_url=os.getenv("PHISHSTATS_API_URL"),
        phishstats_api_key=os.getenv("PHISHSTATS_API_KEY"),
        urlscan_api_url=os.getenv("URLSCAN_API_URL", "https://urlscan.io/api/v1/scan/"),
        urlscan_api_key=os.getenv("URLSCAN_API_KEY"),
        phishtank_app_key=os.getenv("PHISHTANK_APP_KEY"),
        templates_dir=Path(__file__).resolve().parent / "templates",
        source_user_agent=os.getenv("SOURCE_USER_AGENT", "baitdetector/0.2.0 (+https://github.com/giuva/baitdetector)"),
        request_timeout_seconds=_read_int("REQUEST_TIMEOUT_SECONDS", 30),
    )
