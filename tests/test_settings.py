from __future__ import annotations

from pathlib import Path

from baitdetector.settings import _normalize_database_url, _resolve_project_root, get_settings


def test_normalize_database_url_handles_railway_postgres_urls() -> None:
    assert _normalize_database_url("postgres://user:pass@host:5432/baitdetector") == (
        "postgresql+psycopg://user:pass@host:5432/baitdetector"
    )
    assert _normalize_database_url("postgresql://user:pass@host:5432/baitdetector") == (
        "postgresql+psycopg://user:pass@host:5432/baitdetector"
    )


def test_normalize_database_url_leaves_sqlite_and_explicit_driver_urls_unchanged() -> None:
    assert _normalize_database_url("sqlite:////tmp/baitdetector.db") == "sqlite:////tmp/baitdetector.db"
    assert _normalize_database_url("postgresql+psycopg://user:pass@host:5432/baitdetector") == (
        "postgresql+psycopg://user:pass@host:5432/baitdetector"
    )


def test_resolve_project_root_prefers_environment_override(monkeypatch) -> None:
    monkeypatch.setenv("BAITDETECTOR_PROJECT_ROOT", "/tmp/baitdetector-app")

    assert _resolve_project_root() == Path("/tmp/baitdetector-app").resolve()


def test_get_settings_prefers_explicit_data_and_model_dirs(monkeypatch, tmp_path) -> None:
    custom_data_dir = tmp_path / "custom-data"
    custom_model_dir = tmp_path / "runtime-model"
    custom_data_dir.mkdir(parents=True, exist_ok=True)
    custom_model_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("BAITDETECTOR_PROJECT_ROOT", str(tmp_path / "project-root"))
    monkeypatch.setenv("BAITDETECTOR_DATA_DIR", str(custom_data_dir))
    monkeypatch.setenv("BAITDETECTOR_MODEL_DIR", str(custom_model_dir))
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.data_dir == custom_data_dir.resolve()
    assert settings.model_dir == custom_model_dir.resolve()
    assert settings.candidate_model_dir == custom_data_dir.resolve() / "models" / "candidate"

    get_settings.cache_clear()
