from __future__ import annotations

from pathlib import Path

from baitdetector.settings import _normalize_database_url, _resolve_project_root


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
