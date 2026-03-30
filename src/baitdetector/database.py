from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache

from sqlalchemy import Boolean, DateTime, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .settings import Settings


class Base(DeclarativeBase):
    pass


class ScanMetric(Base):
    __tablename__ = "scan_metrics"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    verdict: Mapped[str] = mapped_column(String(32))
    risk_band: Mapped[str] = mapped_column(String(16))
    deep_scan_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    model_version: Mapped[str] = mapped_column(String(64))


@lru_cache(maxsize=4)
def get_engine(database_url: str):
    return create_engine(database_url, future=True)


@lru_cache(maxsize=4)
def get_session_factory(database_url: str):
    return sessionmaker(bind=get_engine(database_url), expire_on_commit=False, future=True)


def init_database(settings: Settings) -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(get_engine(settings.database_url))


def record_scan(settings: Settings, verdict: str, risk_band: str, deep_scan_requested: bool, model_version: str) -> None:
    session_factory = get_session_factory(settings.database_url)
    with session_factory() as session:
        session.add(
            ScanMetric(
                verdict=verdict,
                risk_band=risk_band,
                deep_scan_requested=deep_scan_requested,
                model_version=model_version,
            )
        )
        session.commit()

