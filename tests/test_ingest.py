from __future__ import annotations

import bz2
import io
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from baitdetector.ingest import normalize_rows, parse_phishing_database, parse_phishtank, parse_tranco


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_parse_phishing_database_fixture() -> None:
    rows = parse_phishing_database((FIXTURES / "phishing_database.lst").read_bytes(), observed_at="2026-03-21T00:00:00+00:00")
    assert len(rows) == 2
    assert all(row["label"] == 1 for row in rows)


def test_parse_phishtank_fixture() -> None:
    payload = bz2.compress((FIXTURES / "phishtank.json").read_bytes())
    rows = parse_phishtank(payload)
    assert len(rows) == 2
    assert rows[0]["source"] == "phishtank"


def test_parse_tranco_fixture_and_normalize_rows() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("top-1m.csv", (FIXTURES / "tranco.csv").read_text(encoding="utf-8"))

    benign_rows = parse_tranco(buffer.getvalue(), observed_at="2026-03-21T00:00:00+00:00", limit=3)
    phishing_rows = parse_phishing_database((FIXTURES / "phishing_database.lst").read_bytes(), observed_at="2026-03-21T00:00:00+00:00")
    frame = normalize_rows(benign_rows + phishing_rows)

    assert {"normalized_url", "registrable_domain", "label", "source"}.issubset(frame.columns)
    assert len(frame) == 5


def test_normalize_rows_redacts_secret_like_query_values() -> None:
    frame = normalize_rows(
        [
            {
                "url": "https://compact.link/reset?mode=resetPassword&oobCode=UlNWwoLW0Nt5KimkaIVmA5WYa5gENFl3n2aBkBwEomsAAAGY5NMkHQ&apiKey=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
                "label": 1,
                "source": "phishtank",
                "observed_at": "2026-04-03T00:00:00+00:00",
                "tranco_rank": None,
            }
        ]
    )

    record = frame.iloc[0].to_dict()
    assert "AIza" not in str(record["url"])
    assert "AIza" not in str(record["normalized_url"])
    assert "oobCode=redacted" in str(record["normalized_url"])
