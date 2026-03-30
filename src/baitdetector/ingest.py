from __future__ import annotations

import argparse
import bz2
import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

import pandas as pd
import requests

from .settings import get_settings
from .url_utils import normalize_url

PHISHING_DATABASE_URL = "https://phish.co.za/latest/ALL-phishing-links.lst"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json.bz2"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def _headers(app_key: str | None, user_agent: str) -> dict[str, str]:
    headers = {"User-Agent": user_agent}
    if app_key:
        headers["X-PhishTank-Application"] = app_key
    return headers


def download(url: str, headers: dict[str, str], timeout: int) -> tuple[bytes, dict[str, str]]:
    response = requests.get(url, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response.content, dict(response.headers)


def parse_phishing_database(content: bytes, observed_at: str) -> list[dict[str, object]]:
    rows = []
    for line in content.decode("utf-8", errors="ignore").splitlines():
        url = line.strip()
        if not url.startswith(("http://", "https://")):
            continue
        rows.append({"url": url, "label": 1, "source": "phishing_database", "observed_at": observed_at, "tranco_rank": None})
    return rows


def parse_phishtank(content: bytes) -> list[dict[str, object]]:
    payload = json.loads(bz2.decompress(content).decode("utf-8"))
    rows = []
    for entry in payload:
        url = str(entry.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        rows.append(
            {
                "url": url,
                "label": 1,
                "source": "phishtank",
                "observed_at": entry.get("verification_time") or entry.get("submission_time"),
                "tranco_rank": None,
            }
        )
    return rows


def parse_tranco(content: bytes, observed_at: str, limit: int) -> list[dict[str, object]]:
    rows = []
    with ZipFile(io.BytesIO(content)) as archive:
        first_member = archive.namelist()[0]
        with archive.open(first_member) as handle:
            reader = csv.reader(io.TextIOWrapper(handle, encoding="utf-8"))
            for idx, row in enumerate(reader):
                if idx >= limit:
                    break
                if len(row) < 2:
                    continue
                rank = int(row[0])
                domain = row[1].strip()
                rows.append(
                    {
                        "url": f"https://{domain}/",
                        "label": 0,
                        "source": "tranco",
                        "observed_at": observed_at,
                        "tranco_rank": rank,
                    }
                )
    return rows


def normalize_rows(rows: list[dict[str, object]]) -> pd.DataFrame:
    normalized_rows = []
    for row in rows:
        try:
            normalized = normalize_url(str(row["url"]))
        except ValueError:
            continue
        normalized_rows.append(
            {
                "url": row["url"],
                "normalized_url": normalized.normalized_url,
                "registrable_domain": normalized.registrable_domain,
                "label": int(row["label"]),
                "source": row["source"],
                "observed_at": row["observed_at"],
                "tranco_rank": row["tranco_rank"],
            }
        )

    frame = pd.DataFrame(normalized_rows).drop_duplicates(subset=["normalized_url", "label"])
    if frame.empty:
        return frame

    malicious_domains = set(frame.loc[frame["label"] == 1, "registrable_domain"])
    frame = frame.loc[
        ~((frame["label"] == 0) & (frame["registrable_domain"].isin(malicious_domains)))
    ].copy()
    frame["observed_at"] = pd.to_datetime(frame["observed_at"], utc=True, errors="coerce").fillna(pd.Timestamp.now(tz="UTC"))
    frame = frame.sort_values(["observed_at", "label"], ascending=[True, False]).reset_index(drop=True)
    return frame


def ingest_live(tranco_limit: int = 200_000) -> tuple[pd.DataFrame, dict[str, object], dict[str, bytes]]:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    headers = _headers(settings.phishtank_app_key, settings.source_user_agent)
    payloads: dict[str, bytes] = {}
    manifest: dict[str, object] = {"fetched_at": now.isoformat(), "sources": {}}

    phishing_content, phishing_headers = download(PHISHING_DATABASE_URL, headers, settings.request_timeout_seconds)
    phishtank_content, phishtank_headers = download(PHISHTANK_URL, headers, settings.request_timeout_seconds)
    tranco_content, tranco_headers = download(TRANCO_URL, headers, settings.request_timeout_seconds)

    payloads["phishing_database.lst"] = phishing_content
    payloads["phishtank.json.bz2"] = phishtank_content
    payloads["tranco.csv.zip"] = tranco_content

    phishing_observed_at = phishing_headers.get("last-modified", now.isoformat())
    tranco_observed_at = tranco_headers.get("last-modified", now.isoformat())

    rows = []
    rows.extend(parse_phishing_database(phishing_content, observed_at=phishing_observed_at))
    rows.extend(parse_phishtank(phishtank_content))
    rows.extend(parse_tranco(tranco_content, observed_at=tranco_observed_at, limit=tranco_limit))

    frame = normalize_rows(rows)
    manifest["sources"] = {
        "phishing_database": {"last_modified": phishing_headers.get("last-modified"), "count": int((frame["source"] == "phishing_database").sum())},
        "phishtank": {"last_modified": phishtank_headers.get("last-modified"), "count": int((frame["source"] == "phishtank").sum())},
        "tranco": {"last_modified": tranco_headers.get("last-modified"), "count": int((frame["source"] == "tranco").sum())},
    }
    manifest["total_rows"] = int(len(frame))
    return frame, manifest, payloads


def ingest_demo() -> tuple[pd.DataFrame, dict[str, object], dict[str, bytes]]:
    settings = get_settings()
    frame = pd.read_csv(settings.demo_data_path)
    frame["observed_at"] = pd.to_datetime(frame["observed_at"], utc=True)
    frame = normalize_rows(frame.to_dict(orient="records"))
    manifest = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "demo": {
                "last_modified": settings.demo_data_path.stat().st_mtime_ns,
                "count": int(len(frame)),
            }
        },
        "total_rows": int(len(frame)),
    }
    payloads = {"demo_training.csv": settings.demo_data_path.read_bytes()}
    return frame, manifest, payloads


def write_outputs(frame: pd.DataFrame, manifest: dict[str, object], raw_payloads: dict[str, bytes]) -> None:
    settings = get_settings()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_dir = settings.data_dir / "raw" / run_id
    normalized_dir = settings.data_dir / "normalized"
    raw_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)

    for name, payload in raw_payloads.items():
        (raw_dir / name).write_bytes(payload)

    frame.to_parquet(normalized_dir / f"urls-{run_id}.parquet", index=False)
    frame.to_parquet(normalized_dir / "latest.parquet", index=False)
    (normalized_dir / "latest_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest phishing and benign URL feeds.")
    parser.add_argument("--demo", action="store_true", help="Use the bundled demo dataset instead of live feeds.")
    parser.add_argument("--tranco-limit", type=int, default=200_000, help="How many Tranco rows to ingest.")
    args = parser.parse_args()

    if args.demo:
        frame, manifest, payloads = ingest_demo()
    else:
        frame, manifest, payloads = ingest_live(tranco_limit=args.tranco_limit)

    write_outputs(frame, manifest, payloads)
    print(f"Ingested {len(frame):,} rows into data/normalized/latest.parquet")


if __name__ == "__main__":
    main()

