from __future__ import annotations

from typing import Any

from .modeling import ModelBundle
from .settings import Settings
from .url_utils import NormalizedURL


class IntelService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def gather(self, normalized: NormalizedURL, bundle: ModelBundle, deep_scan: bool = False) -> tuple[list[dict[str, Any]], str]:
        return self._local_hits(normalized, bundle), "skipped"

    def _local_hits(self, normalized: NormalizedURL, bundle: ModelBundle) -> list[dict[str, Any]]:
        tranco_ranks, malicious_last_seen = bundle.get_lookup_context()
        hits: list[dict[str, Any]] = []
        domain = normalized.registrable_domain

        if domain in malicious_last_seen:
            hits.append(
                {
                    "source": "local-phishing-feeds",
                    "status": "match",
                    "detail": "Registrable domain matched locally mirrored phishing signals.",
                    "last_seen": malicious_last_seen[domain],
                }
            )

        if domain in tranco_ranks:
            hits.append(
                {
                    "source": "tranco",
                    "status": "ranked",
                    "detail": f"Domain appears in Tranco at rank {tranco_ranks[domain]:,}.",
                    "last_seen": None,
                }
            )

        return hits
