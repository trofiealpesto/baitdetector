from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

from .url_utils import NormalizedURL, normalize_url, redact_url_secrets

FEATURE_SET_VERSION = "2026-03-22"

SHORTENER_HOSTS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
}

COMMON_TLDS = {"com", "org", "net", "edu", "gov"}
HIGH_RISK_TLDS = {"biz", "click", "club", "info", "live", "online", "shop", "site", "top", "xyz"}
SUSPICIOUS_TOKENS = ("account", "confirm", "login", "password", "secure", "update", "verify", "wallet")
REDIRECT_KEYS = {"continue", "next", "redirect", "return", "target", "url"}

FEATURE_LABELS = {
    "lexical__url_length": "Unusually long URL",
    "lexical__hostname_length": "Long hostname",
    "lexical__path_length": "Long path segment",
    "lexical__query_length": "Long query string",
    "lexical__registrable_domain_length": "Long registrable domain",
    "lexical__subdomain_depth": "Deep subdomain nesting",
    "lexical__num_digits": "Heavy use of digits",
    "lexical__num_dots": "Many dot-separated segments",
    "lexical__num_hyphens": "Hyphen-heavy URL",
    "lexical__num_underscores": "Underscore-heavy URL",
    "lexical__num_slashes": "Many path separators",
    "lexical__num_query_params": "Many query parameters",
    "lexical__has_https": "Uses HTTPS",
    "lexical__has_at_symbol": "@ symbol in URL",
    "lexical__has_login_token": "Contains 'login' token",
    "lexical__has_verify_token": "Contains 'verify' token",
    "lexical__has_secure_token": "Contains 'secure' token",
    "lexical__has_update_token": "Contains 'update' token",
    "lexical__has_account_token": "Contains 'account' token",
    "lexical__has_redirect_param": "Contains redirect-style query parameters",
    "lexical__has_ip_host": "Uses raw IP address as host",
    "lexical__has_punycode": "Uses punycode host labels",
    "lexical__is_shortener": "Uses URL shortener domain",
    "lexical__tld_is_common": "Uses common TLD",
    "lexical__tld_is_high_risk": "Uses high-risk TLD pattern",
    "lexical__tranco_rank_bucket": "Domain is absent from known popular-domain rankings",
    "lexical__known_phishing_hit": "Matched a known phishing feed",
    "lexical__known_phishing_freshness": "Recent local phishing-feed match",
    "lexical__entropy": "High URL entropy",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def rank_bucket(rank: int | None) -> float:
    if rank is None or rank <= 0:
        return 5.0
    if rank <= 100:
        return 0.0
    if rank <= 1_000:
        return 1.0
    if rank <= 10_000:
        return 2.0
    if rank <= 100_000:
        return 3.0
    return 4.0


def recency_score(timestamp: str | None) -> float:
    if not timestamp:
        return 0.0
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    age_days = max(0.0, (now - parsed.astimezone(timezone.utc)).days)
    return max(0.0, 1.0 - min(age_days, 45.0) / 45.0)


def build_lookup_context(rows: Iterable[Mapping[str, Any]]) -> tuple[dict[str, int], dict[str, str]]:
    tranco_ranks: dict[str, int] = {}
    malicious_last_seen: dict[str, str] = {}

    for row in rows:
        domain = str(row.get("registrable_domain") or "").strip().lower()
        if not domain:
            continue
        label = int(row.get("label", 0))
        tranco_rank = row.get("tranco_rank")
        observed_at = str(row.get("observed_at") or "")

        if tranco_rank not in (None, "") and str(tranco_rank).lower() != "nan":
            rank = int(tranco_rank)
            existing = tranco_ranks.get(domain)
            if existing is None or rank < existing:
                tranco_ranks[domain] = rank

        if label == 1:
            current = malicious_last_seen.get(domain)
            if not current or observed_at > current:
                malicious_last_seen[domain] = observed_at

    return tranco_ranks, malicious_last_seen


class LexicalFeatureExtractor(BaseEstimator, TransformerMixin):
    feature_names_ = np.array(
        [
            "url_length",
            "hostname_length",
            "path_length",
            "query_length",
            "registrable_domain_length",
            "subdomain_depth",
            "num_digits",
            "num_dots",
            "num_hyphens",
            "num_underscores",
            "num_slashes",
            "num_query_params",
            "entropy",
            "has_https",
            "has_at_symbol",
            "has_login_token",
            "has_verify_token",
            "has_secure_token",
            "has_update_token",
            "has_account_token",
            "has_redirect_param",
            "has_ip_host",
            "has_punycode",
            "is_shortener",
            "tld_is_common",
            "tld_is_high_risk",
            "tranco_rank_bucket",
            "known_phishing_hit",
            "known_phishing_freshness",
        ],
        dtype=object,
    )

    def __init__(
        self,
        tranco_ranks: Mapping[str, int] | None = None,
        malicious_last_seen: Mapping[str, str] | None = None,
    ) -> None:
        self.tranco_ranks = tranco_ranks
        self.malicious_last_seen = malicious_last_seen

    def fit(self, X: Iterable[str], y: Any = None) -> "LexicalFeatureExtractor":
        return self

    def transform(self, X: Iterable[str]) -> np.ndarray:
        rows = [self._feature_row(normalize_url(redact_url_secrets(url))) for url in X]
        return np.asarray(rows, dtype=float)

    def get_feature_names_out(self, input_features: Any = None) -> np.ndarray:
        return self.feature_names_

    def _feature_row(self, normalized: NormalizedURL) -> list[float]:
        full_text = f"{normalized.host_ascii}{normalized.path}?{normalized.query}"
        lowered = normalized.normalized_url.lower()
        domain = normalized.registrable_domain.lower()
        tranco_ranks = self.tranco_ranks or {}
        malicious_last_seen = self.malicious_last_seen or {}
        tranco_rank = tranco_ranks.get(domain)
        last_seen = malicious_last_seen.get(domain)

        return [
            float(len(normalized.normalized_url)),
            float(len(normalized.host_ascii)),
            float(len(normalized.path)),
            float(len(normalized.query)),
            float(len(normalized.registrable_domain)),
            float(len([part for part in normalized.subdomain.split(".") if part])),
            float(sum(char.isdigit() for char in full_text)),
            float(normalized.normalized_url.count(".")),
            float(normalized.normalized_url.count("-")),
            float(normalized.normalized_url.count("_")),
            float(normalized.normalized_url.count("/")),
            float(len(normalized.query_pairs)),
            float(shannon_entropy(normalized.normalized_url)),
            float(normalized.scheme == "https"),
            float(normalized.has_userinfo or "@" in normalized.original_url),
            float("login" in lowered),
            float("verify" in lowered),
            float("secure" in lowered),
            float("update" in lowered),
            float("account" in lowered),
            float(any(key in REDIRECT_KEYS for key in normalized.query_keys)),
            float(normalized.is_ip_host),
            float(normalized.has_punycode),
            float(domain in SHORTENER_HOSTS or normalized.host_ascii in SHORTENER_HOSTS),
            float(normalized.tld in COMMON_TLDS),
            float(normalized.tld in HIGH_RISK_TLDS),
            rank_bucket(tranco_rank),
            float(domain in malicious_last_seen),
            recency_score(last_seen),
        ]
