from __future__ import annotations

from baitdetector.features import LexicalFeatureExtractor
from baitdetector.url_utils import redact_url_secrets


def _named_vector(url: str):
    extractor = LexicalFeatureExtractor(
        tranco_ranks={"github.com": 58},
        malicious_last_seen={"secure-paypa1-check.xyz": "2026-03-21T00:00:00+00:00"},
    )
    names = extractor.get_feature_names_out().tolist()
    values = extractor.transform([url])[0].tolist()
    return dict(zip(names, values))


def test_feature_extractor_flags_suspicious_patterns() -> None:
    values = _named_vector("http://185.193.88.17/account/login?redirect=https://paypal.com")
    assert values["has_ip_host"] == 1.0
    assert values["has_login_token"] == 1.0
    assert values["has_redirect_param"] == 1.0


def test_feature_extractor_uses_lookup_context() -> None:
    benign = _named_vector("https://github.com/login")
    suspicious = _named_vector("https://secure-paypa1-check.xyz/login")
    assert benign["tranco_rank_bucket"] < suspicious["tranco_rank_bucket"]
    assert suspicious["known_phishing_hit"] == 1.0


def test_feature_extractor_sanitizes_secret_like_inputs() -> None:
    raw_url = "https://compact.link/reset?mode=resetPassword&oobCode=UlNWwoLW0Nt5KimkaIVmA5WYa5gENFl3n2aBkBwEomsAAAGY5NMkHQ&apiKey=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
    assert _named_vector(raw_url) == _named_vector(redact_url_secrets(raw_url))
