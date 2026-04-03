from __future__ import annotations

import pytest

from baitdetector.url_utils import normalize_url, redact_url_secrets


def test_normalize_adds_https_and_strips_fragment() -> None:
    normalized = normalize_url("example.com/path#fragment")
    assert normalized.normalized_url == "https://example.com/path"
    assert normalized.registrable_domain == "example.com"


def test_normalize_detects_userinfo_punycode_and_ip() -> None:
    punycode = normalize_url("https://user:pass@xn--pple-43d.com/login")
    ip_host = normalize_url("http://185.193.88.17/secure")

    assert punycode.has_userinfo is True
    assert punycode.has_punycode is True
    assert ip_host.is_ip_host is True


def test_normalize_rejects_unsupported_scheme() -> None:
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")


def test_redact_url_secrets_masks_path_and_query_tokens() -> None:
    raw_url = (
        "https://example.com/123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
        "?apiKey=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
        "&oobCode=UlNWwoLW0Nt5KimkaIVmA5WYa5gENFl3n2aBkBwEomsAAAGY5NMkHQ"
    )

    sanitized = redact_url_secrets(raw_url)

    assert "AIza" not in sanitized
    assert "123456789:" not in sanitized
    assert "apiKey=redacted" in sanitized
    assert "oobCode=redacted" in sanitized


@pytest.mark.parametrize(
    "value",
    [
        "https//www.google.com",
        "https:/www.google.com",
        "ftp//example.com",
    ],
)
def test_normalize_rejects_malformed_scheme_like_inputs(value: str) -> None:
    with pytest.raises(ValueError, match="Malformed URL"):
        normalize_url(value)
