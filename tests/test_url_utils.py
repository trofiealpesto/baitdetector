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


# Fixtures must match the real secret patterns under test; assembled at runtime
# so secret scanners never see a contiguous token in the source.
FAKE_GOOGLE_API_KEY = "AIza" + "FAKE" * 8 + "000"
FAKE_TELEGRAM_BOT_TOKEN = "123456789" + ":" + "AAEhBOweik6ad9rQXMENQjcrGbqCr4d09w"


def test_redact_url_secrets_masks_path_and_query_tokens() -> None:
    raw_url = (
        "https://example.com/123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
        f"?apiKey={FAKE_GOOGLE_API_KEY}"
        "&oobCode=UlNWwoLW0Nt5KimkaIVmA5WYa5gENFl3n2aBkBwEomsAAAGY5NMkHQ"
    )

    sanitized = redact_url_secrets(raw_url)

    assert "AIza" not in sanitized
    assert "123456789:" not in sanitized
    assert "apiKey=redacted" in sanitized
    assert "oobCode=redacted" in sanitized


def test_redact_url_secrets_masks_tokens_embedded_in_longer_path_segments() -> None:
    raw_url = "https://example.com/cgi-bin/verify-BXp1qah7kgedu6zw8wn5zipp9-step/next?page=1"

    sanitized = redact_url_secrets(raw_url)

    assert "BXp1qah7kgedu6zw8wn5zipp9" not in sanitized
    assert sanitized.startswith("https://example.com/cgi-bin/")
    assert sanitized.endswith("/next?page=1")


def test_redact_url_secrets_masks_tokens_embedded_in_query_keys() -> None:
    raw_url = "http://162.241.87.196/landing/?ouEU54qKb7zLwWBeRzoX7nY1m%2F%7Bemail%7D3COKPKoDFAKEFAKECXue7zh0eC="

    sanitized = redact_url_secrets(raw_url)

    assert "ouEU54qKb7zLwWBeRzoX7nY1m" not in sanitized
    assert "3COKPKoDFAKEFAKECXue7zh0eC" not in sanitized


def test_redact_url_secrets_masks_aws_key_pair() -> None:
    raw_url = (
        "https://example.com/upload?aws_id=AKIAIOSFODNN7EXAMPLE"
        "&blob=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )

    sanitized = redact_url_secrets(raw_url)

    assert "AKIA" not in sanitized
    assert "wJalrXUtnFEMI" not in sanitized


def test_redact_url_secrets_masks_telegram_token_secret_part_in_bot_path() -> None:
    raw_url = f"https://api.telegram.org/bot{FAKE_TELEGRAM_BOT_TOKEN}/sendMessage"

    sanitized = redact_url_secrets(raw_url)

    assert FAKE_TELEGRAM_BOT_TOKEN.split(":")[1] not in sanitized
    assert sanitized.endswith("/sendMessage")


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
