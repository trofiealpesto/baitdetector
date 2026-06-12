from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

import tldextract


_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)
_DEFAULT_SCHEME = "https"
_SCHEME_WITH_COLON = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_SCHEME_LIKE_MISSING_SEPARATOR = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*//")
_REDACTED_VALUE = "redacted"
_GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
_TELEGRAM_BOT_TOKEN = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b")
_AWS_ACCESS_KEY_ID = re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}")
_AWS_SECRET_KEY = re.compile(r"[A-Za-z0-9/+=]{40,}")
_OPAQUE_TOKEN = re.compile(r"^(?=.{24,}$)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]+$")
_EMBEDDED_OPAQUE_TOKEN = re.compile(r"[A-Za-z0-9_-]{24,}")
_SENSITIVE_QUERY_KEYS = {
    "accesstoken",
    "apikey",
    "auth",
    "authcode",
    "authorization",
    "clientsecret",
    "code",
    "idtoken",
    "key",
    "oobcode",
    "password",
    "passwd",
    "refreshtoken",
    "resetcode",
    "secret",
    "session",
    "sessionid",
    "sig",
    "signature",
    "state",
    "token",
}


@dataclass(frozen=True)
class NormalizedURL:
    original_url: str
    normalized_url: str
    scheme: str
    host: str
    host_ascii: str
    registrable_domain: str
    subdomain: str
    path: str
    query: str
    tld: str
    has_userinfo: bool
    is_ip_host: bool
    has_punycode: bool
    query_keys: tuple[str, ...]
    query_pairs: tuple[tuple[str, str], ...]


def _coerce_scheme(value: str) -> str:
    stripped = value.strip()
    if "://" in stripped:
        return stripped
    if stripped.lower().startswith(("http:/", "https:/")) or _SCHEME_LIKE_MISSING_SEPARATOR.match(stripped):
        raise ValueError("Malformed URL. Use http:// or https://, or omit the scheme entirely.")
    if _SCHEME_WITH_COLON.match(stripped):
        return stripped
    return f"{_DEFAULT_SCHEME}://{stripped}"


def _ascii_host(hostname: str) -> str:
    labels = []
    for label in hostname.split("."):
        if not label:
            continue
        labels.append(label.encode("idna").decode("ascii"))
    return ".".join(labels).lower()


def _is_ip_host(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _canonical_query_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _looks_like_opaque_token(value: str) -> bool:
    decoded = unquote(value)
    return bool(_OPAQUE_TOKEN.fullmatch(decoded))


def _contains_letters_and_digits(value: str) -> bool:
    return any(char.isalpha() for char in value) and any(char.isdigit() for char in value)


def _redact_embedded_secrets(text: str) -> str:
    for pattern in (_GOOGLE_API_KEY, _TELEGRAM_BOT_TOKEN, _AWS_ACCESS_KEY_ID):
        text = pattern.sub(_REDACTED_VALUE, text)
    for pattern in (_AWS_SECRET_KEY, _EMBEDDED_OPAQUE_TOKEN):
        text = pattern.sub(
            lambda match: _REDACTED_VALUE if _contains_letters_and_digits(match.group()) else match.group(),
            text,
        )
    return text


def _sanitize_component(value: str) -> str:
    if not value:
        return value
    if _looks_like_opaque_token(value):
        return _REDACTED_VALUE
    sanitized = _redact_embedded_secrets(value)
    if sanitized != value:
        return sanitized
    decoded = unquote(value)
    if decoded != value and _redact_embedded_secrets(decoded) != decoded:
        # Secret only visible after percent-decoding; spans cannot be mapped back safely.
        return _REDACTED_VALUE
    return value


def _sanitize_path(path: str) -> str:
    if not path:
        return path
    return "/".join(_sanitize_component(segment) for segment in path.split("/"))


def _sanitize_query(query: str) -> str:
    if not query:
        return query

    sanitized_pairs = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        canonical_key = _canonical_query_key(key)
        if canonical_key in _SENSITIVE_QUERY_KEYS:
            sanitized_pairs.append((key, _REDACTED_VALUE))
        else:
            sanitized_pairs.append((_sanitize_component(key), _sanitize_component(value)))
    return urlencode(sanitized_pairs, doseq=True)


def redact_url_secrets(url: str) -> str:
    stripped = url.strip()
    if not stripped:
        return stripped

    parsed = urlsplit(stripped)
    if not parsed.scheme or not parsed.netloc:
        return stripped

    if not parsed.hostname:
        return stripped

    host = _ascii_host(parsed.hostname)
    netloc = host if not parsed.port else f"{host}:{parsed.port}"
    path = _sanitize_path(parsed.path)
    query = _sanitize_query(parsed.query)
    fragment = _sanitize_component(parsed.fragment)
    return urlunsplit((parsed.scheme.lower(), netloc, path, query, fragment))


def normalize_url(url: str) -> NormalizedURL:
    if not url or not url.strip():
        raise ValueError("URL is empty.")

    raw = _coerce_scheme(url)
    parsed = urlsplit(raw)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")

    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")

    host_ascii = _ascii_host(parsed.hostname)
    has_punycode = any(label.startswith("xn--") for label in host_ascii.split("."))
    is_ip_host = _is_ip_host(host_ascii)
    extracted = _EXTRACT(host_ascii)

    if extracted.domain and extracted.suffix:
        registrable_domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain
        tld = extracted.suffix.split(".")[-1]
    else:
        registrable_domain = host_ascii
        subdomain = ""
        tld = host_ascii.rsplit(".", 1)[-1] if "." in host_ascii else host_ascii

    path = parsed.path or "/"
    normalized_path = posixpath.normpath(path)
    if path.endswith("/") and not normalized_path.endswith("/"):
        normalized_path += "/"
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"

    query_pairs = tuple((key.lower(), value) for key, value in parse_qsl(parsed.query, keep_blank_values=True))
    normalized_url = urlunsplit(
        (
            parsed.scheme.lower(),
            host_ascii if not parsed.port or parsed.port in {80, 443} else f"{host_ascii}:{parsed.port}",
            normalized_path,
            parsed.query,
            "",
        )
    )

    return NormalizedURL(
        original_url=url.strip(),
        normalized_url=normalized_url,
        scheme=parsed.scheme.lower(),
        host=parsed.hostname.lower(),
        host_ascii=host_ascii,
        registrable_domain=registrable_domain,
        subdomain=subdomain,
        path=normalized_path,
        query=parsed.query,
        tld=tld,
        has_userinfo=bool(parsed.username or parsed.password),
        is_ip_host=is_ip_host,
        has_punycode=has_punycode,
        query_keys=tuple(key for key, _ in query_pairs),
        query_pairs=query_pairs,
    )
