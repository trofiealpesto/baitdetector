from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import tldextract


_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)
_DEFAULT_SCHEME = "https"
_SCHEME_WITH_COLON = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_SCHEME_LIKE_MISSING_SEPARATOR = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*//")


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
