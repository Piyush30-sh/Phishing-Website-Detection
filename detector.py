"""
Advanced rule-based phishing URL detection engine.

This module analyzes URLs using deterministic security heuristics.
No machine learning models, external APIs, or databases are used.
"""

from __future__ import annotations

import binascii
import csv
import gzip
import math
import ipaddress
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qsl, urlparse
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_RISK_SCORE = 100

ENABLE_SSL_INSPECTION = True
ENABLE_REALTIME_BLOCKLIST_CHECK = True
NETWORK_TIMEOUT_SECONDS = 3
BLOCKLIST_CACHE_TTL_SECONDS = 900
BLOCKLIST_MAX_ENTRIES = 250000

WEIGHTS: dict[str, int] = {
    "http_scheme": 10,
    "long_url": 6,
    "at_symbol": 10,
    "ip_address_domain": 14,
    "many_hyphens": 6,
    "many_subdomains": 7,
    "suspicious_keywords": 15,
    "suspicious_tld": 10,
    "shortener_domain": 9,
    "domain_age_heuristic": 7,
    "punycode_idn": 12,
    "double_extension_tld": 12,
    "excessive_query_params": 7,
    "misplaced_www": 8,
    "brand_impersonation": 25,
    "encoded_payload": 14,
    "explicit_port": 7,
    "redirect_markers": 12,
    "mixed_charset_domain": 10,
    "excessive_url_encoding": 10,
    "ssl_certificate_anomaly": 18,
    "realtime_blocklist_hit": 30,
    "typosquatting_domain": 22,
}

RULE_META: dict[str, tuple[str, str]] = {
    "http_scheme": ("Structural", "Medium"),
    "long_url": ("Structural", "Low"),
    "at_symbol": ("Structural", "High"),
    "ip_address_domain": ("Domain-Based", "High"),
    "many_hyphens": ("Domain-Based", "Low"),
    "many_subdomains": ("Domain-Based", "Medium"),
    "suspicious_keywords": ("Keyword-Based", "Medium"),
    "suspicious_tld": ("Domain-Based", "High"),
    "shortener_domain": ("Domain-Based", "Medium"),
    "domain_age_heuristic": ("Domain-Based", "Medium"),
    "punycode_idn": ("Domain-Based", "High"),
    "double_extension_tld": ("Domain-Based", "High"),
    "excessive_query_params": ("Structural", "Medium"),
    "misplaced_www": ("Domain-Based", "Medium"),
    "brand_impersonation": ("Keyword-Based", "High"),
    "encoded_payload": ("Encoding-Based", "High"),
    "explicit_port": ("Structural", "Medium"),
    "redirect_markers": ("Keyword-Based", "Medium"),
    "mixed_charset_domain": ("Domain-Based", "High"),
    "excessive_url_encoding": ("Encoding-Based", "High"),
    "ssl_certificate_anomaly": ("Domain-Based", "High"),
    "realtime_blocklist_hit": ("Domain-Based", "High"),
    "typosquatting_domain": ("Domain-Based", "High"),
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "account",
    "password",
    "update",
    "bank",
    "paypal",
    "confirm",
    "wallet",
    "signin",
    "unlock",
    "recovery",
    "support",
}

SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "cf",
    "gq",
    "xyz",
    "top",
    "rest",
    "cfd",
    "buzz",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "goo.gl",
}

REDIRECT_KEYS = {"redirect", "url", "next", "return", "target", "dest", "continue"}

KNOWN_TLD_TOKENS = {
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "io",
    "co",
    "uk",
    "us",
    "ru",
    "cn",
    "de",
    "in",
    "jp",
    "au",
    "ca",
    "fr",
    "br",
    "it",
    "es",
    "nl",
    "ch",
    "se",
    "pl",
    "sg",
    "za",
    "tr",
    "id",
    "kr",
    "mx",
    "info",
    "biz",
    "online",
    "site",
    "store",
    "tech",
    "app",
}

BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in", "google.co.uk"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com"},
    "bankofamerica": {"bankofamerica.com"},
}

BRAND_DOMAIN_TOP100 = {
    "amazon.com",
    "apple.com",
    "asana.com",
    "atlassian.com",
    "bankofamerica.com",
    "bbc.com",
    "binance.com",
    "booking.com",
    "box.com",
    "canva.com",
    "capitalone.com",
    "chase.com",
    "citi.com",
    "cloudflare.com",
    "crunchyroll.com",
    "deepl.com",
    "discord.com",
    "dropbox.com",
    "duckduckgo.com",
    "ebay.com",
    "etsy.com",
    "facebook.com",
    "fedex.com",
    "figma.com",
    "fiverr.com",
    "github.com",
    "gmail.com",
    "google.com",
    "godaddy.com",
    "hbo.com",
    "hulu.com",
    "ibm.com",
    "ikea.com",
    "instagram.com",
    "intel.com",
    "jira.com",
    "kpmg.com",
    "lego.com",
    "linkedin.com",
    "lowes.com",
    "lyft.com",
    "maersk.com",
    "mastercard.com",
    "mcdonalds.com",
    "microsoft.com",
    "mozilla.org",
    "netflix.com",
    "nike.com",
    "nordstrom.com",
    "office.com",
    "oracle.com",
    "paypal.com",
    "pinterest.com",
    "pnc.com",
    "postmates.com",
    "primevideo.com",
    "reddit.com",
    "robinhood.com",
    "salesforce.com",
    "samsung.com",
    "shell.com",
    "shopify.com",
    "slack.com",
    "snapchat.com",
    "spotify.com",
    "squareup.com",
    "steamcommunity.com",
    "stripe.com",
    "target.com",
    "telegram.org",
    "tesla.com",
    "tiktok.com",
    "tmobile.com",
    "twitch.tv",
    "twitter.com",
    "uber.com",
    "udemy.com",
    "walmart.com",
    "whatsapp.com",
    "wikipedia.org",
    "wix.com",
    "x.com",
    "yahoo.com",
    "yelp.com",
    "youtube.com",
    "zoom.com",
    "alibaba.com",
    "aliexpress.com",
    "airbnb.com",
    "airtable.com",
    "adobe.com",
    "americanexpress.com",
    "aws.amazon.com",
    "cisco.com",
    "dell.com",
    "dhl.com",
    "expedia.com",
    "fast.com",
    "hsbc.com",
    "hp.com",
    "linkedin.com",
    "paypal.com",
}

MULTI_PART_PUBLIC_SUFFIXES = {
    "co.uk",
    "org.uk",
    "net.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.in",
    "com.in",
    "co.jp",
    "com.br",
    "com.mx",
    "com.sg",
    "co.kr",
    "co.nz",
    "co.za",
}


BASE64_LIKE_RE = re.compile(r"(?i)(?:[A-Za-z0-9+/]{16,}={0,2})")
HEX_LIKE_RE = re.compile(r"(?i)(?:0x)?[a-f0-9]{16,}")
ENCODING_TOKEN_RE = re.compile(r"%[0-9a-fA-F]{2}")

BLOCKLIST_FEEDS = (
    {"name": "OpenPhish", "url": "https://openphish.com/feed.txt", "type": "txt"},
    {"name": "PhishTank", "url": "https://data.phishtank.com/data/online-valid.csv", "type": "csv"},
    {"name": "PhishTank", "url": "https://data.phishtank.com/data/online-valid.csv.gz", "type": "csv.gz"},
)

_blocklist_cache_lock = threading.Lock()
_blocklist_cache: dict[str, object] = {
    "updated_at": 0.0,
    "url_set": set(),
    "host_set": set(),
    "sources": [],
    "last_error": "",
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class RuleOutcome:
    """Represents the output of a single detection rule."""

    triggered: bool
    message: str = ""


@dataclass
class URLContext:
    """Normalized URL parsing context used by all rules."""

    original_url: str
    normalized_url: str
    parsed: object
    hostname: str
    host_labels: list[str]
    query_pairs: list[tuple[str, str]]
    ssl_certificate: dict[str, object] | None = None
    realtime_blocklist: dict[str, object] | None = None


@dataclass
class ExternalSignals:
    """Additional network-derived signals used for explainability."""

    ssl_certificate: dict[str, object]
    realtime_blocklist: dict[str, object]


RuleFunction = Callable[[URLContext], RuleOutcome]


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme so parsing is consistent."""
    cleaned = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        return f"http://{cleaned}"
    return cleaned


def _extract_context(raw_url: str) -> URLContext:
    """Build a URL context object once and reuse across all rules."""
    normalized_url = _normalize_url(raw_url)
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").strip(".").lower()
    host_labels = [label for label in hostname.split(".") if label]
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    return URLContext(
        original_url=raw_url,
        normalized_url=normalized_url,
        parsed=parsed,
        hostname=hostname,
        host_labels=host_labels,
        query_pairs=query_pairs,
    )


def _is_ip_address(host: str) -> bool:
    """Return True when host is an IPv4 or IPv6 literal."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_ascii(value: str) -> bool:
    """Return True when all characters are ASCII."""
    return all(ord(ch) < 128 for ch in value)


def _get_registrable_domain(hostname: str) -> str:
    """Return a best-effort registrable domain using a small public-suffix heuristic."""
    labels = [label for label in hostname.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return hostname.lower().strip(".")

    suffix_two = ".".join(labels[-2:])
    suffix_three = ".".join(labels[-3:])

    if suffix_two in MULTI_PART_PUBLIC_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    if suffix_three in MULTI_PART_PUBLIC_SUFFIXES and len(labels) >= 4:
        return ".".join(labels[-4:])

    return ".".join(labels[-2:])


def _levenshtein_distance(left: str, right: str, max_distance: int | None = None) -> int:
    """Compute Levenshtein distance using a memory-efficient dynamic program."""
    left = left.lower()
    right = right.lower()

    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    if len(left) < len(right):
        left, right = right, left

    previous_row = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current_row = [i]
        row_min = i
        for j, right_char in enumerate(right, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            replace_cost = previous_row[j - 1] + (left_char != right_char)
            cell = min(insert_cost, delete_cost, replace_cost)
            current_row.append(cell)
            row_min = min(row_min, cell)

        if max_distance is not None and row_min > max_distance:
            return max_distance + 1

        previous_row = current_row

    return previous_row[-1]


def _best_brand_match(domain: str) -> tuple[str, int] | None:
    """Find the closest brand-domain match from the built-in top-brand corpus."""
    domain = domain.lower().strip(".")
    if not domain:
        return None

    domain_tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    best_match: tuple[str, int] | None = None

    for brand_domain in BRAND_DOMAIN_TOP100:
        if brand_domain == domain:
            continue
        if brand_domain.rsplit(".", 1)[-1] != domain_tld:
            continue

        distance = _levenshtein_distance(domain, brand_domain, max_distance=3)
        if distance > 3:
            continue

        if best_match is None or distance < best_match[1]:
            best_match = (brand_domain, distance)

    return best_match


def _safe_b64_decode(token: str) -> bool:
    """Heuristic check for decodable base64-like chunks."""
    if len(token) < 16:
        return False
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    try:
        binascii.a2b_base64(padded)
        return True
    except binascii.Error:
        return False


def _fetch_bytes(url: str, timeout_seconds: int = NETWORK_TIMEOUT_SECONDS) -> bytes:
    """Fetch URL content bytes with a browser-like user agent."""
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 PhishingDetector/1.0"})
    with urlopen(req, timeout=timeout_seconds) as response:
        return response.read()


def _normalize_url_for_match(url_value: str) -> str:
    """Normalize URL shape for feed matching comparisons."""
    normalized = _normalize_url(url_value).strip()
    if normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized.lower()


def _load_blocklist_cache(force_refresh: bool = False) -> dict[str, object]:
    """Load and cache blocklist entries from public feeds with TTL."""
    now = time.time()

    with _blocklist_cache_lock:
        cache_age = now - float(_blocklist_cache["updated_at"])
        if not force_refresh and _blocklist_cache["updated_at"] and cache_age < BLOCKLIST_CACHE_TTL_SECONDS:
            return {
                "updated_at": _blocklist_cache["updated_at"],
                "url_set": set(_blocklist_cache["url_set"]),
                "host_set": set(_blocklist_cache["host_set"]),
                "sources": list(_blocklist_cache["sources"]),
                "last_error": str(_blocklist_cache["last_error"]),
            }

    url_set: set[str] = set()
    host_set: set[str] = set()
    sources_loaded: list[str] = []
    last_error = ""

    for feed in BLOCKLIST_FEEDS:
        if len(url_set) >= BLOCKLIST_MAX_ENTRIES:
            break

        try:
            raw = _fetch_bytes(feed["url"])
            feed_type = str(feed["type"])

            if feed_type == "csv.gz":
                raw = gzip.decompress(raw)
                feed_type = "csv"

            text = raw.decode("utf-8", errors="ignore")

            if feed_type == "txt":
                for line in text.splitlines():
                    candidate = line.strip()
                    if not candidate or candidate.startswith("#"):
                        continue
                    normalized = _normalize_url_for_match(candidate)
                    url_set.add(normalized)
                    parsed = urlparse(normalized)
                    if parsed.hostname:
                        host_set.add(parsed.hostname.lower())
                    if len(url_set) >= BLOCKLIST_MAX_ENTRIES:
                        break
            elif feed_type == "csv":
                reader = csv.DictReader(text.splitlines())
                for row in reader:
                    candidate = (row.get("url") or "").strip()
                    if not candidate:
                        continue
                    normalized = _normalize_url_for_match(candidate)
                    url_set.add(normalized)
                    parsed = urlparse(normalized)
                    if parsed.hostname:
                        host_set.add(parsed.hostname.lower())
                    if len(url_set) >= BLOCKLIST_MAX_ENTRIES:
                        break

            sources_loaded.append(str(feed["name"]))
        except Exception as exc:
            last_error = str(exc)

    dedup_sources = sorted(set(sources_loaded))

    snapshot = {
        "updated_at": now,
        "url_set": url_set,
        "host_set": host_set,
        "sources": dedup_sources,
        "last_error": last_error,
    }

    with _blocklist_cache_lock:
        _blocklist_cache.update(snapshot)

    return {
        "updated_at": snapshot["updated_at"],
        "url_set": set(snapshot["url_set"]),
        "host_set": set(snapshot["host_set"]),
        "sources": list(snapshot["sources"]),
        "last_error": str(snapshot["last_error"]),
    }


def _inspect_ssl_certificate(hostname: str, timeout_seconds: int = NETWORK_TIMEOUT_SECONDS) -> dict[str, object]:
    """Inspect certificate issuer and validity dates using ssl/socket modules."""
    result: dict[str, object] = {
        "checked": False,
        "valid": None,
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "expires_in_days": None,
        "error": "",
    }

    if not hostname or _is_ip_address(hostname):
        result["error"] = "SSL inspection skipped for missing hostname or IP literal"
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()

        result["checked"] = True

        issuer_parts = cert.get("issuer", ())
        issuer_tokens = []
        for part in issuer_parts:
            for key, value in part:
                issuer_tokens.append(f"{key}={value}")
        result["issuer"] = ", ".join(issuer_tokens)

        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        result["not_before"] = not_before
        result["not_after"] = not_after

        if not_after:
            expiry = ssl.cert_time_to_seconds(not_after)
            now = time.time()
            days_left = int((expiry - now) // 86400)
            result["expires_in_days"] = days_left
            result["valid"] = days_left >= 0
        else:
            result["valid"] = False
            result["error"] = "Certificate does not expose notAfter"

    except Exception as exc:
        result["checked"] = True
        result["valid"] = False
        result["error"] = str(exc)

    return result


def _check_realtime_blocklist(ctx: URLContext) -> dict[str, object]:
    """Check current URL and hostname against cached public phishing feeds."""
    base = {
        "checked": False,
        "listed": False,
        "sources": [],
        "matched_on": "",
        "matched_value": "",
        "entry_count": 0,
        "updated_at": 0,
        "error": "",
    }

    if not ENABLE_REALTIME_BLOCKLIST_CHECK:
        base["error"] = "Realtime blocklist checks are disabled"
        return base

    cache = _load_blocklist_cache()
    normalized_url = _normalize_url_for_match(ctx.normalized_url)
    host = (ctx.hostname or "").lower()

    listed_by_url = normalized_url in cache["url_set"]

    base["checked"] = True
    base["listed"] = listed_by_url
    base["sources"] = cache["sources"]
    base["entry_count"] = len(cache["url_set"])
    base["updated_at"] = int(cache["updated_at"])
    base["error"] = cache["last_error"]

    if listed_by_url:
        base["matched_on"] = "url"
        base["matched_value"] = normalized_url

    return base


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------

def rule_http_scheme(ctx: URLContext) -> RuleOutcome:
    if ctx.parsed.scheme.lower() == "http":
        return RuleOutcome(True, "URL uses HTTP instead of HTTPS")
    return RuleOutcome(False)


def rule_long_url(ctx: URLContext) -> RuleOutcome:
    if len(ctx.normalized_url) > 90:
        return RuleOutcome(True, "URL length is unusually long")
    return RuleOutcome(False)


def rule_at_symbol(ctx: URLContext) -> RuleOutcome:
    if "@" in ctx.normalized_url:
        return RuleOutcome(True, "URL contains '@' which can obscure destination")
    return RuleOutcome(False)


def rule_ip_address_domain(ctx: URLContext) -> RuleOutcome:
    if _is_ip_address(ctx.hostname):
        return RuleOutcome(True, "Host uses raw IP address instead of domain name")
    return RuleOutcome(False)


def rule_many_hyphens(ctx: URLContext) -> RuleOutcome:
    if ctx.hostname.count("-") >= 3:
        return RuleOutcome(True, "Domain contains many hyphens")
    return RuleOutcome(False)


def rule_many_subdomains(ctx: URLContext) -> RuleOutcome:
    subdomain_count = max(0, len(ctx.host_labels) - 2)
    if subdomain_count > 3:
        return RuleOutcome(True, "Domain has more than three subdomains")
    return RuleOutcome(False)


def rule_suspicious_keywords(ctx: URLContext) -> RuleOutcome:
    lowered = ctx.normalized_url.lower()
    found = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered)
    if found:
        return RuleOutcome(True, f"Suspicious keywords detected: {', '.join(found)}")
    return RuleOutcome(False)


def rule_suspicious_tld(ctx: URLContext) -> RuleOutcome:
    if not ctx.host_labels:
        return RuleOutcome(False)
    tld = ctx.host_labels[-1]
    if tld in SUSPICIOUS_TLDS:
        return RuleOutcome(True, f"Suspicious top-level domain detected: .{tld}")
    return RuleOutcome(False)


def rule_shortener_domain(ctx: URLContext) -> RuleOutcome:
    if any(ctx.hostname == d or ctx.hostname.endswith(f".{d}") for d in SHORTENER_DOMAINS):
        return RuleOutcome(True, "Known URL shortener domain used")
    return RuleOutcome(False)


def rule_domain_age_heuristic(ctx: URLContext) -> RuleOutcome:
    if not ctx.host_labels:
        return RuleOutcome(False)
    tld = ctx.host_labels[-1]
    has_random_left_label = bool(ctx.host_labels and re.search(r"\d", ctx.host_labels[0]))
    if tld in SUSPICIOUS_TLDS or has_random_left_label:
        return RuleOutcome(True, "Domain pattern resembles newly registered disposable domain")
    return RuleOutcome(False)


def rule_punycode_idn(ctx: URLContext) -> RuleOutcome:
    if any(label.startswith("xn--") for label in ctx.host_labels):
        return RuleOutcome(True, "Punycode label detected (possible IDN homograph attempt)")
    return RuleOutcome(False)


def rule_double_extension_tld(ctx: URLContext) -> RuleOutcome:
    if len(ctx.host_labels) < 3:
        return RuleOutcome(False)

    tld_like_tail = []
    for label in reversed(ctx.host_labels):
        if label in KNOWN_TLD_TOKENS or (label.isalpha() and len(label) <= 3):
            tld_like_tail.append(label)
        else:
            break

    if len(tld_like_tail) >= 2 and ctx.host_labels[-1] in SUSPICIOUS_TLDS:
        return RuleOutcome(True, "Domain ends with chained/double extension pattern")
    return RuleOutcome(False)


def rule_excessive_query_params(ctx: URLContext) -> RuleOutcome:
    if len(ctx.query_pairs) > 4:
        return RuleOutcome(True, "URL has excessive number of query parameters")
    return RuleOutcome(False)


def rule_misplaced_www(ctx: URLContext) -> RuleOutcome:
    labels = ctx.host_labels
    if "www" in labels[1:]:
        return RuleOutcome(True, "'www' appears in an unusual subdomain position")
    return RuleOutcome(False)


def rule_brand_impersonation(ctx: URLContext) -> RuleOutcome:
    haystack = f"{ctx.hostname}{ctx.parsed.path}{ctx.parsed.query}".lower()
    for brand, domains in BRAND_DOMAINS.items():
        if brand in haystack:
            domain_match = any(ctx.hostname == d or ctx.hostname.endswith(f".{d}") for d in domains)
            if not domain_match:
                return RuleOutcome(
                    True,
                    f"Brand keyword '{brand}' present but domain does not match official brand domain",
                )
    return RuleOutcome(False)


def rule_encoded_payload(ctx: URLContext) -> RuleOutcome:
    combined = f"{ctx.parsed.path}?{ctx.parsed.query}"

    base64_hits = [m.group(0) for m in BASE64_LIKE_RE.finditer(combined)]
    for token in base64_hits:
        if _safe_b64_decode(token):
            return RuleOutcome(True, "Base64-like encoded payload found in path/query")

    if HEX_LIKE_RE.search(combined):
        return RuleOutcome(True, "Long hexadecimal payload found in path/query")

    return RuleOutcome(False)


def rule_explicit_port(ctx: URLContext) -> RuleOutcome:
    if ctx.parsed.port is None:
        return RuleOutcome(False)
    if ctx.parsed.port in {80, 443}:
        return RuleOutcome(True, f"Explicit standard port specified in URL: {ctx.parsed.port}")
    return RuleOutcome(True, f"Uncommon port specified in URL: {ctx.parsed.port}")


def rule_redirect_markers(ctx: URLContext) -> RuleOutcome:
    lower_query = ctx.parsed.query.lower()
    found = [key for key in REDIRECT_KEYS if f"{key}=" in lower_query]
    if found:
        return RuleOutcome(True, f"Redirect marker(s) detected in query: {', '.join(sorted(found))}")
    return RuleOutcome(False)


def rule_mixed_charset_domain(ctx: URLContext) -> RuleOutcome:
    if not ctx.hostname:
        return RuleOutcome(False)

    has_non_ascii = not _is_ascii(ctx.hostname)
    has_ascii = any(ord(ch) < 128 for ch in ctx.hostname)
    if has_non_ascii and has_ascii:
        return RuleOutcome(True, "Mixed ASCII and non-ASCII characters found in domain")
    if has_non_ascii:
        return RuleOutcome(True, "Non-ASCII characters found in domain")
    return RuleOutcome(False)


def rule_excessive_url_encoding(ctx: URLContext) -> RuleOutcome:
    all_tokens = ENCODING_TOKEN_RE.findall(ctx.normalized_url)
    if len(all_tokens) < 4:
        return RuleOutcome(False)

    interesting = [token.lower() for token in all_tokens if token.lower() in {"%2f", "%40", "%2e", "%3a"}]
    if len(interesting) >= 3:
        return RuleOutcome(True, "Repeated encoded control characters detected (URL obfuscation)")

    return RuleOutcome(True, "Heavy URL encoding detected")


def rule_ssl_certificate_anomaly(ctx: URLContext) -> RuleOutcome:
    """Rule based on TLS certificate inspection outcome for HTTPS hosts."""
    if not ENABLE_SSL_INSPECTION:
        return RuleOutcome(False)

    if ctx.parsed.scheme.lower() != "https":
        return RuleOutcome(False)

    ssl_info = ctx.ssl_certificate if isinstance(ctx.ssl_certificate, dict) else _inspect_ssl_certificate(ctx.hostname)
    if not ssl_info.get("checked"):
        return RuleOutcome(False)

    if ssl_info.get("valid") is False:
        if ssl_info.get("error"):
            return RuleOutcome(True, f"SSL certificate anomaly: {ssl_info['error']}")
        return RuleOutcome(True, "SSL certificate appears invalid or expired")

    expires_in_days = ssl_info.get("expires_in_days")
    if isinstance(expires_in_days, int) and expires_in_days < 15:
        return RuleOutcome(True, f"SSL certificate expires soon ({expires_in_days} day(s))")

    return RuleOutcome(False)


def rule_realtime_blocklist_hit(ctx: URLContext) -> RuleOutcome:
    """Rule based on public phishing blocklist matches."""
    blocklist = ctx.realtime_blocklist if isinstance(ctx.realtime_blocklist, dict) else _check_realtime_blocklist(ctx)
    if blocklist.get("checked") and blocklist.get("listed"):
        matched_on = blocklist.get("matched_on", "url")
        return RuleOutcome(True, f"Realtime blocklist hit on {matched_on}")
    return RuleOutcome(False)


def rule_typosquatting_domain(ctx: URLContext) -> RuleOutcome:
    """Rule that flags domains close to a built-in list of major brand domains."""
    registrable_domain = _get_registrable_domain(ctx.hostname)
    if not registrable_domain:
        return RuleOutcome(False)

    if registrable_domain in BRAND_DOMAIN_TOP100:
        return RuleOutcome(False)

    best_match = _best_brand_match(registrable_domain)
    if not best_match:
        return RuleOutcome(False)

    matched_brand, distance = best_match
    domain_len = max(len(registrable_domain), len(matched_brand))
    normalized_distance = distance / domain_len if domain_len else 1.0

    if distance <= 2 or normalized_distance <= 0.2:
        return RuleOutcome(
            True,
            f"Domain '{registrable_domain}' is close to brand domain '{matched_brand}' (edit distance {distance})",
        )

    return RuleOutcome(False)


RULES: list[tuple[str, RuleFunction]] = [
    ("http_scheme", rule_http_scheme),
    ("long_url", rule_long_url),
    ("at_symbol", rule_at_symbol),
    ("ip_address_domain", rule_ip_address_domain),
    ("many_hyphens", rule_many_hyphens),
    ("many_subdomains", rule_many_subdomains),
    ("suspicious_keywords", rule_suspicious_keywords),
    ("suspicious_tld", rule_suspicious_tld),
    ("shortener_domain", rule_shortener_domain),
    ("domain_age_heuristic", rule_domain_age_heuristic),
    ("punycode_idn", rule_punycode_idn),
    ("double_extension_tld", rule_double_extension_tld),
    ("excessive_query_params", rule_excessive_query_params),
    ("misplaced_www", rule_misplaced_www),
    ("brand_impersonation", rule_brand_impersonation),
    ("encoded_payload", rule_encoded_payload),
    ("explicit_port", rule_explicit_port),
    ("redirect_markers", rule_redirect_markers),
    ("mixed_charset_domain", rule_mixed_charset_domain),
    ("excessive_url_encoding", rule_excessive_url_encoding),
    ("ssl_certificate_anomaly", rule_ssl_certificate_anomaly),
    ("realtime_blocklist_hit", rule_realtime_blocklist_hit),
    ("typosquatting_domain", rule_typosquatting_domain),
]


# ---------------------------------------------------------------------------
# Scoring and explanation helpers
# ---------------------------------------------------------------------------

def _classify_risk(score: int) -> tuple[str, str, str]:
    """Map risk score to risk label, color token, and recommendation."""
    if score <= 15:
        return (
            "Safe",
            "green",
            "Low phishing indicators detected. Continue with standard caution.",
        )
    if score <= 35:
        return (
            "Caution",
            "yellow",
            "Some suspicious indicators found. Verify destination before interacting.",
        )
    if score <= 65:
        return (
            "Suspicious",
            "orange",
            "Multiple phishing indicators found. Avoid entering credentials.",
        )
    return (
        "High Risk",
        "red",
        "Strong phishing pattern detected. Do not visit or submit sensitive data.",
    )


def _build_confidence(triggered_count: int, total_rules: int) -> int:
    """Estimate confidence based on proportion of triggered rules."""
    if total_rules <= 0:
        return 85

    # A clean result should still be high-confidence when no rules are triggered.
    if triggered_count <= 0:
        return 95

    ratio = triggered_count / total_rules

    # Keep confidence in a realistic but not alarming range for low-trigger cases.
    if ratio <= 0.10:
        return 80
    if ratio <= 0.25:
        return 86
    if ratio <= 0.50:
        return 92
    return 97


def _empty_reason_groups() -> dict[str, list[dict[str, str]]]:
    """Return grouped reason buckets with stable category keys."""
    return {
        "Structural": [],
        "Keyword-Based": [],
        "Encoding-Based": [],
        "Domain-Based": [],
    }


def _calculate_logistic_risk(triggered_rule_names: list[str], ctx: URLContext) -> int:
    """Convert triggered rule evidence into a logistic-style risk score."""
    if not triggered_rule_names:
        return 0

    weighted_sum = sum(WEIGHTS.get(rule_name, 0) for rule_name in triggered_rule_names)
    features = set(triggered_rule_names)

    interaction_bonus = 0.0

    if "realtime_blocklist_hit" in features:
        interaction_bonus += 1.4

    if "typosquatting_domain" in features and "brand_impersonation" in features:
        interaction_bonus += 0.9

    if "punycode_idn" in features and ("brand_impersonation" in features or "typosquatting_domain" in features):
        interaction_bonus += 0.85

    if "ip_address_domain" in features and (
        {"suspicious_keywords", "brand_impersonation", "redirect_markers", "excessive_query_params"} & features
    ):
        interaction_bonus += 1.0

    if "ssl_certificate_anomaly" in features and ("http_scheme" in features or "explicit_port" in features):
        interaction_bonus += 0.4

    if len({"suspicious_keywords", "brand_impersonation", "redirect_markers", "typosquatting_domain"} & features) >= 3:
        interaction_bonus += 0.35

    domain_rules = {
        "ip_address_domain",
        "many_hyphens",
        "many_subdomains",
        "suspicious_tld",
        "shortener_domain",
        "domain_age_heuristic",
        "punycode_idn",
        "double_extension_tld",
        "misplaced_www",
        "brand_impersonation",
        "mixed_charset_domain",
        "ssl_certificate_anomaly",
        "realtime_blocklist_hit",
        "typosquatting_domain",
    }
    keyword_rules = {"suspicious_keywords", "brand_impersonation", "redirect_markers"}
    structural_rules = {"http_scheme", "long_url", "at_symbol", "excessive_query_params", "explicit_port"}
    encoding_rules = {"encoded_payload", "excessive_url_encoding"}

    domain_hits = len(domain_rules & features)
    keyword_hits = len(keyword_rules & features)
    structural_hits = len(structural_rules & features)
    encoding_hits = len(encoding_rules & features)

    if domain_hits >= 3:
        interaction_bonus += 0.2 * (domain_hits - 2)
    if keyword_hits >= 2 and domain_hits >= 2:
        interaction_bonus += 0.45
    if structural_hits >= 3:
        interaction_bonus += 0.25
    if encoding_hits >= 2:
        interaction_bonus += 0.25

    logit = -3.8 + (weighted_sum / 13.0) + interaction_bonus
    probability = 1.0 / (1.0 + math.exp(-logit))
    return max(0, min(MAX_RISK_SCORE, int(round(probability * 100))))


def _calculate_scoring_details(triggered_rule_names: list[str], ctx: URLContext) -> dict[str, object]:
    """Return the intermediate values used by the logistic scoring engine."""
    if not triggered_rule_names:
        return {
            "weighted_sum": 0,
            "interaction_bonus": 0.0,
            "logit": -3.8,
            "probability": 0.0,
            "triggered_rules": [],
            "category_mix": {},
        }

    weighted_sum = sum(WEIGHTS.get(rule_name, 0) for rule_name in triggered_rule_names)
    features = set(triggered_rule_names)

    interaction_bonus = 0.0
    interaction_reasons: list[str] = []

    if "realtime_blocklist_hit" in features:
        interaction_bonus += 1.4
        interaction_reasons.append("Realtime blocklist hit carries a strong multiplier")

    if "typosquatting_domain" in features and "brand_impersonation" in features:
        interaction_bonus += 0.9
        interaction_reasons.append("Typosquatting plus brand impersonation strengthens the score")

    if "punycode_idn" in features and ("brand_impersonation" in features or "typosquatting_domain" in features):
        interaction_bonus += 0.85
        interaction_reasons.append("Punycode combined with brand similarity raises confidence in abuse")

    if "ip_address_domain" in features and (
        {"suspicious_keywords", "brand_impersonation", "redirect_markers", "excessive_query_params"} & features
    ):
        interaction_bonus += 1.0
        interaction_reasons.append("IP-hosted phishing plus lure or redirect behavior is more dangerous")

    if "ssl_certificate_anomaly" in features and ("http_scheme" in features or "explicit_port" in features):
        interaction_bonus += 0.4
        interaction_reasons.append("Transport issues combined with certificate anomalies increase risk")

    if len({"suspicious_keywords", "brand_impersonation", "redirect_markers", "typosquatting_domain"} & features) >= 3:
        interaction_bonus += 0.35
        interaction_reasons.append("Multiple lure and domain tricks are present together")

    domain_rules = {
        "ip_address_domain",
        "many_hyphens",
        "many_subdomains",
        "suspicious_tld",
        "shortener_domain",
        "domain_age_heuristic",
        "punycode_idn",
        "double_extension_tld",
        "misplaced_www",
        "brand_impersonation",
        "mixed_charset_domain",
        "ssl_certificate_anomaly",
        "realtime_blocklist_hit",
        "typosquatting_domain",
    }
    keyword_rules = {"suspicious_keywords", "brand_impersonation", "redirect_markers"}
    structural_rules = {"http_scheme", "long_url", "at_symbol", "excessive_query_params", "explicit_port"}
    encoding_rules = {"encoded_payload", "excessive_url_encoding"}

    category_mix = {
        "domain": len(domain_rules & features),
        "keyword": len(keyword_rules & features),
        "structural": len(structural_rules & features),
        "encoding": len(encoding_rules & features),
    }

    if category_mix["domain"] >= 3:
        interaction_bonus += 0.2 * (category_mix["domain"] - 2)
    if category_mix["keyword"] >= 2 and category_mix["domain"] >= 2:
        interaction_bonus += 0.45
        interaction_reasons.append("Keyword and domain signals reinforce each other")
    if category_mix["structural"] >= 3:
        interaction_bonus += 0.25
    if category_mix["encoding"] >= 2:
        interaction_bonus += 0.25

    logit = -3.8 + (weighted_sum / 13.0) + interaction_bonus
    probability = 1.0 / (1.0 + math.exp(-logit))

    typosquat_match = None
    registrable_domain = _get_registrable_domain(ctx.hostname)
    if registrable_domain and registrable_domain not in BRAND_DOMAIN_TOP100:
        match = _best_brand_match(registrable_domain)
        if match:
            matched_brand, distance = match
            domain_len = max(len(registrable_domain), len(matched_brand))
            normalized_distance = distance / domain_len if domain_len else 1.0
            if distance <= 2 or normalized_distance <= 0.2:
                typosquat_match = {
                    "domain": registrable_domain,
                    "matched_brand": matched_brand,
                    "distance": distance,
                }

    return {
        "weighted_sum": weighted_sum,
        "interaction_bonus": round(interaction_bonus, 3),
        "logit": round(logit, 3),
        "probability": round(probability, 4),
        "triggered_rules": list(triggered_rule_names),
        "category_mix": category_mix,
        "interaction_reasons": interaction_reasons,
        "typosquat_match": typosquat_match,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_url(raw_url: str) -> dict:
    """
    Analyze one URL and return a structured phishing assessment.

    Returns payload keys:
    - url, normalized_url
    - risk_score, risk_level, color
    - confidence
    - reasons: flat list of reason objects
    - reason_groups: reasons grouped by category
    - triggered_rules, total_rules_checked
    - recommendation
    """
    if not raw_url or not raw_url.strip():
        return {
            "url": raw_url,
            "normalized_url": "",
            "risk_score": 0,
            "risk_level": "Invalid",
            "color": "gray",
            "confidence": 45,
            "reasons": [
                {
                    "category": "Structural",
                    "severity": "Low",
                    "rule": "invalid_input",
                    "message": "No URL provided",
                }
            ],
            "reason_groups": {
                "Structural": [
                    {
                        "severity": "Low",
                        "rule": "invalid_input",
                        "message": "No URL provided",
                    }
                ],
                "Keyword-Based": [],
                "Encoding-Based": [],
                "Domain-Based": [],
            },
            "triggered_rules": 0,
            "total_rules_checked": len(RULES),
            "recommendation": "Provide a valid URL for analysis.",
        }

    ctx = _extract_context(raw_url)

    ssl_certificate = _inspect_ssl_certificate(ctx.hostname) if (ENABLE_SSL_INSPECTION and ctx.parsed.scheme.lower() == "https") else {
        "checked": False,
        "valid": None,
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "expires_in_days": None,
        "error": "SSL inspection only applies to HTTPS URLs",
    }
    realtime_blocklist = _check_realtime_blocklist(ctx)
    ctx.ssl_certificate = ssl_certificate
    ctx.realtime_blocklist = realtime_blocklist
    external_signals = ExternalSignals(
        ssl_certificate=ssl_certificate,
        realtime_blocklist=realtime_blocklist,
    )

    reasons: list[dict[str, str]] = []
    reason_groups = _empty_reason_groups()
    triggered_rule_names: list[str] = []

    for rule_name, rule_fn in RULES:
        outcome = rule_fn(ctx)
        if not outcome.triggered:
            continue

        category, severity = RULE_META[rule_name]
        triggered_rule_names.append(rule_name)

        reason_item = {
            "category": category,
            "severity": severity,
            "rule": rule_name,
            "message": outcome.message,
        }
        reasons.append(reason_item)
        reason_groups[category].append(
            {
                "severity": severity,
                "rule": rule_name,
                "message": outcome.message,
            }
        )

    risk_score = _calculate_logistic_risk(triggered_rule_names, ctx)
    risk_level, color, recommendation = _classify_risk(risk_score)

    if not reasons:
        reasons.append(
            {
                "category": "Structural",
                "severity": "Low",
                "rule": "clean_scan",
                "message": "No suspicious patterns detected by configured heuristics",
            }
        )
        reason_groups["Structural"].append(
            {
                "severity": "Low",
                "rule": "clean_scan",
                "message": "No suspicious patterns detected by configured heuristics",
            }
        )

    confidence = _build_confidence(len(triggered_rule_names), len(RULES))

    return {
        "url": raw_url,
        "normalized_url": ctx.normalized_url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "color": color,
        "confidence": confidence,
        "reasons": reasons,
        "reason_groups": reason_groups,
        "triggered_rules": len(triggered_rule_names),
        "total_rules_checked": len(RULES),
        "recommendation": recommendation,
        "external_signals": {
            "ssl_certificate": external_signals.ssl_certificate,
            "realtime_blocklist": external_signals.realtime_blocklist,
        },
        "scoring_details": _calculate_scoring_details(triggered_rule_names, ctx),
    }
