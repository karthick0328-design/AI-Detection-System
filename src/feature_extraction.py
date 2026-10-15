"""
URL Parsing and Reusable Feature Extraction Module.

Extracts lexical, structural, and semantic indicators from a URL string
without issuing network requests or executing arbitrary web content.
The same feature list and order is guaranteed across training, evaluation, and inference.
"""

import re
import ipaddress
from urllib.parse import urlparse, urlsplit
from typing import Dict, Any, Tuple, List, Optional

# Pre-compiled regex patterns for performance and security
IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DISALLOWED_SCHEMES = {"javascript", "data", "file", "vbscript", "about"}
ALLOWED_SCHEMES = {"http", "https"}

# High-risk keywords commonly found in credential-harvesting phishing campaigns
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "secure", "banking",
    "signin", "wallet", "authenticate", "checkpoint", "confirm",
    "password", "support", "security", "recovery", "service", "billing"
]

# High-abuse Top-Level Domains frequently associated with disposable phishing campaigns
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "club",
    "icu", "buzz", "rest", "cam", "bid", "space", "live", "date"
}

# Ordered canonical list of numeric feature names used by ML models
FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "subdomain_count",
    "hyphen_count",
    "at_symbol_count",
    "digit_count_hostname",
    "digit_ratio_url",
    "is_ip_address",
    "is_https",
    "has_suspicious_keyword",
    "suspicious_keyword_count",
    "has_suspicious_tld",
    "has_non_standard_port",
    "has_punycode",
    "special_char_count"
]

def sanitize_and_normalize_url(raw_url: str) -> Tuple[str, str]:
    """
    Validates, sanitizes, and normalizes an input URL.
    
    Returns:
        Tuple[str, str]: (normalized_url, error_message)
    """
    if not raw_url or not isinstance(raw_url, str):
        return "", "URL cannot be empty."

    url = raw_url.strip()
    if len(url) > 2048:
        return "", "URL exceeds maximum permitted length of 2048 characters."

    # Check for disallowed dangerous schemes
    lower_url = url.lower()
    for scheme in DISALLOWED_SCHEMES:
        if lower_url.startswith(f"{scheme}:"):
            return "", f"Disallowed scheme '{scheme}:'. For security, only HTTP and HTTPS are permitted."

    # Ensure URL has a scheme for safe parsing
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    try:
        parsed = urlsplit(url)
    except Exception as exc:
        return "", f"Malformed URL syntax: {exc}"

    if not parsed.hostname:
        return "", "URL is missing a valid hostname or domain."

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return "", f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS are allowed."

    # Return normalized URL
    normalized_url = parsed.geturl()
    return normalized_url, ""


def is_ip_hostname(hostname: str) -> int:
    """Detects if hostname is a raw IPv4 or IPv6 address."""
    if not hostname:
        return 0
    # Strip optional port if present
    clean_host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        pass
    if IPV4_PATTERN.match(clean_host):
        return 1
    return 0


def count_subdomains(hostname: str) -> int:
    """Counts subdomains beyond the main second-level and top-level domain."""
    if not hostname or is_ip_hostname(hostname):
        return 0
    parts = hostname.split(".")
    # Filter empty parts from trailing or duplicate dots
    parts = [p for p in parts if p]
    if len(parts) <= 2:
        return 0
    # e.g., 'sub.example.com' has 1 subdomain ('sub')
    # e.g., 'a.b.example.co.uk' has 2 subdomains
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "edu", "net"} and len(parts[-1]) <= 3:
        # ccTLD with second-level domain (e.g. .co.uk)
        return max(0, len(parts) - 3)
    return max(0, len(parts) - 2)


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts numerical features and rich signal metadata from a URL.
    
    Returns:
        Dict[str, Any]: Contains:
            - 'features': Dict[str, float] with exact FEATURE_NAMES keys
            - 'normalized_url': str
            - 'hostname': str
            - 'signals': Dict[str, Dict] explaining each signal for Explainable AI
    """
    normalized_url, error = sanitize_and_normalize_url(raw_url)
    if error:
        raise ValueError(error)

    parsed = urlsplit(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = normalized_url

    # Numerical characteristics
    url_len = len(full_url)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)
    dot_cnt = full_url.count(".")
    subdomain_cnt = count_subdomains(hostname)
    hyphen_cnt = hostname.count("-")
    at_cnt = full_url.count("@")
    digits_host = sum(1 for c in hostname if c.isdigit())
    digits_url = sum(1 for c in full_url if c.isdigit())
    digit_ratio = round(digits_url / max(1, url_len), 4)
    ip_flag = is_ip_hostname(hostname)
    https_flag = 1 if parsed.scheme.lower() == "https" else 0

    # Keyword analysis
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url.lower()]
    has_keyword = 1 if len(keyword_hits) > 0 else 0
    keyword_cnt = len(keyword_hits)

    # TLD analysis
    tld = hostname.split(".")[-1] if "." in hostname else ""
    has_sus_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Port analysis
    has_custom_port = 0
    if parsed.port:
        if parsed.scheme.lower() == "http" and parsed.port != 80:
            has_custom_port = 1
        elif parsed.scheme.lower() == "https" and parsed.port != 443:
            has_custom_port = 1

    # Punycode / IDN homograph attack indicator
    has_punycode = 1 if "xn--" in hostname else 0

    # Special characters
    special_chars = set("?=&%-+~_!$*,")
    special_cnt = sum(1 for c in full_url if c in special_chars)

    numeric_features = {
        "url_length": float(url_len),
        "hostname_length": float(host_len),
        "path_length": float(path_len),
        "query_length": float(query_len),
        "dot_count": float(dot_cnt),
        "subdomain_count": float(subdomain_cnt),
        "hyphen_count": float(hyphen_cnt),
        "at_symbol_count": float(at_cnt),
        "digit_count_hostname": float(digits_host),
        "digit_ratio_url": float(digit_ratio),
        "is_ip_address": float(ip_flag),
        "is_https": float(https_flag),
        "has_suspicious_keyword": float(has_keyword),
        "suspicious_keyword_count": float(keyword_cnt),
        "has_suspicious_tld": float(has_sus_tld),
        "has_non_standard_port": float(has_custom_port),
        "has_punycode": float(has_punycode),
        "special_char_count": float(special_cnt)
    }

    # Signal explanation catalog for Explainable AI
    signals = {
        "is_ip_address": {
            "name": "Direct IP Hostname",
            "observed_value": "Yes" if ip_flag else "No (Domain Name)",
            "flagged": bool(ip_flag),
            "severity": "high" if ip_flag else "neutral",
            "why_it_matters": "Legitimate websites rarely direct public visitors to raw IP addresses. Attackers use direct IPs to evade domain name registration oversight.",
            "limitation": "Some enterprise intranet portals or testing environments legitimately use IP addresses."
        },
        "url_length": {
            "name": "URL Length",
            "observed_value": f"{url_len} characters",
            "flagged": url_len > 75,
            "severity": "medium" if url_len > 100 else ("low" if url_len > 75 else "neutral"),
            "why_it_matters": "Phishing URLs often pack deep tokens, redirection parameters, or obfuscated payloads resulting in unusually long URLs.",
            "limitation": "Legitimate search queries and marketing affiliate links also produce long URLs."
        },
        "is_https": {
            "name": "HTTPS Scheme Presence",
            "observed_value": "HTTPS" if https_flag else "HTTP (Unencrypted)",
            "flagged": not bool(https_flag),
            "severity": "medium" if not https_flag else "neutral",
            "why_it_matters": "Modern web services predominantly enforce HTTPS. Lack of encryption is a risk factor.",
            "limitation": "IMPORTANT: Modern phishing sites frequently use free SSL/TLS certificates (e.g., Let's Encrypt). HTTPS alone NEVER proves authenticity."
        },
        "has_suspicious_keyword": {
            "name": "Suspicious Security / Auth Keywords",
            "observed_value": ", ".join(keyword_hits) if keyword_hits else "None detected",
            "flagged": bool(has_keyword),
            "severity": "high" if keyword_cnt >= 2 else ("medium" if keyword_cnt == 1 else "neutral"),
            "why_it_matters": "Attackers disguise malicious landing pages with keywords like 'verify', 'update', 'banking', or 'wallet' to induce urgency.",
            "limitation": "Authentic portal and login pages naturally contain keywords like 'login' or 'account'."
        },
        "subdomain_count": {
            "name": "Subdomain Hierarchy",
            "observed_value": f"{subdomain_cnt} subdomains detected",
            "flagged": subdomain_cnt >= 2,
            "severity": "high" if subdomain_cnt >= 3 else ("medium" if subdomain_cnt == 2 else "neutral"),
            "why_it_matters": "Attackers often abuse deep subdomains on free hosting providers to mimic reputable brand names (e.g. paypal.verification.portal.com).",
            "limitation": "Large distributed content delivery networks (CDNs) occasionally use multiple subdomain tiers."
        },
        "has_suspicious_tld": {
            "name": "High-Abuse Top Level Domain (TLD)",
            "observed_value": f".{tld}" if tld else "None",
            "flagged": bool(has_sus_tld),
            "severity": "high" if has_sus_tld else "neutral",
            "why_it_matters": "Certain TLDs (.xyz, .tk, .top, .ml) provide free or low-cost domain registration, heavily exploited by bulk phishing campaigns.",
            "limitation": "Legitimate startups and projects also register modern generic TLDs."
        },
        "at_symbol_count": {
            "name": "'@' Symbol in URL",
            "observed_value": f"{at_cnt} found",
            "flagged": at_cnt > 0,
            "severity": "high" if at_cnt > 0 else "neutral",
            "why_it_matters": "The '@' symbol in a URL causes browsers to ignore all preceding characters as user authentication credentials, obscuring the true destination.",
            "limitation": "Rarely used in modern web applications; its presence is a strong heuristic warning."
        },
        "hyphen_count": {
            "name": "Hyphens in Hostname",
            "observed_value": f"{hyphen_cnt} hyphens",
            "flagged": hyphen_cnt >= 2,
            "severity": "medium" if hyphen_cnt >= 2 else "neutral",
            "why_it_matters": "Attackers use hyphens to stitch together impersonated brand names with security terms (e.g. 'paypal-security-update').",
            "limitation": "Many legitimate corporate domain names contain single hyphens."
        },
        "has_punycode": {
            "name": "Punycode (IDN Homograph)",
            "observed_value": "Detected ('xn--')" if has_punycode else "None",
            "flagged": bool(has_punycode),
            "severity": "high" if has_punycode else "neutral",
            "why_it_matters": "Punycode domain encodings can disguise Cyrillic or Greek characters that look identical to Latin characters (e.g., 'gооgle.com').",
            "limitation": "Legitimate international non-Latin language websites legitimately use IDN punycode."
        },
        "has_non_standard_port": {
            "name": "Non-Standard Port",
            "observed_value": f"Port {parsed.port}" if parsed.port else "Standard (80/443)",
            "flagged": bool(has_custom_port),
            "severity": "medium" if has_custom_port else "neutral",
            "why_it_matters": "Unusual ports (e.g. :8080, :8888) can bypass basic perimeter firewalls or point to ephemeral web servers.",
            "limitation": "Development, staging, and local proxy environments often use custom ports."
        }
    }

    return {
        "features": numeric_features,
        "feature_vector": [numeric_features[col] for col in FEATURE_NAMES],
        "normalized_url": normalized_url,
        "hostname": hostname,
        "scheme": parsed.scheme.lower(),
        "signals": signals
    }
