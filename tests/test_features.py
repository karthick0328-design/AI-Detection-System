"""
Unit Tests for URL Parsing and Feature Extraction.
"""

import pytest
from src.feature_extraction import (
    sanitize_and_normalize_url,
    extract_features,
    is_ip_hostname,
    count_subdomains,
    FEATURE_NAMES
)

def test_valid_urls():
    url, err = sanitize_and_normalize_url("https://www.google.com")
    assert err == ""
    assert url == "https://www.google.com"

    url2, err2 = sanitize_and_normalize_url("github.com/torvalds/linux")
    assert err2 == ""
    assert url2 == "http://github.com/torvalds/linux"


def test_invalid_urls():
    url, err = sanitize_and_normalize_url("")
    assert err != ""
    assert url == ""

    # Disallowed dangerous schemes
    for bad in ["javascript:alert(1)", "data:text/html,test", "file:///etc/passwd"]:
        url, err = sanitize_and_normalize_url(bad)
        assert err != ""
        assert "Disallowed scheme" in err


def test_ip_address_detection():
    assert is_ip_hostname("192.168.1.1") == 1
    assert is_ip_hostname("8.8.8.8") == 1
    assert is_ip_hostname("google.com") == 0
    assert is_ip_hostname("paypal.com.account.verify") == 0


def test_subdomain_counting():
    assert count_subdomains("google.com") == 0
    assert count_subdomains("mail.google.com") == 1
    assert count_subdomains("a.b.c.example.com") == 3
    assert count_subdomains("bbc.co.uk") == 0
    assert count_subdomains("news.bbc.co.uk") == 1


def test_feature_vector_schema_and_order():
    res = extract_features("https://www.google.com/search?q=test")
    assert len(res["feature_vector"]) == len(FEATURE_NAMES)
    assert set(res["features"].keys()) == set(FEATURE_NAMES)

    # Feature vector matches exact order of FEATURE_NAMES
    for idx, name in enumerate(FEATURE_NAMES):
        assert res["feature_vector"][idx] == res["features"][name]


def test_suspicious_url_signals():
    phish_url = "http://192.168.1.1:8080/paypal-account-login-verify.php?user=test@hack.xyz"
    res = extract_features(phish_url)
    f = res["features"]
    
    assert f["is_ip_address"] == 1.0
    assert f["has_suspicious_keyword"] == 1.0
    assert f["has_non_standard_port"] == 1.0
    assert f["at_symbol_count"] == 1.0
    assert f["is_https"] == 0.0
    assert res["signals"]["is_ip_address"]["flagged"] is True
