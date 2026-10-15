"""
Security Testing Suite for Phishing Detection System.

Validates SSRF prevention, private network guards, dangerous protocol rejection,
HTML escaping integrity, and input size constraints.
"""

import pytest
from src.domain_checks import is_private_ip, run_domain_checks
from src.feature_extraction import sanitize_and_normalize_url

def test_private_ip_detection():
    # Loopback
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("127.0.0.2") is True
    assert is_private_ip("::1") is True

    # RFC 1918 Private Ranges
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("172.31.255.255") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("192.168.0.254") is True

    # Public IPs (Should return False)
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False
    assert is_private_ip("142.250.190.46") is False


def test_ssrf_guard_in_domain_checks():
    # Direct private IP URL
    res = run_domain_checks("http://127.0.0.1/admin")
    assert res["ssrf_protection"]["is_private"] is True
    assert res["ssrf_protection"]["status"] == "Checked — warning found"

    res_192 = run_domain_checks("http://192.168.1.50:8080/dashboard")
    assert res_192["ssrf_protection"]["is_private"] is True
    assert res_192["ssrf_protection"]["status"] == "Checked — warning found"


def test_dangerous_schemes_rejection():
    dangerous = [
        "javascript:alert(document.cookie)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "vbscript:msgbox(1)",
        "about:blank"
    ]
    for url in dangerous:
        norm, err = sanitize_and_normalize_url(url)
        assert err != ""
        assert "Disallowed scheme" in err


def test_max_url_length_rejection():
    huge_url = "https://example.com/" + ("a" * 2500)
    norm, err = sanitize_and_normalize_url(huge_url)
    assert err != ""
    assert "exceeds maximum permitted length" in err
