# Verification & Automated Testing Report

**Date of Execution:** 2026-10-14  
**Test Runner:** `pytest 9.1.1` under Python 3.11.9 (Windows 64-bit)  
**Total Tests:** 24 Executed  
**Passed:** 24 (100%)  
**Failed:** 0  
**Execution Duration:** 2.23 seconds  

---

### 1. Test Suite Execution Summary

```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\AI- Detection System,
collected 24 items

tests/test_database.py::test_db_lifecycle PASSED                         [  4%]
tests/test_features.py::test_valid_urls PASSED                           [  8%]
tests/test_features.py::test_invalid_urls PASSED                         [ 12%]
tests/test_features.py::test_ip_address_detection PASSED                 [ 16%]
tests/test_features.py::test_subdomain_counting PASSED                   [ 20%]
tests/test_features.py::test_feature_vector_schema_and_order PASSED      [ 25%]
tests/test_features.py::test_suspicious_url_signals PASSED               [ 29%]
tests/test_prediction.py::test_analyze_url_basic PASSED                  [ 33%]
tests/test_prediction.py::test_analyze_phishing_url PASSED               [ 37%]
tests/test_prediction.py::test_risk_assessment_calculation PASSED        [ 41%]
tests/test_prediction.py::test_unparseable_url_raises_value_error PASSED [ 45%]
tests/test_routes.py::test_home_page PASSED                              [ 50%]
tests/test_routes.py::test_health_check PASSED                           [ 54%]
tests/test_routes.py::test_about_page PASSED                             [ 58%]
tests/test_routes.py::test_history_page PASSED                           [ 62%]
tests/test_routes.py::test_analytics_page PASSED                         [ 66%]
tests/test_routes.py::test_export_csv_route PASSED                       [ 70%]
tests/test_routes.py::test_api_analyze PASSED                            [ 75%]
tests/test_routes.py::test_result_and_explain_views PASSED               [ 79%]
tests/test_routes.py::test_csrf_protection_on_post PASSED                [ 83%]
tests/test_security.py::test_private_ip_detection PASSED                 [ 87%]
tests/test_security.py::test_ssrf_guard_in_domain_checks PASSED          [ 91%]
tests/test_security.py::test_dangerous_schemes_rejection PASSED          [ 95%]
tests/test_security.py::test_max_url_length_rejection PASSED             [100%]

============================= 24 passed in 2.23s ==============================
```

---

### 2. Category Breakdown & Validation Coverage

#### 2.1 Feature Engineering (`tests/test_features.py`)
- Verified URL normalization for schemes, missing protocols, and trailing slashes.
- Verified exact 18-element feature vector dimensionality matching `FEATURE_NAMES`.
- Verified regex detection for IPv4 addresses (`192.168.1.1`, `8.8.8.8`) versus domain names.
- Verified subdomain counting logic handling ccTLDs (`.co.uk`) and multi-level subdomains (`a.b.c.example.com`).
- Verified suspicious keyword tracking (`login`, `verify`, `banking`, `wallet`).

#### 2.2 Prediction & Risk Assessment (`tests/test_prediction.py`)
- Verified live inference on legitimate URLs (`https://www.google.com`) returns `Lower detected risk` with score within expected bounds.
- Verified live inference on phishing sample URLs (`http://192.168.1.1/paypal-account-verify-login.php`) returns `Higher risk` and `Predicted Phishing`.
- Verified composite mathematical score calculation.
- Verified exception safety on unparseable or malicious schemes.

#### 2.3 Database Management (`tests/test_database.py`)
- Used isolated SQLite temporary files (`tempfile.mkstemp`) to ensure test independence.
- Tested complete record lifecycle: insertion, retrieval, listing, filtering by category, single deletion, and complete table purge.
- Tested CSV generation formatting and string escaping.
- Tested real-time analytics aggregation query performance.

#### 2.4 Cyber Security & SSRF Protection (`tests/test_security.py`)
- Tested private IP detection across RFC 1918 Class A (`10.0.0.1`), Class B (`172.16.0.1`), Class C (`192.168.1.1`), Loopback (`127.0.0.1`), Link-Local (`169.254.0.1`), and IPv6 (`::1`).
- Tested SSRF prevention intercepting private loopback domain queries.
- Tested rejection of dangerous URI schemes (`javascript:`, `data:`, `file:`, `vbscript:`).
- Tested 2,048 character buffer overflow prevention.

#### 2.5 Flask Routes & CSRF (`tests/test_routes.py`)
- Tested all web views (`/`, `/history`, `/analytics`, `/about`, `/health`, `/result/<id>`, `/explain/<id>`).
- Tested JSON REST endpoints (`/api/analyze`, `/health`, `/export/csv`).
- Tested CSRF rejection on state-modifying POST requests when CSRF token is omitted.
