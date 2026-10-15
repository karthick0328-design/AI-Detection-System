"""
Route Integration and Endpoint Tests for Flask Server.
"""

import pytest
from app import app
from src.database import save_scan

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with app.app_context():
            yield client


def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Phishing Website" in response.data
    assert b"Analyze Website" in response.data


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "sqlite_ready"


def test_health_check_browser_ui(client):
    response = client.get("/health", headers={"Accept": "text/html,application/xhtml+xml"})
    assert response.status_code == 200
    assert b"System Health &amp; Live Status" in response.data or b"System Health" in response.data
    assert b"Random Forest" in response.data
    assert b"Open Scanner" in response.data


def test_about_page(client):
    response = client.get("/about")
    assert response.status_code == 200
    assert b"Methodology" in response.data


def test_history_page(client):
    response = client.get("/history")
    assert response.status_code == 200
    assert b"Scan History" in response.data


def test_analytics_page(client):
    response = client.get("/analytics")
    assert response.status_code == 200
    assert b"Threat Analytics" in response.data


def test_export_csv_route(client):
    response = client.get("/export/csv")
    assert response.status_code == 200
    assert response.content_type == "text/csv; charset=utf-8"
    assert b"Scan ID" in response.data


def test_api_analyze(client):
    response = client.post("/api/analyze", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "prediction" in data
    assert "risk_score" in data
    assert "scan_id" in data


def test_result_and_explain_views(client):
    # Insert a dummy scan to test view rendering
    scan_id = save_scan(
        submitted_url="https://test-example.com",
        normalized_url="https://test-example.com",
        hostname="test-example.com",
        prediction="Predicted Legitimate",
        risk_category="Lower detected risk",
        risk_score=20.0,
        model_probability=0.2,
        warning_count=0,
        dns_status="Checked — no warning returned",
        signals={"url_length": {"name": "URL Length", "observed_value": "24", "flagged": False, "why_it_matters": "test", "limitation": "test"}}
    )
    
    res_page = client.get(f"/result/{scan_id}")
    assert res_page.status_code == 200
    assert b"Website Risk Assessment" in res_page.data
    assert b"test-example.com" in res_page.data

    exp_page = client.get(f"/explain/{scan_id}")
    assert exp_page.status_code == 200
    assert b"Explainable AI" in exp_page.data


def test_csrf_protection_on_post(client):
    # Posting without session or token should be rejected (403 Forbidden)
    res = client.post("/analyze", data={"url": "https://example.com"})
    assert res.status_code == 403


def test_csp_headers(client):
    res = client.get("/")
    assert res.status_code == 200
    csp = res.headers.get("Content-Security-Policy", "")
    assert "https://cdn.jsdelivr.net" in csp
    assert "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:" in csp
    assert "connect-src 'self' https://cdn.jsdelivr.net" in csp


def test_new_suite_routes(client):
    # Test Screen 2: URL Scanner
    r = client.get("/scanner")
    assert r.status_code == 200
    assert b"URL Scanner" in r.data

    # Test Screen 5: Bulk Scanner & CSV template
    r = client.get("/bulk-scanner")
    assert r.status_code == 200
    assert b"Bulk URL Scanner" in r.data

    r_tmpl = client.get("/bulk/template.csv")
    assert r_tmpl.status_code == 200
    assert b"url" in r_tmpl.data

    # Test Batch Scan API
    r_api = client.post("/api/bulk-scan", json={"urls": ["https://google.com", "https://bit.ly/secure-login"]})
    assert r_api.status_code == 200
    assert r_api.get_json()["success"] is True

    # Test Screen 6: QR Scanner
    r = client.get("/qr-scanner")
    assert r.status_code == 200
    assert b"QR Code Scanner" in r.data

    # Test Screen 7: Email Analyzer & API
    r = client.get("/email-analyzer")
    assert r.status_code == 200
    assert b"Email Phishing Analyzer" in r.data

    r_em = client.post("/api/email-analyze", json={"content": "URGENT! Account suspended, verify at http://1.2.3.4/login"})
    assert r_em.status_code == 200
    data = r_em.get_json()
    assert data["success"] is True
    assert data["result"]["risk_score"] > 0

    # Test Screen 8: User Account
    r = client.get("/account")
    assert r.status_code == 200
    assert b"User Account" in r.data

    # Test Screen 9: Security Education
    r = client.get("/education")
    assert r.status_code == 200
    assert b"Security Education Centre" in r.data

    # Test Screen 12: Navigation Overview
    r = client.get("/navigation")
    assert r.status_code == 200
    assert b"Site Navigation Overview" in r.data

    # Test Account Settings Update API
    r_update = client.post("/api/account/update", json={
        "name": "Karthick A",
        "email": "karthick.updated@security.org",
        "role": "Lead Security Analyst"
    })
    assert r_update.status_code == 200
    update_data = r_update.get_json()
    assert update_data["success"] is True
    assert update_data["user"]["email"] == "karthick.updated@security.org"

    # Test PDF Report Audit View
    r_pdf = client.get("/account/report/pdf")
    assert r_pdf.status_code == 200
    assert b"PhishingGuard" in r_pdf.data
    assert b"Executive Cybersecurity Telemetry" in r_pdf.data

    # Test Enterprise Registration Page
    r_reg = client.get("/register")
    assert r_reg.status_code == 200
    assert b"Create Security Analyst Account" in r_reg.data

    # Test Header Notifications Dropdown
    assert b"Security Notifications" in r.data
    assert b"notificationsDropdown" in r.data


