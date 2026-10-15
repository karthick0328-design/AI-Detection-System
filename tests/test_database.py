"""
Unit Tests for Database Operations, Migrations, and CSV Export.
"""

import tempfile
import os
import pytest
from src.database import (
    init_db, save_scan, get_scan, list_scans,
    delete_scan, clear_history, get_analytics_summary, export_scans_csv
)

@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_db_lifecycle(temp_db):
    # Verify empty analytics
    summary = get_analytics_summary(temp_db)
    assert summary["total_scans"] == 0

    # Save a record
    scan_id = save_scan(
        submitted_url="https://www.example.com",
        normalized_url="https://www.example.com",
        hostname="example.com",
        prediction="Predicted Legitimate",
        risk_category="Lower detected risk",
        risk_score=15.0,
        model_probability=0.10,
        warning_count=0,
        dns_status="Checked — no warning returned",
        signals={"test": {"flagged": False}},
        db_path=temp_db
    )
    assert scan_id > 0

    # Retrieve record
    record = get_scan(scan_id, temp_db)
    assert record is not None
    assert record["hostname"] == "example.com"
    assert record["risk_score"] == 15.0

    # List records
    scans, count = list_scans(db_path=temp_db)
    assert count == 1
    assert len(scans) == 1

    # Filter records
    phish_scans, p_count = list_scans(prediction="Predicted Phishing", db_path=temp_db)
    assert p_count == 0

    # Export CSV
    csv_str = export_scans_csv(temp_db)
    assert "https://www.example.com" in csv_str
    assert "Predicted Legitimate" in csv_str

    # Analytics check
    summary2 = get_analytics_summary(temp_db)
    assert summary2["total_scans"] == 1
    assert summary2["legitimate_count"] == 1

    # Delete single record
    del_ok = delete_scan(scan_id, temp_db)
    assert del_ok is True
    assert get_scan(scan_id, temp_db) is None

    # Clear history
    save_scan(
        submitted_url="https://test.com", normalized_url="https://test.com",
        hostname="test.com", prediction="Predicted Phishing", risk_category="Higher risk",
        risk_score=90.0, model_probability=0.9, warning_count=2,
        dns_status="Checked — warning found", signals={}, db_path=temp_db
    )
    cleared = clear_history(temp_db)
    assert cleared == 1
    scans3, count3 = list_scans(db_path=temp_db)
    assert count3 == 0
