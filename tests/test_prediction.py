"""
Unit Tests for Prediction and Risk Assessment Engine.
"""

import pytest
from src.prediction import analyze_url
from src.risk_assessment import calculate_risk_assessment

def test_analyze_url_basic():
    res = analyze_url("https://www.google.com")
    assert "prediction" in res
    assert "risk_score" in res
    assert "risk_category" in res
    assert "formula_explanation" in res
    assert "warning_signals" in res
    assert isinstance(res["risk_score"], (int, float))
    assert 0 <= res["risk_score"] <= 100


def test_analyze_phishing_url():
    phish_url = "http://192.168.1.1/paypal-account-verify-login.php?update=1"
    res = analyze_url(phish_url)
    assert res["risk_category"] == "Higher risk"
    assert "Phishing" in res["prediction"]
    assert res["risk_score"] >= 60.0


def test_risk_assessment_calculation():
    # Test High Risk Combination
    high_signals = {
        "is_ip_address": {
            "name": "Direct IP", "observed_value": "Yes", "flagged": True,
            "why_it_matters": "test", "limitation": "test"
        }
    }
    domain_res = {"dns_resolution": {"status": "Checked — no warning returned"}, "ssrf_protection": {"is_private": False}}
    res_high = calculate_risk_assessment(
        model_probability=0.85,
        model_predicted_class=1,
        signals=high_signals,
        domain_results=domain_res
    )
    assert res_high["risk_category"] == "Higher risk"
    assert res_high["prediction_label"] == "Predicted Phishing"

    # Test Lower Detected Risk Combination
    low_signals = {
        "is_ip_address": {
            "name": "Direct IP", "observed_value": "No", "flagged": False,
            "why_it_matters": "test", "limitation": "test"
        }
    }
    res_low = calculate_risk_assessment(
        model_probability=0.15,
        model_predicted_class=0,
        signals=low_signals,
        domain_results=domain_res
    )
    assert res_low["risk_category"] == "Lower detected risk"
    assert res_low["prediction_label"] == "Predicted Legitimate"


def test_unparseable_url_raises_value_error():
    with pytest.raises(ValueError):
        analyze_url("javascript:alert('attack')")
