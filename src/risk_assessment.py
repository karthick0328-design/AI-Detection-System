"""
Explainable Risk Assessment and Decision Layer.

Combines the trained machine learning model probability with heuristic URL indicators
and domain resolution results into a transparent composite risk score.

Categorizes results into three well-defined safety tiers:
1. "Higher risk"
2. "Lower detected risk"
3. "Uncertain"
"""

from typing import Dict, Any, Optional, List
from config import Config

# Heuristic weights representing relative severity of suspicious indicators (0 - 100 scale)
HEURISTIC_WEIGHTS = {
    "is_ip_address": 35.0,
    "has_punycode": 25.0,
    "at_symbol_count": 25.0,
    "has_suspicious_tld": 20.0,
    "has_suspicious_keyword": 15.0,
    "subdomain_count": 10.0,
    "is_https": 15.0,  # Flagged if HTTP (not HTTPS)
    "url_length": 10.0,
    "has_non_standard_port": 15.0,
    "hyphen_count": 10.0
}

def calculate_risk_assessment(
    model_probability: Optional[float],
    model_predicted_class: Optional[int],
    signals: Dict[str, Any],
    domain_results: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes a transparent composite risk assessment.
    
    Formula:
        If model_probability is present:
            Heuristic Severity Score = min(100, sum(weights of flagged heuristic signals))
            Composite Risk Score = (Model Probability * 100 * 0.70) + (Heuristic Severity Score * 0.30)
        If model_probability is unavailable:
            Composite Risk Score = Heuristic Severity Score
            Category defaults to 'Uncertain' or 'Higher risk' if severe flags exist.
    """
    # Count flagged warnings and compute heuristic severity
    warning_signals: List[Dict[str, Any]] = []
    positive_signals: List[Dict[str, Any]] = []
    total_heuristic_penalty = 0.0

    for key, info in signals.items():
        if info.get("flagged"):
            weight = HEURISTIC_WEIGHTS.get(key, 5.0)
            total_heuristic_penalty += weight
            warning_signals.append({
                "signal_key": key,
                "name": info["name"],
                "observed_value": info["observed_value"],
                "severity": info.get("severity", "medium"),
                "why_it_matters": info["why_it_matters"],
                "limitation": info["limitation"]
            })
        else:
            positive_signals.append({
                "signal_key": key,
                "name": info["name"],
                "observed_value": info["observed_value"]
            })

    # Domain check influences
    dns_info = domain_results.get("dns_resolution", {})
    ssrf_info = domain_results.get("ssrf_protection", {})
    if ssrf_info.get("is_private"):
        total_heuristic_penalty += 40.0
    if dns_info.get("status") == "Checked — warning found" and not dns_info.get("resolved_ip"):
        total_heuristic_penalty += 20.0

    heuristic_score = min(100.0, total_heuristic_penalty)

    # Calculate composite risk score
    if model_probability is not None:
        base_model_score = model_probability * 100.0
        composite_score = round(min(100.0, max(0.0, (base_model_score * 0.70) + (heuristic_score * 0.30))), 1)
        formula_explanation = (
            f"Composite Score ({composite_score}/100) = [Model Probability ({model_probability:.1%}) × 70%] + "
            f"[Heuristic Severity ({heuristic_score:.1f}/100) × 30%]."
        )
    else:
        composite_score = round(heuristic_score, 1)
        formula_explanation = (
            f"Composite Score ({composite_score}/100) derived purely from heuristic rules ({heuristic_score:.1f}/100) "
            "because the ML model output was unavailable."
        )

    # Determine risk category & prediction class
    has_critical_flag = ssrf_info.get("is_private") or any(
        w.get("signal_key") in {"is_ip_address", "has_punycode", "at_symbol_count"}
        for w in warning_signals
    )

    if has_critical_flag or (model_probability is not None and model_probability >= Config.HIGH_RISK_THRESHOLD) or composite_score >= 60.0:
        risk_category = "Higher risk"
        prediction_label = "Predicted Phishing"
        summary_verdict = "Suspicious signals or model evidence indicate elevated risk of phishing or deceptive practices."
        badge_class = "danger"
    elif not has_critical_flag and (
        (model_probability is not None and model_probability <= Config.LOW_RISK_THRESHOLD)
        or (composite_score <= 40.0 and len(warning_signals) <= 1)
    ):
        risk_category = "Lower detected risk"
        prediction_label = "Predicted Legitimate"
        summary_verdict = "The ML model and heuristic checks found fewer warning signals. Common deceptive patterns were not detected."
        badge_class = "success"
    else:
        risk_category = "Uncertain"
        prediction_label = "Uncertain / Insufficient Evidence"
        summary_verdict = "Conflicting indicators or intermediate confidence level. Manual caution is advised."
        badge_class = "warning"

    # Actionable guidance
    if risk_category == "Higher risk":
        recommendations = [
            "DO NOT enter sensitive credentials, passwords, or credit card details on this website.",
            "Verify the exact domain name letter-by-letter against the legitimate service provider.",
            "If this link arrived via email, SMS, or private message, treat it as suspicious and do not interact.",
            "Report this URL to your IT security administrator or PhishTank/Google Safe Browsing."
        ]
    elif risk_category == "Lower detected risk":
        recommendations = [
            "Fewer risk signals detected, but no automated system can guarantee safety.",
            "Ensure the site uses a valid, trusted SSL certificate and the browser shows a padlock.",
            "Always check that the address bar matches the intended organization before entering personal data."
        ]
    else:
        recommendations = [
            "Evidence is inconclusive. The URL exhibits mixed characteristics.",
            "Inspect the domain name carefully to confirm it belongs to the intended entity.",
            "Avoid downloading files or entering private authentication credentials until verified through a trusted channel."
        ]

    return {
        "risk_category": risk_category,
        "prediction_label": prediction_label,
        "risk_score": composite_score,
        "formula_explanation": formula_explanation,
        "summary_verdict": summary_verdict,
        "badge_class": badge_class,
        "warning_count": len(warning_signals),
        "warning_signals": warning_signals,
        "positive_signals": positive_signals,
        "recommendations": recommendations,
        "heuristic_score": heuristic_score,
        "model_probability": model_probability
    }
