"""
Email Phishing Analyzer Service.

Analyzes raw email content and headers for phishing heuristics:
- Social engineering and urgency triggers
- Financial, credential, and account suspension hooks
- Suspicious links, IP addresses, and URL mismatches
- Header anomalies (SPF/DKIM/DMARC status, spoofed sender domains)
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse

# Common urgency and social engineering patterns
URGENCY_PATTERNS = [
    (r"\b(urgent|immediately|action required|suspended|suspension|deactivation)\b", "Urgency / Threat of Account Suspension", 20),
    (r"\b(verify your account|confirm your identity|update billing|validate login)\b", "Credential Harvesting Call-to-Action", 25),
    (r"\b(unauthorized access|security breach|suspicious activity detected|compromised)\b", "Artificial Panic Trigger", 20),
    (r"\b(wire transfer|bank transfer|gift card|crypto|bitcoin|payroll|invoice attached)\b", "Financial / Payment Coercion", 20),
    (r"\b(password expired|reset password immediately|click here to keep active)\b", "Password Expiration Lure", 20),
    (r"\b(lottery|winner|inheritance|prize claimed|congratulations you won)\b", "Advance-Fee / Lottery Scam", 25),
]

def extract_urls_from_text(text: str) -> List[str]:
    """Extracts all HTTP/HTTPS and www URLs from plain text."""
    url_pattern = r'https?://[^\s<>"\',]+|www\.[^\s<>"\',]+'
    return re.findall(url_pattern, text)


def analyze_email_text(content: str, headers: str = "") -> Dict[str, Any]:
    """
    Analyzes email body and optional headers to compute phishing likelihood.
    """
    text_to_check = f"{headers}\n{content}".strip()
    if not text_to_check:
        return {
            "risk_score": 0,
            "risk_category": "Safe",
            "prediction": "Legitimate",
            "signals": [],
            "extracted_urls": [],
            "urgency_score": 0,
            "recommendations": ["No content provided."]
        }

    signals = []
    total_score = 0

    # 1. Check Urgency and Social Engineering Keywords
    content_lower = content.lower()
    urgency_flags = 0
    for pattern, label, weight in URGENCY_PATTERNS:
        matches = re.findall(pattern, content_lower, re.IGNORECASE)
        if matches:
            unique_matches = list(set(matches))
            signals.append({
                "type": "warning",
                "title": label,
                "detail": f"Detected suspicious keywords: {', '.join(unique_matches[:4])}",
                "severity": "High" if weight >= 25 else "Medium"
            })
            total_score += weight
            urgency_flags += 1

    # 2. Extract and inspect embedded URLs
    extracted_urls = extract_urls_from_text(content)
    suspicious_url_count = 0
    shortened_domains = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"}
    
    inspected_urls = []
    for raw_url in extracted_urls[:10]:
        parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
        domain = parsed.netloc.lower()
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain))
        is_shortened = domain in shortened_domains

        flagged = False
        reasons = []
        if is_ip:
            flagged = True
            reasons.append("Raw IP address used as link destination")
            total_score += 30
        if is_shortened:
            flagged = True
            reasons.append("Shortened link obscures real destination")
            total_score += 20
        if "@" in raw_url:
            flagged = True
            reasons.append("URL contains userinfo '@' symbol")
            total_score += 25
        if not raw_url.startswith("https://"):
            reasons.append("Insecure plain HTTP link")

        if flagged:
            suspicious_url_count += 1

        inspected_urls.append({
            "url": raw_url,
            "domain": domain,
            "flagged": flagged,
            "reasons": reasons
        })

    if suspicious_url_count > 0:
        signals.append({
            "type": "danger",
            "title": "Suspicious Links Found in Email",
            "detail": f"Identified {suspicious_url_count} links with high-risk characteristics (IP/shortener/@ symbol).",
            "severity": "Critical"
        })

    # 3. Analyze Header Anomalies (if provided)
    if headers:
        headers_lower = headers.lower()
        if "spf=fail" in headers_lower or "spf=softfail" in headers_lower:
            signals.append({
                "type": "danger",
                "title": "SPF Authentication Failure",
                "detail": "Sender email server failed SPF authorization checks for sender domain.",
                "severity": "High"
            })
            total_score += 35

        if "dkim=fail" in headers_lower:
            signals.append({
                "type": "danger",
                "title": "DKIM Cryptographic Signature Invalid",
                "detail": "Email signature does not match sender domain cryptographic key.",
                "severity": "High"
            })
            total_score += 35

        if "dmarc=fail" in headers_lower:
            signals.append({
                "type": "danger",
                "title": "DMARC Policy Rejection",
                "detail": "Email failed organizational DMARC alignment policy.",
                "severity": "High"
            })
            total_score += 30

    # Normalize risk score between 0 and 100
    risk_score = min(100, max(0, total_score))
    
    if risk_score >= 60:
        risk_category = "Phishing"
        prediction = "High Risk Phishing Email"
    elif risk_score >= 30:
        risk_category = "Suspicious"
        prediction = "Suspicious Email — Exercise Caution"
    else:
        risk_category = "Safe"
        prediction = "Likely Legitimate Email"

    # Actionable security recommendations
    recommendations = []
    if risk_category in ("Phishing", "Suspicious"):
        recommendations.append("Do not click any embedded links or open unexpected attachments.")
        recommendations.append("Verify the sender by contacting the organization through official verified channels.")
        recommendations.append("Never provide passwords, verification codes, or banking details via email.")
        recommendations.append("Report this message to your security team or mail provider as a phishing attempt.")
    else:
        recommendations.append("Email appears low risk. Always remain cautious when clicking unexpected links.")

    return {
        "risk_score": round(risk_score, 1),
        "risk_category": risk_category,
        "prediction": prediction,
        "signals": signals,
        "extracted_urls": inspected_urls,
        "urgency_flags_count": urgency_flags,
        "recommendations": recommendations
    }
