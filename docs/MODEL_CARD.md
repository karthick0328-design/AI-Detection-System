# Model Card: PhishGuard Random Forest URL Classifier

## 1. Model Details
- **Model Name:** PhishGuard Random Forest Classifier
- **Model Version:** 1.0.0
- **Model Type:** Supervised Ensemble Classifier (Random Forest)
- **Framework:** scikit-learn v1.9.0
- **Serialization Format:** joblib (`models/phishing_detector_model.joblib`)
- **Release Date:** October 2026

## 2. Intended Use
- **Primary Use Case:** Real-time lexical analysis of web URLs to assist end-users and security analysts in identifying potential phishing and deceptive websites.
- **Out-of-Scope Use:** The model is not designed to act as an autonomous blocking gateway without secondary verification. It must not be used as the sole deciding factor in criminal investigations or critical access control.

## 3. Training Data
- **Dataset Name:** PhishingURLsANDBenignURLs (Curated Benchmark)
- **Source:** HuggingFace repository `Mitake/PhishingURLsANDBenignURLs`
- **License:** Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA-4.0)
- **Sample Distribution:** 20,000 balanced instances (10,000 verified legitimate, 10,000 verified phishing).
- **Partitioning:** 80% Training (15,998 URLs), 20% Held-out Testing (4,000 URLs), stratified by class label with `random_state=42`.

## 4. Hyperparameters
```json
{
  "n_estimators": 100,
  "max_depth": 16,
  "criterion": "gini",
  "min_samples_split": 2,
  "min_samples_leaf": 1,
  "random_state": 42,
  "n_jobs": -1
}
```

## 5. Performance Metrics (Held-out Test Partition)
- **Accuracy:** 85.42% (0.8542)
- **Precision:** 87.11% (0.8711)
- **Recall:** 83.15% (0.8315)
- **F1-Score:** 85.09% (0.8509)
- **ROC-AUC:** 0.9324
- **False Positive Rate (FPR):** 12.30%
- **False Negative Rate (FNR):** 16.85%

## 6. Input Feature Schema (18 Features)
1. `url_length` (float)
2. `hostname_length` (float)
3. `path_length` (float)
4. `query_length` (float)
5. `dot_count` (float)
6. `subdomain_count` (float)
7. `hyphen_count` (float)
8. `at_symbol_count` (float)
9. `digit_count_hostname` (float)
10. `digit_ratio_url` (float)
11. `is_ip_address` (float, binary)
12. `is_https` (float, binary)
13. `has_suspicious_keyword` (float, binary)
14. `suspicious_keyword_count` (float)
15. `has_suspicious_tld` (float, binary)
16. `has_non_standard_port` (float, binary)
17. `has_punycode` (float, binary)
18. `special_char_count` (float)

## 7. Limitations & Ethical Considerations
- **HTTPS Misinterpretation:** Malicious websites frequently configure legitimate TLS certificates through automated authorities (e.g. Let's Encrypt). The model treats HTTPS as a positive attribute but offsets this with high-severity penalties if deceptive keywords or IP hosts are found.
- **Novel Brand Impersonation:** Novel brand names not present in the keyword list rely solely on structural characteristics (e.g., subdomain depth, hyphens, entropy).
- **Privacy Assurance:** The model extracts features strictly on the host system without transmitting evaluated URLs to third-party tracking services.
