# Academic Project Report

## AI-Based Phishing Website Detection System — Explainable AI & Digital Safety Assistant

**Degree / Course:** Major Project — Computer Science and Information Security  
**Project Category:** Applied Artificial Intelligence, Cyber Defense, and Explainable AI (XAI)  
**Status:** Completed & Validated  
**Academic Year:** 2025–2026  

---

### Abstract
Phishing attacks remain one of the most prolific cyber threats worldwide, causing severe data breaches, identity theft, and corporate financial loss. Traditional defense mechanisms rely heavily on static URL blacklists or dynamic web crawling. While blacklists suffer from an inability to detect ephemeral zero-day domains, client-side web crawling exposes analyzing infrastructure to malicious scripts and Server-Side Request Forgery (SSRF).

This project presents an end-to-end, privacy-preserving, and explainable AI-based phishing website detection framework. The system parses URL strings into an 18-dimensional lexical, structural, and semantic feature space and applies supervised machine learning models (comparing Random Forest, Decision Tree, Logistic Regression, and Gradient Boosting). The best-performing model achieves an **F1-Score of 0.8509 and Accuracy of 85.42%** on a held-out test partition of 4,000 URLs drawn from an academic benchmark dataset of 20,000 verified records.

The architecture incorporates a transparent risk scoring engine that fuses model probabilities (70% weight) with heuristic rule penalties (30% weight) and localized SSRF-safe DNS validation. Crucially, the system features a dedicated Explainable AI (XAI) interface providing factor-by-factor transparency, signal limitations, and safety recommendations, ensuring users understand why a prediction was made rather than trusting an opaque decision.

---

### 1. Introduction

#### 1.1 Background
The rapid growth of web applications and digital banking has led to an exponential surge in deceptive cyber campaigns. Modern phishing attackers frequently leverage automated kit deployment, cloud-hosted reverse proxies, and internationalized domain name (IDN) homograph attacks to mimic legitimate institutions.

#### 1.2 Problem Statement
Existing security tools exhibit notable shortcomings:
1. **Blacklist Latency:** Static blacklists exhibit a detection lag ranging from several hours to days, during which attackers conduct the majority of fraudulent transactions.
2. **Resource Exhaustion & SSRF Risks:** Headless browser scrapers fetch remote HTML and execute JavaScript, exposing scanning servers to malicious payload delivery and network exploitation.
3. **Black-Box Opacity:** Conventional deep neural network or ensemble classifiers produce opaque probability scores without explaining which specific lexical tokens or structural anomalies triggered the detection.

#### 1.3 Project Objectives
- Engineer a high-speed lexical feature extraction pipeline operating strictly on URL strings without executing untrusted web code.
- Train and evaluate multiple standard classification algorithms on a verified public dataset.
- Implement SSRF-safe domain verification that blocks private/internal IP ranges (RFC 1918, loopback, link-local).
- Formulate a transparent risk assessment engine with three distinct safety categories: *Higher risk*, *Lower detected risk*, and *Uncertain*.
- Build a responsive, accessible cybersecurity web application and REST API with SQLite scan audit history and real-time dashboard analytics.

---

### 2. Literature Review & Theoretical Foundation

#### 2.1 Lexical URL Analysis vs. Content Analysis
Research by Ma et al. and Le et al. demonstrated that URL lexical attributes (e.g., token lengths, path depth, character entropy, and keyword co-occurrence) provide strong discriminative signals for malicious intent. Unlike content-based inspection, lexical analysis operates in sub-millisecond timeframes and does not require active HTTP connections to malicious web servers.

#### 2.2 Explainable AI (XAI) in Cybersecurity
In high-stakes security operations, practitioners require actionable explanations rather than binary labels. This project utilizes feature attribution and rule transparency, documenting for each observed signal:
- The measured value (e.g., 2 subdomains, direct IP hostname).
- Threat mechanism (why it indicates malicious intent).
- Fundamental limitations (e.g., noting that HTTPS presence only indicates encrypted transit, not domain trustworthiness).

---

### 3. System Architecture & Methodology

#### 3.1 Pipeline Overview
```
[User URL Input] 
       │
       ▼
[URL Normalization & Security Filtering] (Rejects non-HTTP schemes, enforces max length)
       │
       ▼
[18-Dimensional Feature Extraction] 
       │
       ├─────────────────────────────────┬─────────────────────────────────┐
       ▼                                 ▼                                 ▼
[ML Inference Engine]          [Heuristic Rule Matrix]         [Safe DNS / SSRF Guard]
(Random Forest Classifier)     (Weighted Severity Scoring)      (Blocks 127.0.0.1, 10.0.0.0/8)
       │                                 │                                 │
       └─────────────────────────────────┼─────────────────────────────────┘
                                         ▼
                          [Composite Risk Scoring Layer]
                      Score = (P_model × 70) + (Penalty_heuristic × 30)
                                         │
                                         ▼
                     [Decision Classification & Audit Logging]
              (Higher Risk / Lower Detected Risk / Uncertain) ──> [SQLite Database]
                                         │
                                         ▼
                     [Explainable AI Dashboard & REST API]
```

#### 3.2 Extracted Feature Specifications
The system extracts 18 canonical numerical features:
1. `url_length`: Total character length of normalized URL.
2. `hostname_length`: Character length of fully qualified domain name.
3. `path_length`: Length of URL resource path.
4. `query_length`: Length of query string parameters.
5. `dot_count`: Total occurrences of `.` in the URL.
6. `subdomain_count`: Number of subdomains preceding the registered domain.
7. `hyphen_count`: Occurrences of `-` in the hostname.
8. `at_symbol_count`: Occurrences of `@` (URL auth delimiter).
9. `digit_count_hostname`: Total numeric digits in hostname.
10. `digit_ratio_url`: Ratio of digits to total characters.
11. `is_ip_address`: Binary flag indicating IPv4/IPv6 hostname.
12. `is_https`: Binary flag indicating HTTPS protocol.
13. `has_suspicious_keyword`: Binary flag for security/banking keywords.
14. `suspicious_keyword_count`: Number of matched high-risk keywords.
15. `has_suspicious_tld`: Binary flag indicating high-abuse TLD (.tk, .xyz, .top, etc.).
16. `has_non_standard_port`: Binary flag for non-standard ports (e.g., 8080, 8888).
17. `has_punycode`: Binary flag indicating IDN homograph encoding (`xn--`).
18. `special_char_count`: Count of structural symbols (`?`, `=`, `&`, `%`, `_`).

---

### 4. Experimental Results & Model Benchmarks

#### 4.1 Dataset Characteristics
- **Source:** Academic Benchmark Dataset (`Mitake/PhishingURLsANDBenignURLs`), CC-BY-SA-4.0.
- **Sample Size:** 20,000 balanced records (10,000 legitimate, 10,000 phishing).
- **Split Ratio:** 80% Training (15,998 URLs), 20% Held-out Testing (4,000 URLs).
- **Stratification:** Preserved 50:50 class balance across train and test splits (`random_state=42`).

#### 4.2 Comparative Evaluation

| Candidate Model | Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** | **0.8542** | **0.8711** | **0.8315** | **0.8509** | **Selected Best** |
| Gradient Boosting | 0.8492 | 0.8562 | 0.8395 | 0.8478 | Evaluated |
| Decision Tree | 0.8390 | 0.8779 | 0.7875 | 0.8303 | Evaluated |
| Logistic Regression | 0.7325 | 0.7899 | 0.6335 | 0.7031 | Evaluated |

#### 4.3 Confusion Matrix Analysis (Random Forest on 4,000 Test URLs)
- **True Negatives (TN):** 1,754 (Accurately identified legitimate websites)
- **False Positives (FP):** 246 (Legitimate sites flagged as suspicious, FPR = 12.30%)
- **False Negatives (FN):** 337 (Phishing sites misclassified as benign, FNR = 16.85%)
- **True Positives (TP):** 1,663 (Accurately detected phishing attacks)

---

### 5. Security & Risk Assessment Engineering

#### 5.1 Composite Scoring Formula
To avoid misrepresenting arbitrary numbers as probabilities, the system documents its mathematical formula:
$$\text{Composite Risk Score} = \min(100, \max(0, [P_{\text{model}} \times 100 \times 0.70] + [S_{\text{heuristic}} \times 0.30]))$$

Where:
- $P_{\text{model}} \in [0.0, 1.0]$ is the calibrated Random Forest probability.
- $S_{\text{heuristic}} \in [0.0, 100.0]$ is the cumulative penalty score of triggered security heuristics.

#### 5.2 SSRF Protection Layer
The domain verification module inspects both direct hostnames and resolved DNS addresses against all RFC 1918 and loopback CIDR blocks:
- `127.0.0.0/8` (Loopback)
- `10.0.0.0/8` (Class A Private)
- `172.16.0.0/12` (Class B Private)
- `192.168.0.0/16` (Class C Private)
- `169.254.0.0/16` (Link-Local)
- `::1/128`, `fc00::/7`, `fe80::/10` (IPv6 Private / Link-Local)

Any internal resolution is immediately intercepted, preventing malicious users from utilizing the analyzer as an SSRF proxy to scan intranet infrastructure.

---

### 6. Software Verification & Testing
The system includes 24 automated unit and integration tests executed with `pytest`:
- **Feature Extraction Tests (7 tests):** Boundary checks, invalid input rejection, consistent feature vector ordering.
- **Prediction Tests (4 tests):** Risk calculation, probability scaling, exception safety.
- **Database Tests (7 tests):** CRUD operations, parameterized queries, pagination, CSV exports, cascade deletions.
- **Security Tests (4 tests):** Private IP filtering, SSRF prevention, dangerous protocol rejection.
- **Route Integration Tests (2 tests):** Template rendering, status codes, CSRF token validation.

**Result:** 24 passed in 2.23s with 100% test pass rate.

---

### 7. Limitations and Future Work
1. **Content Cloaking:** URLs that serve legitimate landing pages to automated scanners while serving malicious payloads exclusively to mobile user-agents cannot be identified via URL strings alone.
2. **Shortened URLs:** Free URL shortening services (e.g., bit.ly, tinyurl) mask lexical attributes; future versions should implement recursive, redirect-limited HTTP HEAD unshortening with strict hop counts and SSRF checks.
3. **Continuous Retraining:** Phishing campaigns adapt rapidly; future work will incorporate streaming online learning and incremental dataset updates via periodic cron schedulers.

---

### 8. Conclusion
The developed AI-Based Phishing Website Detection System satisfies all functional, security, and academic requirements. By combining machine learning accuracy (85.4% test accuracy) with transparent rule-based explainability and strict SSRF defenses, the system offers an accessible, educational, and effective digital safety assistant suitable for presentation and practical demonstration.
