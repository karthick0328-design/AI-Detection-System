# AI-Based Phishing Website Detection System — Explainable AI & Digital Safety Assistant

[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/backend-Flask%203.1-black.svg)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/ML-scikit--learn%201.9-orange.svg)](https://scikit-learn.org/)
[![Database](https://img.shields.io/badge/database-SQLite%203-lightgrey.svg)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-green.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
[![Tests](https://img.shields.io/badge/tests-24%20passed-brightgreen.svg)](docs/TESTING_REPORT.md)

---

## 1. Project Overview & Abstract

Phishing attacks deceive users into surrendering financial credentials, passwords, and private identities by mimicking authentic brand domains. Conventional protection mechanisms rely on static domain blacklists (which suffer from high zero-day latency) or client-side web crawling (which exposes scanning infrastructure to malicious JavaScript and Server-Side Request Forgery).

**PhishGuard AI** is an academic-grade, privacy-preserving, and explainable phishing website detection system. The application parses URL strings into an 18-dimensional lexical, structural, and semantic feature space and applies a trained **Random Forest Classifier** benchmarked against Decision Trees, Logistic Regression, and Gradient Boosting.

Trained on a curated academic benchmark dataset of 20,000 verified URLs, the model achieves an **F1-Score of 0.8509 and Accuracy of 85.42%** on a held-out test partition. It delivers composite risk scoring (70% model probability + 30% heuristic severity), localized SSRF-safe DNS checks, an interactive Explainable AI (XAI) feature attribution report, an SQLite scan audit log, and real-time dashboard analytics.

---

## 2. Key Features

- **Client-Safe Lexical Inspection:** Evaluates URLs without visiting or executing untrusted remote code.
- **Explainable AI (XAI) Breakdown:** Transparently displays observed values, threat rationale, and signal limitations for all 18 indicators.
- **SSRF Defense:** Automatically blocks and flags private IP addresses (RFC 1918, 127.0.0.1, link-local, IPv6).
- **Three Safety Categories:** Categorizes websites into *Higher risk*, *Lower detected risk*, and *Uncertain*.
- **Comprehensive Audit Trail:** Stores scan history in SQLite with search, filters, pagination, and CSV export.
- **Dynamic Threat Analytics:** Computes live distribution metrics, volume trends over time, and frequently triggered threat indicators.
- **Dual Interface:** Accessible via a dark-navy glassmorphism web interface or programmatic JSON REST API.

---

## 3. System Architecture & Pipeline

```text
[User URL Input] ──> [URL Normalizer & Protocol Guard] 
                               │
                               ▼
                 [18-Dimensional Feature Vector]
                               │
               ┌───────────────┼───────────────┐
               ▼               ▼               ▼
        [Random Forest]  [Rule Matrix]  [SSRF / DNS Check]
        (Probabilistic)  (Weighted)     (Local Resolver)
               │               │               │
               └───────────────┼───────────────┘
                               ▼
                 [Composite Risk Score (0-100)]
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
     [Web Report & XAI]                  [SQLite Scan Audit]
```

---

## 4. Empirical Model Benchmarks

Models were trained and evaluated on an 80/20 stratified split (15,998 training, 4,000 held-out test URLs) from the benchmark dataset (`Mitake/PhishingURLsANDBenignURLs`):

| Model Candidate | Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest Classifier** | **0.8542** | **0.8711** | **0.8315** | **0.8509** | **Selected Production Model** |
| Gradient Boosting | 0.8492 | 0.8562 | 0.8395 | 0.8478 | Benchmark Candidate |
| Decision Tree | 0.8390 | 0.8779 | 0.7875 | 0.8303 | Benchmark Candidate |
| Logistic Regression | 0.7325 | 0.7899 | 0.6335 | 0.7031 | Benchmark Candidate |

### Confusion Matrix (Held-out Test Partition: 4,000 URLs)
- **True Negatives (TN):** 1,754
- **False Positives (FP):** 246 (FPR = 12.30%)
- **False Negatives (FN):** 337 (FNR = 16.85%)
- **True Positives (TP):** 1,663

---

## 5. Input Feature Schema (18 Features)

| Feature Name | Type | Description |
| :--- | :--- | :--- |
| `url_length` | Numeric | Total character length of URL |
| `hostname_length` | Numeric | Character length of the fully qualified domain name |
| `path_length` | Numeric | Character length of resource path |
| `query_length` | Numeric | Length of URL query parameters |
| `dot_count` | Numeric | Count of `.` characters across the URL |
| `subdomain_count` | Numeric | Hierarchical subdomain depth |
| `hyphen_count` | Numeric | Count of `-` in hostname |
| `at_symbol_count` | Numeric | Count of `@` symbols (credential masquerade) |
| `digit_count_hostname` | Numeric | Digits contained in hostname |
| `digit_ratio_url` | Numeric | Ratio of numeric digits to total URL length |
| `is_ip_address` | Binary | 1 if hostname is a direct IPv4/IPv6 address; else 0 |
| `is_https` | Binary | 1 if protocol is HTTPS; else 0 |
| `has_suspicious_keyword` | Binary | 1 if credential/security keywords detected; else 0 |
| `suspicious_keyword_count`| Numeric | Total security keywords detected (`login`, `verify`, etc.) |
| `has_suspicious_tld` | Binary | 1 if high-abuse disposable TLD (.tk, .xyz, .top); else 0 |
| `has_non_standard_port` | Binary | 1 if port is not 80 or 443; else 0 |
| `has_punycode` | Binary | 1 if IDN homograph encoding (`xn--`) detected; else 0 |
| `special_char_count` | Numeric | Count of structural delimiters (`?`, `=`, `&`, `%`, `_`) |

---

## 6. Project Structure

```text
E:\AI- Detection System\
├── app.py                      # Flask Application Controller & REST API
├── config.py                   # Central Application & Security Configuration
├── requirements.txt            # Python Dependencies
├── README.md                   # Complete Documentation
├── .env.example                # Sample Environment Variables
├── .gitignore                  # Git Ignore Rules
├── data/
│   ├── README.md               # Dataset Provenance & License Documentation
│   ├── dataset.csv             # 20,000 Balanced URL Records (CC-BY-SA-4.0)
│   └── test_fixture.csv        # 50 Static URLs for Fast Offline Unit Tests
├── models/
│   ├── README.md               # Model Artifacts Documentation
│   ├── phishing_detector_model.joblib # Serialized Random Forest Classifier
│   ├── feature_names.json      # 18 Canonical Feature Names
│   ├── metadata.json           # Training Configuration & Timestamps
│   ├── evaluation_report.json  # Held-out Test Metrics
│   └── confusion_matrix.png    # Confusion Matrix Visualization
├── src/
│   ├── __init__.py
│   ├── feature_extraction.py   # Lexical URL Parsing & Signal Explanations
│   ├── download_data.py        # Dataset Fetching & Cleaning Pipeline
│   ├── train_model.py          # Multi-Model Benchmark & Serialization
│   ├── evaluation.py           # Metric Calculations & Plotting
│   ├── prediction.py           # Inference Service & Model Caching
│   ├── risk_assessment.py      # Composite Scoring Logic
│   ├── domain_checks.py        # Safe Local DNS & SSRF Guard
│   └── database.py             # SQLite Connection & Queries
├── templates/
│   ├── base.html               # Base Cyber UI Layout & Navbar
│   ├── index.html              # Landing Page & URL Input
│   ├── result.html             # Detailed Risk Report
│   ├── explain.html            # Dedicated Explainable AI Page
│   ├── history.html            # Scan Audit Trail & Filtering
│   ├── analytics.html          # Threat Telemetry Dashboard
│   └── about.html              # Methodology & Academic Architecture
├── static/
│   ├── css/style.css           # Custom Cybersecurity Dark Glassmorphism CSS
│   ├── js/main.js              # Client Interaction & Clipboard Scripts
│   └── images/logo.svg         # Vector Brand Logo
├── tests/
│   ├── __init__.py
│   ├── test_features.py        # URL Parsing & Feature Extraction Tests
│   ├── test_prediction.py      # Inference & Risk Calculation Tests
│   ├── test_database.py        # SQLite Database CRUD & Export Tests
│   ├── test_security.py        # SSRF, Private IP, & Scheme Rejection Tests
│   └── test_routes.py          # Flask Web & API Route Tests
└── docs/
    ├── PROJECT_REPORT.md       # Comprehensive Academic Project Report
    ├── SYSTEM_ARCHITECTURE.md  # Architectural Flowcharts & Specifications
    ├── TESTING_REPORT.md       # Automated Verification Results
    └── MODEL_CARD.md           # Model Capabilities, Intended Use & Ethics
```

---

## 7. Local Setup & Execution Guide (Windows)

### Step 1: Clone or Open the Workspace
```powershell
cd "E:\AI- Detection System,"
```

### Step 2: (Optional) Create & Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: (Optional) Re-download Dataset
The dataset is already acquired and saved at `data/dataset.csv`. To re-download or refresh:
```powershell
python src/download_data.py
```

### Step 5: (Optional) Re-train the Machine Learning Models
To retrain candidate models, generate confusion matrix plots, and persist artifacts to `models/`:
```powershell
python src/train_model.py --dataset data/dataset.csv
```

### Step 6: Run Automated Tests
Execute the full test suite with verbose output:
```powershell
pytest -v
```

### Step 7: Launch the Application
Start the local Flask development server:
```powershell
python app.py
```
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 8. REST API Reference

### 1. Analyze Website
- **Endpoint:** `POST /api/analyze`
- **Request Body (JSON):**
  ```json
  {
    "url": "https://www.google.com"
  }
  ```
- **Example Response (200 OK):**
  ```json
  {
    "success": true,
    "scan_id": 1,
    "submitted_url": "https://www.google.com",
    "normalized_url": "https://www.google.com",
    "hostname": "www.google.com",
    "prediction": "Predicted Legitimate",
    "risk_category": "Lower detected risk",
    "risk_score": 31.6,
    "model_probability": 0.4518,
    "warning_count": 0,
    "formula_explanation": "Composite Score (31.6/100) = [Model Probability (45.2%) × 70%] + [Heuristic Severity (0.0/100) × 30%]."
  }
  ```

### 2. Retrieve Scan by ID
- **Endpoint:** `GET /api/scan/<scan_id>`
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "scan": { "id": 1, "submitted_url": "https://www.google.com", ... }
  }
  ```

### 3. System Health Check
- **Endpoint:** `GET /health`
- **Response (200 OK):**
  ```json
  {
    "status": "healthy",
    "model_loaded": true,
    "database": "sqlite_ready"
  }
  ```

### 4. Export Scan Records to CSV
- **Endpoint:** `GET /export/csv`
- Returns formatted CSV file download.

---

## 9. Security & Safety Limitations

1. **Probabilistic Nature:** No machine learning classifier can guarantee 100% safety. A "Lower detected risk" label indicates the absence of known malicious patterns, not an endorsement of complete security.
2. **HTTPS Presence Warning:** Attackers readily configure free SSL/TLS certificates. HTTPS encrypts communication in transit but does not attest to organizational legitimacy.
3. **SSRF Guard:** The application never contacts arbitrary remote web servers directly; local DNS lookups are strictly bound to public networks.

---

## 10. References & Acknowledgments

- **Dataset:** Mitake/PhishingURLsANDBenignURLs under CC-BY-SA-4.0.
- **Tranco:** A Research-Oriented Top Sites Ranking (P. Le Pochat et al.).
- **PhishTank:** Collaborative clearing house for data and information about phishing on the Internet.
- **Scikit-Learn:** Pedregosa et al., JMLR 12, pp. 2825-2830, 2011.
