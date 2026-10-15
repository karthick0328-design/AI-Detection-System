import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Application configuration with secure defaults."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "phishing-detector-academic-dev-key-2026")
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH",
        "/tmp/phishing_detector.db" if os.environ.get("VERCEL") else str(BASE_DIR / "phishing_detector.db")
    )
    
    # Model Artifacts
    MODEL_DIR = BASE_DIR / "models"
    MODEL_PATH = os.environ.get("MODEL_PATH", str(MODEL_DIR / "phishing_detector_model.joblib"))
    METADATA_PATH = os.environ.get("METADATA_PATH", str(MODEL_DIR / "metadata.json"))
    FEATURES_PATH = os.environ.get("FEATURES_PATH", str(MODEL_DIR / "feature_names.json"))
    EVALUATION_PATH = os.environ.get("EVALUATION_PATH", str(MODEL_DIR / "evaluation_report.json"))
    
    # Data Paths
    DATA_DIR = BASE_DIR / "data"
    DEFAULT_DATASET_PATH = DATA_DIR / "dataset.csv"
    TEST_FIXTURE_PATH = DATA_DIR / "test_fixture.csv"
    
    # Security & Execution Controls
    ENABLE_EXTERNAL_CHECKS = os.environ.get("ENABLE_EXTERNAL_CHECKS", "0").lower() in ("1", "true", "yes")
    DOMAIN_CHECK_TIMEOUT = float(os.environ.get("DOMAIN_CHECK_TIMEOUT", "3.0"))
    MAX_URL_LENGTH = 2048
    MAX_CONTENT_LENGTH = 16 * 1024  # 16KB max request payload to prevent DoS
    
    # Risk Assessment Thresholds
    # Model probability >= HIGH_RISK_THRESHOLD -> Higher Risk
    # Model probability <= LOW_RISK_THRESHOLD -> Lower Detected Risk
    # Intermediate or conflicting -> Uncertain
    HIGH_RISK_THRESHOLD = 0.55
    LOW_RISK_THRESHOLD = 0.48
    
    # CSRF Token Expiration (seconds)
    CSRF_EXPIRATION = 3600
