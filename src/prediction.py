"""
Prediction and Inference Service.

Loads trained model artifacts, verifies feature alignment, executes inference,
performs domain verification, and coordinates with the risk assessment engine.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import numpy as np
import joblib

from config import Config
from src.feature_extraction import extract_features, FEATURE_NAMES
from src.domain_checks import run_domain_checks
from src.risk_assessment import calculate_risk_assessment

_MODEL_CACHE: Optional[Any] = None
_FEATURE_NAMES_CACHE: Optional[List[str]] = None
_METADATA_CACHE: Optional[Dict[str, Any]] = None

def get_model_artifacts() -> Tuple[Optional[Any], Optional[List[str]], Optional[Dict[str, Any]]]:
    """
    Loads and caches model, feature schema, and metadata artifacts.
    Returns (None, None, None) gracefully if artifacts are not yet trained.
    """
    global _MODEL_CACHE, _FEATURE_NAMES_CACHE, _METADATA_CACHE
    
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE, _FEATURE_NAMES_CACHE, _METADATA_CACHE

    model_path = Path(Config.MODEL_PATH)
    features_path = Path(Config.FEATURES_PATH)
    metadata_path = Path(Config.METADATA_PATH)

    if not model_path.exists():
        return None, None, None

    try:
        model = joblib.load(model_path)
        feature_names = FEATURE_NAMES
        if features_path.exists():
            with open(features_path, "r", encoding="utf-8") as f:
                feature_names = json.load(f)

        metadata = {}
        if metadata_path.exists():
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)

        _MODEL_CACHE = model
        _FEATURE_NAMES_CACHE = feature_names
        _METADATA_CACHE = metadata
        return _MODEL_CACHE, _FEATURE_NAMES_CACHE, _METADATA_CACHE
    except Exception as exc:
        print(f"[-] Warning: Failed to load model artifacts: {exc}")
        return None, None, None


def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    End-to-end analysis of an input URL string.
    
    1. Extracts URL characteristics and heuristic signals.
    2. Runs trained machine learning inference.
    3. Runs domain and DNS safety verification.
    4. Computes composite risk score and transparent explanations.
    """
    # Step 1: Feature Extraction
    feat_data = extract_features(raw_url)
    features_dict = feat_data["features"]
    normalized_url = feat_data["normalized_url"]
    hostname = feat_data["hostname"]
    signals = feat_data["signals"]

    # Step 2: Model Inference
    model, feature_names, metadata = get_model_artifacts()
    model_probability = None
    predicted_class = None
    model_name = "Not Loaded / Heuristic Fallback"
    model_version = "N/A"

    if model is not None and feature_names is not None:
        model_name = (metadata or {}).get("model_name", type(model).__name__)
        model_version = (metadata or {}).get("version", "1.0.0")
        
        # Align features strictly with trained schema
        vector = np.array([[features_dict.get(fn, 0.0) for fn in feature_names]], dtype=np.float32)
        
        try:
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(vector)[0]
                model_probability = round(float(probs[1]), 4)
                predicted_class = int(np.argmax(probs))
            else:
                predicted_class = int(model.predict(vector)[0])
                model_probability = 1.0 if predicted_class == 1 else 0.0
        except Exception as exc:
            print(f"[-] Model prediction failed: {exc}")
            model_probability = None
            predicted_class = None

    # Step 3: Domain Safety Checks
    domain_results = run_domain_checks(normalized_url)

    # Step 4: Risk Assessment Calculation
    assessment = calculate_risk_assessment(
        model_probability=model_probability,
        model_predicted_class=predicted_class,
        signals=signals,
        domain_results=domain_results
    )

    return {
        "submitted_url": raw_url,
        "normalized_url": normalized_url,
        "hostname": hostname,
        "model_name": model_name,
        "model_version": model_version,
        "model_available": model is not None,
        "model_probability": model_probability,
        "prediction": assessment["prediction_label"],
        "risk_category": assessment["risk_category"],
        "risk_score": assessment["risk_score"],
        "formula_explanation": assessment["formula_explanation"],
        "summary_verdict": assessment["summary_verdict"],
        "badge_class": assessment["badge_class"],
        "warning_count": assessment["warning_count"],
        "warning_signals": assessment["warning_signals"],
        "positive_signals": assessment["positive_signals"],
        "recommendations": assessment["recommendations"],
        "domain_checks": domain_results,
        "raw_features": features_dict,
        "all_signals": signals
    }
