"""
Reproducible Machine Learning Training and Model Selection Pipeline.

Trains, evaluates, and benchmarks multiple classification algorithms:
1. Logistic Regression (with Standard Scaling)
2. Decision Tree Classifier
3. Random Forest Classifier
4. Gradient Boosting Classifier

Selects the best performing model based on held-out validation F1-score and saves
production artifacts (model, feature schema, metadata, evaluation report).
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple

import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

# Ensure src modules are resolvable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.feature_extraction import extract_features, FEATURE_NAMES
from src.evaluation import evaluate_model
from config import Config

def extract_features_from_dataframe(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """
    Extracts features for all URLs in DataFrame, skipping unparseable rows.
    """
    X_list = []
    y_list = []
    valid_indices = []

    print(f"[*] Extracting lexical and structural features for {len(df):,} URLs...")
    for idx, row in df.iterrows():
        raw_url = str(row["url"])
        label = int(row["label"])
        try:
            feat_dict = extract_features(raw_url)
            X_list.append(feat_dict["feature_vector"])
            y_list.append(label)
            valid_indices.append(idx)
        except Exception:
            continue

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    valid_df = df.loc[valid_indices].reset_index(drop=True)
    print(f"[+] Feature extraction completed: {len(X):,} valid records extracted.")
    return X, y, valid_df


def train_and_compare_models(dataset_path: Path, output_dir: Path) -> Dict[str, Any]:
    """
    Executes model training pipeline across candidates and persists the best model.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at '{dataset_path}'. "
            f"Please run 'python src/download_data.py' first or specify a valid CSV file."
        )

    print(f"[*] Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path, on_bad_lines="skip")
    df.columns = [c.strip().lower() for c in df.columns]
    
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(f"Dataset must contain 'url' and 'label' columns. Found: {list(df.columns)}")

    # Clean missing and duplicate values
    df = df.dropna(subset=["url", "label"])
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1])]
    df = df.drop_duplicates(subset=["url"])

    print(f"[+] Dataset preprocessed: {len(df):,} unique records.")
    print(f"    - Legitimate (0): {(df['label'] == 0).sum():,}")
    print(f"    - Phishing (1):   {(df['label'] == 1).sum():,}")

    # Extract features
    X, y, clean_df = extract_features_from_dataframe(df)
    
    # Train-test split (80/20) with fixed seed and stratification
    print("[*] Splitting dataset into 80% train and 20% test sets (random_state=42, stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[+] Train samples: {len(X_train):,}, Test samples: {len(X_test):,}")

    # Define candidate models
    candidates = {
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=16, random_state=42, n_jobs=-1
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12, random_state=42
        ),
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=1000, random_state=42))
        ]),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42
        )
    }

    results = {}
    best_name = None
    best_f1 = -1.0
    best_model = None
    best_report = None

    print("\n" + "=" * 65)
    print(f"{'Candidate Model':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8}")
    print("-" * 65)

    for name, model in candidates.items():
        print(f"[*] Training {name}...")
        model.fit(X_train, y_train)
        
        report = evaluate_model(
            model=model,
            X_test=X_test,
            y_test=y_test,
            model_name=name,
            save_plot_path=None
        )
        
        m = report["metrics"]
        print(f"{name:<22} | {m['accuracy']:<9.4f} | {m['precision']:<9.4f} | {m['recall']:<8.4f} | {m['f1_score']:<8.4f}")
        results[name] = report
        
        if m["f1_score"] > best_f1:
            best_f1 = m["f1_score"]
            best_name = name
            best_model = model
            best_report = report

    print("=" * 65)
    print(f"\n[+] Selected Best Model: '{best_name}' with F1-Score: {best_f1:.4f}")

    # Re-evaluate best model and save confusion matrix visualization
    cm_plot_path = output_dir / "confusion_matrix.png"
    final_report = evaluate_model(
        model=best_model,
        X_test=X_test,
        y_test=y_test,
        model_name=best_name,
        save_plot_path=cm_plot_path
    )
    final_report["all_candidates"] = {
        k: v["metrics"] for k, v in results.items()
    }

    # Save artifacts
    model_path = output_dir / "phishing_detector_model.joblib"
    features_path = output_dir / "feature_names.json"
    metadata_path = output_dir / "metadata.json"
    evaluation_path = output_dir / "evaluation_report.json"

    print(f"[*] Saving serialized model to: {model_path}")
    joblib.dump(best_model, model_path)

    print(f"[*] Saving feature schema to: {features_path}")
    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    metadata = {
        "model_name": best_name,
        "version": "1.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": 42,
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "training_sample_count": int(len(X_train)),
        "test_sample_count": int(len(X_test)),
        "dataset_source": str(dataset_path.name),
        "best_metrics": final_report["metrics"]
    }

    print(f"[*] Saving model metadata to: {metadata_path}")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[*] Saving evaluation report to: {evaluation_path}")
    with open(evaluation_path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    print(f"[+] All artifacts successfully saved in '{output_dir}'.")
    return final_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AI Phishing Website Detection models.")
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(Config.DEFAULT_DATASET_PATH),
        help="Path to training dataset CSV."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(Config.MODEL_DIR),
        help="Directory to save model artifacts."
    )
    args = parser.parse_args()
    
    ds_path = Path(args.dataset)
    if not ds_path.exists():
        # Check if test fixture exists as a test demonstration
        if Config.TEST_FIXTURE_PATH.exists():
            print(f"[!] Target dataset '{ds_path}' not found.")
            print(f"[*] Falling back to test fixture '{Config.TEST_FIXTURE_PATH}' for demonstration...")
            ds_path = Config.TEST_FIXTURE_PATH
        else:
            print(f"[-] Dataset not found: {ds_path}")
            print("[*] Run 'python src/download_data.py' to download the full academic benchmark dataset.")
            sys.exit(1)

    train_and_compare_models(ds_path, Path(args.output_dir))
