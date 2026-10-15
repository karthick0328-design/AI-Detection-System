"""
Model Evaluation and Metrics Reporting Module.

Calculates comprehensive classification metrics, confusion matrix, ROC-AUC,
False Positive Rate, False Negative Rate, and generates visualization artifacts.
"""

import json
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server/script rendering
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

def evaluate_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str = "Trained Model",
    save_plot_path: Path = None
) -> Dict[str, Any]:
    """
    Evaluates a trained classifier on a held-out test set.
    
    Returns:
        Dict[str, Any]: Detailed evaluation metrics dictionary.
    """
    y_pred = model.predict(X_test)
    
    # Check if model supports predict_proba
    has_proba = hasattr(model, "predict_proba")
    if has_proba:
        try:
            y_proba = model.predict_proba(X_test)[:, 1]
            roc_auc = float(roc_auc_score(y_test, y_proba))
        except Exception:
            roc_auc = None
            y_proba = None
    else:
        roc_auc = None
        y_proba = None

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    report = {
        "model_name": model_name,
        "test_sample_count": int(len(y_test)),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4)
        },
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "matrix": cm.tolist()
        },
        "discussion": {
            "false_positives_impact": "Blocks legitimate users from accessing genuine websites, harming user trust.",
            "false_negatives_impact": "Fails to detect malicious sites, leaving users vulnerable to credential theft and malware.",
            "operational_tradeoff": "A balanced F1-score is prioritized, with conservative risk categorizations for borderline predictions."
        }
    }

    # Generate and save confusion matrix visualization if requested
    if save_plot_path:
        save_plot_path.parent.mkdir(parents=True, exist_ok=True)
        plt.figure(figsize=(6, 5))
        plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        plt.title(f"Confusion Matrix — {model_name}")
        plt.colorbar()
        tick_marks = np.arange(2)
        plt.xticks(tick_marks, ["Legitimate (0)", "Phishing (1)"])
        plt.yticks(tick_marks, ["Legitimate (0)", "Phishing (1)"])

        thresh = cm.max() / 2.0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                plt.text(
                    j, i, format(cm[i, j], "d"),
                    horizontalalignment="center",
                    color="white" if cm[i, j] > thresh else "black"
                )

        plt.ylabel("True Class")
        plt.xlabel("Predicted Class")
        plt.tight_layout()
        plt.savefig(save_plot_path, dpi=150)
        plt.close()

    return report
