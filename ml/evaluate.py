"""
evaluate.py
-----------
Re-evaluate a saved pipeline against any compatible CSV dataset and print
or save a fresh evaluation report. Useful for comparing demo vs. real
performance on new data without retraining.

Usage
-----
    python ml/evaluate.py --data-path data/sample/demo_data.csv
    python ml/evaluate.py --data-path /path/to/CICIDS2017.csv --output ml/artifacts/eval_report_real.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.path.join(THIS_DIR, "artifacts")

PIPELINE_PATH = os.path.join(ARTIFACTS, "pipeline.joblib")
FEATURES_PATH = os.path.join(ARTIFACTS, "feature_names.json")

LABEL_COL    = "label"
BENIGN_LABEL = "benign"
ATTACK_LABEL = "suspicious"


def _load_pipeline():
    if not os.path.exists(PIPELINE_PATH):
        sys.exit("[evaluate] Pipeline not found. Run 'python ml/train.py' first.")
    return joblib.load(PIPELINE_PATH)


def _load_features() -> list[str]:
    if not os.path.exists(FEATURES_PATH):
        sys.exit("[evaluate] feature_names.json not found. Run 'python ml/train.py' first.")
    with open(FEATURES_PATH) as fh:
        return json.load(fh)


def evaluate(data_path: str, output_path: str | None = None) -> dict:
    pipeline = _load_pipeline()
    feature_names = _load_features()

    df = pd.read_csv(data_path, low_memory=False)
    df.columns = df.columns.str.strip()

    missing = [c for c in feature_names + [LABEL_COL] if c not in df.columns]
    if missing:
        sys.exit(f"[evaluate] Missing columns: {missing}")

    df = df[feature_names + [LABEL_COL]].copy()
    df[feature_names] = df[feature_names].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=feature_names)

    X = df[feature_names].values
    y = df[LABEL_COL].values

    classes   = list(pipeline.classes_)
    y_pred    = pipeline.predict(X)

    acc       = float(accuracy_score(y, y_pred))
    f1_w      = float(f1_score(y, y_pred, average="weighted", zero_division=0))
    f1_mac    = float(f1_score(y, y_pred, average="macro",    zero_division=0))
    prec_w    = float(precision_score(y, y_pred, average="weighted", zero_division=0))
    rec_w     = float(recall_score(y, y_pred,    average="weighted", zero_division=0))
    cm        = confusion_matrix(y, y_pred, labels=classes).tolist()
    report    = classification_report(y, y_pred, labels=classes, output_dict=True, zero_division=0)

    metrics = {
        "accuracy":           acc,
        "precision_weighted": prec_w,
        "recall_weighted":    rec_w,
        "f1_weighted":        f1_w,
        "f1_macro":           f1_mac,
        "confusion_matrix":   cm,
        "confusion_matrix_labels": classes,
        "classification_report":   report,
        "dataset_size":       int(len(df)),
        "classes":            classes,
    }

    print(f"[evaluate] Accuracy:      {acc:.4f}")
    print(f"[evaluate] F1 (weighted): {f1_w:.4f}")
    print(f"[evaluate] F1 (macro):    {f1_mac:.4f}")

    if output_path:
        with open(output_path, "w") as fh:
            json.dump(metrics, fh, indent=2)
        print(f"[evaluate] Report saved → {output_path}")

    return metrics


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Evaluate saved CyberSentinel pipeline")
    p.add_argument("--data-path", required=True)
    p.add_argument("--output", default=None)
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    evaluate(args.data_path, args.output)
