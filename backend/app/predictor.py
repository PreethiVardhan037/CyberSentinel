"""
predictor.py
------------
Loads the trained pipeline artifact and provides a thin prediction interface
consumed by the FastAPI endpoints.

Design notes
------------
- The pipeline is loaded once at module import time (singleton pattern).
- Feature validation happens before forwarding to sklearn to return
  meaningful API errors rather than cryptic sklearn exceptions.
- Probabilities are returned as model outputs; they are NOT calibrated
  confidence intervals and should not be interpreted as attack-likelihood
  guarantees.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Artifact paths (resolved relative to this file's parent, not cwd)
# ---------------------------------------------------------------------------
_THIS_DIR     = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT    = os.path.dirname(os.path.dirname(_THIS_DIR))  # backend/app → backend → CyberSentinel
_ARTIFACTS    = os.path.join(_REPO_ROOT, "ml", "artifacts")

PIPELINE_PATH  = os.path.join(_ARTIFACTS, "pipeline.joblib")
FEATURES_PATH  = os.path.join(_ARTIFACTS, "feature_names.json")
EVAL_PATH      = os.path.join(_ARTIFACTS, "eval_report.json")
MODE_PATH      = os.path.join(_ARTIFACTS, "mode.json")


# ---------------------------------------------------------------------------
# Module-level state (loaded once)
# ---------------------------------------------------------------------------
_pipeline    = None
_features:    list[str] | None = None
_eval_report: dict | None      = None
_mode:        str | None       = None


def load() -> bool:
    """
    Attempt to load all artifacts.  Returns True if successful, False if
    the model is unavailable (demo mode can still serve the info endpoint).
    """
    global _pipeline, _features, _eval_report, _mode

    if not os.path.exists(PIPELINE_PATH):
        return False

    try:
        _pipeline = joblib.load(PIPELINE_PATH)
    except Exception as exc:
        raise RuntimeError(f"Failed to load pipeline: {exc}") from exc

    if os.path.exists(FEATURES_PATH):
        with open(FEATURES_PATH) as fh:
            _features = json.load(fh)
    else:
        # Fall back to the pipeline's own feature ordering if available
        _features = None

    if os.path.exists(EVAL_PATH):
        with open(EVAL_PATH) as fh:
            _eval_report = json.load(fh)

    if os.path.exists(MODE_PATH):
        with open(MODE_PATH) as fh:
            _mode = json.load(fh).get("mode", "unknown")

    return True


def is_loaded() -> bool:
    return _pipeline is not None


def get_feature_names() -> list[str]:
    if _features:
        return _features
    raise RuntimeError("Feature names not available; train the model first.")


def get_eval_report() -> dict | None:
    return _eval_report


def get_mode() -> str:
    return _mode or "unknown"


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

MAX_BATCH_SIZE = 5_000   # guard against memory exhaustion


@dataclass
class PredictionResult:
    label:        str
    is_suspicious: bool
    probabilities: dict[str, float] = field(default_factory=dict)
    note:          str = (
        "Probabilities are raw model outputs and are NOT calibrated "
        "confidence intervals. Do not interpret them as attack-likelihood guarantees."
    )


def _validate_features(records: list[dict]) -> pd.DataFrame:
    """
    Convert a list of feature-value dicts to a validated DataFrame.
    Raises ValueError with a descriptive message on any problem.
    """
    if not is_loaded():
        raise RuntimeError("Model is not loaded. Train the model first.")

    if not records:
        raise ValueError("Empty record list.")

    if len(records) > MAX_BATCH_SIZE:
        raise ValueError(
            f"Batch size {len(records)} exceeds maximum of {MAX_BATCH_SIZE}."
        )

    feature_names = get_feature_names()
    df = pd.DataFrame(records)

    missing = [f for f in feature_names if f not in df.columns]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    # Select and reorder to match training schema
    df = df[feature_names].copy()

    # Coerce to float; non-numeric values become NaN
    for col in feature_names:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Replace infinities
    df = df.replace([float("inf"), float("-inf")], float("nan"))

    bad_rows = df.isnull().any(axis=1)
    if bad_rows.any():
        bad_cols = df.columns[df.isnull().any()].tolist()
        raise ValueError(
            f"Rows {bad_rows[bad_rows].index.tolist()} contain invalid "
            f"(NaN/inf/non-numeric) values in columns: {bad_cols}"
        )

    return df


def predict_batch(records: list[dict]) -> list[PredictionResult]:
    """Predict a batch of network-flow records."""
    df = _validate_features(records)
    X  = df.values

    labels = _pipeline.predict(X)
    probas = _pipeline.predict_proba(X)
    classes = list(_pipeline.classes_)

    results = []
    for label, proba_row in zip(labels, probas):
        prob_dict = {cls: float(p) for cls, p in zip(classes, proba_row)}
        results.append(PredictionResult(
            label=str(label),
            is_suspicious=(str(label) == "suspicious"),
            probabilities=prob_dict,
        ))
    return results


def get_feature_importances() -> dict[str, float]:
    """Return feature importances from the fitted Random Forest."""
    if not is_loaded():
        raise RuntimeError("Model is not loaded.")
    rf = _pipeline.named_steps.get("clf")
    if rf is None or not hasattr(rf, "feature_importances_"):
        raise RuntimeError("Classifier does not support feature importances.")
    return dict(zip(get_feature_names(), rf.feature_importances_.tolist()))
