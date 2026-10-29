"""
data_service.py
---------------
Shared utilities for CSV parsing and validation used by the API layer.
Kept separate from predictor.py to maintain single-responsibility.
"""

from __future__ import annotations

import io
from typing import Tuple

import numpy as np
import pandas as pd

from . import predictor

MAX_CSV_ROWS    = 10_000
MAX_CSV_BYTES   = 50 * 1024 * 1024   # 50 MB
DISPLAY_LIMIT   = 500                  # rows returned in JSON response


def parse_and_predict_csv(
    content: bytes,
    filename: str,
) -> dict:
    """
    Parse a CSV upload, run batch inference, and return aggregated results.

    Parameters
    ----------
    content  : Raw bytes of the uploaded file.
    filename : Original filename (used for type-checking only, not as a path).

    Returns
    -------
    dict with keys matching CsvAnalysisResponse.
    """
    warnings: list[str] = []

    # --- Type check --------------------------------------------------------
    if not filename.lower().endswith(".csv"):
        raise ValueError("Only .csv files are accepted.")

    # --- Size check --------------------------------------------------------
    if len(content) > MAX_CSV_BYTES:
        raise ValueError(
            f"File size {len(content) / 1e6:.1f} MB exceeds the "
            f"{MAX_CSV_BYTES / 1e6:.0f} MB limit."
        )

    # --- Parse -------------------------------------------------------------
    try:
        df = pd.read_csv(io.BytesIO(content), low_memory=False)
    except Exception as exc:
        raise ValueError(f"Could not parse CSV: {exc}") from exc

    df.columns = df.columns.str.strip()
    total_rows = len(df)

    if total_rows == 0:
        raise ValueError("The uploaded CSV is empty.")

    if total_rows > MAX_CSV_ROWS:
        warnings.append(
            f"CSV has {total_rows} rows; only the first {MAX_CSV_ROWS} will be analyzed."
        )
        df = df.head(MAX_CSV_ROWS)

    # --- Feature validation ------------------------------------------------
    feature_names = predictor.get_feature_names()
    missing_cols  = [f for f in feature_names if f not in df.columns]
    if missing_cols:
        raise ValueError(
            f"CSV is missing required columns: {missing_cols}. "
            f"Found columns: {list(df.columns[:20])}"
        )

    # Select only the required feature columns to avoid label-leakage issues
    df_feat = df[feature_names].copy()

    # Coerce to numeric
    for col in feature_names:
        df_feat[col] = pd.to_numeric(df_feat[col], errors="coerce")

    # Replace inf
    df_feat = df_feat.replace([np.inf, -np.inf], np.nan)

    # Mark and skip bad rows
    bad_mask = df_feat.isnull().any(axis=1)
    skipped  = int(bad_mask.sum())
    if skipped > 0:
        warnings.append(
            f"{skipped} rows were skipped because they contained "
            "invalid (NaN/Inf/non-numeric) feature values."
        )

    df_clean  = df_feat[~bad_mask].copy()
    clean_idx = df_feat[~bad_mask].index.tolist()
    analyzed  = len(df_clean)

    if analyzed == 0:
        raise ValueError(
            "No valid rows remained after cleaning. "
            "Check that your CSV contains the required numeric feature columns."
        )

    # --- Inference ---------------------------------------------------------
    records  = df_clean.to_dict(orient="records")
    preds    = predictor.predict_batch(records)

    benign_count     = sum(1 for p in preds if not p.is_suspicious)
    suspicious_count = sum(1 for p in preds if p.is_suspicious)
    suspicious_pct   = (suspicious_count / analyzed * 100) if analyzed else 0.0

    # --- Build row-level output (limited to DISPLAY_LIMIT) -----------------
    display_records = []
    for i, (orig_idx, pred) in enumerate(zip(clean_idx, preds)):
        if i >= DISPLAY_LIMIT:
            if len(preds) > DISPLAY_LIMIT:
                warnings.append(
                    f"Only the first {DISPLAY_LIMIT} row predictions are returned "
                    f"in this response; all {analyzed} were classified in the counts above."
                )
            break

        # Include a curated subset of features for the UI inspection panel
        feature_subset = {
            k: float(df_clean.loc[orig_idx, k])
            for k in [
                "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
                "flow_byts_s", "flow_pkts_s", "syn_flag_cnt",
                "urg_flag_cnt", "pkt_len_mean",
            ]
            if k in df_clean.columns
        }

        display_records.append({
            "row_index":     int(orig_idx),
            "label":         pred.label,
            "is_suspicious": pred.is_suspicious,
            "probabilities": pred.probabilities,
            "features":      feature_subset,
        })

    return {
        "total_rows":       total_rows,
        "analyzed_rows":    analyzed,
        "skipped_rows":     skipped,
        "benign_count":     benign_count,
        "suspicious_count": suspicious_count,
        "suspicious_pct":   round(suspicious_pct, 2),
        "predictions":      display_records,
        "warnings":         warnings,
    }
