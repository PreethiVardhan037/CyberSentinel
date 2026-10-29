"""
main.py
-------
CyberSentinel FastAPI application.

Endpoints
---------
GET  /health                  – Liveness / readiness check
GET  /api/v1/info             – Application and model metadata
GET  /api/v1/metrics          – Evaluation metrics from last training run
POST /api/v1/predict          – Single-record or batch prediction
POST /api/v1/analyze-csv      – CSV upload analysis
GET  /api/v1/feature-importance – Ranked feature importances (RF only)
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .predictor import (
    load as load_model,
    is_loaded,
    get_feature_names,
    get_eval_report,
    get_mode,
    get_feature_importances,
    predict_batch,
)
from .schemas import (
    BatchPredictRequest,
    BatchPredictResponse,
    CsvAnalysisResponse,
    HealthResponse,
    InfoResponse,
    MetricsResponse,
    SinglePrediction,
)
from .data_service import parse_and_predict_csv

# ---------------------------------------------------------------------------
# Application version
# ---------------------------------------------------------------------------
APP_VERSION = "1.0.0"
APP_NAME    = "CyberSentinel"


# ---------------------------------------------------------------------------
# CORS origins
# CYBERSENTINEL_ALLOWED_ORIGINS env-var is a comma-separated list of origins.
# Defaults to localhost for development.  Production should set this to the
# deployed frontend URL.
# ---------------------------------------------------------------------------
def _get_allowed_origins() -> list[str]:
    raw = os.getenv(
        "CYBERSENTINEL_ALLOWED_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
    )
    return [o.strip() for o in raw.split(",") if o.strip()]


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ML artifacts on startup (non-fatal if unavailable)."""
    try:
        loaded = load_model()
        if loaded:
            print(f"[startup] Model loaded successfully (mode: {get_mode()})")
        else:
            print("[startup] Model artifacts not found — running without a model.")
            print("[startup] Run 'python ml/train.py' to train the model.")
    except Exception as exc:
        print(f"[startup] WARNING: Could not load model: {exc}")
    yield  # application runs here
    # (cleanup would go here if needed)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "An ML-based network intrusion detection dashboard. "
        "Analyzes supplied network-flow records; does NOT capture live traffic. "
        "Synthetic-demo results do NOT establish real-world IDS effectiveness."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def _global_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error", "detail": str(exc)},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health() -> HealthResponse:
    """Liveness and readiness check."""
    return HealthResponse(
        status="ok",
        model_loaded=is_loaded(),
        version=APP_VERSION,
    )


@app.get("/api/v1/info", response_model=InfoResponse, tags=["Info"])
async def info() -> InfoResponse:
    """Application and model metadata."""
    if is_loaded():
        features = get_feature_names()
    else:
        # Return the expected schema from the training module even if
        # the model isn't loaded, so the frontend can show the feature list.
        try:
            import json, os
            feat_path = os.path.join(
                os.path.dirname(__file__), "..", "..", "ml", "artifacts", "feature_names.json"
            )
            feat_path = os.path.normpath(feat_path)
            if os.path.exists(feat_path):
                with open(feat_path) as fh:
                    features = json.load(fh)
            else:
                features = []
        except Exception:
            features = []

    return InfoResponse(
        app_name=APP_NAME,
        version=APP_VERSION,
        model_type="RandomForestClassifier (scikit-learn)",
        mode=get_mode(),
        model_available=is_loaded(),
        expected_features=features,
        feature_count=len(features),
    )


@app.get("/api/v1/metrics", response_model=MetricsResponse, tags=["Metrics"])
async def metrics() -> MetricsResponse:
    """
    Return evaluation metrics from the most recent training run.

    Notes on metrics
    ----------------
    - All metrics are computed on a held-out test split (default 20%).
    - weighted-F1 accounts for class imbalance by weighting per-class scores
      by support; macro-F1 treats every class equally regardless of size.
    - For a binary suspicious-traffic detector, recall (sensitivity) matters
      most: a missed attack (false negative) is more dangerous than a false
      alarm.  The false-positive rate determines analyst fatigue.
    """
    report = get_eval_report()
    if report is None:
        return MetricsResponse(available=False)

    return MetricsResponse(
        available=True,
        accuracy=report.get("accuracy"),
        precision_weighted=report.get("precision_weighted"),
        recall_weighted=report.get("recall_weighted"),
        f1_weighted=report.get("f1_weighted"),
        f1_macro=report.get("f1_macro"),
        precision_macro=report.get("precision_macro"),
        recall_macro=report.get("recall_macro"),
        confusion_matrix=report.get("confusion_matrix"),
        confusion_matrix_labels=report.get("confusion_matrix_labels"),
        classification_report=report.get("classification_report"),
        feature_importances=report.get("feature_importances"),
        dataset_size=report.get("dataset_size"),
        train_size=report.get("train_size"),
        test_size=report.get("test_size"),
        class_distribution=report.get("class_distribution"),
        classes=report.get("classes"),
    )


@app.post("/api/v1/predict", response_model=BatchPredictResponse, tags=["Prediction"])
async def predict(request: BatchPredictRequest) -> BatchPredictResponse:
    """
    Predict benign / suspicious for one or more network-flow records.

    Probabilities are raw model outputs; see the `probability_note` field
    for an important disclaimer.
    """
    if not is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded. Run 'python ml/train.py' to train it first.",
        )

    try:
        raw_records = [r.to_dict() for r in request.records]
        preds       = predict_batch(raw_records)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=str(exc))

    predictions = [
        SinglePrediction(
            label=p.label,
            is_suspicious=p.is_suspicious,
            probabilities=p.probabilities,
        )
        for p in preds
    ]
    return BatchPredictResponse(count=len(predictions), predictions=predictions)


@app.post("/api/v1/analyze-csv", response_model=CsvAnalysisResponse, tags=["Analysis"])
async def analyze_csv(file: UploadFile = File(...)) -> CsvAnalysisResponse:
    """
    Accept a CSV upload of network-flow records and return aggregate and
    row-level predictions.

    Restrictions
    ------------
    - Only .csv files.
    - Maximum 50 MB / 10 000 rows (first 10 000 used if larger).
    - Maximum 500 rows returned in the JSON response (all rows are classified).
    - Uploaded files are NOT saved to disk permanently.
    - File content is NOT executed.
    """
    if not is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded. Run 'python ml/train.py' to train it first.",
        )

    content = await file.read()

    try:
        result = parse_and_predict_csv(content, file.filename or "upload.csv")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=str(exc))

    return CsvAnalysisResponse(**result)


@app.get("/api/v1/feature-importance", tags=["Explanation"])
async def feature_importance() -> dict:
    """
    Return sorted feature importances from the fitted Random Forest.

    Disclaimer
    ----------
    Feature importance describes how much each feature reduces impurity in
    the fitted model; it does NOT establish that any feature CAUSES a network
    attack.  Importance values depend on the training data and model
    configuration.
    """
    if not is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded.",
        )
    try:
        importances = get_feature_importances()
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=str(exc))

    sorted_imp = dict(
        sorted(importances.items(), key=lambda x: x[1], reverse=True)
    )
    return {
        "feature_importances": sorted_imp,
        "disclaimer": (
            "Feature importance reflects the model's learned decision structure "
            "on the training dataset and does NOT imply causation."
        ),
    }
