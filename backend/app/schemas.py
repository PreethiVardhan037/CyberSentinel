"""
schemas.py
----------
Pydantic v2 models for request validation and response serialization.
All input values are strictly typed; missing or coercible fields raise
HTTP 422 before reaching the prediction logic.
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Prediction request
# ---------------------------------------------------------------------------

class NetworkFlowRecord(BaseModel):
    """A single network-flow feature record for inference."""

    flow_duration:      float = Field(..., description="Flow duration in microseconds")
    tot_fwd_pkts:       float = Field(..., description="Total forward packets")
    tot_bwd_pkts:       float = Field(..., description="Total backward packets")
    totlen_fwd_pkts:    float = Field(..., description="Total length of forward packets (bytes)")
    totlen_bwd_pkts:    float = Field(..., description="Total length of backward packets (bytes)")
    fwd_pkt_len_mean:   float = Field(..., description="Mean forward packet length")
    bwd_pkt_len_mean:   float = Field(..., description="Mean backward packet length")
    flow_byts_s:        float = Field(..., description="Flow bytes per second")
    flow_pkts_s:        float = Field(..., description="Flow packets per second")
    fwd_iat_mean:       float = Field(..., description="Mean forward inter-arrival time (µs)")
    bwd_iat_mean:       float = Field(..., description="Mean backward inter-arrival time (µs)")
    fwd_psh_flags:      float = Field(..., description="Forward PSH flag count")
    bwd_psh_flags:      float = Field(..., description="Backward PSH flag count")
    fwd_urg_flags:      float = Field(..., description="Forward URG flag count")
    bwd_urg_flags:      float = Field(..., description="Backward URG flag count")
    fin_flag_cnt:       float = Field(..., description="FIN flag count")
    syn_flag_cnt:       float = Field(..., description="SYN flag count")
    rst_flag_cnt:       float = Field(..., description="RST flag count")
    psh_flag_cnt:       float = Field(..., description="PSH flag count")
    ack_flag_cnt:       float = Field(..., description="ACK flag count")
    urg_flag_cnt:       float = Field(..., description="URG flag count")
    pkt_len_mean:       float = Field(..., description="Mean packet length")
    pkt_len_std:        float = Field(..., description="Std deviation of packet length")
    pkt_len_var:        float = Field(..., description="Variance of packet length")
    fwd_header_len:     float = Field(..., description="Total forward header length")
    bwd_header_len:     float = Field(..., description="Total backward header length")
    init_fwd_win_byts:  float = Field(..., description="Initial forward window size (bytes)")
    init_bwd_win_byts:  float = Field(..., description="Initial backward window size (bytes)")
    active_mean:        float = Field(..., description="Mean active time (µs)")
    idle_mean:          float = Field(..., description="Mean idle time (µs)")

    @field_validator("*", mode="before")
    @classmethod
    def _no_inf_nan(cls, v: Any) -> Any:
        """Reject inf and NaN at the boundary before any processing."""
        if isinstance(v, float):
            import math
            if math.isnan(v) or math.isinf(v):
                raise ValueError("Feature values must be finite numbers (no NaN or Inf).")
        return v

    def to_dict(self) -> dict[str, float]:
        return self.model_dump()


class BatchPredictRequest(BaseModel):
    records: list[NetworkFlowRecord] = Field(
        ..., min_length=1, max_length=5_000,
        description="One or more network-flow records"
    )


# ---------------------------------------------------------------------------
# Prediction responses
# ---------------------------------------------------------------------------

class SinglePrediction(BaseModel):
    label:         str
    is_suspicious: bool
    probabilities: dict[str, float]
    probability_note: str = (
        "Probabilities are raw model outputs and are NOT calibrated confidence "
        "intervals. They should not be interpreted as attack-likelihood guarantees."
    )


class BatchPredictResponse(BaseModel):
    count:       int
    predictions: list[SinglePrediction]


# ---------------------------------------------------------------------------
# CSV analysis response
# ---------------------------------------------------------------------------

class CsvRowPrediction(BaseModel):
    row_index:     int
    label:         str
    is_suspicious: bool
    probabilities: dict[str, float]
    features:      dict[str, float]  # selected features for inspection


class CsvAnalysisResponse(BaseModel):
    total_rows:        int
    analyzed_rows:     int
    skipped_rows:      int
    benign_count:      int
    suspicious_count:  int
    suspicious_pct:    float
    predictions:       list[CsvRowPrediction]
    warnings:          list[str] = []
    note:              str = (
        "This is a static CSV analysis, NOT live network monitoring. "
        "Results reflect model predictions on supplied flow records only."
    )


# ---------------------------------------------------------------------------
# Info / health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status:      str
    model_loaded: bool
    version:     str


class InfoResponse(BaseModel):
    app_name:           str
    version:            str
    model_type:         str
    mode:               str
    model_available:    bool
    expected_features:  list[str]
    feature_count:      int


class MetricsResponse(BaseModel):
    available:               bool
    accuracy:                Optional[float] = None
    precision_weighted:      Optional[float] = None
    recall_weighted:         Optional[float] = None
    f1_weighted:             Optional[float] = None
    f1_macro:                Optional[float] = None
    precision_macro:         Optional[float] = None
    recall_macro:            Optional[float] = None
    confusion_matrix:        Optional[list[list[int]]] = None
    confusion_matrix_labels: Optional[list[str]] = None
    classification_report:   Optional[dict[str, Any]] = None
    feature_importances:     Optional[dict[str, float]] = None
    dataset_size:            Optional[int] = None
    train_size:              Optional[int] = None
    test_size:               Optional[int] = None
    class_distribution:      Optional[dict[str, int]] = None
    classes:                 Optional[list[str]] = None
    metrics_note:            str = (
        "Metrics are computed on a held-out test split (20% of training data). "
        "They reflect model performance on the training dataset and do NOT "
        "guarantee real-world intrusion detection effectiveness."
    )


class ErrorResponse(BaseModel):
    error:   str
    detail:  Optional[str] = None
    status:  int
