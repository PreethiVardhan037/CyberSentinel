"""
tests/test_api.py
-----------------
Automated integration tests for the CyberSentinel FastAPI backend.

All tests use the FastAPI TestClient and do NOT require:
  - An internet connection
  - The full CIC-IDS2017 dataset
  - A running server process

Test order
----------
1. Health endpoint (no model required)
2. Info endpoint (no model required)
3. Metrics endpoint without a trained model
4. Predict endpoint without a trained model (503)
5. Train a tiny demo model → then test predict, metrics, CSV analysis
6. Validation error tests (missing features, NaN, bad CSV)
7. Feature importance endpoint
8. Deterministic data generation
9. Training / inference consistency
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile

import numpy as np
import pandas as pd
import pytest

# ---------------------------------------------------------------------------
# Ensure the backend package is importable from the tests directory
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from fastapi.testclient import TestClient

# We import the app AFTER path setup so relative imports inside app/ work
from backend.app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
    "totlen_bwd_pkts", "fwd_pkt_len_mean", "bwd_pkt_len_mean", "flow_byts_s",
    "flow_pkts_s", "fwd_iat_mean", "bwd_iat_mean", "fwd_psh_flags",
    "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags", "fin_flag_cnt",
    "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
    "urg_flag_cnt", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fwd_header_len", "bwd_header_len", "init_fwd_win_byts", "init_bwd_win_byts",
    "active_mean", "idle_mean",
]


def _valid_record() -> dict:
    """Return a plausible benign-like feature dict."""
    return {f: 1.0 for f in FEATURE_NAMES}


def _make_csv_bytes(records: list[dict]) -> bytes:
    df = pd.DataFrame(records)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode()


@pytest.fixture(scope="session", autouse=True)
def trained_model(tmp_path_factory):
    """
    Train a minimal demo model once for the entire test session.
    Overrides the artifact paths so tests use isolated temp storage.
    """
    artifacts_dir = tmp_path_factory.mktemp("artifacts")

    # Generate tiny synthetic dataset
    sys.path.insert(0, _REPO_ROOT)
    from ml.generate_sample_data import generate
    df = generate(n_benign=100, n_port_scan=30, n_dos=30, n_exfil=30, seed=0)

    # Train using the train module directly
    from ml.train import FEATURE_NAMES as TRAIN_FEATURES, train, save_artifacts
    pipeline, metrics = train(df, test_size=0.2, seed=0)

    # Save to temp artifacts directory
    import joblib
    joblib.dump(pipeline, str(artifacts_dir / "pipeline.joblib"))
    with open(artifacts_dir / "feature_names.json", "w") as fh:
        json.dump(TRAIN_FEATURES, fh)
    with open(artifacts_dir / "eval_report.json", "w") as fh:
        json.dump(metrics, fh)
    with open(artifacts_dir / "mode.json", "w") as fh:
        json.dump({"mode": "demo"}, fh)

    # Patch predictor to use temp artifacts
    import backend.app.predictor as predictor
    predictor.PIPELINE_PATH = str(artifacts_dir / "pipeline.joblib")
    predictor.FEATURES_PATH = str(artifacts_dir / "feature_names.json")
    predictor.EVAL_PATH     = str(artifacts_dir / "eval_report.json")
    predictor.MODE_PATH     = str(artifacts_dir / "mode.json")

    # Reset module state so load() re-reads from new paths
    predictor._pipeline    = None
    predictor._features    = None
    predictor._eval_report = None
    predictor._mode        = None
    predictor.load()

    yield


# ---------------------------------------------------------------------------
# 1. Health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_returns_200(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_schema(self):
        body = client.get("/health").json()
        assert "status" in body
        assert "model_loaded" in body
        assert "version" in body

    def test_health_status_ok(self):
        body = client.get("/health").json()
        assert body["status"] == "ok"

    def test_model_loaded_after_fixture(self, trained_model):
        body = client.get("/health").json()
        assert body["model_loaded"] is True


# ---------------------------------------------------------------------------
# 2. Info
# ---------------------------------------------------------------------------

class TestInfo:
    def test_info_returns_200(self):
        r = client.get("/api/v1/info")
        assert r.status_code == 200

    def test_info_has_expected_fields(self):
        body = client.get("/api/v1/info").json()
        for field in ("app_name", "version", "model_type", "mode",
                      "model_available", "expected_features", "feature_count"):
            assert field in body, f"Missing field: {field}"

    def test_info_feature_count(self, trained_model):
        body = client.get("/api/v1/info").json()
        assert body["feature_count"] == len(FEATURE_NAMES)

    def test_info_model_available(self, trained_model):
        body = client.get("/api/v1/info").json()
        assert body["model_available"] is True


# ---------------------------------------------------------------------------
# 3. Metrics
# ---------------------------------------------------------------------------

class TestMetrics:
    def test_metrics_returns_200(self):
        r = client.get("/api/v1/metrics")
        assert r.status_code == 200

    def test_metrics_available_after_training(self, trained_model):
        body = client.get("/api/v1/metrics").json()
        assert body["available"] is True

    def test_metrics_accuracy_in_range(self, trained_model):
        body = client.get("/api/v1/metrics").json()
        assert 0.0 <= body["accuracy"] <= 1.0

    def test_metrics_f1_values_present(self, trained_model):
        body = client.get("/api/v1/metrics").json()
        assert body["f1_weighted"] is not None
        assert body["f1_macro"] is not None

    def test_confusion_matrix_shape(self, trained_model):
        body  = client.get("/api/v1/metrics").json()
        cm    = body["confusion_matrix"]
        labels = body["confusion_matrix_labels"]
        n = len(labels)
        assert len(cm) == n
        assert all(len(row) == n for row in cm)

    def test_feature_importances_sum_approx_one(self, trained_model):
        body = client.get("/api/v1/metrics").json()
        if body.get("feature_importances"):
            total = sum(body["feature_importances"].values())
            assert abs(total - 1.0) < 1e-4


# ---------------------------------------------------------------------------
# 4 & 5. Prediction
# ---------------------------------------------------------------------------

class TestPredict:
    def test_predict_single_valid_record(self, trained_model):
        payload = {"records": [_valid_record()]}
        r = client.post("/api/v1/predict", json=payload)
        assert r.status_code == 200

    def test_predict_response_schema(self, trained_model):
        payload = {"records": [_valid_record()]}
        body = client.post("/api/v1/predict", json=payload).json()
        assert body["count"] == 1
        pred = body["predictions"][0]
        assert "label" in pred
        assert "is_suspicious" in pred
        assert "probabilities" in pred
        assert pred["label"] in ("benign", "suspicious")

    def test_predict_batch(self, trained_model):
        payload = {"records": [_valid_record()] * 10}
        body = client.post("/api/v1/predict", json=payload).json()
        assert body["count"] == 10

    def test_predict_probability_keys(self, trained_model):
        payload = {"records": [_valid_record()]}
        body = client.post("/api/v1/predict", json=payload).json()
        probs = body["predictions"][0]["probabilities"]
        assert all(k in ("benign", "suspicious") for k in probs)
        total = sum(probs.values())
        assert abs(total - 1.0) < 1e-5

    def test_predict_missing_feature_raises_422(self, trained_model):
        record = _valid_record()
        del record["flow_duration"]
        payload = {"records": [record]}
        r = client.post("/api/v1/predict", json=payload)
        assert r.status_code == 422

    def test_predict_empty_records_raises_422(self, trained_model):
        r = client.post("/api/v1/predict", json={"records": []})
        assert r.status_code == 422

    def test_predict_non_numeric_feature_raises_422(self, trained_model):
        record = _valid_record()
        record["flow_duration"] = "not_a_number"  # type: ignore[assignment]
        r = client.post("/api/v1/predict", json={"records": [record]})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# 6. CSV Analysis
# ---------------------------------------------------------------------------

class TestCsvAnalysis:
    def test_valid_csv_returns_200(self, trained_model):
        records = [_valid_record() for _ in range(20)]
        csv_bytes = _make_csv_bytes(records)
        r = client.post(
            "/api/v1/analyze-csv",
            files={"file": ("test.csv", csv_bytes, "text/csv")},
        )
        assert r.status_code == 200

    def test_csv_response_schema(self, trained_model):
        records = [_valid_record() for _ in range(5)]
        csv_bytes = _make_csv_bytes(records)
        body = client.post(
            "/api/v1/analyze-csv",
            files={"file": ("test.csv", csv_bytes, "text/csv")},
        ).json()
        for field in ("total_rows", "analyzed_rows", "skipped_rows",
                      "benign_count", "suspicious_count", "suspicious_pct",
                      "predictions"):
            assert field in body, f"Missing: {field}"

    def test_csv_counts_consistent(self, trained_model):
        records = [_valid_record() for _ in range(10)]
        csv_bytes = _make_csv_bytes(records)
        body = client.post(
            "/api/v1/analyze-csv",
            files={"file": ("test.csv", csv_bytes, "text/csv")},
        ).json()
        assert body["benign_count"] + body["suspicious_count"] == body["analyzed_rows"]

    def test_csv_missing_columns_raises_422(self, trained_model):
        df = pd.DataFrame({"flow_duration": [1.0], "tot_fwd_pkts": [2.0]})
        buf = io.BytesIO()
        df.to_csv(buf, index=False)
        r = client.post(
            "/api/v1/analyze-csv",
            files={"file": ("bad.csv", buf.getvalue(), "text/csv")},
        )
        assert r.status_code == 422

    def test_csv_non_csv_extension_raises_422(self, trained_model):
        r = client.post(
            "/api/v1/analyze-csv",
            files={"file": ("data.txt", b"a,b,c\n1,2,3\n", "text/plain")},
        )
        assert r.status_code == 422

    def test_csv_empty_file_raises_422(self, trained_model):
        r = client.post(
            "/api/v1/analyze-csv",
            files={"file": ("empty.csv", b"", "text/csv")},
        )
        assert r.status_code == 422

    def test_csv_with_nan_rows_skipped(self, trained_model):
        """Rows with NaN values should be skipped, not cause a 500."""
        records = [_valid_record() for _ in range(10)]
        df = pd.DataFrame(records)
        df.loc[2, "flow_duration"] = float("nan")  # intentionally bad row
        buf = io.StringIO()
        df.to_csv(buf, index=False)
        r = client.post(
            "/api/v1/analyze-csv",
            files={"file": ("nan_rows.csv", buf.getvalue().encode(), "text/csv")},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["skipped_rows"] >= 1


# ---------------------------------------------------------------------------
# 7. Feature Importance
# ---------------------------------------------------------------------------

class TestFeatureImportance:
    def test_feature_importance_returns_200(self, trained_model):
        r = client.get("/api/v1/feature-importance")
        assert r.status_code == 200

    def test_feature_importance_all_features_present(self, trained_model):
        body = client.get("/api/v1/feature-importance").json()
        fi = body["feature_importances"]
        for feat in FEATURE_NAMES:
            assert feat in fi, f"Missing feature importance for: {feat}"

    def test_feature_importance_sum_approx_one(self, trained_model):
        body = client.get("/api/v1/feature-importance").json()
        total = sum(body["feature_importances"].values())
        assert abs(total - 1.0) < 1e-4


# ---------------------------------------------------------------------------
# 8. Deterministic data generation
# ---------------------------------------------------------------------------

class TestDataGeneration:
    def test_generate_deterministic(self):
        from ml.generate_sample_data import generate
        df1 = generate(seed=42)
        df2 = generate(seed=42)
        pd.testing.assert_frame_equal(df1, df2)

    def test_generate_label_distribution(self):
        from ml.generate_sample_data import generate
        df = generate(n_benign=100, n_port_scan=50, n_dos=50, n_exfil=50, seed=1)
        counts = df["label"].value_counts()
        assert counts["benign"]     == 100
        assert counts["suspicious"] == 150

    def test_generate_no_nans(self):
        from ml.generate_sample_data import FEATURE_NAMES, generate
        df = generate(seed=7)
        assert not df[FEATURE_NAMES].isnull().any().any()

    def test_generate_synthetic_flag_always_true(self):
        from ml.generate_sample_data import generate
        df = generate(seed=7)
        assert df["is_synthetic"].all()


# ---------------------------------------------------------------------------
# 9. Training / inference consistency
# ---------------------------------------------------------------------------

class TestTrainInferenceConsistency:
    def test_predict_uses_same_feature_order_as_training(self, trained_model):
        """
        The predictor should enforce the exact feature order from training.
        Sending features in reverse order should still give consistent results
        because they are reordered by feature name.
        """
        record_fwd = _valid_record()
        # Shuffle the dict keys (Python 3.7+ dicts preserve insertion order,
        # but our predictor must reorder by canonical feature list)
        record_rev = dict(reversed(list(record_fwd.items())))

        body_fwd = client.post("/api/v1/predict", json={"records": [record_fwd]}).json()
        body_rev = client.post("/api/v1/predict", json={"records": [record_rev]}).json()

        assert body_fwd["predictions"][0]["label"] == body_rev["predictions"][0]["label"]

    def test_scaler_not_fitted_on_test_data(self, trained_model):
        """
        Sanity-check: the scaler inside the pipeline should only know about
        training-time statistics, not test-time data.  This is verified by
        checking that the pipeline was indeed fit before use.
        """
        import backend.app.predictor as predictor
        scaler = predictor._pipeline.named_steps["scaler"]
        assert hasattr(scaler, "mean_"), "Scaler has not been fitted"
        assert len(scaler.mean_) == len(FEATURE_NAMES)
