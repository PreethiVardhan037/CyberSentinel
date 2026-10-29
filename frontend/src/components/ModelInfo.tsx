import React from "react";
import type { InfoResponse, MetricsResponse, FeatureImportanceResponse } from "../services/api";

interface Props {
  info: InfoResponse | null;
  metrics: MetricsResponse | null;
  featureImportance: FeatureImportanceResponse | null;
  loading?: boolean;
}

const ModelInfo: React.FC<Props> = ({ info, metrics, featureImportance, loading }) => {
  if (loading) {
    return (
      <div className="card">
        <div className="state-container">
          <div className="spinner" />
          <div className="state-title">Loading model information…</div>
        </div>
      </div>
    );
  }

  if (!info) {
    return (
      <div className="card">
        <div className="state-container">
          <div className="state-icon">🔌</div>
          <div className="state-title">Backend unavailable</div>
          <div className="state-desc">
            Start the FastAPI server with <code>uvicorn backend.app.main:app --reload</code>
          </div>
        </div>
      </div>
    );
  }

  const topFeatures = featureImportance
    ? Object.entries(featureImportance.feature_importances)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 15)
    : [];

  const maxImportance = topFeatures.length > 0 ? topFeatures[0][1] : 1;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Model metadata */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Model Details</span>
          </div>
          <div className="metric-row">
            <span className="metric-name">Model type</span>
            <span className="metric-value" style={{ fontSize: "0.85rem" }}>
              {info.model_type}
            </span>
          </div>
          <div className="metric-row">
            <span className="metric-name">Operating mode</span>
            <span className={`label-badge ${info.mode === "demo" ? "benign" : "suspicious"}`}>
              {info.mode}
            </span>
          </div>
          <div className="metric-row">
            <span className="metric-name">Model available</span>
            <span className={`label-badge ${info.model_available ? "benign" : "suspicious"}`}>
              {info.model_available ? "Yes" : "No — run train.py"}
            </span>
          </div>
          <div className="metric-row">
            <span className="metric-name">Feature count</span>
            <span className="metric-value">{info.feature_count}</span>
          </div>
          <div className="metric-row">
            <span className="metric-name">App version</span>
            <span className="metric-value">{info.version}</span>
          </div>
        </div>

        {/* Test-set evaluation summary */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Test-Set Evaluation (20% hold-out)</span>
          </div>
          {metrics?.available ? (
            <>
              <div className="metric-row">
                <span className="metric-name">Dataset size</span>
                <span className="metric-value">{metrics.dataset_size?.toLocaleString()}</span>
              </div>
              <div className="metric-row">
                <span className="metric-name">Training rows</span>
                <span className="metric-value">{metrics.train_size?.toLocaleString()}</span>
              </div>
              <div className="metric-row">
                <span className="metric-name">Test rows</span>
                <span className="metric-value">{metrics.test_size?.toLocaleString()}</span>
              </div>
              <div className="metric-row">
                <span className="metric-name">Accuracy</span>
                <span className="metric-value">
                  {((metrics.accuracy ?? 0) * 100).toFixed(2)}%
                </span>
              </div>
              <div className="metric-row">
                <span className="metric-name">F1 (weighted)</span>
                <span className="metric-value">
                  {((metrics.f1_weighted ?? 0) * 100).toFixed(2)}%
                </span>
              </div>
              <div className="metric-row">
                <span className="metric-name">Recall (weighted)</span>
                <span className="metric-value">
                  {((metrics.recall_weighted ?? 0) * 100).toFixed(2)}%
                </span>
              </div>
              <p className="disclaimer" style={{ marginTop: 12 }}>
                {metrics.metrics_note}
              </p>
            </>
          ) : (
            <div className="state-container" style={{ padding: "24px 0" }}>
              <div className="state-icon">📊</div>
              <div className="state-title">Metrics not available</div>
              <div className="state-desc">
                Run <code>python ml/train.py</code> to generate evaluation metrics.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Feature importance */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Top 15 Feature Importances (Random Forest)</span>
        </div>
        {topFeatures.length > 0 ? (
          <>
            {topFeatures.map(([name, val]) => (
              <div key={name} className="fi-row">
                <span className="fi-name" title={name}>{name}</span>
                <div className="fi-bar-wrap">
                  <div
                    className="fi-bar"
                    style={{ width: `${(val / maxImportance) * 100}%` }}
                  />
                </div>
                <span className="fi-val">{(val * 100).toFixed(2)}%</span>
              </div>
            ))}
            <p className="disclaimer" style={{ marginTop: 12 }}>
              {featureImportance?.disclaimer}
            </p>
          </>
        ) : (
          <div className="state-container" style={{ padding: "24px 0" }}>
            <div className="state-icon">📉</div>
            <div className="state-title">Feature importances not available</div>
            <div className="state-desc">Train the model to see feature importances.</div>
          </div>
        )}
      </div>

      {/* Expected feature schema */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Expected CSV Feature Schema ({info.feature_count} features)</span>
        </div>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "6px",
            marginBottom: 12,
          }}
        >
          {info.expected_features.map((f) => (
            <code
              key={f}
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--border-subtle)",
                borderRadius: 4,
                padding: "2px 8px",
                fontSize: "0.75rem",
                color: "var(--text-accent)",
              }}
            >
              {f}
            </code>
          ))}
        </div>
        <p className="disclaimer">
          Your CSV must contain all of the above columns with numeric values.
          Extra columns are ignored.
        </p>
      </div>

      {/* Limitations */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Limitations &amp; Data Provenance</span>
        </div>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 10,
            fontSize: "0.85rem",
            color: "var(--text-secondary)",
          }}
        >
          <div className="notice warning">
            <span>⚠</span>
            <span>
              <strong>Demo mode warning:</strong> If operating in demo mode, the
              model was trained on synthetic data generated by transparent
              heuristic rules. Synthetic-data performance does NOT establish
              real-world intrusion detection capability. Results should not be
              used to make security decisions.
            </span>
          </div>
          <div className="notice info">
            <span>ℹ</span>
            <span>
              This system analyzes supplied CSV flow records. It does NOT
              capture live network traffic. It is an educational portfolio
              prototype and NOT a replacement for a production IDS.
            </span>
          </div>
          <div className="notice info">
            <span>ℹ</span>
            <span>
              For real-world use, train the model on the CIC-IDS2017 dataset
              from the University of New Brunswick (
              <a
                href="https://www.unb.ca/cic/datasets/ids-2017.html"
                target="_blank"
                rel="noopener noreferrer"
              >
                unb.ca
              </a>
              ) and validate against independent datasets before any deployment.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModelInfo;
