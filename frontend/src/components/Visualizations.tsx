import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
} from "recharts";
import type { MetricsResponse } from "../services/api";

interface Props {
  metrics: MetricsResponse | null;
  benignCount?: number;
  suspiciousCount?: number;
  loading?: boolean;
}

const PIE_COLORS = ["#22c55e", "#ef4444"];
const BAR_COLORS = {
  precision: "#3b82f6",
  recall: "#22c55e",
  f1: "#f59e0b",
};

const MetricRow: React.FC<{ label: string; value: number }> = ({
  label,
  value,
}) => (
  <div className="metric-row">
    <span className="metric-name">{label}</span>
    <div className="metric-bar-container">
      <div
        className="metric-bar"
        style={{ width: `${Math.round(value * 100)}%` }}
      />
    </div>
    <span className="metric-value">{(value * 100).toFixed(1)}%</span>
  </div>
);

const Visualizations: React.FC<Props> = ({
  metrics,
  benignCount,
  suspiciousCount,
  loading,
}) => {
  const hasCsvData =
    benignCount !== undefined &&
    suspiciousCount !== undefined &&
    (benignCount + suspiciousCount) > 0;

  // Build bar-chart data from classification report
  const barData: { name: string; precision: number; recall: number; f1: number }[] = [];
  if (metrics?.classification_report) {
    const rpt = metrics.classification_report;
    for (const cls of ["benign", "suspicious"]) {
      if (rpt[cls]) {
        barData.push({
          name: cls,
          precision: rpt[cls].precision,
          recall: rpt[cls].recall,
          f1: rpt[cls]["f1-score"],
        });
      }
    }
  }

  const cmLabels = metrics?.confusion_matrix_labels ?? [];
  const cm = metrics?.confusion_matrix ?? [];

  // Colour confusion matrix cells
  function cmCellStyle(row: number, col: number) {
    const isCorrect = row === col;
    if (isCorrect) {
      return { background: "rgba(34, 197, 94, 0.15)", color: "#22c55e" };
    }
    return { background: "rgba(239, 68, 68, 0.1)", color: "#ef4444" };
  }

  if (loading) {
    return (
      <div className="card">
        <div className="state-container">
          <div className="spinner" />
          <div className="state-title">Loading metrics…</div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Row 1: Pie + Metrics bars */}
      <div className="grid-2">
        {/* Pie chart */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              {hasCsvData ? "CSV Analysis: Classification" : "Training Set Distribution"}
            </span>
          </div>

          {hasCsvData ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={[
                      { name: "Benign", value: benignCount },
                      { name: "Suspicious", value: suspiciousCount },
                    ]}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, percent }) =>
                      `${name}: ${(percent * 100).toFixed(0)}%`
                    }
                    labelLine={false}
                  >
                    {PIE_COLORS.map((color, idx) => (
                      <Cell key={idx} fill={color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#111d30",
                      border: "1px solid rgba(148,163,184,0.15)",
                      borderRadius: 8,
                      color: "#e2e8f0",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <p className="disclaimer" style={{ textAlign: "center" }}>
                From uploaded CSV — not live network monitoring.
              </p>
            </>
          ) : metrics?.class_distribution ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={Object.entries(metrics.class_distribution).map(
                      ([k, v]) => ({ name: k, value: v })
                    )}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, percent }) =>
                      `${name}: ${(percent * 100).toFixed(0)}%`
                    }
                    labelLine={false}
                  >
                    {PIE_COLORS.map((color, idx) => (
                      <Cell key={idx} fill={color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#111d30",
                      border: "1px solid rgba(148,163,184,0.15)",
                      borderRadius: 8,
                      color: "#e2e8f0",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <p className="disclaimer" style={{ textAlign: "center" }}>
                Training dataset class distribution
              </p>
            </>
          ) : (
            <div className="state-container" style={{ padding: "32px 0" }}>
              <div className="state-icon">📊</div>
              <div className="state-title">No data yet</div>
              <div className="state-desc">Upload a CSV to see classification results.</div>
            </div>
          )}
        </div>

        {/* Scalar metrics */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Model Evaluation Metrics (Test Set)</span>
          </div>
          {metrics?.available ? (
            <>
              <MetricRow label="Accuracy"            value={metrics.accuracy!} />
              <MetricRow label="Precision (weighted)" value={metrics.precision_weighted!} />
              <MetricRow label="Recall (weighted)"    value={metrics.recall_weighted!} />
              <MetricRow label="F1 (weighted)"        value={metrics.f1_weighted!} />
              <MetricRow label="F1 (macro)"           value={metrics.f1_macro!} />
              <p className="disclaimer" style={{ marginTop: 12 }}>
                {metrics.metrics_note}
              </p>
            </>
          ) : (
            <div className="state-container" style={{ padding: "32px 0" }}>
              <div className="state-icon">📈</div>
              <div className="state-title">Metrics unavailable</div>
              <div className="state-desc">
                Run <code>python ml/train.py</code> to generate evaluation metrics.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Row 2: Per-class bars + Confusion matrix */}
      <div className="grid-2">
        {/* Per-class bar chart */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Per-Class Precision / Recall / F1</span>
          </div>
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart
                data={barData}
                margin={{ top: 8, right: 16, left: -8, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                <XAxis
                  dataKey="name"
                  tick={{ fill: "#94a3b8", fontSize: 12 }}
                  axisLine={{ stroke: "rgba(148,163,184,0.15)" }}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 1]}
                  tick={{ fill: "#94a3b8", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
                />
                <Tooltip
                  formatter={(v: number) => `${(v * 100).toFixed(1)}%`}
                  contentStyle={{
                    background: "#111d30",
                    border: "1px solid rgba(148,163,184,0.15)",
                    borderRadius: 8,
                    color: "#e2e8f0",
                    fontSize: 12,
                  }}
                />
                <Legend iconType="circle" iconSize={8} />
                <Bar dataKey="precision" fill={BAR_COLORS.precision} name="Precision" radius={[3, 3, 0, 0]} />
                <Bar dataKey="recall"    fill={BAR_COLORS.recall}    name="Recall"    radius={[3, 3, 0, 0]} />
                <Bar dataKey="f1"        fill={BAR_COLORS.f1}        name="F1-Score"  radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="state-container" style={{ padding: "32px 0" }}>
              <div className="state-icon">📉</div>
              <div className="state-title">No per-class metrics</div>
            </div>
          )}
        </div>

        {/* Confusion matrix */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Confusion Matrix (Test Set)</span>
          </div>
          {cm.length > 0 ? (
            <div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <th
                        style={{
                          padding: "6px 12px",
                          fontSize: "0.7rem",
                          color: "var(--text-muted)",
                          textAlign: "center",
                        }}
                        colSpan={2}
                      >
                        ← Predicted →
                      </th>
                      {cmLabels.map((l) => (
                        <th
                          key={l}
                          style={{
                            padding: "6px 12px",
                            fontSize: "0.72rem",
                            color: "var(--text-secondary)",
                            textTransform: "uppercase",
                            letterSpacing: "0.06em",
                            fontWeight: 600,
                            textAlign: "center",
                          }}
                        >
                          {l}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {cm.map((row, ri) => (
                      <tr key={ri}>
                        {ri === 0 && (
                          <td
                            rowSpan={cm.length}
                            style={{
                              writingMode: "vertical-rl",
                              transform: "rotate(180deg)",
                              fontSize: "0.72rem",
                              color: "var(--text-muted)",
                              textTransform: "uppercase",
                              letterSpacing: "0.06em",
                              padding: "0 6px",
                              textAlign: "center",
                              whiteSpace: "nowrap",
                            }}
                          >
                            Actual
                          </td>
                        )}
                        <td
                          style={{
                            padding: "6px 12px",
                            fontSize: "0.72rem",
                            color: "var(--text-secondary)",
                            textTransform: "uppercase",
                            letterSpacing: "0.06em",
                            fontWeight: 600,
                            whiteSpace: "nowrap",
                          }}
                        >
                          {cmLabels[ri]}
                        </td>
                        {row.map((val, ci) => (
                          <td key={ci} style={{ padding: "4px 8px", textAlign: "center" }}>
                            <div
                              className="cm-cell"
                              style={cmCellStyle(ri, ci)}
                            >
                              {val}
                            </div>
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="disclaimer" style={{ marginTop: 10 }}>
                Green diagonal = correct predictions. Red off-diagonal = errors.
                Evaluated on held-out test split.
              </p>
            </div>
          ) : (
            <div className="state-container" style={{ padding: "32px 0" }}>
              <div className="state-icon">🔲</div>
              <div className="state-title">No confusion matrix yet</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Visualizations;
