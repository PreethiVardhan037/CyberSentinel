import React from "react";
import type { SummaryStats } from "../types";

interface Props {
  stats: SummaryStats | null;
  loading?: boolean;
}

const SummaryCards: React.FC<Props> = ({ stats, loading }) => {
  if (loading) {
    return (
      <div className="grid-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="stat-card" style={{ minHeight: 100 }}>
            <div className="state-container" style={{ padding: "20px 0" }}>
              <div className="spinner" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="grid-4">
        <div className="stat-card total">
          <div className="stat-label">Total Flows Analyzed</div>
          <div className="stat-value total">—</div>
          <div className="stat-sub">Upload a CSV to begin</div>
        </div>
        <div className="stat-card benign">
          <div className="stat-label">Benign</div>
          <div className="stat-value benign">—</div>
          <div className="stat-sub">Normal traffic flows</div>
        </div>
        <div className="stat-card susp">
          <div className="stat-label">Suspicious</div>
          <div className="stat-value susp">—</div>
          <div className="stat-sub">Detected anomalies</div>
        </div>
        <div className="stat-card pct">
          <div className="stat-label">Suspicious %</div>
          <div className="stat-value pct">—</div>
          <div className="stat-sub">Of analyzed flows</div>
        </div>
      </div>
    );
  }

  return (
    <div className="grid-4">
      <div className="stat-card total">
        <div className="stat-label">Total Flows Analyzed</div>
        <div className="stat-value total">{stats.total.toLocaleString()}</div>
        <div className="stat-sub">From uploaded CSV</div>
      </div>
      <div className="stat-card benign">
        <div className="stat-label">Benign</div>
        <div className="stat-value benign">{stats.benign.toLocaleString()}</div>
        <div className="stat-sub">Normal traffic flows</div>
      </div>
      <div className="stat-card susp">
        <div className="stat-label">Suspicious</div>
        <div className="stat-value susp">{stats.suspicious.toLocaleString()}</div>
        <div className="stat-sub">Detected anomalies</div>
      </div>
      <div className="stat-card pct">
        <div className="stat-label">Suspicious %</div>
        <div className="stat-value pct">{stats.suspiciousPct.toFixed(1)}%</div>
        <div className="stat-sub">Of analyzed flows</div>
      </div>
    </div>
  );
};

export default SummaryCards;
