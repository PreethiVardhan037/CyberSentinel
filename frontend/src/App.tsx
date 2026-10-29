import React, { useCallback, useEffect, useRef, useState } from "react";
import "./index.css";

import Header        from "./components/Header";
import SummaryCards  from "./components/SummaryCards";
import Visualizations from "./components/Visualizations";
import CsvUpload     from "./components/CsvUpload";
import ResultsTable  from "./components/ResultsTable";
import ModelInfo     from "./components/ModelInfo";

import { api } from "./services/api";
import type {
  CsvAnalysisResponse,
  FeatureImportanceResponse,
  InfoResponse,
  MetricsResponse,
} from "./services/api";
import type { ConnectionStatus, SummaryStats } from "./types";

type Tab = "dashboard" | "csv" | "model";

function App() {
  // Global state
  const [connection, setConnection] = useState<ConnectionStatus>("checking");
  const [modelLoaded, setModelLoaded] = useState(false);
  const [mode, setMode]             = useState("unknown");
  const [version, setVersion]       = useState("");

  const [info, setInfo]                           = useState<InfoResponse | null>(null);
  const [metrics, setMetrics]                     = useState<MetricsResponse | null>(null);
  const [featureImportance, setFeatureImportance] = useState<FeatureImportanceResponse | null>(null);

  const [csvResult, setCsvResult] = useState<CsvAnalysisResponse | null>(null);
  const [stats, setStats]         = useState<SummaryStats | null>(null);

  const [activeTab, setActiveTab]     = useState<Tab>("dashboard");
  const [metricsLoading, setMetricsLoading] = useState(true);
  const [infoLoading, setInfoLoading]     = useState(true);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ---------------------------------------------------------------------------
  // Bootstrap: health → info → metrics → feature importance
  // ---------------------------------------------------------------------------
  const loadAll = useCallback(async () => {
    // 1. Health
    try {
      const h = await api.health();
      setConnection("online");
      setModelLoaded(h.model_loaded);
      setVersion(h.version);
    } catch {
      setConnection("offline");
      setModelLoaded(false);
      setMetricsLoading(false);
      setInfoLoading(false);
      return;
    }

    // 2. Info
    setInfoLoading(true);
    try {
      const i = await api.info();
      setInfo(i);
      setMode(i.mode);
    } catch {
      /* info unavailable — not fatal */
    } finally {
      setInfoLoading(false);
    }

    // 3. Metrics
    setMetricsLoading(true);
    try {
      const m = await api.metrics();
      setMetrics(m);
    } catch {
      setMetrics(null);
    } finally {
      setMetricsLoading(false);
    }

    // 4. Feature importance (only if model is loaded)
    try {
      const fi = await api.featureImportance();
      setFeatureImportance(fi);
    } catch {
      setFeatureImportance(null);
    }
  }, []);

  useEffect(() => {
    loadAll();
    // Poll health every 30 s so the status badge updates if server restarts
    pollRef.current = setInterval(async () => {
      try {
        const h = await api.health();
        setConnection("online");
        setModelLoaded(h.model_loaded);
        if (!h.model_loaded) {
          setMetrics(null);
          setFeatureImportance(null);
        }
      } catch {
        setConnection("offline");
        setModelLoaded(false);
      }
    }, 30_000);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [loadAll]);

  // ---------------------------------------------------------------------------
  // CSV upload callback
  // ---------------------------------------------------------------------------
  const handleCsvResult = useCallback((result: CsvAnalysisResponse) => {
    setCsvResult(result);
    setStats({
      total:         result.analyzed_rows,
      benign:        result.benign_count,
      suspicious:    result.suspicious_count,
      suspiciousPct: result.suspicious_pct,
    });
    // Switch to dashboard to show the updated distribution chart
    setActiveTab("dashboard");
  }, []);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="app-shell">
      <Header
        connection={connection}
        modelLoaded={modelLoaded}
        mode={mode}
        version={version}
      />

      {/* Navigation */}
      <div className="main-content">
        <nav className="nav-tabs" aria-label="Dashboard sections">
          <button
            id="tab-dashboard"
            className={`nav-tab ${activeTab === "dashboard" ? "active" : ""}`}
            onClick={() => setActiveTab("dashboard")}
            aria-selected={activeTab === "dashboard"}
          >
            📊 Dashboard
          </button>
          <button
            id="tab-csv"
            className={`nav-tab ${activeTab === "csv" ? "active" : ""}`}
            onClick={() => setActiveTab("csv")}
            aria-selected={activeTab === "csv"}
          >
            📁 CSV Analysis
          </button>
          <button
            id="tab-model"
            className={`nav-tab ${activeTab === "model" ? "active" : ""}`}
            onClick={() => setActiveTab("model")}
            aria-selected={activeTab === "model"}
          >
            🤖 Model Info
          </button>
        </nav>

        {/* ----------------------------------------------------------------
            Tab: Dashboard
        ---------------------------------------------------------------- */}
        {activeTab === "dashboard" && (
          <div>
            {/* Offline notice */}
            {connection === "offline" && (
              <div className="notice danger" style={{ margin: "16px 0" }}>
                <span>⚠</span>
                <span>
                  Backend is offline. Start the server with{" "}
                  <code>uvicorn backend.app.main:app --reload --port 8000</code>
                </span>
              </div>
            )}

            {/* Summary cards */}
            <div className="section">
              <div className="section-title">Analysis Summary</div>
              <SummaryCards stats={stats} />
            </div>

            {!stats && (
              <div className="notice info" style={{ margin: "16px 0" }}>
                <span>ℹ</span>
                <span>
                  No CSV uploaded yet. Go to the{" "}
                  <button
                    style={{
                      background: "none",
                      border: "none",
                      color: "var(--accent-secondary)",
                      cursor: "pointer",
                      font: "inherit",
                      textDecoration: "underline",
                    }}
                    onClick={() => setActiveTab("csv")}
                  >
                    CSV Analysis tab
                  </button>{" "}
                  to upload flow records for prediction. Charts below show
                  training-set evaluation metrics.
                </span>
              </div>
            )}

            {/* Visualizations */}
            <div className="section">
              <div className="section-title">Visualizations</div>
              <Visualizations
                metrics={metrics}
                benignCount={csvResult?.benign_count}
                suspiciousCount={csvResult?.suspicious_count}
                loading={metricsLoading}
              />
            </div>
          </div>
        )}

        {/* ----------------------------------------------------------------
            Tab: CSV Analysis
        ---------------------------------------------------------------- */}
        {activeTab === "csv" && (
          <div>
            <div className="section">
              <CsvUpload onResult={handleCsvResult} modelLoaded={modelLoaded} />
            </div>

            {csvResult ? (
              <div className="section">
                <div className="section-title">Prediction Results</div>
                <div className="card">
                  <ResultsTable result={csvResult} />
                </div>
              </div>
            ) : (
              <div className="section">
                <div className="card">
                  <div className="state-container">
                    <div className="state-icon">📋</div>
                    <div className="state-title">No results yet</div>
                    <div className="state-desc">
                      Upload a compatible CSV file above to see row-level predictions.
                      <br />
                      <br />
                      You can use <code>data/sample/demo_data.csv</code> as a test file.
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ----------------------------------------------------------------
            Tab: Model Info
        ---------------------------------------------------------------- */}
        {activeTab === "model" && (
          <div className="section">
            <ModelInfo
              info={info}
              metrics={metrics}
              featureImportance={featureImportance}
              loading={infoLoading}
            />
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
