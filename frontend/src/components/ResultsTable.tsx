import React, { useMemo, useState } from "react";
import type { CsvAnalysisResponse, CsvRowPrediction } from "../services/api";

interface Props {
  result: CsvAnalysisResponse;
}

const PAGE_SIZE = 25;

const ResultsTable: React.FC<Props> = ({ result }) => {
  const [filter, setFilter]     = useState<"all" | "benign" | "suspicious">("all");
  const [search, setSearch]     = useState("");
  const [page, setPage]         = useState(1);
  const [expanded, setExpanded] = useState<number | null>(null);

  const filtered: CsvRowPrediction[] = useMemo(() => {
    return result.predictions.filter((p) => {
      if (filter === "benign"     && p.is_suspicious)  return false;
      if (filter === "suspicious" && !p.is_suspicious) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          p.label.includes(q) ||
          p.row_index.toString().includes(q) ||
          Object.values(p.features).some((v) =>
            v.toString().includes(q)
          )
        );
      }
      return true;
    });
  }, [result.predictions, filter, search]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageData   = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleFilterChange = (f: "all" | "benign" | "suspicious") => {
    setFilter(f);
    setPage(1);
    setExpanded(null);
  };

  const handleSearch = (q: string) => {
    setSearch(q);
    setPage(1);
    setExpanded(null);
  };

  const featureKeys = Object.keys(result.predictions[0]?.features ?? {});

  return (
    <div>
      {/* Summary bar */}
      <div
        style={{
          display: "flex",
          gap: 20,
          marginBottom: 16,
          flexWrap: "wrap",
          alignItems: "center",
        }}
      >
        <div className="notice ok" style={{ flex: "none", padding: "8px 14px" }}>
          <span>Total rows: <strong>{result.total_rows}</strong></span>
          <span style={{ margin: "0 12px", opacity: 0.4 }}>|</span>
          <span>Analyzed: <strong>{result.analyzed_rows}</strong></span>
          {result.skipped_rows > 0 && (
            <>
              <span style={{ margin: "0 12px", opacity: 0.4 }}>|</span>
              <span>Skipped: <strong style={{ color: "var(--warning)" }}>{result.skipped_rows}</strong></span>
            </>
          )}
          <span style={{ margin: "0 12px", opacity: 0.4 }}>|</span>
          <span>Benign: <strong style={{ color: "var(--ok)" }}>{result.benign_count}</strong></span>
          <span style={{ margin: "0 12px", opacity: 0.4 }}>|</span>
          <span>Suspicious: <strong style={{ color: "var(--danger)" }}>{result.suspicious_count}</strong></span>
        </div>
      </div>

      {/* Warnings */}
      {result.warnings.map((w, i) => (
        <div key={i} className="notice warning" style={{ marginBottom: 8 }}>
          <span>⚠</span>
          <span>{w}</span>
        </div>
      ))}

      {/* Note */}
      <div className="notice info" style={{ marginBottom: 12 }}>
        <span>ℹ</span>
        <span>{result.note}</span>
      </div>

      {/* Filters */}
      <div className="filter-row">
        <input
          className="search-input"
          placeholder="Search by row index, label, or feature value…"
          value={search}
          onChange={(e) => handleSearch(e.target.value)}
          id="result-search"
          aria-label="Search results"
        />
        <select
          className="filter-select"
          value={filter}
          onChange={(e) => handleFilterChange(e.target.value as typeof filter)}
          id="result-filter"
          aria-label="Filter by classification"
        >
          <option value="all">All ({result.predictions.length})</option>
          <option value="benign">Benign ({result.benign_count})</option>
          <option value="suspicious">Suspicious ({result.suspicious_count})</option>
        </select>
      </div>

      {filtered.length === 0 ? (
        <div className="state-container">
          <div className="state-icon">🔍</div>
          <div className="state-title">No matching records</div>
          <div className="state-desc">Try clearing the search or filter.</div>
        </div>
      ) : (
        <>
          <div className="table-wrapper">
            <table id="results-table">
              <thead>
                <tr>
                  <th>Row</th>
                  <th>Classification</th>
                  <th>Prob (benign)</th>
                  <th>Prob (suspicious)</th>
                  {featureKeys.map((k) => (
                    <th key={k}>{k.replace(/_/g, " ")}</th>
                  ))}
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {pageData.map((row) => (
                  <React.Fragment key={row.row_index}>
                    <tr>
                      <td>
                        <code style={{ color: "var(--text-muted)", fontSize: "0.78rem" }}>
                          #{row.row_index}
                        </code>
                      </td>
                      <td>
                        <span className={`label-badge ${row.label}`}>
                          {row.is_suspicious ? "⚠ " : "✓ "}
                          {row.label}
                        </span>
                      </td>
                      <td>
                        {(row.probabilities["benign"] * 100).toFixed(1)}%
                      </td>
                      <td>
                        {(row.probabilities["suspicious"] * 100).toFixed(1)}%
                      </td>
                      {featureKeys.map((k) => (
                        <td key={k}>
                          {typeof row.features[k] === "number"
                            ? row.features[k].toLocaleString(undefined, {
                                maximumFractionDigits: 2,
                              })
                            : "—"}
                        </td>
                      ))}
                      <td>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "3px 8px", fontSize: "0.75rem" }}
                          onClick={() =>
                            setExpanded(
                              expanded === row.row_index ? null : row.row_index
                            )
                          }
                          aria-label={`Toggle details for row ${row.row_index}`}
                        >
                          {expanded === row.row_index ? "Hide" : "Details"}
                        </button>
                      </td>
                    </tr>

                    {expanded === row.row_index && (
                      <tr>
                        <td
                          colSpan={4 + featureKeys.length + 1}
                          style={{ padding: "12px 16px", background: "var(--bg-elevated)" }}
                        >
                          <strong style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                            Prediction probabilities (raw model output)
                          </strong>
                          <div style={{ display: "flex", gap: 20, marginTop: 8 }}>
                            {Object.entries(row.probabilities).map(([cls, prob]) => (
                              <div key={cls}>
                                <span
                                  className={`label-badge ${cls}`}
                                  style={{ marginRight: 6 }}
                                >
                                  {cls}
                                </span>
                                <span
                                  style={{
                                    fontSize: "1rem",
                                    fontWeight: 700,
                                    color:
                                      cls === "suspicious"
                                        ? "var(--danger)"
                                        : "var(--ok)",
                                  }}
                                >
                                  {(prob * 100).toFixed(2)}%
                                </span>
                              </div>
                            ))}
                          </div>
                          <p className="disclaimer" style={{ marginTop: 8 }}>
                            Probabilities are raw Random Forest outputs and are NOT
                            calibrated confidence intervals. They do not represent
                            a guaranteed attack likelihood.
                          </p>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="pagination" aria-label="Table pagination">
              <button
                className="page-btn"
                onClick={() => setPage(1)}
                disabled={page === 1}
                aria-label="First page"
              >
                «
              </button>
              <button
                className="page-btn"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                aria-label="Previous page"
              >
                ‹
              </button>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                const start = Math.max(1, Math.min(page - 2, totalPages - 4));
                const p     = start + i;
                return (
                  <button
                    key={p}
                    className={`page-btn ${p === page ? "active" : ""}`}
                    onClick={() => setPage(p)}
                    aria-label={`Page ${p}`}
                  >
                    {p}
                  </button>
                );
              })}
              <button
                className="page-btn"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                aria-label="Next page"
              >
                ›
              </button>
              <button
                className="page-btn"
                onClick={() => setPage(totalPages)}
                disabled={page === totalPages}
                aria-label="Last page"
              >
                »
              </button>
              <span
                style={{
                  fontSize: "0.78rem",
                  color: "var(--text-muted)",
                  marginLeft: 8,
                }}
              >
                Page {page} of {totalPages} · {filtered.length} records
              </span>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default ResultsTable;
