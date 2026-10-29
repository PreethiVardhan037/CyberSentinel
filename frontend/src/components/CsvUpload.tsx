import React, { useCallback, useRef, useState } from "react";
import { api, type CsvAnalysisResponse } from "../services/api";

interface Props {
  onResult: (result: CsvAnalysisResponse) => void;
  modelLoaded: boolean;
}

const CsvUpload: React.FC<Props> = ({ onResult, modelLoaded }) => {
  const [dragging, setDragging]     = useState(false);
  const [uploading, setUploading]   = useState(false);
  const [progress, setProgress]     = useState(0);
  const [error, setError]           = useState<string | null>(null);
  const [filename, setFilename]     = useState<string | null>(null);
  const inputRef                    = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    async (file: File) => {
      if (!file.name.toLowerCase().endsWith(".csv")) {
        setError("Only .csv files are accepted.");
        return;
      }
      setError(null);
      setFilename(file.name);
      setUploading(true);
      setProgress(0);

      try {
        const result = await api.analyzeCsv(file, (pct) => setProgress(pct));
        onResult(result);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Upload failed");
      } finally {
        setUploading(false);
        setProgress(0);
      }
    },
    [onResult]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  const onInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
      // Reset so the same file can be re-uploaded
      if (inputRef.current) inputRef.current.value = "";
    },
    [handleFile]
  );

  if (!modelLoaded) {
    return (
      <div className="card">
        <div className="state-container">
          <div className="state-icon">🔒</div>
          <div className="state-title">Model Not Loaded</div>
          <div className="state-desc">
            Run <code>python ml/train.py</code> to train the model before
            uploading a CSV for analysis.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">CSV Analysis — Upload Network Flow Records</span>
      </div>

      <div
        className={`upload-zone ${dragging ? "drag-over" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !uploading && inputRef.current?.click()}
        id="csv-upload-zone"
        aria-label="CSV file upload area"
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv"
          onChange={onInputChange}
          disabled={uploading}
          tabIndex={-1}
          aria-hidden="true"
        />
        <div className="upload-zone-icon">📁</div>
        <div className="upload-zone-title">
          {uploading
            ? `Uploading ${filename}…`
            : "Drop your CSV here or click to browse"}
        </div>
        <div className="upload-zone-sub">
          Accepts .csv files up to 50 MB · up to 10 000 rows analyzed
        </div>

        {uploading && (
          <div
            style={{ marginTop: 16, width: "100%", maxWidth: 360, margin: "16px auto 0" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="progress-bar-wrapper">
              <div
                className="progress-bar-fill"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div
              style={{
                textAlign: "center",
                fontSize: "0.78rem",
                color: "var(--text-muted)",
                marginTop: 4,
              }}
            >
              {progress}%
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="notice danger" style={{ marginTop: 12 }}>
          <span>⚠</span>
          <span>{error}</span>
        </div>
      )}

      <div className="notice info" style={{ marginTop: 12 }}>
        <span>ℹ</span>
        <span>
          CSV must contain the required network-flow feature columns. See the
          Model Info tab for the expected schema. Uploaded files are not saved
          permanently and are not executed.
        </span>
      </div>
    </div>
  );
};

export default CsvUpload;
