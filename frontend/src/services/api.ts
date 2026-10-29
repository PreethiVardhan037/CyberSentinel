// API service layer for CyberSentinel backend
// All requests use the base URL from the environment variable.

const BASE_URL = (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";

export interface HealthResponse {
  status: string;
  model_loaded: boolean;
  version: string;
}

export interface InfoResponse {
  app_name: string;
  version: string;
  model_type: string;
  mode: string;
  model_available: boolean;
  expected_features: string[];
  feature_count: number;
}

export interface MetricsResponse {
  available: boolean;
  accuracy?: number;
  precision_weighted?: number;
  recall_weighted?: number;
  f1_weighted?: number;
  f1_macro?: number;
  precision_macro?: number;
  recall_macro?: number;
  confusion_matrix?: number[][];
  confusion_matrix_labels?: string[];
  classification_report?: Record<string, any>;
  feature_importances?: Record<string, number>;
  dataset_size?: number;
  train_size?: number;
  test_size?: number;
  class_distribution?: Record<string, number>;
  classes?: string[];
  metrics_note?: string;
}

export interface SinglePrediction {
  label: string;
  is_suspicious: boolean;
  probabilities: Record<string, number>;
  probability_note?: string;
}

export interface BatchPredictResponse {
  count: number;
  predictions: SinglePrediction[];
}

export interface CsvRowPrediction {
  row_index: number;
  label: string;
  is_suspicious: boolean;
  probabilities: Record<string, number>;
  features: Record<string, number>;
}

export interface CsvAnalysisResponse {
  total_rows: number;
  analyzed_rows: number;
  skipped_rows: number;
  benign_count: number;
  suspicious_count: number;
  suspicious_pct: number;
  predictions: CsvRowPrediction[];
  warnings: string[];
  note?: string;
}

export interface FeatureImportanceResponse {
  feature_importances: Record<string, number>;
  disclaimer: string;
}

async function fetchJson<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, options);
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || body.error || detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => fetchJson<HealthResponse>("/health"),

  info: () => fetchJson<InfoResponse>("/api/v1/info"),

  metrics: () => fetchJson<MetricsResponse>("/api/v1/metrics"),

  featureImportance: () =>
    fetchJson<FeatureImportanceResponse>("/api/v1/feature-importance"),

  predict: (records: Record<string, number>[]) =>
    fetchJson<BatchPredictResponse>("/api/v1/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ records }),
    }),

  analyzeCsv: (file: File, onProgress?: (pct: number) => void) => {
    return new Promise<CsvAnalysisResponse>((resolve, reject) => {
      const formData = new FormData();
      formData.append("file", file);

      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${BASE_URL}/api/v1/analyze-csv`);

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && onProgress) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(JSON.parse(xhr.responseText) as CsvAnalysisResponse);
        } else {
          let msg = `HTTP ${xhr.status}`;
          try {
            msg = JSON.parse(xhr.responseText).detail || msg;
          } catch {
            /* ignore */
          }
          reject(new Error(msg));
        }
      };

      xhr.onerror = () => reject(new Error("Network error during CSV upload"));
      xhr.send(formData);
    });
  },
};
