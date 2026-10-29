// Shared TypeScript types for the CyberSentinel dashboard

export type ConnectionStatus = "checking" | "online" | "offline";
export type ModelStatus = "available" | "unavailable" | "checking";
export type DataMode = "demo" | "real" | "unknown";

export interface AppStatus {
  connection: ConnectionStatus;
  modelLoaded: boolean;
  mode: DataMode;
  version: string;
}

export interface SummaryStats {
  total: number;
  benign: number;
  suspicious: number;
  suspiciousPct: number;
}
