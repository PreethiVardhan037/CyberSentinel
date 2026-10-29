import React from "react";
import type { ConnectionStatus } from "../types";

interface Props {
  connection: ConnectionStatus;
  modelLoaded: boolean;
  mode: string;
  version: string;
}

const Header: React.FC<Props> = ({ connection, modelLoaded, mode, version }) => {
  const connBadge =
    connection === "online"
      ? { cls: "ok", icon: "●", label: "API Online" }
      : connection === "offline"
      ? { cls: "danger", icon: "●", label: "API Offline" }
      : { cls: "warning", icon: "●", label: "Connecting…" };

  const modelBadge = modelLoaded
    ? { cls: "ok", label: "Model Ready" }
    : { cls: "danger", label: "Model Not Loaded" };

  const modeBadge =
    mode === "demo"
      ? { cls: "info", label: "Demo Mode (Synthetic Data)" }
      : mode === "real"
      ? { cls: "ok", label: "Real Dataset Mode" }
      : { cls: "warning", label: "Mode Unknown" };

  return (
    <header className="header">
      <div className="header-inner">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <div>
            <div className="brand-name">CyberSentinel</div>
            <div className="brand-tagline">ML-Based Network Intrusion Detection</div>
          </div>
        </div>

        <div className="header-status">
          <span className={`status-badge ${connBadge.cls}`}>
            <span className={`status-dot ${connection === "checking" ? "pulse" : ""}`} />
            {connBadge.label}
          </span>
          <span className={`status-badge ${modelBadge.cls}`}>
            <span className="status-dot" />
            {modelBadge.label}
          </span>
          <span className={`status-badge ${modeBadge.cls}`}>
            {modeBadge.label}
          </span>
          {version && (
            <span className="status-badge info" style={{ opacity: 0.6 }}>
              v{version}
            </span>
          )}
        </div>
      </div>
    </header>
  );
};

export default Header;
