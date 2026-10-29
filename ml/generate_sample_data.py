"""
generate_sample_data.py
-----------------------
Generates a small, deterministic, clearly labelled synthetic network-flow
dataset for CyberSentinel's demo mode.

Rules used to distinguish benign from suspicious traffic are intentionally
transparent and documented below.  This data is NOT representative of real
network attacks; it is only useful for exercising the full application
pipeline.

Synthetic-data simulation rules
--------------------------------
Benign flows:
  - Short-to-medium duration (100 ms – 10 s)
  - Balanced fwd/bwd packet ratios
  - Small to moderate packet lengths
  - Low flag counts (mostly SYN + ACK)
  - Moderate bytes-per-second rates

Suspicious flows are drawn from three simplified archetypes:
  1. Port scan   – very short duration, many fwd packets, few bwd packets,
                   tiny payloads, many SYN flags, near-zero bwd bytes.
  2. DoS/flood   – very high packet rate, large bwd byte counts,
                   extremely high bytes-per-second, many URG flags.
  3. Data exfil  – long duration, very large fwd byte totals,
                   high fwd-to-bwd byte ratio, low packet rate.

These rules are heuristics for generating distinguishable synthetic samples
and do NOT reflect validated threat intelligence.
"""

from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Feature names match the schema expected by the preprocessing pipeline and
# the FastAPI prediction schema.
# ---------------------------------------------------------------------------
FEATURE_NAMES: list[str] = [
    "flow_duration",          # microseconds
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",        # total bytes in fwd direction
    "totlen_bwd_pkts",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_byts_s",            # bytes per second
    "flow_pkts_s",            # packets per second
    "fwd_iat_mean",           # inter-arrival time mean (microseconds)
    "bwd_iat_mean",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_urg_flags",
    "bwd_urg_flags",
    "fin_flag_cnt",
    "syn_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "ack_flag_cnt",
    "urg_flag_cnt",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_var",
    "fwd_header_len",
    "bwd_header_len",
    "init_fwd_win_byts",
    "init_bwd_win_byts",
    "active_mean",
    "idle_mean",
]

LABEL_COL = "label"          # "benign" or "suspicious"
SYNTHETIC_FLAG_COL = "is_synthetic"  # always True in this file


def _clip_positive(arr: np.ndarray) -> np.ndarray:
    """Replace negatives with 0 (flow stats cannot be negative)."""
    return np.clip(arr, 0, None)


def _generate_benign(n: int, rng: np.random.Generator) -> pd.DataFrame:
    rows: dict[str, np.ndarray] = {}

    duration = rng.uniform(100_000, 10_000_000, n)          # 0.1 s – 10 s in µs
    tot_fwd = rng.integers(5, 80, n)
    tot_bwd = (tot_fwd * rng.uniform(0.5, 1.5, n)).astype(int)

    fwd_pkt_len = rng.uniform(100, 1200, n)
    bwd_pkt_len = rng.uniform(80, 1000, n)

    totlen_fwd = tot_fwd * fwd_pkt_len
    totlen_bwd = tot_bwd * bwd_pkt_len

    flow_bytes = (totlen_fwd + totlen_bwd) / (duration / 1e6)
    flow_pkts  = (tot_fwd + tot_bwd) / (duration / 1e6)

    rows["flow_duration"]      = duration
    rows["tot_fwd_pkts"]       = tot_fwd
    rows["tot_bwd_pkts"]       = tot_bwd
    rows["totlen_fwd_pkts"]    = totlen_fwd
    rows["totlen_bwd_pkts"]    = totlen_bwd
    rows["fwd_pkt_len_mean"]   = fwd_pkt_len
    rows["bwd_pkt_len_mean"]   = bwd_pkt_len
    rows["flow_byts_s"]        = _clip_positive(flow_bytes)
    rows["flow_pkts_s"]        = _clip_positive(flow_pkts)
    rows["fwd_iat_mean"]       = rng.uniform(1_000, 500_000, n)
    rows["bwd_iat_mean"]       = rng.uniform(1_000, 500_000, n)
    rows["fwd_psh_flags"]      = rng.integers(0, 5, n)
    rows["bwd_psh_flags"]      = rng.integers(0, 5, n)
    rows["fwd_urg_flags"]      = np.zeros(n, dtype=int)
    rows["bwd_urg_flags"]      = np.zeros(n, dtype=int)
    rows["fin_flag_cnt"]       = rng.integers(0, 3, n)
    rows["syn_flag_cnt"]       = rng.integers(1, 3, n)
    rows["rst_flag_cnt"]       = rng.integers(0, 2, n)
    rows["psh_flag_cnt"]       = rng.integers(0, 6, n)
    rows["ack_flag_cnt"]       = rng.integers(1, 10, n)
    rows["urg_flag_cnt"]       = np.zeros(n, dtype=int)
    pkt_len_mean               = (fwd_pkt_len + bwd_pkt_len) / 2
    rows["pkt_len_mean"]       = pkt_len_mean
    rows["pkt_len_std"]        = rng.uniform(10, 200, n)
    rows["pkt_len_var"]        = rows["pkt_len_std"] ** 2
    rows["fwd_header_len"]     = tot_fwd * 20
    rows["bwd_header_len"]     = tot_bwd * 20
    rows["init_fwd_win_byts"]  = rng.integers(1024, 65535, n)
    rows["init_bwd_win_byts"]  = rng.integers(1024, 65535, n)
    rows["active_mean"]        = rng.uniform(1_000, 100_000, n)
    rows["idle_mean"]          = rng.uniform(10_000, 5_000_000, n)

    df = pd.DataFrame(rows)
    df[LABEL_COL] = "benign"
    return df


def _generate_port_scan(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Short bursts, many SYN, tiny payloads, almost no response."""
    rows: dict[str, np.ndarray] = {}

    duration = rng.uniform(100, 5_000, n)           # very short: 0.1 ms – 5 ms
    tot_fwd  = rng.integers(1, 5, n)
    tot_bwd  = rng.integers(0, 2, n)

    fwd_pkt_len = rng.uniform(20, 80, n)
    bwd_pkt_len = np.where(tot_bwd > 0, rng.uniform(20, 60, n), 0.0)

    totlen_fwd = tot_fwd * fwd_pkt_len
    totlen_bwd = tot_bwd * bwd_pkt_len

    flow_bytes = (totlen_fwd + totlen_bwd) / np.maximum(duration / 1e6, 1e-9)
    flow_pkts  = (tot_fwd + tot_bwd) / np.maximum(duration / 1e6, 1e-9)

    rows["flow_duration"]      = duration
    rows["tot_fwd_pkts"]       = tot_fwd
    rows["tot_bwd_pkts"]       = tot_bwd
    rows["totlen_fwd_pkts"]    = totlen_fwd
    rows["totlen_bwd_pkts"]    = totlen_bwd
    rows["fwd_pkt_len_mean"]   = fwd_pkt_len
    rows["bwd_pkt_len_mean"]   = bwd_pkt_len
    rows["flow_byts_s"]        = _clip_positive(flow_bytes)
    rows["flow_pkts_s"]        = _clip_positive(flow_pkts)
    rows["fwd_iat_mean"]       = rng.uniform(100, 5_000, n)
    rows["bwd_iat_mean"]       = np.where(tot_bwd > 0, rng.uniform(100, 5_000, n), 0.0)
    rows["fwd_psh_flags"]      = np.zeros(n, dtype=int)
    rows["bwd_psh_flags"]      = np.zeros(n, dtype=int)
    rows["fwd_urg_flags"]      = np.zeros(n, dtype=int)
    rows["bwd_urg_flags"]      = np.zeros(n, dtype=int)
    rows["fin_flag_cnt"]       = np.zeros(n, dtype=int)
    rows["syn_flag_cnt"]       = rng.integers(1, 4, n)    # many SYN probes
    rows["rst_flag_cnt"]       = rng.integers(0, 3, n)
    rows["psh_flag_cnt"]       = np.zeros(n, dtype=int)
    rows["ack_flag_cnt"]       = rng.integers(0, 2, n)
    rows["urg_flag_cnt"]       = np.zeros(n, dtype=int)
    pkt_len_mean               = (fwd_pkt_len + bwd_pkt_len) / 2
    rows["pkt_len_mean"]       = pkt_len_mean
    rows["pkt_len_std"]        = rng.uniform(1, 20, n)
    rows["pkt_len_var"]        = rows["pkt_len_std"] ** 2
    rows["fwd_header_len"]     = tot_fwd * 20
    rows["bwd_header_len"]     = tot_bwd * 20
    rows["init_fwd_win_byts"]  = rng.integers(0, 512, n)
    rows["init_bwd_win_byts"]  = np.zeros(n, dtype=int)
    rows["active_mean"]        = rng.uniform(100, 5_000, n)
    rows["idle_mean"]          = rng.uniform(1_000, 100_000, n)

    df = pd.DataFrame(rows)
    df[LABEL_COL] = "suspicious"
    return df


def _generate_dos_flood(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Very high packet and byte rates, many URG flags."""
    rows: dict[str, np.ndarray] = {}

    duration   = rng.uniform(500_000, 5_000_000, n)     # 0.5 s – 5 s
    tot_fwd    = rng.integers(500, 5000, n)
    tot_bwd    = rng.integers(200, 2000, n)

    fwd_pkt_len = rng.uniform(40, 200, n)
    bwd_pkt_len = rng.uniform(500, 1500, n)

    totlen_fwd = tot_fwd * fwd_pkt_len
    totlen_bwd = tot_bwd * bwd_pkt_len

    flow_bytes = (totlen_fwd + totlen_bwd) / (duration / 1e6)
    flow_pkts  = (tot_fwd + tot_bwd) / (duration / 1e6)

    rows["flow_duration"]      = duration
    rows["tot_fwd_pkts"]       = tot_fwd
    rows["tot_bwd_pkts"]       = tot_bwd
    rows["totlen_fwd_pkts"]    = totlen_fwd
    rows["totlen_bwd_pkts"]    = totlen_bwd
    rows["fwd_pkt_len_mean"]   = fwd_pkt_len
    rows["bwd_pkt_len_mean"]   = bwd_pkt_len
    rows["flow_byts_s"]        = _clip_positive(flow_bytes)
    rows["flow_pkts_s"]        = _clip_positive(flow_pkts)
    rows["fwd_iat_mean"]       = rng.uniform(50, 2_000, n)
    rows["bwd_iat_mean"]       = rng.uniform(50, 2_000, n)
    rows["fwd_psh_flags"]      = rng.integers(5, 50, n)
    rows["bwd_psh_flags"]      = rng.integers(5, 50, n)
    rows["fwd_urg_flags"]      = rng.integers(1, 20, n)   # elevated URG
    rows["bwd_urg_flags"]      = rng.integers(1, 20, n)
    rows["fin_flag_cnt"]       = rng.integers(0, 5, n)
    rows["syn_flag_cnt"]       = rng.integers(0, 5, n)
    rows["rst_flag_cnt"]       = rng.integers(0, 10, n)
    rows["psh_flag_cnt"]       = rng.integers(10, 100, n)
    rows["ack_flag_cnt"]       = rng.integers(10, 200, n)
    rows["urg_flag_cnt"]       = rng.integers(1, 20, n)
    pkt_len_mean               = (fwd_pkt_len + bwd_pkt_len) / 2
    rows["pkt_len_mean"]       = pkt_len_mean
    rows["pkt_len_std"]        = rng.uniform(100, 600, n)
    rows["pkt_len_var"]        = rows["pkt_len_std"] ** 2
    rows["fwd_header_len"]     = tot_fwd * 20
    rows["bwd_header_len"]     = tot_bwd * 20
    rows["init_fwd_win_byts"]  = rng.integers(0, 1024, n)
    rows["init_bwd_win_byts"]  = rng.integers(4096, 65535, n)
    rows["active_mean"]        = rng.uniform(100_000, 1_000_000, n)
    rows["idle_mean"]          = rng.uniform(100, 10_000, n)

    df = pd.DataFrame(rows)
    df[LABEL_COL] = "suspicious"
    return df


def _generate_data_exfil(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Long flows, high fwd bytes, low packet rate."""
    rows: dict[str, np.ndarray] = {}

    duration   = rng.uniform(30_000_000, 300_000_000, n)  # 30 s – 5 min
    tot_fwd    = rng.integers(50, 300, n)
    tot_bwd    = rng.integers(5, 30, n)

    fwd_pkt_len = rng.uniform(1000, 1500, n)
    bwd_pkt_len = rng.uniform(50, 200, n)

    totlen_fwd = tot_fwd * fwd_pkt_len
    totlen_bwd = tot_bwd * bwd_pkt_len

    flow_bytes = (totlen_fwd + totlen_bwd) / (duration / 1e6)
    flow_pkts  = (tot_fwd + tot_bwd) / (duration / 1e6)

    rows["flow_duration"]      = duration
    rows["tot_fwd_pkts"]       = tot_fwd
    rows["tot_bwd_pkts"]       = tot_bwd
    rows["totlen_fwd_pkts"]    = totlen_fwd
    rows["totlen_bwd_pkts"]    = totlen_bwd
    rows["fwd_pkt_len_mean"]   = fwd_pkt_len
    rows["bwd_pkt_len_mean"]   = bwd_pkt_len
    rows["flow_byts_s"]        = _clip_positive(flow_bytes)
    rows["flow_pkts_s"]        = _clip_positive(flow_pkts)
    rows["fwd_iat_mean"]       = rng.uniform(100_000, 5_000_000, n)
    rows["bwd_iat_mean"]       = rng.uniform(100_000, 5_000_000, n)
    rows["fwd_psh_flags"]      = rng.integers(2, 20, n)
    rows["bwd_psh_flags"]      = rng.integers(0, 5, n)
    rows["fwd_urg_flags"]      = np.zeros(n, dtype=int)
    rows["bwd_urg_flags"]      = np.zeros(n, dtype=int)
    rows["fin_flag_cnt"]       = rng.integers(0, 3, n)
    rows["syn_flag_cnt"]       = rng.integers(1, 3, n)
    rows["rst_flag_cnt"]       = rng.integers(0, 2, n)
    rows["psh_flag_cnt"]       = rng.integers(5, 30, n)
    rows["ack_flag_cnt"]       = rng.integers(5, 50, n)
    rows["urg_flag_cnt"]       = np.zeros(n, dtype=int)
    pkt_len_mean               = (fwd_pkt_len + bwd_pkt_len) / 2
    rows["pkt_len_mean"]       = pkt_len_mean
    rows["pkt_len_std"]        = rng.uniform(200, 500, n)
    rows["pkt_len_var"]        = rows["pkt_len_std"] ** 2
    rows["fwd_header_len"]     = tot_fwd * 20
    rows["bwd_header_len"]     = tot_bwd * 20
    rows["init_fwd_win_byts"]  = rng.integers(8192, 65535, n)
    rows["init_bwd_win_byts"]  = rng.integers(512, 4096, n)
    rows["active_mean"]        = rng.uniform(1_000_000, 10_000_000, n)
    rows["idle_mean"]          = rng.uniform(500_000, 50_000_000, n)

    df = pd.DataFrame(rows)
    df[LABEL_COL] = "suspicious"
    return df


def generate(
    n_benign: int = 1200,
    n_port_scan: int = 200,
    n_dos: int = 200,
    n_exfil: int = 200,
    seed: int = 42,
    output_path: str | None = None,
) -> pd.DataFrame:
    """
    Generate a synthetic demo dataset and return (and optionally save) it.

    Parameters
    ----------
    n_benign     : Number of benign-flow samples.
    n_port_scan  : Number of port-scan suspicious samples.
    n_dos        : Number of DoS/flood suspicious samples.
    n_exfil      : Number of data-exfiltration suspicious samples.
    seed         : Random seed for reproducibility.
    output_path  : If given, save the CSV to this path.
    """
    rng = np.random.default_rng(seed)

    parts = [
        _generate_benign(n_benign, rng),
        _generate_port_scan(n_port_scan, rng),
        _generate_dos_flood(n_dos, rng),
        _generate_data_exfil(n_exfil, rng),
    ]
    df = pd.concat(parts, ignore_index=True)
    df[SYNTHETIC_FLAG_COL] = True

    # Shuffle so the file is not trivially ordered by class
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"[generate_sample_data] Saved {len(df)} rows → {output_path}")
        print(f"  Label counts:\n{df[LABEL_COL].value_counts().to_string()}")

    return df


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate synthetic CyberSentinel demo data")
    p.add_argument("--output", default="data/sample/demo_data.csv",
                   help="Output CSV path (default: data/sample/demo_data.csv)")
    p.add_argument("--n-benign",    type=int, default=1200)
    p.add_argument("--n-port-scan", type=int, default=200)
    p.add_argument("--n-dos",       type=int, default=200)
    p.add_argument("--n-exfil",     type=int, default=200)
    p.add_argument("--seed",        type=int, default=42)
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    generate(
        n_benign=args.n_benign,
        n_port_scan=args.n_port_scan,
        n_dos=args.n_dos,
        n_exfil=args.n_exfil,
        seed=args.seed,
        output_path=args.output,
    )
