#!/usr/bin/env python3
"""
Generate synthetic simulation_dataset.csv matching NS-3 feature extractor output.
Produces realistic non-IID distributions across 8 vehicle nodes.
Node 3 is the grey-hole attacker.
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import pandas as pd
from pathlib import Path
from feature_config import LABELS, LABEL2ID

np.random.seed(42)


def generate_node_dataset(node_id: int, n_windows: int = 500) -> pd.DataFrame:
    rows = []
    is_highway  = node_id in [3, 4, 5]
    is_attacker = (node_id == 3)
    speed_base  = np.random.uniform(65, 90) if is_highway else np.random.uniform(30, 55)
    attack_variants = LABELS[1:]

    for i in range(n_windows):
        is_attack = is_attacker and (np.random.rand() < 0.35)
        variant   = np.random.choice(attack_variants) if is_attack else "BENIGN"

        speed_kmh  = float(speed_base + np.random.normal(0, 8))
        is_handoff = int(np.random.rand() < (0.15 if is_highway else 0.05))

        if is_attack:
            if variant == "S1_DP_FR":
                pdr_mean = np.random.uniform(0.20, 0.55)
                pdr_var  = np.random.uniform(0.001, 0.04)
                kl_div   = np.random.uniform(0.00, 0.10)
                ac_peak  = np.random.uniform(0.00, 0.15)
            elif variant == "S2_DP_IT":
                pdr_mean = np.random.uniform(0.55, 0.78)
                pdr_var  = np.random.uniform(0.12, 0.35)
                kl_div   = np.random.uniform(0.00, 0.12)
                ac_peak  = np.random.uniform(0.50, 0.95)
            elif variant == "S3_DP_TS":
                pdr_mean = np.random.uniform(0.60, 0.88)
                pdr_var  = np.random.uniform(0.04, 0.15)
                kl_div   = np.random.uniform(0.60, 1.80)
                ac_peak  = np.random.uniform(0.00, 0.20)
            else:
                pdr_mean = np.random.uniform(0.30, 0.60)
                pdr_var  = np.random.uniform(0.001, 0.20)
                kl_div   = np.random.uniform(0.10, 1.00)
                ac_peak  = np.random.uniform(0.00, 0.60)
        else:
            pdr_mean = np.random.uniform(0.78, 0.99)
            pdr_var  = np.random.uniform(0.000, 0.04)
            kl_div   = np.random.uniform(0.00, 0.08)
            ac_peak  = np.random.uniform(0.00, 0.10)

        speed_ms = speed_kmh / 3.6
        ho_loss  = (speed_ms * 0.30 / 300.0) * 0.15
        pdr_corr = min(1.0, pdr_mean + ho_loss)

        n_rx  = int(np.random.uniform(50, 150))
        n_fwd = max(0, min(n_rx, int(n_rx * pdr_mean + np.random.normal(0, 2))))

        rows.append({
            "node_id":                node_id,
            "window_start":           round(i * 1.0, 1),
            "window_end":             round(i * 1.0 + 10.0, 1),
            "pdr_mean":               round(float(pdr_mean), 4),
            "pdr_var":                round(float(pdr_var), 4),
            "pdr_corrected":          round(float(pdr_corr), 4),
            "speed_kmh":              round(speed_kmh, 1),
            "is_handoff":             is_handoff,
            "kl_divergence":          round(float(kl_div), 4),
            "autocorr_peak":          round(float(ac_peak), 4),
            "rsu_id":                 f"RSU_0{(node_id % 3) + 1}",
            "packets_received_total": n_rx,
            "packets_forwarded_total":n_fwd,
            "ground_truth_label":     variant,
            "is_attacker":            int(is_attacker and is_attack),
        })

    return pd.DataFrame(rows)


def main():
    out_dir = Path(__file__).parent / "mock"
    out_dir.mkdir(parents=True, exist_ok=True)

    all_dfs = []
    for node_id in range(8):
        df = generate_node_dataset(node_id, n_windows=500)
        all_dfs.append(df)
        print(f"  Node {node_id}: {len(df)} windows  "
              f"attack_rate={df['is_attacker'].mean():.2f}")

    full_df = pd.concat(all_dfs, ignore_index=True)
    out_path = out_dir / "simulation_dataset.csv"
    full_df.to_csv(out_path, index=False)

    print(f"\n[OK] Dataset: {len(full_df)} rows -> {out_path}")
    print(f"Label distribution:\n{full_df['ground_truth_label'].value_counts()}")


if __name__ == "__main__":
    main()
