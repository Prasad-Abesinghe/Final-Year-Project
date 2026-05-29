#!/usr/bin/env python3
"""
Partition simulation_dataset.csv into per-node slices (non-IID).
Each vehicle client only sees its own node's data — matching real SDVN.
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from feature_config import FEATURES, LABELS, LABEL2ID, label_to_binary


def partition_by_node(csv_path: str, output_dir: str = None):
    if output_dir is None:
        output_dir = str(Path(__file__).parent / "partitions")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    df       = pd.read_csv(csv_path)
    node_ids = df["node_id"].unique()

    for node_id in node_ids:
        node_df = df[df["node_id"] == node_id].copy().reset_index(drop=True)

        node_df["label_multiclass"] = node_df["ground_truth_label"].map(LABEL2ID)
        node_df["label_binary"]     = node_df["ground_truth_label"].apply(label_to_binary)

        train_df, temp_df = train_test_split(
            node_df, test_size=0.30,
            stratify=node_df["label_binary"], random_state=42
        )
        val_df, test_df = train_test_split(
            temp_df, test_size=0.50,
            stratify=temp_df["label_binary"], random_state=42
        )

        node_df.to_csv(out  / f"node_{node_id}_all.csv",   index=False)
        train_df.to_csv(out / f"node_{node_id}_train.csv", index=False)
        val_df.to_csv(out   / f"node_{node_id}_val.csv",   index=False)
        test_df.to_csv(out  / f"node_{node_id}_test.csv",  index=False)

        n_mal = node_df["label_binary"].sum()
        print(f"  Node {node_id}: {len(node_df)} windows  "
              f"malicious={n_mal} ({n_mal/len(node_df):.1%})")

    print(f"\n[OK] Partitions written to {output_dir}/")
    return list(node_ids)


if __name__ == "__main__":
    csv = str(Path(__file__).parent / "mock" / "simulation_dataset.csv")
    partition_by_node(csv)
