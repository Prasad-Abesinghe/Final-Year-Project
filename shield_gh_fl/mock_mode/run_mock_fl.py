#!/usr/bin/env python3
"""
SHIELD-GH Federated Learning — full simulation in a single process.
No separate server/client processes needed.

Steps:
  1. Generate mock dataset (if not present)
  2. Partition data non-IID by node
  3. Run N FL rounds:
       - Each vehicle client trains locally (Eq 3.20)
       - Commits gradient hash to blockchain (Eq 3.22)
       - Server verifies hashes and runs weighted FedAvg (Eq 3.21)
  4. Evaluate global model and export fl_score_{node_id}.json
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import torch
import numpy as np
import pandas as pd
from pathlib import Path

from data.generate_mock_dataset import main as gen_data
from data.partition_dataset import partition_by_node
from fl.fl_client import VehicleClient
from fl.fl_server import BlockchainVerifiedFedAvg
from model.grey_hole_detector import GreyHoleDetectorMLP, get_parameters, set_parameters
from data.feature_config import FEATURES, LABELS, ID2LABEL

BASE_DIR        = Path(__file__).parent.parent
DATASET_CSV     = BASE_DIR / "data" / "mock" / "simulation_dataset.csv"
PARTITIONS_DIR  = str(BASE_DIR / "data" / "partitions")
OUTPUT_SCORES   = BASE_DIR / "output" / "fl_scores"
OUTPUT_SCORES.mkdir(parents=True, exist_ok=True)

N_CLIENTS = 8
N_ROUNDS  = 15


def export_fl_scores(global_model: GreyHoleDetectorMLP, round_num: int):
    """Evaluate each node and write fl_score_{node_id}.json (Fusion Engine input)."""
    print(f"\n--- Exporting FL scores (round {round_num}) ---")

    for node_id in range(N_CLIENTS):
        csv_path = Path(PARTITIONS_DIR) / f"node_{node_id}_val.csv"
        if not csv_path.exists():
            continue

        df = pd.read_csv(csv_path)
        X  = torch.FloatTensor(df[FEATURES].values)

        global_model.eval()
        with torch.no_grad():
            probs = torch.softmax(global_model(X), dim=1)

        mal_prob   = float(1 - probs[:, 0].mean().item())
        pred_idx   = int(probs.mean(0).argmax().item())
        pred_label = ID2LABEL[pred_idx]
        confidence = float(probs.mean(0).max().item())

        y_true = df["label_multiclass"].values
        y_pred = probs.argmax(dim=1).numpy()
        acc    = float((y_pred == y_true).mean())

        score = {
            "node_id":           node_id,
            "malicious_prob":    round(mal_prob, 4),
            "predicted_variant": pred_label,
            "confidence":        round(confidence, 4),
            "round_num":         round_num,
            "local_accuracy":    round(acc, 4),
            "timestamp":         float(df["window_end"].max()),
        }

        out_path = OUTPUT_SCORES / f"fl_score_{node_id}.json"
        with open(out_path, "w") as f:
            json.dump(score, f, indent=2)

        flag = " <- ATTACKER" if mal_prob > 0.4 else ""
        print(f"  Node {node_id}: mal_prob={mal_prob:.4f}  "
              f"pred={pred_label:<12}  acc={acc:.4f}{flag}")

    print(f"\n[DONE] FL scores -> {OUTPUT_SCORES}/")


def main():
    print("=== SHIELD-GH Federated Learning Simulation ===\n")

    # Step 1 — Generate data if missing
    if not DATASET_CSV.exists():
        print("[SETUP] Generating mock dataset...")
        os.chdir(str(BASE_DIR / "data"))
        gen_data()
        os.chdir(str(BASE_DIR))

    # Step 2 — Partition if missing
    if not (Path(PARTITIONS_DIR) / "node_0_train.csv").exists():
        print("[SETUP] Partitioning dataset (non-IID by node)...")
        partition_by_node(str(DATASET_CSV), PARTITIONS_DIR)

    # Step 3 — Initialise clients and server
    print(f"\n[FL] Initialising {N_CLIENTS} vehicle clients...")
    clients = []
    for node_id in range(N_CLIENTS):
        c = VehicleClient(node_id=node_id, data_dir=PARTITIONS_DIR, use_blockchain=True)
        clients.append(c)
        print(f"  Client {node_id}: {c.n_train} training samples")

    global_model  = GreyHoleDetectorMLP()
    global_weights = get_parameters(global_model)
    server         = BlockchainVerifiedFedAvg()

    print(f"\n[FL] Starting {N_ROUNDS} rounds of federated learning...\n")

    # Step 4 — FL rounds
    for round_num in range(1, N_ROUNDS + 1):
        print(f"\n{'='*50}")
        print(f" Round {round_num}/{N_ROUNDS}")
        print(f"{'='*50}")

        # Each client trains locally
        client_results = []
        for client in clients:
            weights, n_samples, metrics = client.fit(global_weights, round_num)
            client_results.append((client.node_id, weights, n_samples, metrics))

        # Server aggregates (with blockchain verification)
        aggregated, summary = server.aggregate(round_num, client_results)

        if aggregated is None:
            print(f"  [SKIP] Round {round_num} — no valid updates")
            continue

        global_weights = aggregated
        set_parameters(global_model, global_weights)

        # Evaluate global model this round
        accs = []
        for client in clients:
            result = client.evaluate(global_weights)
            accs.append(result["accuracy"])

        avg_acc = float(np.mean(accs))
        print(f"\n  Round {round_num} summary: "
              f"accepted={summary['accepted']}/{N_CLIENTS}  "
              f"rejected={summary['rejected']}  "
              f"avg_accuracy={avg_acc:.4f}")

    # Step 5 — Save trained model weights
    model_path = BASE_DIR / "output" / "global_model.pth"
    torch.save(global_model.state_dict(), model_path)
    print(f"\n[SAVED] Global model -> {model_path}")

    # Step 6 — Export final scores
    export_fl_scores(global_model, N_ROUNDS)

    # Step 6 — Final evaluation summary
    print(f"\n{'='*50}")
    print(" Final Per-Node Evaluation")
    print(f"{'='*50}")
    for client in clients:
        result = client.evaluate(global_weights)
        print(f"  Node {result['node_id']}: "
              f"accuracy={result['accuracy']:.4f}  "
              f"loss={result['loss']:.4f}")


if __name__ == "__main__":
    main()
