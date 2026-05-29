"""
SHIELD-GH FL Aggregation Server.
Blockchain-verified FedAvg: verifies gradient hashes (Eq 3.22)
then applies dataset-size-weighted averaging (Eq 3.21).
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import numpy as np
import json
from pathlib import Path
from fl.blockchain_bridge import BlockchainBridge

OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


class BlockchainVerifiedFedAvg:
    """
    Implements Eq 3.21–3.22:
    - Verifies each gradient update against its blockchain commitment
    - Rejects poisoned/tampered gradients before aggregation
    - Weights aggregation by local dataset size (Eq 3.21)
    """

    def __init__(self):
        self.round_log = []

    def aggregate(self, round_num: int,
                  client_results: list) -> tuple:
        """
        client_results: list of (node_id, weights, n_samples, metrics)
        Returns (aggregated_weights, round_summary)
        """
        accepted_weights  = []
        accepted_sizes    = []
        rejected_nodes    = []

        for node_id, weights, n_samples, metrics in client_results:
            bridge    = BlockchainBridge(node_id)
            is_valid  = bridge.verify_gradient(weights, round_num)

            if is_valid:
                accepted_weights.append(weights)
                accepted_sizes.append(n_samples)
                print(f"  [FedAvg R{round_num}] Node {node_id}: ACCEPTED "
                      f"(loss={metrics.get('train_loss', 0):.4f})")
            else:
                rejected_nodes.append(node_id)
                print(f"  [FedAvg R{round_num}] Node {node_id}: REJECTED — "
                      f"gradient hash mismatch")

        summary = {
            "round":    round_num,
            "accepted": len(accepted_weights),
            "rejected": rejected_nodes,
        }
        self.round_log.append(summary)
        with open(OUTPUT_DIR / "round_log.json", "w") as f:
            json.dump(self.round_log, f, indent=2)

        if not accepted_weights:
            print(f"  [WARNING] Round {round_num}: all clients rejected!")
            return None, summary

        # Eq 3.21 — weighted FedAvg
        total_samples = sum(accepted_sizes)
        aggregated = []
        for layer_idx in range(len(accepted_weights[0])):
            layer_agg = np.zeros_like(accepted_weights[0][layer_idx], dtype=np.float64)
            for weights, n in zip(accepted_weights, accepted_sizes):
                layer_agg += weights[layer_idx] * (n / total_samples)
            aggregated.append(layer_agg.astype(np.float32))

        return aggregated, summary
