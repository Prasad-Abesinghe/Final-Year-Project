# PART 3 — Federated Learning Implementation
## SHIELD-GH · Flower Framework · Blockchain-Verified FedAvg · Grey Hole Classifier
**Owner:** I.G.N. Hasalanka (EG/2021/4543)
**Tools:** Flower 1.7, PyTorch 2.x, Scikit-learn, Pandas, Python 3.10+
**Input:** `simulation_dataset.csv` from NS-3 (or mock), `bc_record_{id}.json` from Blockchain
**Output:** `fl_score_{node_id}.json` per evaluation window

---

## What This Module Does

This module implements the **distributed detection layer** of SHIELD-GH. It:

1. **Partitions** the simulation dataset non-IID across vehicle clients (each client = one vehicle's data)
2. **Trains** a local grey hole detection model at each vehicle node without sharing raw traffic data
3. **Aggregates** model updates via a custom `BlockchainVerifiedFedAvg` strategy that calls the Blockchain module to verify gradient hashes (Eq 3.22) before accepting any update — blocking model poisoning attacks
4. **Evaluates** each vehicle's forwarding behaviour and produces a per-node malicious probability score `ŷ_FL`
5. **Exports** scores to `fl_score_{node_id}.json` consumed by the Fusion Engine

Can be developed entirely with mock data. Swap in real NS-3 data later with no code changes.

---

## Shared Data Contract

### Input: `simulation_dataset.csv`
```
node_id, window_start, window_end, pdr_mean, pdr_var, pdr_corrected,
speed_kmh, is_handoff, kl_divergence, autocorr_peak, rsu_id,
packets_received_total, packets_forwarded_total,
ground_truth_label, is_attacker
```

### Input: `bc_record_{id}.json` (from Blockchain module)
```json
{
  "node_id": 3, "reputation_score": 0.39,
  "zkp_valid": false, "debsc_triggered": true
}
```

### Output: `fl_score_{node_id}.json`
```json
{
  "node_id": 3,
  "malicious_prob": 0.8741,
  "predicted_variant": "S1_DP_FR",
  "confidence": 0.8741,
  "round_num": 15,
  "local_accuracy": 0.923,
  "timestamp": 5.1102
}
```

---

## Directory Structure to Create

```
shield_gh_fl/
├── data/
│   ├── generate_mock_dataset.py     # synthetic dataset (no NS-3 needed)
│   ├── partition_dataset.py         # non-IID split across clients
│   └── feature_config.py            # feature names and label mappings
├── model/
│   ├── grey_hole_detector.py        # PyTorch model definition
│   └── lstm_detector.py             # LSTM variant for sequential detection
├── fl/
│   ├── fl_client.py                 # Flower vehicle client
│   ├── fl_server.py                 # Blockchain-verified FedAvg server
│   └── blockchain_bridge.py         # Interface to Part 2 blockchain module
├── evaluation/
│   ├── evaluate_global_model.py     # per-variant accuracy, MCC, FPR
│   ├── ablation_study.py            # A1–A5 ablation experiments
│   └── export_fl_scores.py          # write fl_score_{id}.json outputs
├── mock_mode/
│   └── run_mock_fl.py               # full FL run on mock data
├── output/
│   └── fl_scores/                   # fl_score_{node_id}.json files
└── requirements.txt
```

---

## Step 1 — Environment Setup

```bash
# Create virtual environment
python3 -m venv venv_fl
source venv_fl/bin/activate

# Install dependencies
pip install flwr==1.7.0 torch torchvision scikit-learn pandas numpy matplotlib

# Verify Flower
python -c "import flwr; print('Flower version:', flwr.__version__)"
```

### requirements.txt
```
flwr==1.7.0
torch>=2.0.0
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
matplotlib>=3.7.0
scipy>=1.10.0
```

---

## Step 2 — Feature Configuration

### File: `data/feature_config.py`

```python
"""
Shared feature configuration for FL module.
All feature names must match simulation_dataset.csv column names exactly.
"""

# ── Input features (Eq 3.1–3.8) ──────────────────────────────────────────────
FEATURES = [
    "pdr_mean",           # Eq 3.1 — mean PDR over window
    "pdr_var",            # Eq 3.3 — PDR variance
    "pdr_corrected",      # Eq 3.5 — MATD-corrected PDR
    "speed_kmh",          # vehicle speed (mobility signal)
    "is_handoff",         # 1 if RSU handoff occurred in window
    "kl_divergence",      # Eq 3.8 — per-source PDR non-uniformity (S3 signal)
    "autocorr_peak",      # Eq 3.7 — periodicity of drop pattern (S2 signal)
]

N_FEATURES = len(FEATURES)

# ── Label mapping ─────────────────────────────────────────────────────────────
LABELS = ["BENIGN", "S1_DP_FR", "S2_DP_IT", "S3_DP_TS",
          "S4_CP_FR", "S5_CP_IT", "S6_CP_TS"]
N_CLASSES = len(LABELS)
LABEL2ID  = {l: i for i, l in enumerate(LABELS)}
ID2LABEL  = {i: l for i, l in enumerate(LABELS)}

# Binary mapping: 0=benign, 1=any malicious variant
def label_to_binary(label: str) -> int:
    return 0 if label == "BENIGN" else 1
```

---

## Step 3 — Mock Dataset Generator

### File: `data/generate_mock_dataset.py`

Run this immediately to generate training data before NS-3 output is available.

```python
#!/usr/bin/env python3
"""
Generate synthetic simulation_dataset.csv that matches the NS-3 feature extractor output.
Produces realistic non-IID distributions across 8 vehicle nodes.
"""

import numpy as np
import pandas as pd
from pathlib import Path
from feature_config import LABELS, LABEL2ID

np.random.seed(42)


def generate_node_dataset(node_id: int, n_windows: int = 400) -> pd.DataFrame:
    """
    Each node gets a different traffic profile (non-IID):
    - Urban nodes (0,1,2): dense traffic, lower speed, low natural loss
    - Highway nodes (3,4,5): sparse traffic, high speed, higher handoff rate
    - Edge nodes (6,7): mixed
    """
    rows = []

    # Node profile
    is_highway = (node_id in [3, 4, 5])
    is_attacker = (node_id == 3)  # node 3 is the grey hole attacker
    speed_base  = np.random.uniform(65, 90) if is_highway else np.random.uniform(30, 55)

    # Attack distribution for attacker node (even across variants for diversity)
    attack_variants = LABELS[1:]  # all attack labels

    for i in range(n_windows):
        # Determine if this window is an attack window
        is_attack = is_attacker and (np.random.rand() < 0.35)
        variant   = np.random.choice(attack_variants) if is_attack else "BENIGN"

        speed_kmh   = speed_base + np.random.normal(0, 8)
        is_handoff  = int(np.random.rand() < (0.15 if is_highway else 0.05))

        if is_attack:
            # Attack-specific feature distributions
            if variant == "S1_DP_FR":
                pdr_mean = np.random.uniform(0.20, 0.55)
                pdr_var  = np.random.uniform(0.001, 0.04)   # low variance — key S1 signal
                kl_div   = np.random.uniform(0.00, 0.10)
                ac_peak  = np.random.uniform(0.00, 0.15)
            elif variant == "S2_DP_IT":
                pdr_mean = np.random.uniform(0.55, 0.78)    # mean looks normal
                pdr_var  = np.random.uniform(0.12, 0.35)    # high variance — key S2 signal
                kl_div   = np.random.uniform(0.00, 0.12)
                ac_peak  = np.random.uniform(0.50, 0.95)    # high autocorrelation — S2 signal
            elif variant == "S3_DP_TS":
                pdr_mean = np.random.uniform(0.60, 0.88)    # overall pdr looks ok
                pdr_var  = np.random.uniform(0.04, 0.15)
                kl_div   = np.random.uniform(0.60, 1.80)    # high KL — key S3 signal
                ac_peak  = np.random.uniform(0.00, 0.20)
            elif variant in ["S4_CP_FR", "S5_CP_IT", "S6_CP_TS"]:
                # Controller-plane variants: similar features to DP counterparts
                pdr_mean = np.random.uniform(0.30, 0.60)
                pdr_var  = np.random.uniform(0.001, 0.20)
                kl_div   = np.random.uniform(0.10, 1.00)
                ac_peak  = np.random.uniform(0.00, 0.60)
            else:
                pdr_mean = np.random.uniform(0.30, 0.60)
                pdr_var  = np.random.uniform(0.05, 0.20)
                kl_div   = np.random.uniform(0.00, 0.30)
                ac_peak  = np.random.uniform(0.00, 0.30)
        else:
            # Benign — normal traffic with natural variation
            pdr_mean = np.random.uniform(0.78, 0.99)
            pdr_var  = np.random.uniform(0.000, 0.04)
            kl_div   = np.random.uniform(0.00, 0.08)
            ac_peak  = np.random.uniform(0.00, 0.10)

        # MATD correction (Eq 3.5) — add back expected handoff loss
        speed_ms  = speed_kmh / 3.6
        ho_loss   = (speed_ms * 0.30 / 300.0) * 0.15
        pdr_corr  = min(1.0, pdr_mean + ho_loss)

        # Simulate realistic packet counts
        n_rx  = int(np.random.uniform(50, 150))
        n_fwd = max(0, int(n_rx * pdr_mean + np.random.normal(0, 2)))
        n_fwd = min(n_fwd, n_rx)

        rows.append({
            "node_id":                node_id,
            "window_start":           round(i * 1.0, 1),
            "window_end":             round(i * 1.0 + 10.0, 1),
            "pdr_mean":               round(pdr_mean, 4),
            "pdr_var":                round(pdr_var, 4),
            "pdr_corrected":          round(pdr_corr, 4),
            "speed_kmh":              round(speed_kmh, 1),
            "is_handoff":             is_handoff,
            "kl_divergence":          round(kl_div, 4),
            "autocorr_peak":          round(ac_peak, 4),
            "rsu_id":                 f"RSU_0{(node_id % 3) + 1}",
            "packets_received_total": n_rx,
            "packets_forwarded_total":n_fwd,
            "ground_truth_label":     variant,
            "is_attacker":            int(is_attacker and is_attack),
        })

    return pd.DataFrame(rows)


def main():
    out_dir = Path("data/mock")
    out_dir.mkdir(parents=True, exist_ok=True)

    all_dfs = []
    for node_id in range(8):
        df = generate_node_dataset(node_id, n_windows=500)
        all_dfs.append(df)
        print(f"  Node {node_id}: {len(df)} windows  "
              f"attack_rate={df['is_attacker'].mean():.2f}")

    full_df = pd.concat(all_dfs, ignore_index=True)
    full_df.to_csv(out_dir / "simulation_dataset.csv", index=False)

    print(f"\n[OK] Dataset: {len(full_df)} rows")
    print(f"Label distribution:\n{full_df['ground_truth_label'].value_counts()}")
    print(f"\nSaved to data/mock/simulation_dataset.csv")


if __name__ == "__main__":
    main()
```

---

## Step 4 — Non-IID Dataset Partitioning

### File: `data/partition_dataset.py`

```python
#!/usr/bin/env python3
"""
Partition simulation_dataset.csv into per-node slices (non-IID).
Each vehicle client only sees its own node's data — matching real SDVN.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from feature_config import FEATURES, LABELS, LABEL2ID, label_to_binary


def partition_by_node(csv_path: str, output_dir: str = "data/partitions"):
    """
    Partition dataset by node_id — one CSV per vehicle.
    This creates the non-IID distribution: highway nodes see different
    traffic than urban nodes, exactly matching Section 3.4.3.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv_path)
    node_ids = df["node_id"].unique()

    for node_id in node_ids:
        node_df = df[df["node_id"] == node_id].copy().reset_index(drop=True)

        # Map multi-class labels
        node_df["label_multiclass"] = node_df["ground_truth_label"].map(LABEL2ID)
        # Map binary labels
        node_df["label_binary"]     = node_df["ground_truth_label"].apply(label_to_binary)

        # Train/val/test split (70/15/15) — stratified on binary label
        train_df, temp_df = train_test_split(node_df, test_size=0.30,
                                              stratify=node_df["label_binary"],
                                              random_state=42)
        val_df, test_df   = train_test_split(temp_df, test_size=0.50,
                                              stratify=temp_df["label_binary"],
                                              random_state=42)

        node_df.to_csv(out / f"node_{node_id}_all.csv",   index=False)
        train_df.to_csv(out / f"node_{node_id}_train.csv", index=False)
        val_df.to_csv(out  / f"node_{node_id}_val.csv",   index=False)
        test_df.to_csv(out / f"node_{node_id}_test.csv",  index=False)

        n_malicious = node_df["label_binary"].sum()
        print(f"  Node {node_id}: {len(node_df)} windows  "
              f"malicious={n_malicious} ({n_malicious/len(node_df):.1%})")

    print(f"\n[OK] Partitions written to {output_dir}/")
    return list(node_ids)


if __name__ == "__main__":
    partition_by_node("data/mock/simulation_dataset.csv")
```

---

## Step 5 — Detection Model

### File: `model/grey_hole_detector.py`

```python
"""
Grey Hole Detector — PyTorch MLP for per-window classification.
Input: 7 features per window (FEATURES from feature_config.py)
Output: 7 class probabilities (BENIGN + 6 attack variants)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from feature_config import N_FEATURES, N_CLASSES


class GreyHoleDetectorMLP(nn.Module):
    """
    Multi-layer perceptron for grey hole detection.
    Used as the local model in each Flower client (Eq 3.20).
    Lightweight enough for edge deployment.
    """

    def __init__(self, n_features: int = N_FEATURES,
                 n_classes: int = N_CLASSES,
                 hidden: list = [64, 32, 16]):
        super().__init__()
        layers = []
        in_dim = n_features
        for h in hidden:
            layers += [nn.Linear(in_dim, h), nn.BatchNorm1d(h), nn.ReLU(), nn.Dropout(0.3)]
            in_dim = h
        layers.append(nn.Linear(in_dim, n_classes))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            return F.softmax(self.forward(x), dim=-1)

    def malicious_probability(self, x: torch.Tensor) -> float:
        """Returns P(malicious) = 1 - P(BENIGN) — used as ŷ_FL score."""
        proba = self.predict_proba(x)
        benign_prob = proba[:, 0].mean().item()  # class 0 = BENIGN
        return 1.0 - benign_prob


def get_parameters(model: nn.Module) -> list:
    """Extract model parameters as list of numpy arrays (Flower format)."""
    return [p.data.cpu().numpy() for p in model.parameters()]


def set_parameters(model: nn.Module, parameters: list) -> None:
    """Set model parameters from list of numpy arrays."""
    import numpy as np
    for p, w in zip(model.parameters(), parameters):
        p.data = torch.tensor(np.array(w), dtype=torch.float32)
```

---

## Step 6 — Flower Client (Vehicle Node)

### File: `fl/fl_client.py`

```python
"""
Flower FL Client — one instance per vehicle node.
Implements local training (Eq 3.20) and gradient commitment to blockchain.
"""

import flwr as fl
import torch
import torch.nn as nn
import torch.nn.functional as F
import pandas as pd
import numpy as np
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from model.grey_hole_detector import GreyHoleDetectorMLP, get_parameters, set_parameters
from data.feature_config import FEATURES, N_CLASSES, LABEL2ID
from fl.blockchain_bridge import BlockchainBridge


class VehicleClient(fl.client.NumPyClient):
    """
    Flower NumPy client representing one vehicle node in the FL federation.
    Each client trains locally on its own data (Eq 3.20) and submits
    gradient updates with blockchain hash commitments (Eq 3.22).
    """

    def __init__(self, node_id: int, data_dir: str = "data/partitions",
                 use_blockchain: bool = True):
        self.node_id    = node_id
        self.blockchain = BlockchainBridge(node_id) if use_blockchain else None
        self.model      = GreyHoleDetectorMLP()

        # Load this node's training data
        train_path = Path(data_dir) / f"node_{node_id}_train.csv"
        val_path   = Path(data_dir) / f"node_{node_id}_val.csv"

        if not train_path.exists():
            raise FileNotFoundError(f"Run partition_dataset.py first. Missing: {train_path}")

        self.train_loader = self._load_data(str(train_path))
        self.val_loader   = self._load_data(str(val_path))
        self.n_train      = sum(len(b[0]) for b in self.train_loader)
        print(f"[CLIENT {node_id}] Loaded {self.n_train} training samples")

    def _load_data(self, csv_path: str, batch_size: int = 32) -> DataLoader:
        df   = pd.read_csv(csv_path)
        X    = torch.FloatTensor(df[FEATURES].values)
        y    = torch.LongTensor(df["label_multiclass"].values)
        return DataLoader(TensorDataset(X, y), batch_size=batch_size, shuffle=True)

    def get_parameters(self, config: dict) -> list:
        return get_parameters(self.model)

    def fit(self, parameters: list, config: dict) -> tuple:
        """
        Eq 3.20 — Local model training.
        Train on local dataset D_i to minimise cross-entropy loss.
        Then commit gradient hash to blockchain before returning.
        """
        round_num = config.get("round_num", 0)
        set_parameters(self.model, parameters)

        optimizer = torch.optim.Adam(self.model.parameters(), lr=1e-3, weight_decay=1e-4)
        loss_fn   = nn.CrossEntropyLoss()

        self.model.train()
        total_loss = 0.0
        n_batches  = 0

        for epoch in range(3):  # 3 local epochs
            for X_batch, y_batch in self.train_loader:
                optimizer.zero_grad()
                logits = self.model(X_batch)
                loss   = loss_fn(logits, y_batch)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
                n_batches  += 1

        avg_loss = total_loss / max(n_batches, 1)
        updated_params = get_parameters(self.model)

        # Eq 3.22 — commit gradient hash to blockchain BEFORE returning
        if self.blockchain:
            self.blockchain.commit_gradient(updated_params, round_num)

        metrics = {
            "node_id":    self.node_id,
            "train_loss": avg_loss,
            "n_samples":  self.n_train,
        }
        return updated_params, self.n_train, metrics

    def evaluate(self, parameters: list, config: dict) -> tuple:
        """Evaluate global model on this node's local validation set."""
        set_parameters(self.model, parameters)
        self.model.eval()

        loss_fn = nn.CrossEntropyLoss()
        total_loss = correct = total = 0

        with torch.no_grad():
            for X_batch, y_batch in self.val_loader:
                logits = self.model(X_batch)
                total_loss += loss_fn(logits, y_batch).item()
                preds       = logits.argmax(dim=1)
                correct    += (preds == y_batch).sum().item()
                total      += len(y_batch)

        accuracy = correct / max(total, 1)
        avg_loss = total_loss / max(len(self.val_loader), 1)

        return avg_loss, total, {"accuracy": accuracy, "node_id": self.node_id}
```

---

## Step 7 — Blockchain Bridge

### File: `fl/blockchain_bridge.py`

```python
"""
Blockchain bridge for FL module.
Interfaces with Part 2's fl_gradient_commit.py.
In integration: import directly from shield_gh_blockchain/client/fl_gradient_commit.py
In standalone mode: uses file-based mock.
"""

import hashlib
import json
import numpy as np
from pathlib import Path

# ── Try to import from Part 2 blockchain module ───────────────────────────────
try:
    import sys
    sys.path.insert(0, "../../shield_gh_blockchain/client")
    from fl_gradient_commit import commit_gradient as bc_commit
    from fl_gradient_commit import verify_gradient as bc_verify
    BLOCKCHAIN_AVAILABLE = True
    print("[FL] Using live blockchain module from Part 2")
except ImportError:
    BLOCKCHAIN_AVAILABLE = False
    print("[FL] Blockchain module not found — using file-based mock ledger")

# ── File-based mock ledger (fallback) ─────────────────────────────────────────
MOCK_LEDGER_PATH = Path("output/mock_ledger.json")

def _load_ledger() -> dict:
    if MOCK_LEDGER_PATH.exists():
        return json.load(open(MOCK_LEDGER_PATH))
    return {}

def _save_ledger(ledger: dict):
    MOCK_LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    json.dump(ledger, open(MOCK_LEDGER_PATH, "w"), indent=2)

def _hash_weights(weights: list) -> str:
    serialized = json.dumps(
        [w.tolist() if hasattr(w, "tolist") else w for w in weights],
        sort_keys=True
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


class BlockchainBridge:
    def __init__(self, node_id: int):
        self.node_id = node_id

    def commit_gradient(self, weights: list, round_num: int) -> str:
        if BLOCKCHAIN_AVAILABLE:
            return bc_commit(weights, self.node_id, round_num)
        # Mock fallback
        ledger = _load_ledger()
        h = _hash_weights(weights)
        ledger[f"grad_{self.node_id}_{round_num}"] = h
        _save_ledger(ledger)
        print(f"  [MOCK LEDGER] Committed grad node={self.node_id} round={round_num} hash={h[:16]}...")
        return h

    def verify_gradient(self, weights: list, round_num: int) -> bool:
        if BLOCKCHAIN_AVAILABLE:
            return bc_verify(weights, self.node_id, round_num)
        ledger = _load_ledger()
        key    = f"grad_{self.node_id}_{round_num}"
        if key not in ledger:
            return False
        return _hash_weights(weights) == ledger[key]
```

---

## Step 8 — Blockchain-Verified FedAvg Server

### File: `fl/fl_server.py`

```python
"""
SHIELD-GH FL Aggregation Server.
Custom FedAvg that verifies gradient blockchain commitments (Eq 3.22)
and applies dataset-size-weighted averaging (Eq 3.21).
"""

import flwr as fl
import numpy as np
from flwr.common import Parameters, FitRes, EvaluateRes, parameters_to_ndarrays
from flwr.server.client_proxy import ClientProxy
from typing import List, Tuple, Optional, Dict, Union
from fl.blockchain_bridge import BlockchainBridge, _hash_weights, _load_ledger
import json
from pathlib import Path

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)


class BlockchainVerifiedFedAvg(fl.server.strategy.FedAvg):
    """
    Custom FedAvg that implements Eq 3.21–3.22:
    - Verifies each gradient update against its blockchain commitment
    - Rejects poisoned/tampered gradients before aggregation
    - Weights aggregation by local dataset size (Eq 3.21)
    """

    def __init__(self, n_clients: int, **kwargs):
        super().__init__(**kwargs)
        self.n_clients   = n_clients
        self.round_log   = []

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, FitRes]],
        failures: List[Union[Tuple[ClientProxy, FitRes], BaseException]],
    ) -> Tuple[Optional[Parameters], Dict]:
        """
        Eq 3.21–3.22 — blockchain-verified weighted FedAvg.
        """
        accepted = []
        rejected = []

        ledger = _load_ledger()

        for client, fit_res in results:
            metrics  = fit_res.metrics
            node_id  = int(metrics.get("node_id", -1))
            weights  = parameters_to_ndarrays(fit_res.parameters)

            # Eq 3.22 — verify gradient hash against blockchain commitment
            bridge  = BlockchainBridge(node_id)
            is_valid = bridge.verify_gradient(weights, server_round)

            if is_valid:
                accepted.append((client, fit_res))
                print(f"  [FedAvg R{server_round}] Node {node_id}: ACCEPTED "
                      f"(loss={metrics.get('train_loss',0):.4f})")
            else:
                rejected.append(node_id)
                print(f"  [FedAvg R{server_round}] Node {node_id}: REJECTED — "
                      f"gradient hash mismatch (poisoning attempt?)")

        self.round_log.append({
            "round":    server_round,
            "accepted": len(accepted),
            "rejected": rejected,
        })
        json.dump(self.round_log, open(OUTPUT_DIR/"round_log.json","w"), indent=2)

        if not accepted:
            print(f"  [WARNING] Round {server_round}: all clients rejected!")
            return None, {}

        return super().aggregate_fit(server_round, accepted, failures)

    def aggregate_evaluate(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, EvaluateRes]],
        failures,
    ) -> Tuple[Optional[float], Dict]:
        losses_weighted = []
        accuracies      = []
        for client, eval_res in results:
            n = eval_res.num_examples
            losses_weighted.append(eval_res.loss * n)
            accuracies.append(eval_res.metrics.get("accuracy", 0.0))

        if not losses_weighted:
            return None, {}

        agg_loss = sum(losses_weighted) / sum(r.num_examples for _, r in results)
        avg_acc  = np.mean(accuracies)
        print(f"  [Eval R{server_round}] Loss={agg_loss:.4f}  Accuracy={avg_acc:.4f}")
        return agg_loss, {"accuracy": avg_acc}


def run_fl_server(n_rounds: int = 15, n_clients: int = 8):
    strategy = BlockchainVerifiedFedAvg(
        n_clients=n_clients,
        fraction_fit=1.0,
        fraction_evaluate=1.0,
        min_fit_clients=max(2, n_clients // 2),
        min_evaluate_clients=max(2, n_clients // 2),
        min_available_clients=max(2, n_clients // 2),
    )
    fl.server.start_server(
        server_address="0.0.0.0:8080",
        config=fl.server.ServerConfig(num_rounds=n_rounds),
        strategy=strategy,
    )
```

---

## Step 9 — Mock FL Runner (No Separate Processes Needed)

### File: `mock_mode/run_mock_fl.py`

```python
#!/usr/bin/env python3
"""
Run complete FL simulation in a single process using Flower's in-process simulation.
No need to start separate server/client processes — ideal for development.
"""

import flwr as fl
import torch
import numpy as np
import json
from pathlib import Path
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from data.generate_mock_dataset import main as gen_data
from data.partition_dataset import partition_by_node
from fl.fl_client import VehicleClient
from fl.fl_server import BlockchainVerifiedFedAvg
from model.grey_hole_detector import GreyHoleDetectorMLP, set_parameters, get_parameters
from data.feature_config import FEATURES, ID2LABEL

OUTPUT_DIR = Path("output/fl_scores")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def client_fn(cid: str) -> fl.client.Client:
    node_id = int(cid)
    return VehicleClient(node_id=node_id, data_dir="data/partitions",
                         use_blockchain=True).to_client()


def run_simulation(n_rounds: int = 15, n_clients: int = 8):
    print("=== SHIELD-GH Federated Learning Simulation ===\n")

    # Step 1: Generate data if not present
    if not Path("data/mock/simulation_dataset.csv").exists():
        print("[SETUP] Generating mock dataset...")
        gen_data()

    if not Path(f"data/partitions/node_0_train.csv").exists():
        print("[SETUP] Partitioning dataset (non-IID by node)...")
        partition_by_node("data/mock/simulation_dataset.csv")

    # Step 2: Define strategy
    strategy = BlockchainVerifiedFedAvg(
        n_clients=n_clients,
        fraction_fit=1.0,
        fraction_evaluate=1.0,
        min_fit_clients=n_clients,
        min_evaluate_clients=n_clients,
        min_available_clients=n_clients,
    )

    # Step 3: Run FL simulation
    history = fl.simulation.start_simulation(
        client_fn=client_fn,
        num_clients=n_clients,
        config=fl.server.ServerConfig(num_rounds=n_rounds),
        strategy=strategy,
        client_resources={"num_cpus": 1, "num_gpus": 0.0},
    )

    print(f"\n[DONE] FL simulation complete — {n_rounds} rounds")
    return history


def export_fl_scores(model_path: str = None, n_clients: int = 8):
    """
    After training, evaluate each node and export fl_score_{node_id}.json
    """
    import pandas as pd

    global_model = GreyHoleDetectorMLP()
    if model_path and Path(model_path).exists():
        global_model.load_state_dict(torch.load(model_path))

    for node_id in range(n_clients):
        csv_path = Path(f"data/partitions/node_{node_id}_val.csv")
        if not csv_path.exists():
            continue
        df = pd.read_csv(csv_path)
        X  = torch.FloatTensor(df[FEATURES].values)
        global_model.eval()
        with torch.no_grad():
            probs = torch.softmax(global_model(X), dim=1)
        mal_prob  = (1 - probs[:, 0]).mean().item()  # 1 - P(BENIGN)
        pred_idx  = probs.mean(0).argmax().item()
        pred_label= ID2LABEL[pred_idx]
        confidence= probs.mean(0).max().item()

        score = {
            "node_id":          node_id,
            "malicious_prob":   round(mal_prob, 4),
            "predicted_variant":pred_label,
            "confidence":       round(confidence, 4),
            "round_num":        15,
            "local_accuracy":   0.0,  # filled below
            "timestamp":        float(df["window_end"].max() if "window_end" in df.columns else 0.0),
        }

        # Compute local accuracy
        y_true = df["label_multiclass"].values
        y_pred = probs.argmax(dim=1).numpy()
        score["local_accuracy"] = round(float((y_pred == y_true).mean()), 4)

        out_path = OUTPUT_DIR / f"fl_score_{node_id}.json"
        with open(out_path, "w") as f:
            json.dump(score, f, indent=2)
        print(f"  [OK] Node {node_id}: malicious_prob={mal_prob:.4f}  "
              f"pred={pred_label}  acc={score['local_accuracy']:.4f}")

    print(f"\n[DONE] FL scores written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    history = run_simulation(n_rounds=15, n_clients=8)
    export_fl_scores(n_clients=8)
```

---

## Step 10 — Evaluation

### File: `evaluation/evaluate_global_model.py`

```python
#!/usr/bin/env python3
"""Evaluate trained global model — accuracy, MCC, FPR per attack variant."""

import torch
import pandas as pd
import numpy as np
from sklearn.metrics import (accuracy_score, matthews_corrcoef,
                              confusion_matrix, classification_report)
from pathlib import Path
import sys
sys.path.insert(0, "..")
from model.grey_hole_detector import GreyHoleDetectorMLP, set_parameters
from data.feature_config import FEATURES, LABELS, ID2LABEL, label_to_binary

def evaluate_all_nodes(model: GreyHoleDetectorMLP, data_dir: str = "data/partitions"):
    all_y_true, all_y_pred, all_y_true_bin, all_y_pred_bin = [], [], [], []

    for node_id in range(8):
        csv = Path(data_dir) / f"node_{node_id}_val.csv"
        if not csv.exists(): continue
        df  = pd.read_csv(csv)
        X   = torch.FloatTensor(df[FEATURES].values)
        y   = df["label_multiclass"].values

        model.eval()
        with torch.no_grad():
            preds = model(X).argmax(dim=1).numpy()

        all_y_true.extend(y.tolist())
        all_y_pred.extend(preds.tolist())

        # Binary
        y_bin     = [label_to_binary(LABELS[i]) for i in y]
        pred_bin  = [label_to_binary(LABELS[i]) for i in preds]
        all_y_true_bin.extend(y_bin)
        all_y_pred_bin.extend(pred_bin)

    acc = accuracy_score(all_y_true, all_y_pred)
    mcc = matthews_corrcoef(all_y_true_bin, all_y_pred_bin)
    cm  = confusion_matrix(all_y_true_bin, all_y_pred_bin)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2,2) else (0,0,0,0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n=== Global Model Evaluation ===")
    print(f"Accuracy:  {acc:.4f}")
    print(f"MCC:       {mcc:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"\n{classification_report(all_y_true, all_y_pred, target_names=LABELS)}")
    return {"accuracy": acc, "mcc": mcc, "fpr": fpr}

if __name__ == "__main__":
    model = GreyHoleDetectorMLP()
    evaluate_all_nodes(model)
```

---

## Completion Checklist

- [ ] `mock_mode/run_mock_fl.py` runs 15 FL rounds without errors
- [ ] FL server logs show accepted/rejected clients per round
- [ ] `output/fl_scores/fl_score_{0..7}.json` all exist with correct schema
- [ ] Global model accuracy > 70% on mock data (higher with real NS-3 data)
- [ ] Gradient poisoning test: manually tamper one client's gradient → server rejects it
- [ ] Non-IID check: node 3 (attacker) should have higher `malicious_prob` than others
- [ ] `evaluation/evaluate_global_model.py` prints accuracy, MCC, FPR per variant

---

## Files to Hand Off

| File | Used By |
|------|---------|
| `output/fl_scores/fl_score_{id}.json` | Fusion Engine |
| `fl/blockchain_bridge.py` | Blockchain module can use this as template |
| `data/feature_config.py` | LLM module needs consistent feature names |
| `data/mock/simulation_dataset.csv` | LLM module (for tokenisation training) |
