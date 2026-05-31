# SHIELD-GH Federated Learning Module Architecture

## Overview

The federated learning module implements the **distributed, privacy-preserving detection layer** of SHIELD-GH. Each vehicle trains a local grey hole detector on its own forwarding-log data and contributes gradient updates to a global model — without ever sharing raw packet data. The global model improves across FL rounds and provides the `ŷ_FL` classification score used by the LLM fusion engine.

A critical design constraint is **gradient integrity**: a malicious vehicle could submit poisoned gradient updates to degrade the global model's ability to detect its own attack pattern. The FL module counters this by requiring every vehicle to commit a SHA-256 hash of its gradient to the blockchain *before* transmitting it. The aggregator verifies the hash before including any update in FedAvg.

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| FL framework | Flower (`flwr`) — lightweight, framework-agnostic |
| Local model | PyTorch (`torch.nn`) |
| Aggregation | Custom `BlockchainVerifiedFedAvg` (weighted FedAvg, Eq 3.21) |
| Gradient integrity | SHA-256 hash committed to blockchain (Eq 3.22) |
| Data format | CSV files per vehicle (`node_{id}_train.csv`, `node_{id}_val.csv`) |
| Evaluation | scikit-learn metrics (accuracy, F1, MCC, confusion matrix) |

---

## Module Directory Structure

```
shield_gh_fl/
├── fl/
│   ├── fl_client.py              # Vehicle FL client — local training (Eq 3.20)
│   ├── fl_server.py              # Aggregation server — blockchain-verified FedAvg (Eq 3.21–3.22)
│   └── blockchain_bridge.py     # Hash commit/verify interface to blockchain module
├── model/
│   ├── grey_hole_detector.py     # PyTorch MLP — 7-feature → 7-class classifier
│   └── __init__.py
├── data/
│   ├── feature_config.py         # Feature list, class labels, class count
│   └── (node_{id}_train/val.csv) # Per-vehicle partitioned datasets
├── evaluation/
│   └── (metrics scripts)
├── mock_mode/
│   └── (standalone simulation without live blockchain)
├── output/
│   ├── global_model.pth          # Saved global model after training
│   ├── fl_score_{round}.json     # Per-node FL scores (malicious_prob, variant, confidence)
│   ├── round_log.json            # Per-round accepted/rejected gradient summary
│   └── mock_ledger.json          # File-based ledger (mock mode only)
├── verify.py                     # Standalone evaluation script
└── requirements.txt
```

---

## Detection Model

### Architecture — `GreyHoleDetectorMLP`

File: `model/grey_hole_detector.py`

A multi-layer perceptron trained independently at each vehicle node (Eq 3.20).

```
Input (7 features)
    → Linear(7 → 64) + BatchNorm1d + ReLU + Dropout(0.3)
    → Linear(64 → 32) + BatchNorm1d + ReLU + Dropout(0.3)
    → Linear(32 → 16) + BatchNorm1d + ReLU + Dropout(0.3)
    → Linear(16 → 7)   [logits — one per class]
    → Softmax           [class probabilities]
```

**Input features (7):** PDR, corrected PDR, handoff loss rate, raw trust, MATD trust, reputation score, reputation deficit — all derived from the MATD blockchain pipeline.

**Output classes (7):**
- Class 0: BENIGN
- Class 1: S1_DP_FR (Data-plane fixed-rate)
- Class 2: S2_DP_IT (Data-plane intermittent)
- Class 3: S3_DP_TS (Data-plane target-specific)
- Class 4: S4_CP_FR (Control-plane fixed-rate)
- Class 5: S5_CP_IT (Control-plane intermittent)
- Class 6: S6_CP_TS (Control-plane target-specific)

**Key methods:**
- `forward(x)` — raw logits
- `predict_proba(x)` — softmax probabilities
- `malicious_probability(x)` → `1 - P(BENIGN)` used as `ŷ_FL` score in the fusion equation (Eq 3.24)

---

## FL Client — `VehicleClient`

File: `fl/fl_client.py`

One instance per vehicle. Trains only on local data (Eq 3.20). No raw data ever leaves the vehicle.

### Local Training (Eq 3.20)

```
L_i(w) = (1/|D_i|) · Σ_{(x,y) ∈ D_i} ℓ(f(x; w), y)
```

- Loss function: cross-entropy
- Optimizer: Adam (`lr=1e-3`, `weight_decay=1e-4`)
- Local epochs per round: 3
- Batch size: 32

### Gradient Integrity Commitment (Eq 3.22)

Before returning updated weights to the aggregator:

```python
# Serialize and hash the weight tensors
hash = SHA-256(JSON(weights))

# Write hash to blockchain BEFORE transmitting weights
blockchain.commit_gradient(weights, round_num)
```

This ensures a malicious vehicle cannot retroactively alter its committed gradient. The blockchain's immutability makes this tamper-proof.

### Evaluation

The client also evaluates the incoming global model on its local validation set, returning `accuracy` and `loss` for per-node diagnostics without centralising data.

---

## FL Aggregation Server — `BlockchainVerifiedFedAvg`

File: `fl/fl_server.py`

### Blockchain Hash Verification (Eq 3.22)

Before including any gradient in aggregation:

```python
Accept(Δw_i) = 1[H_BC(Δw_i) = Hash(Δw_i)]
```

- `H_BC(Δw_i)` = hash retrieved from blockchain ledger (committed by vehicle before transmission)
- `Hash(Δw_i)` = hash computed from received gradient
- Mismatch → gradient REJECTED (gradient poisoning attempt or transmission error)

### Weighted FedAvg (Eq 3.21)

```
w^(r+1) = Σ_{i ∈ A} (|D_i| / |D_A|) · w_i^(r)
```

- `A` = set of vehicles whose gradients passed blockchain verification
- `|D_i|` = size of vehicle i's local training dataset
- `|D_A|` = total accepted samples across all accepted vehicles

Dataset-size weighting accounts for heterogeneous observation volumes across vehicles operating in dense vs. sparse network segments.

**Round output:** saves `global_model.pth` and `round_log.json` (per-round accepted/rejected node summary).

---

## Blockchain Bridge — `BlockchainBridge`

File: `fl/blockchain_bridge.py`

Provides a unified interface that works in two modes:

**Integration mode** (live blockchain available): delegates to `shield_gh_blockchain/client/fl_gradient_commit.py` for real Hyperledger Fabric interactions.

**Mock mode** (standalone): uses a file-based JSON ledger at `output/mock_ledger.json`. Functionally identical — same SHA-256 hash commitment and verification logic, without Fabric dependency.

```python
bridge = BlockchainBridge(node_id=3)
bridge.commit_gradient(weights, round_num=5)   # writes hash to ledger
bridge.verify_gradient(weights, round_num=5)   # True if hashes match
```

---

## Mathematical Formulations Implemented

| Equation | Description | Location |
|----------|-------------|----------|
| Eq 3.20 | Local training loss (cross-entropy FedAvg) | `fl_client.py` → `fit()` |
| Eq 3.21 | Weighted FedAvg aggregation | `fl_server.py` → `aggregate()` |
| Eq 3.22 | Blockchain gradient integrity check | `fl_server.py` + `blockchain_bridge.py` |

---

## Non-IID Distribution Challenge

Vehicle mobility produces non-IID local datasets:
- Urban vehicle: dense traffic, high PDR, low variance
- Highway vehicle: sparse, high-variance traffic with frequent legitimate packet loss

The FL module addresses this via:
1. **Dataset-size weighting** (Eq 3.21) — sparse-segment vehicles with fewer observations have lower weight in aggregation.
2. **Blockchain gradient integrity** — prevents a vehicle in a low-density region (where the global model has poor local coverage) from submitting poisoned updates to further degrade detection in that region.

---

## Output Format

After each FL round, `output/fl_score_{round}.json` contains per-node records:

```json
{
  "node_id": 3,
  "malicious_prob": 0.9231,
  "predicted_variant": "S1_DP_FR",
  "confidence": 0.9231,
  "local_accuracy": 0.9143,
  "round_num": 15
}
```

These records are consumed by:
- The **LLM threat scorer** as the `fl` input dictionary
- The **fusion engine** (Eq 3.24) for the `ŷ_FL` component
- The **dashboard** for per-node FL classification display

---

## Fusion Role in Detection (Eq 3.24)

The FL module contributes `ŷ_FL` to the final detection decision:

```
ŷ_i(t) = 1[μ₁·S_total(v_i) + μ₂·Q_i(t) + μ₃·(1 - R_i(t)) > θ_det]
```

- `S_total(v_i)` = max signature score from lightweight rule-based detector
- `Q_i(t)` = LLM semantic threat score
- `(1 - R_i(t))` = blockchain reputation deficit

The FL malicious probability (`malicious_prob`) is passed to the LLM module for narrative generation and contributes to the threat score computation:

```python
score = 0.25 * rep_deficit + 0.30 * mal_prob + 0.15 * zkp_penalty + 0.30 * Q_i
```

---

## Integration Points

| Module | Interface |
|--------|-----------|
| Blockchain | `BlockchainBridge` for gradient commit/verify; reads reputation scores, ZKP status from ledger |
| LLM scorer | Writes `fl_score_{round}.json`; LLM reads `malicious_prob`, `predicted_variant`, `confidence` |
| NS-3 simulation | Feature vectors derived from NS-3 forwarding event logs |
| Dashboard | REST endpoint reads `fl_score` records for per-node classification display |

---

## Privacy Guarantees

- No raw packet data ever leaves a vehicle — only model weight updates are shared.
- Gradient updates are further protected by blockchain hash commitment, which prevents both poisoning and retroactive tampering.
- The aggregator only sees gradient weights, never individual vehicle routing or location data.
- This satisfies the Federated Learning privacy model (Assumption A2 from the threat model): global intelligence is pooled without centralising sensitive vehicle data.
