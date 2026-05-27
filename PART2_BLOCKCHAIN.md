# PART 2 — Blockchain Implementation
## SHIELD-GH · Hyperledger Fabric · DEBSC · MATD · ZKP · PQC
**Owner:** B.M.L.P. Abesinghe (EG/2021/4377)
**Tools:** Hyperledger Fabric 2.5, Docker, Node.js (chaincode), Python (SDK client), oqs-python (PQC)
**Input:** `vehicle_event.jsonl` from NS-3 (or mock data)
**Output:** `bc_record_{node_id}.json`, `grad_commit` ledger entries, isolation commands

---

## What This Module Does

This module implements the **trust layer** of SHIELD-GH. It:

1. **Ingests** per-vehicle forwarding events and computes MATD-corrected trust scores (Eq 3.16–3.18)
2. **Stores** cryptographic forwarding proof commitments (simplified Pedersen, Eq 3.29)
3. **Runs** the Dual-Evidence Blockchain Smart Contract (DEBSC) that gates isolation on both a statistical AND a cryptographic failure (Eq 3.19)
4. **Verifies** FL gradient hashes to block poisoning attacks (Eq 3.22)
5. **Executes** threshold-signed node isolation using CRYSTALS-Dilithium + Kyber (Eq 3.27–3.33)

Can be developed entirely against the mock JSON data from Part 1 with no NS-3 needed.

---

## Shared Data Contract

### Input: `vehicle_event.json` (from NS-3 / mock)
```json
{
  "node_id": 3, "timestamp": 2.9638,
  "packets_received": 30, "packets_forwarded": 14,
  "pdr": 0.4667, "speed_kmh": 72.4,
  "rsu_id": "RSU_02", "is_handoff": false,
  "src_vehicle": 1, "dst_vehicle": 4
}
```

### Output: `bc_record_{node_id}.json`
```json
{
  "record_id": "bc_a3f9d1",
  "node_id": 3,
  "zkp_valid": false,
  "reputation_score": 0.39,
  "reputation_deficit": 0.61,
  "total_interactions": 47,
  "matd_corrected_trust": 0.37,
  "isolation_status": "ISOLATED",
  "debsc_triggered": true,
  "timestamp": 5.1102
}
```

---

## Directory Structure to Create

```
shield_gh_blockchain/
├── fabric_network/
│   ├── docker-compose.yml           # Hyperledger Fabric network
│   ├── crypto-config.yaml           # Org and peer certificates
│   └── configtx.yaml                # Channel config
├── chaincode/
│   ├── debsc/
│   │   ├── debsc.js                 # DEBSC smart contract (Node.js)
│   │   └── package.json
│   └── fl_integrity/
│       ├── fl_integrity.js          # Gradient hash verification chaincode
│       └── package.json
├── client/
│   ├── blockchain_client.py         # Python SDK — main interface
│   ├── matd_trust.py                # MATD scoring (Eq 3.16–3.18)
│   ├── zkp_commitment.py            # ZKP / Pedersen commitment (Eq 3.29–3.30)
│   ├── pqc_mitigation.py            # Dilithium + Kyber (Eq 3.25–3.33)
│   ├── pqc_lkh.py                   # PQC-LKH group re-keying (Eq 3.34–3.36)
│   ├── ingestion_pipeline.py        # Main event processing loop
│   └── fl_gradient_commit.py        # FL gradient hash interface
├── mock_mode/
│   ├── mock_ledger.py               # In-memory ledger (no Fabric needed)
│   └── run_mock_pipeline.py         # Full pipeline on mock data
├── output/
│   └── bc_records/                  # Output bc_record_{id}.json files
└── requirements.txt
```

---

## Step 1 — Environment Setup

### 1.1 Install Docker and Fabric Prerequisites

```bash
# Docker
sudo apt-get update
sudo apt-get install -y docker.io docker-compose curl git jq
sudo usermod -aG docker $USER
newgrp docker

# Node.js 18 (for chaincode)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Python dependencies
pip install hfc fabric-sdk-py requests hashlib cryptography
```

### 1.2 Install Hyperledger Fabric Binaries

```bash
mkdir -p ~/fabric && cd ~/fabric
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.5

# Add to PATH
echo 'export PATH=$PATH:~/fabric/fabric-samples/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
peer version
```

### 1.3 Install PQC Library (liboqs)

```bash
# Install liboqs for CRYSTALS-Kyber and Dilithium
sudo apt-get install -y cmake ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip

git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja .. && ninja && sudo ninja install

# Python bindings
pip install oqs
python3 -c "import oqs; print('OQS OK:', oqs.get_enabled_sig_mechanisms()[:3])"
```

### 1.4 requirements.txt

```
oqs>=0.9.0
cryptography>=41.0.0
pandas>=2.0.0
numpy>=1.24.0
requests>=2.31.0
jsonschema>=4.17.0
hashlib
```

---

## Step 2 — MATD Trust Scoring

### File: `client/matd_trust.py`

Implements Equations 3.4, 3.5, 3.16, 3.17, 3.18 from the paper exactly.

```python
"""
MATD Trust Scoring — Implements Eq 3.4, 3.5, 3.16, 3.17, 3.18
Mobility-Aware Trust Decay for SHIELD-GH Blockchain module.
"""

import math
from dataclasses import dataclass, field
from typing import List, Dict

# ── Calibrated constants (tune from NS-3 benign runs) ────────────────────────
LAMBDA_S   = 0.010   # mobility decay coefficient
DELTA_T    = 1.0     # observation slot duration (seconds)
RSU_R      = 300.0   # RSU coverage radius (metres)
DELTA_THO  = 0.30    # average handoff transition duration (seconds)
RHO_MAX    = 0.15    # worst-case handoff loss rate (calibrated from simulation)
ALPHA_PRIOR = 1.0    # Beta distribution prior — forwarding successes
BETA_PRIOR  = 1.0    # Beta distribution prior — forwarding failures


@dataclass
class VehicleHistory:
    node_id: int
    matd_scores: List[float] = field(default_factory=list)  # all RSU interactions

    def add_interaction(self, score: float):
        self.matd_scores.append(score)

    def reputation(self) -> float:
        """Eq 3.18 — mean MATD trust over all historical interactions."""
        if not self.matd_scores:
            return 1.0
        return sum(self.matd_scores) / len(self.matd_scores)


def compute_handoff_loss_rate(speed_kmh: float) -> float:
    """
    Eq 3.4 — Expected RSU handoff-induced packet loss rate.
    ρ_ho(v_i, t) = s_i(t) · Δt_ho / R_RSU · ρ_max
    """
    speed_ms = speed_kmh / 3.6
    return (speed_ms * DELTA_THO / RSU_R) * RHO_MAX


def compute_corrected_pdr(observed_pdr: float, speed_kmh: float) -> float:
    """
    Eq 3.5 — Mobility-corrected PDR.
    PDR̂_i(t, W) = PDR_i(t, W) + ρ_ho(v_i, t)
    """
    return min(1.0, observed_pdr + compute_handoff_loss_rate(speed_kmh))


def compute_instantaneous_trust(n_fwd: int, n_drop: int) -> float:
    """
    Eq 3.16 — Beta-distribution instantaneous trust score.
    T_i(t) = (α + n_fwd) / (α + n_fwd + β + n_drop)
    """
    return (ALPHA_PRIOR + n_fwd) / (ALPHA_PRIOR + n_fwd + BETA_PRIOR + n_drop)


def compute_matd_trust(n_fwd: int, n_drop: int, speed_kmh: float) -> float:
    """
    Eq 3.17 — Mobility-Aware Trust Decay.
    T^mob_i(t) = T_i(t) · exp(-λ_s · s_i(t) · Δt)
    """
    raw_trust = compute_instantaneous_trust(n_fwd, n_drop)
    speed_ms  = speed_kmh / 3.6
    penalty   = math.exp(-LAMBDA_S * speed_ms * DELTA_T)
    return raw_trust * penalty


class MATDEngine:
    """
    Processes vehicle events and maintains per-node reputation history.
    Central class used by the ingestion pipeline.
    """

    def __init__(self):
        self.histories: Dict[int, VehicleHistory] = {}

    def process_event(self, event: dict) -> dict:
        """
        Process one vehicle_event and return updated trust record.
        Returns a dict ready to be written to the blockchain ledger.
        """
        node_id  = event["node_id"]
        n_rx     = event["packets_received"]
        n_fwd    = event["packets_forwarded"]
        n_drop   = n_rx - n_fwd
        speed    = event["speed_kmh"]
        timestamp= event["timestamp"]

        # Compute trust scores
        raw_trust   = compute_instantaneous_trust(n_fwd, n_drop)
        matd_trust  = compute_matd_trust(n_fwd, n_drop, speed)
        pdr_raw     = n_fwd / n_rx if n_rx > 0 else 1.0
        pdr_corr    = compute_corrected_pdr(pdr_raw, speed)
        handoff_loss= compute_handoff_loss_rate(speed)

        # Update history
        if node_id not in self.histories:
            self.histories[node_id] = VehicleHistory(node_id)
        self.histories[node_id].add_interaction(matd_trust)
        reputation = self.histories[node_id].reputation()

        return {
            "node_id":            node_id,
            "timestamp":          timestamp,
            "n_rx":               n_rx,
            "n_fwd":              n_fwd,
            "n_drop":             n_drop,
            "pdr_raw":            round(pdr_raw,  4),
            "pdr_corrected":      round(pdr_corr, 4),
            "handoff_loss_rate":  round(handoff_loss, 4),
            "raw_trust":          round(raw_trust,  4),
            "matd_trust":         round(matd_trust, 4),
            "reputation_score":   round(reputation, 4),
            "reputation_deficit": round(1 - reputation, 4),
            "total_interactions": len(self.histories[node_id].matd_scores),
            "speed_kmh":          speed,
            "rsu_id":             event.get("rsu_id", "RSU_01"),
            "is_handoff":         event.get("is_handoff", False),
        }
```

---

## Step 3 — ZKP Forwarding Proof

### File: `client/zkp_commitment.py`

```python
"""
ZKP Forwarding Proof — Simplified Pedersen Commitment for SHIELD-GH.
Implements Eq 3.29–3.30.

Full production design: zk-SNARK via snarkjs or gnark.
Simulation design: Pedersen commitment with discrepancy check.
Both are documented in the report; simulation uses this simplified version.
"""

import hashlib
import secrets
import json
from typing import Tuple


# ── Pedersen Commitment Parameters ───────────────────────────────────────────
# For simulation: use SHA-256 based commitment (not full elliptic curve)
# This preserves the binding + hiding properties needed for detection logic.

def commit(n_fwd: int, blinding: bytes = None) -> Tuple[str, bytes]:
    """
    Eq 3.29 (simplified) — Commit to forwarded packet count.
    C_i = Hash(n_fwd || r)  where r is random blinding factor.

    Returns:
        commitment_hex: the commitment string (stored on blockchain)
        blinding:       the secret blinding factor (kept by vehicle)
    """
    if blinding is None:
        blinding = secrets.token_bytes(32)

    data = json.dumps({"n_fwd": n_fwd, "r": blinding.hex()},
                      sort_keys=True).encode()
    commitment = hashlib.sha256(data).hexdigest()
    return commitment, blinding


def open_commitment(commitment_hex: str, n_fwd: int, blinding: bytes) -> bool:
    """
    Eq 3.30 (simplified) — Verify that the commitment opens to the claimed n_fwd.
    Returns True if the proof is valid (vehicle forwarded what it claimed).
    """
    data = json.dumps({"n_fwd": n_fwd, "r": blinding.hex()},
                      sort_keys=True).encode()
    expected = hashlib.sha256(data).hexdigest()
    return expected == commitment_hex


def simulate_zkp_verification(committed_n_fwd: int,
                               observed_n_fwd:  int,
                               tolerance: float = 0.05) -> bool:
    """
    Simulation-level ZKP check used by DEBSC.

    In the real system: the vehicle generates π_i = ZKP.Prove(C_i, n_fwd, r)
    and the blockchain verifies it against independently observable receipt counts.

    In simulation: ZKP FAILS if the committed count differs from the
    observable (independently measured) count by more than tolerance*n_rx.
    This models the same detection property: a grey hole attacker that dropped
    packets cannot produce a valid proof for the dropped batch.
    """
    if committed_n_fwd == 0 and observed_n_fwd == 0:
        return True
    if observed_n_fwd == 0:
        return committed_n_fwd == 0
    ratio = abs(committed_n_fwd - observed_n_fwd) / max(observed_n_fwd, 1)
    return ratio <= tolerance


class ZKPStore:
    """
    Stores per-vehicle forwarding commitments on the (simulated) blockchain.
    In production: these are on-chain Hyperledger Fabric state entries.
    """

    def __init__(self):
        self._commitments = {}  # node_id -> (commitment_hex, blinding, n_fwd_committed)
        self._observed    = {}  # node_id -> n_fwd_observed (from network monitoring)

    def vehicle_commit(self, node_id: int, n_fwd: int) -> str:
        """Called by vehicle before forwarding. Returns commitment hex."""
        commitment, blinding = commit(n_fwd)
        self._commitments[node_id] = (commitment, blinding, n_fwd)
        return commitment

    def rsu_report_observed(self, node_id: int, n_fwd_observed: int):
        """RSU reports what it independently observed the vehicle forwarding."""
        self._observed[node_id] = n_fwd_observed

    def verify_proof(self, node_id: int) -> bool:
        """
        DEBSC calls this — returns False (ZKP FAIL) if discrepancy detected.
        A grey hole attacker: committed n_fwd=30, but RSU observed n_fwd=14.
        → ratio = |30-14|/30 = 0.53 > tolerance → ZKP FAILS → DEBSC triggers.
        """
        if node_id not in self._commitments:
            return True  # no commitment = assume honest (first interaction)
        if node_id not in self._observed:
            return True  # RSU hasn't reported yet

        _, blinding, n_fwd_committed = self._commitments[node_id]
        n_fwd_observed = self._observed[node_id]

        return simulate_zkp_verification(n_fwd_committed, n_fwd_observed)
```

---

## Step 4 — DEBSC Smart Contract Logic

### File: `client/debsc.py`

```python
"""
DEBSC — Dual-Evidence Blockchain Smart Contract.
Implements Eq 3.12, 3.13, 3.19.

In production: this is a Hyperledger Fabric chaincode (debsc/debsc.js).
In simulation: this Python class mirrors the chaincode logic exactly.
"""

from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum


class IsolationDecision(Enum):
    BENIGN              = "BENIGN"
    RATE_LIMIT          = "RATE_LIMIT"
    REQUIRE_ZKP         = "REQUIRE_ZKP_PER_BATCH"
    ISOLATED            = "ISOLATED"
    FALSE_POSITIVE_BLOCKED = "FALSE_POSITIVE_BLOCKED"


@dataclass
class NodeState:
    node_id:          int
    reputation_score: float = 1.0
    suspicion_window: List[bool] = field(default_factory=list)  # recent stat_gate firings
    isolation_status: IsolationDecision = IsolationDecision.BENIGN


class DEBSC:
    """
    Dual-Evidence Blockchain Smart Contract.

    Isolation requires BOTH:
      (1) reputation_deficit > θ_R  (statistical gate)
      (2) ZKP proof FAILS           (cryptographic gate)

    A legitimate vehicle during RSU handoff:
      → statistical gate MAY fire (temporarily low PDR)
      → ZKP proof VALID (vehicle did forward what it committed)
      → Result: FALSE_POSITIVE_BLOCKED — no isolation

    A grey hole attacker:
      → statistical gate fires (low PDR)
      → ZKP proof FAILS (dropped packets ≠ committed count)
      → Result: ISOLATED
    """

    def __init__(self,
                 theta_R:  float = 0.40,   # reputation deficit threshold
                 lambda1:  int   = 3,      # rate-limit threshold
                 lambda2:  int   = 6,      # ZKP-per-batch threshold
                 ws_size:  int   = 10):    # suspicion window size
        self.theta_R = theta_R
        self.lambda1 = lambda1
        self.lambda2 = lambda2
        self.ws_size = ws_size
        self.node_states: Dict[int, NodeState] = {}

    def _get_state(self, node_id: int) -> NodeState:
        if node_id not in self.node_states:
            self.node_states[node_id] = NodeState(node_id)
        return self.node_states[node_id]

    def evaluate(self, node_id: int, reputation_score: float,
                 zkp_valid: bool) -> IsolationDecision:
        """
        Main DEBSC evaluation — Eq 3.19.

        Args:
            node_id:          vehicle identifier
            reputation_score: R_i(t) from MATD engine (Eq 3.18)
            zkp_valid:        result of ZKP proof verification (Eq 3.30)

        Returns:
            IsolationDecision enum value
        """
        state = self._get_state(node_id)
        state.reputation_score = reputation_score

        # Eq 3.19 — gate conditions
        reputation_deficit = 1 - reputation_score
        statistical_gate   = reputation_deficit > self.theta_R
        crypto_gate        = not zkp_valid

        # Eq 3.13 — update suspicion window
        state.suspicion_window.append(statistical_gate)
        if len(state.suspicion_window) > self.ws_size:
            state.suspicion_window.pop(0)
        suspicion_level = sum(state.suspicion_window)   # Λ_i(t)

        # Already isolated — stays isolated
        if state.isolation_status == IsolationDecision.ISOLATED:
            return IsolationDecision.ISOLATED

        # Both gates fire → ISOLATE
        if statistical_gate and crypto_gate and suspicion_level >= self.lambda2:
            state.isolation_status = IsolationDecision.ISOLATED
            return IsolationDecision.ISOLATED

        # Statistical gate fires but ZKP valid → false positive blocked
        if statistical_gate and not crypto_gate:
            return IsolationDecision.FALSE_POSITIVE_BLOCKED

        # Graduated response based on suspicion level
        if suspicion_level >= self.lambda2:
            return IsolationDecision.REQUIRE_ZKP
        if suspicion_level >= self.lambda1:
            return IsolationDecision.RATE_LIMIT

        return IsolationDecision.BENIGN

    def get_all_states(self) -> List[dict]:
        """Export current state of all nodes as list of dicts."""
        result = []
        for nid, state in self.node_states.items():
            result.append({
                "node_id":          nid,
                "reputation_score": round(state.reputation_score, 4),
                "reputation_deficit": round(1 - state.reputation_score, 4),
                "suspicion_level":  sum(state.suspicion_window),
                "isolation_status": state.isolation_status.value,
                "debsc_triggered":  state.isolation_status == IsolationDecision.ISOLATED,
            })
        return result
```

---

## Step 5 — PQC Mitigation

### File: `client/pqc_mitigation.py`

```python
"""
Post-Quantum Cryptographic Mitigation — CRYSTALS-Kyber + Dilithium.
Implements Eq 3.25–3.33.
Requires: pip install oqs
"""

import oqs
import json
import hashlib
import secrets
from typing import List, Tuple, Dict


# ── CRYSTALS-Kyber KEM — Eq 3.25–3.26 ───────────────────────────────────────

def kyber_keygen() -> Tuple[bytes, bytes]:
    """Generate a Kyber-768 key pair (pk, sk)."""
    with oqs.KeyEncapsulation("Kyber768") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


def kyber_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
    """
    Eq 3.25 — Encapsulate a fresh session key under recipient's public key.
    Returns (session_key K, ciphertext c).
    """
    with oqs.KeyEncapsulation("Kyber768") as kem:
        ciphertext, session_key = kem.encap_secret(pk)
    return session_key, ciphertext


def kyber_decapsulate(sk: bytes, ciphertext: bytes, pk: bytes) -> bytes:
    """
    Eq 3.26 — Recover session key K from ciphertext using private key sk.
    """
    with oqs.KeyEncapsulation("Kyber768", secret_key=sk) as kem:
        session_key = kem.decap_secret(ciphertext)
    return session_key


# ── CRYSTALS-Dilithium Signatures — Eq 3.27–3.28 ────────────────────────────

def dilithium_keygen() -> Tuple[bytes, bytes]:
    """Generate a Dilithium3 (ML-DSA) signing key pair (pk, sk)."""
    with oqs.Signature("Dilithium3") as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
    return pk, sk


def dilithium_sign(sk: bytes, message: bytes) -> bytes:
    """
    Eq 3.27 — Sign a flow modification command with Dilithium private key.
    σ = Dilithium.Sign(sk_c, M)
    """
    with oqs.Signature("Dilithium3", secret_key=sk) as signer:
        signature = signer.sign(message)
    return signature


def dilithium_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """
    Eq 3.28 — Verify Dilithium signature. Returns True if valid.
    b = Dilithium.Verify(pk_c, M, σ) ∈ {0, 1}
    """
    try:
        with oqs.Signature("Dilithium3") as verifier:
            return verifier.verify(message, signature, pk)
    except Exception:
        return False


# ── Threshold Signatures — Eq 3.31–3.33 ─────────────────────────────────────

class ThresholdSignatureScheme:
    """
    (k, n)-threshold signature scheme for collective blacklisting.
    Simulation: k individual Dilithium signatures aggregated.
    Production: use BLS threshold signatures for compact aggregation.
    """

    def __init__(self, k: int, n: int):
        self.k = k  # minimum co-signers
        self.n = n  # total RSUs
        # Generate key pairs for n RSUs
        self.rsu_keys = []
        for _ in range(n):
            pk, sk = dilithium_keygen()
            self.rsu_keys.append({"pk": pk, "sk": sk})
        # Group public key = hash of all RSU PKs
        combined = b"".join(kp["pk"] for kp in self.rsu_keys)
        self.group_pk = hashlib.sha256(combined).digest()

    def partial_sign(self, rsu_idx: int, message: bytes) -> bytes:
        """Eq 3.31 — RSU j produces partial signature over blacklist message."""
        sk = self.rsu_keys[rsu_idx]["sk"]
        return dilithium_sign(sk, message)

    def combine_signatures(self, partial_sigs: List[bytes],
                           message: bytes) -> bytes:
        """
        Eq 3.32 — Combine k partial signatures into aggregate σ*.
        Simulation: concatenate and hash (production: BLS aggregation).
        """
        if len(partial_sigs) < self.k:
            raise ValueError(f"Need {self.k} signatures, got {len(partial_sigs)}")
        combined = b"".join(partial_sigs[:self.k])
        sigma_star = hashlib.sha256(combined + message).digest()
        return sigma_star

    def verify_aggregate(self, sigma_star: bytes,
                         partial_sigs: List[bytes], message: bytes) -> bool:
        """
        Eq 3.33 — Verify aggregate signature against group public key.
        Returns True only if k valid partial signatures exist.
        """
        if len(partial_sigs) < self.k:
            return False
        # Verify each partial signature individually
        valid_count = 0
        for i, sig in enumerate(partial_sigs[:self.k]):
            pk = self.rsu_keys[i]["pk"]
            if dilithium_verify(pk, message, sig):
                valid_count += 1
        if valid_count < self.k:
            return False
        # Verify aggregate matches expected
        expected = hashlib.sha256(b"".join(partial_sigs[:self.k]) + message).digest()
        return sigma_star == expected


# ── Full PQC Mitigation Pipeline ─────────────────────────────────────────────

class PQCMitigationEngine:
    """
    Algorithm 4 (PQC-Mit) — Full post-quantum mitigation pipeline.
    Called when DEBSC confirms ISOLATED verdict.
    """

    def __init__(self, n_rsus: int = 3, k_threshold: int = 2):
        self.ts       = ThresholdSignatureScheme(k=k_threshold, n=n_rsus)
        self.ctrl_pk, self.ctrl_sk = dilithium_keygen()
        self.n_rsus   = n_rsus
        self.k        = k_threshold

    def run_isolation(self, node_id: int, zkp_store) -> dict:
        """
        Full Algorithm 4 execution.
        Returns dict summarising mitigation actions taken.
        """
        result = {"node_id": node_id, "steps": []}

        # Step 1 — ZKP verification (Eq 3.30)
        zkp_valid = zkp_store.verify_proof(node_id)
        if zkp_valid:
            return {"node_id": node_id, "action": "ABORT_FALSE_POSITIVE",
                    "reason": "ZKP proof valid — statistical detection was false positive"}
        result["steps"].append({"step": 1, "name": "ZKP_VERIFICATION",
                                 "result": "FAIL — confirmed attacker"})

        # Step 2 — Threshold-signed blacklisting (Eq 3.31–3.33)
        blacklist_msg = json.dumps({"isolate": node_id,
                                    "reason": "grey_hole_confirmed"}).encode()
        partial_sigs  = [self.ts.partial_sign(i, blacklist_msg)
                         for i in range(self.n_rsus)]
        sigma_star    = self.ts.combine_signatures(partial_sigs[:self.k], blacklist_msg)
        sig_valid     = self.ts.verify_aggregate(sigma_star, partial_sigs, blacklist_msg)

        if not sig_valid:
            return {"node_id": node_id, "action": "ABORT_INSUFFICIENT_SIGNATURES",
                    "reason": f"Only {len(partial_sigs)} RSUs — need {self.k}"}
        result["steps"].append({"step": 2, "name": "THRESHOLD_SIGNING",
                                 "result": f"sigma* valid ({self.k}/{self.n_rsus} RSUs)"})

        # Step 3 — SDN flow modification (Eq 3.27–3.28)
        flowmod_cmd = json.dumps({"action": "BLOCK", "target_node": node_id,
                                   "priority": 65535}).encode()
        flowmod_sig = dilithium_sign(self.ctrl_sk, flowmod_cmd)
        verified    = dilithium_verify(self.ctrl_pk, flowmod_cmd, flowmod_sig)
        result["steps"].append({"step": 3, "name": "FLOWMOD_SIGN",
                                 "result": f"Dilithium signature valid={verified}",
                                 "flowmod": flowmod_cmd.decode()})

        result["action"] = "NODE_ISOLATED"
        result["sigma_star_hex"] = sigma_star.hex()[:32] + "..."
        return result
```

---

## Step 6 — FL Gradient Hash Commitment

### File: `client/fl_gradient_commit.py`

```python
"""
Blockchain-verified FL gradient integrity — Eq 3.22.
The FL module calls these functions to commit and verify gradient hashes.
"""

import hashlib
import json
from typing import Any

# ── Simulated on-chain ledger (replace with Fabric SDK calls in production) ──
_ledger: dict = {}


def commit_gradient(gradient_weights: Any, node_id: int, round_num: int) -> str:
    """
    Called by FL vehicle client BEFORE submitting gradient to aggregator.
    Stores hash on blockchain so aggregator can verify integrity.

    Eq 3.22: Accept(Δw_i) = 1[ H_BC(Δw_i) = Hash(Δw_i) ]

    Args:
        gradient_weights: list of numpy arrays (model parameters)
        node_id:          vehicle identifier
        round_num:        FL round number

    Returns:
        commitment_hash: hex string stored on blockchain
    """
    import numpy as np
    # Serialize gradient deterministically
    if hasattr(gradient_weights, '__iter__'):
        serialized = json.dumps(
            [arr.tolist() if hasattr(arr, 'tolist') else arr
             for arr in gradient_weights],
            sort_keys=True
        ).encode()
    else:
        serialized = str(gradient_weights).encode()

    key  = f"grad_{node_id}_{round_num}"
    hash_val = hashlib.sha256(serialized).hexdigest()
    _ledger[key] = hash_val
    print(f"[BLOCKCHAIN] Committed gradient: node={node_id} round={round_num} hash={hash_val[:16]}...")
    return hash_val


def verify_gradient(gradient_weights: Any, node_id: int, round_num: int) -> bool:
    """
    Called by FL aggregator to verify gradient was not tampered with.
    Returns False if gradient was poisoned or hash mismatches.
    """
    import numpy as np
    key = f"grad_{node_id}_{round_num}"
    if key not in _ledger:
        print(f"[BLOCKCHAIN] No commitment found for node={node_id} round={round_num} — rejecting")
        return False

    if hasattr(gradient_weights, '__iter__'):
        serialized = json.dumps(
            [arr.tolist() if hasattr(arr, 'tolist') else arr
             for arr in gradient_weights],
            sort_keys=True
        ).encode()
    else:
        serialized = str(gradient_weights).encode()

    actual_hash = hashlib.sha256(serialized).hexdigest()
    expected    = _ledger[key]
    match = (actual_hash == expected)
    if not match:
        print(f"[BLOCKCHAIN] GRADIENT MISMATCH node={node_id} round={round_num} — POISONING DETECTED")
    return match
```

---

## Step 7 — Main Ingestion Pipeline

### File: `client/ingestion_pipeline.py`

```python
#!/usr/bin/env python3
"""
Main blockchain ingestion pipeline.
Reads vehicle_event.jsonl (real or mock), computes trust, runs DEBSC,
writes bc_record_{node_id}.json for each node.
"""

import json
import glob
import os
from pathlib import Path
from matd_trust import MATDEngine
from zkp_commitment import ZKPStore
from debsc import DEBSC, IsolationDecision
from pqc_mitigation import PQCMitigationEngine

OUTPUT_DIR = Path("output/bc_records")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def process_simulation_run(events_file: str, pqc_engine: PQCMitigationEngine) -> list:
    matd    = MATDEngine()
    zkp     = ZKPStore()
    debsc   = DEBSC(theta_R=0.40, lambda1=3, lambda2=6)
    records = {}

    with open(events_file) as f:
        events = [json.loads(line) for line in f if line.strip()]

    print(f"\nProcessing {len(events)} events from {Path(events_file).name}")

    for ev in events:
        node_id = ev["node_id"]
        n_fwd   = ev["packets_forwarded"]
        n_rx    = ev["packets_received"]

        # Vehicle commits to forwarded count
        zkp.vehicle_commit(node_id, n_fwd)
        # RSU independently observes (in simulation: observed = actual forwarded)
        zkp.rsu_report_observed(node_id, n_fwd)

        # MATD trust scoring
        trust_record = matd.process_event(ev)
        rep_score    = trust_record["reputation_score"]

        # ZKP verification
        zkp_valid    = zkp.verify_proof(node_id)

        # DEBSC evaluation
        decision     = debsc.evaluate(node_id, rep_score, zkp_valid)

        # Trigger PQC mitigation if isolated
        mitigation = None
        if decision == IsolationDecision.ISOLATED:
            mitigation = pqc_engine.run_isolation(node_id, zkp)
            print(f"  [ISOLATION] Node {node_id}: {mitigation.get('action')}")

        # Build blockchain record
        records[node_id] = {
            "record_id":            f"bc_{node_id:04x}",
            "node_id":              node_id,
            "zkp_valid":            zkp_valid,
            "reputation_score":     rep_score,
            "reputation_deficit":   round(1 - rep_score, 4),
            "total_interactions":   trust_record["total_interactions"],
            "matd_corrected_trust": trust_record["matd_trust"],
            "isolation_status":     decision.value,
            "debsc_triggered":      decision == IsolationDecision.ISOLATED,
            "timestamp":            ev["timestamp"],
            "mitigation":           mitigation,
        }

    return list(records.values())


def main():
    pqc_engine = PQCMitigationEngine(n_rsus=3, k_threshold=2)

    # Try real NS-3 output first, fall back to mock data
    files = (glob.glob("../ns3/output/vehicle_events/*.jsonl") or
             glob.glob("../mock_data/output/*.jsonl") or
             glob.glob("mock_data/output/*.jsonl"))

    if not files:
        print("[ERROR] No input files found. Run NS-3 or generate mock data first.")
        return

    all_records = []
    for f in files[:5]:  # process first 5 runs
        records = process_simulation_run(f, pqc_engine)
        all_records.extend(records)

    # Write output — one file per node (latest record)
    by_node = {}
    for rec in all_records:
        by_node[rec["node_id"]] = rec

    for node_id, record in by_node.items():
        out_path = OUTPUT_DIR / f"bc_record_{node_id}.json"
        with open(out_path, "w") as f:
            json.dump(record, f, indent=2)
        status = "ISOLATED" if record["debsc_triggered"] else "BENIGN"
        print(f"  [OK] Node {node_id}: rep={record['reputation_score']:.3f} "
              f"zkp={record['zkp_valid']} → {status}")

    print(f"\n[DONE] {len(by_node)} bc_record files written to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
```

---

## Step 8 — Mock Mode (No Fabric Needed)

### File: `mock_mode/run_mock_pipeline.py`

```python
#!/usr/bin/env python3
"""
Run the full blockchain pipeline in mock mode — no Hyperledger Fabric needed.
Use this to develop and test all logic before deploying to Fabric.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from ingestion_pipeline import main

if __name__ == "__main__":
    print("=== SHIELD-GH Blockchain Mock Mode ===")
    print("Running full pipeline with in-memory ledger...")
    main()
```

---

## Step 9 — Hyperledger Fabric Chaincode (Production)

### File: `chaincode/debsc/debsc.js`

Deploy this after mock mode is validated.

```javascript
'use strict';
const { Contract } = require('fabric-contract-api');
const crypto       = require('crypto');

class DESBCContract extends Contract {

    // Submit a vehicle forwarding event to the ledger
    async SubmitForwardingEvent(ctx, nodeId, timestamp, nFwd, nRx, speedKmh, rsuId, isHandoff) {
        const nDrop   = parseInt(nRx) - parseInt(nFwd);
        const speed   = parseFloat(speedKmh);
        const rawTrust= (1.0 + parseInt(nFwd)) / (1.0 + parseInt(nFwd) + 1.0 + nDrop);
        const penalty = Math.exp(-0.010 * (speed/3.6) * 1.0);
        const matdTrust = rawTrust * penalty;

        // Get existing history
        const histKey  = `HISTORY_${nodeId}`;
        const histBytes= await ctx.stub.getState(histKey);
        const history  = histBytes.length > 0 ? JSON.parse(histBytes.toString()) : [];
        history.push(matdTrust);
        await ctx.stub.putState(histKey, Buffer.from(JSON.stringify(history)));

        // Compute reputation (Eq 3.18)
        const reputation = history.reduce((a,b)=>a+b, 0) / history.length;

        // Retrieve ZKP commitment
        const zkpKey   = `ZKP_${nodeId}`;
        const zkpBytes = await ctx.stub.getState(zkpKey);
        const zkpData  = zkpBytes.length > 0 ? JSON.parse(zkpBytes.toString()) : null;
        const zkpValid = zkpData ? Math.abs(zkpData.committed - parseInt(nFwd)) / Math.max(parseInt(nFwd),1) <= 0.05 : true;

        // DEBSC evaluation (Eq 3.19)
        const deficit  = 1 - reputation;
        const isolated = (deficit > 0.40) && !zkpValid;

        const record = { nodeId, timestamp, matdTrust, reputation,
                         reputationDeficit: deficit, zkpValid, isolated,
                         totalInteractions: history.length };
        await ctx.stub.putState(`RECORD_${nodeId}`, Buffer.from(JSON.stringify(record)));
        return JSON.stringify(record);
    }

    // Store ZKP commitment from vehicle
    async CommitForwardingProof(ctx, nodeId, committedNFwd) {
        const key = `ZKP_${nodeId}`;
        await ctx.stub.putState(key, Buffer.from(JSON.stringify({
            committed: parseInt(committedNFwd),
            timestamp: new Date().toISOString()
        })));
        return 'OK';
    }

    // Store FL gradient hash commitment (Eq 3.22)
    async CommitGradient(ctx, nodeId, roundNum, gradientHash) {
        const key = `GRAD_${nodeId}_${roundNum}`;
        await ctx.stub.putState(key, Buffer.from(JSON.stringify({
            hash: gradientHash, timestamp: new Date().toISOString()
        })));
        return 'OK';
    }

    // Verify FL gradient (called by FL aggregator)
    async VerifyGradient(ctx, nodeId, roundNum, receivedHash) {
        const key  = `GRAD_${nodeId}_${roundNum}`;
        const data = await ctx.stub.getState(key);
        if (data.length === 0) return JSON.stringify({ valid: false, reason: 'no_commitment' });
        const stored = JSON.parse(data.toString());
        return JSON.stringify({ valid: stored.hash === receivedHash });
    }

    // Query latest record for a node
    async GetRecord(ctx, nodeId) {
        const data = await ctx.stub.getState(`RECORD_${nodeId}`);
        return data.length > 0 ? data.toString() : JSON.stringify(null);
    }
}

module.exports = { contracts: [DESBCContract] };
```

---

## Completion Checklist

- [ ] `mock_mode/run_mock_pipeline.py` runs without errors on mock data from Part 1
- [ ] MATD trust scores computed correctly: compare Eq 3.16–3.18 output manually for 3–4 cases
- [ ] DEBSC correctly blocks false positives: a handoff event should give `FALSE_POSITIVE_BLOCKED`, not `ISOLATED`
- [ ] DEBSC correctly isolates attacker: a node with PDR=0.47 and ZKP failure should give `ISOLATED`
- [ ] PQC: `dilithium_sign` + `dilithium_verify` round-trip passes
- [ ] PQC: `kyber_encapsulate` + `kyber_decapsulate` round-trip gives same session key
- [ ] FL gradient commit/verify round-trip passes; tampered gradient returns `False`
- [ ] `output/bc_records/bc_record_{id}.json` files match the shared output schema

---

## Files to Hand Off

| File | Used By |
|------|---------|
| `output/bc_records/bc_record_{id}.json` | FL module, LLM module, Fusion Engine |
| `client/fl_gradient_commit.py` | FL module (import directly) |
| `client/pqc_mitigation.py` | Integration / Fusion Engine |
