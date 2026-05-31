# SHIELD-GH Blockchain Module Architecture

## Overview

The blockchain module forms the **Trust Layer** of SHIELD-GH, providing an immutable, tamper-proof foundation for vehicle reputation tracking, forwarding proof anchoring, and cryptographic mitigation enforcement. It sits between the vehicular data plane and the intelligence layer, acting as the ground-truth store that all other modules read from and write to.

The module implements:
- Mobility-Aware Trust Decay (MATD) and blockchain reputation scoring
- Dual-Evidence Blockchain Smart Contract (DEBSC) for graduated node isolation
- ZKP-based forwarding proof commitment and verification
- FL gradient hash commitment and verification
- Post-Quantum Cryptographic mitigation pipeline (CRYSTALS-Kyber + Dilithium)
- PQC-LKH post-quantum group re-keying

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Ledger platform | Hyperledger Fabric (permissioned, BFT consensus, RSU nodes only) |
| Chaincode language | JavaScript (Node.js, `fabric-contract-api`) |
| Python client | `hfc` / direct REST gateway calls |
| Post-quantum cryptography | `liboqs` / `oqs-python` (Open Quantum Safe) |
| ZKP commitment | SHA-256 Pedersen commitment (simulation); zk-SNARK via snarkjs/gnark in production |
| Hash functions | SHA-256 (gradient integrity, commitment binding) |
| Simulation / mock mode | File-based JSON ledger (`mock_ledger.py`) |

---

## Module Directory Structure

```
shield_gh_blockchain/
├── chaincode/
│   ├── debsc/
│   │   └── debsc.js              # Hyperledger Fabric chaincode
│   └── fl_integrity/
│       └── fl_integrity.js       # FL gradient integrity chaincode
├── client/
│   ├── debsc.py                  # Python mirror of DEBSC logic (Eq 3.12–3.19)
│   ├── matd_trust.py             # MATD trust scoring (Eq 3.4–3.18)
│   ├── zkp_commitment.py         # ZKP forwarding proofs (Eq 3.29–3.30)
│   ├── pqc_mitigation.py         # CRYSTALS-Kyber + Dilithium (Eq 3.25–3.33)
│   ├── pqc_lkh.py                # Post-quantum LKH group re-keying (Eq 3.34–3.36)
│   ├── fl_gradient_commit.py     # Gradient hash commitment interface
│   ├── ingestion_pipeline.py     # Main event ingestion + pipeline orchestration
│   └── oqs.py                    # OQS wrapper helpers
└── mock_mode/
    ├── mock_ledger.py            # File-based ledger for standalone simulation
    └── run_mock_pipeline.py      # End-to-end pipeline runner (no Fabric required)
```

---

## Architecture Layers

### 1. Hyperledger Fabric Ledger

The ledger is maintained exclusively by RSU nodes using BFT consensus. The SDN controller has **read-only** access and cannot write records or trigger mitigation. This architectural isolation prevents a compromised controller from manipulating the reputation store.

Key ledger state entries:

| Key pattern | Content |
|-------------|---------|
| `HISTORY_{nodeId}` | Array of all MATD trust scores across RSU interactions |
| `RECORD_{nodeId}` | Latest computed record (trust, reputation, ZKP status, isolation flag) |
| `ZKP_{nodeId}` | Committed forwarded-packet count from vehicle (Eq 3.29) |
| `GRAD_{nodeId}_{round}` | SHA-256 hash of FL gradient update pre-submitted by vehicle |

### 2. DEBSC Chaincode (`chaincode/debsc/debsc.js`)

The on-chain smart contract implements the complete trust + isolation pipeline each time a forwarding event is submitted.

**Key methods:**

- `SubmitForwardingEvent(ctx, nodeId, timestamp, nFwd, nRx, speedKmh, rsuId, isHandoff)` — Computes MATD trust (Eq 3.17), updates reputation history (Eq 3.18), retrieves ZKP commitment, evaluates the dual-gate isolation condition (Eq 3.19), and writes the result to the ledger.
- `CommitForwardingProof(ctx, nodeId, committedNFwd)` — Stores the vehicle's Pedersen commitment to its forwarded count (Eq 3.29).
- `CommitGradient(ctx, nodeId, roundNum, gradientHash)` — Stores the FL gradient hash before transmission to the aggregator (Eq 3.22).
- `VerifyGradient(ctx, nodeId, roundNum, receivedHash)` — Called by the FL aggregator to confirm hash integrity (Eq 3.22).
- `GetRecord(ctx, nodeId)` / `GetHistory(ctx, nodeId)` — Query interfaces for the intelligence layer and dashboard.

---

## Mathematical Formulations Implemented

### MATD — Mobility-Aware Trust Decay

**Handoff-induced loss rate (Eq 3.4):**
```
ρ_ho(v_i, t) = s_i(t) · Δt_ho / R_RSU · ρ_max
```
Parameters: `DELTA_THO = 0.30 s`, `RSU_R = 300 m`, `RHO_MAX = 0.15`

**Mobility-corrected PDR (Eq 3.5):**
```
PDR̂_i(t, W) = PDR_i(t, W) + ρ_ho(v_i, t)
```

**Beta-distribution instantaneous trust (Eq 3.16):**
```
T_i(t) = (α + n_fwd) / (α + n_fwd + β + n_drop)
```
Priors: `α = β = 1.0` (uniform Beta prior)

**MATD exponential penalty (Eq 3.17):**
```
T^mob_i(t) = T_i(t) · exp(-λ_s · s_i(t) · Δt)
```
`λ_s = 0.010`, `Δt = 1.0 s`

**Blockchain reputation score (Eq 3.18):**
```
R_i(t) = (1 / |H_i|) · Σ_{h ∈ H_i} T^mob_i(h)
```
Aggregates all MATD scores across the full history on the append-only ledger.

### DEBSC — Dual-Evidence Smart Contract

**Dual-gate isolation condition (Eq 3.19):**
```
Isolate(v_i) = 1[(1 - R_i(t)) > θ_R]  ∧  1[Π_ZKP(v_i, t) = FAIL]
```
`θ_R = 0.40`

**Suspicion level (Eq 3.13):**
```
Λ_i(t) = Σ_{τ=t-W_s}^{t} 1[(1 - R_i(τ)) > θ_R]
```

**Graduated responses:**
- `Λ_i < λ_1 (=3)` → BENIGN or RATE_LIMIT
- `λ_1 ≤ Λ_i < λ_2 (=6)` → REQUIRE_ZKP_PER_BATCH
- `Λ_i ≥ λ_2` and ZKP FAIL → ISOLATED

### ZKP Forwarding Proof

**Pedersen commitment (Eq 3.29, simplified):**
```
C_i = SHA-256(n_fwd || r)   where r is a 32-byte random blinding factor
```

**Proof verification (Eq 3.30):**
ZKP FAILS when `|committed_n_fwd - observed_n_fwd| / max(observed_n_fwd, 1) > 0.05`

A grey hole attacker cannot produce a valid proof for dropped packets because its committed count will diverge from the RSU-observed count.

---

## Post-Quantum Cryptography

Implemented in `client/pqc_mitigation.py` using `oqs-python` bindings to `liboqs`.

### CRYSTALS-Kyber KEM (Eq 3.25–3.26)

Algorithm: **Kyber-768** (NIST FIPS 203 / ML-KEM)

```python
# Key generation
pk, sk = kyber_keygen()          # Kyber768 key pair

# Encapsulation (Eq 3.25)
K, ciphertext = kyber_encapsulate(pk)   # fresh session key + ciphertext

# Decapsulation (Eq 3.26)
K = kyber_decapsulate(sk, ciphertext, pk)
```

Used for session key establishment during group re-keying after node isolation.

### CRYSTALS-Dilithium Signatures (Eq 3.27–3.28)

Algorithm: **Dilithium3** (NIST FIPS 204 / ML-DSA)

```python
# Key generation
pk, sk = dilithium_keygen()

# Sign (Eq 3.27) — SDN controller signs FlowMod command
σ = dilithium_sign(sk, message)

# Verify (Eq 3.28) — OpenFlow switch verifies before installing rule
b = dilithium_verify(pk, message, σ)   # True = valid
```

All SDN isolation FlowMod commands are signed with Dilithium. An OpenFlow switch that receives a block rule verifies the signature before applying it, preventing replay or spoofed isolation commands.

### Threshold Signatures (Eq 3.31–3.33)

`(k=2, n=3)` threshold scheme — requires `k` independent RSUs to co-sign before isolation is enacted.

```python
ts = ThresholdSignatureScheme(k=2, n=3)

# Each RSU produces partial signature (Eq 3.31)
σ_j = ts.partial_sign(rsu_idx, blacklist_message)

# Combine into aggregate σ* (Eq 3.32)
σ_star = ts.combine_signatures(partial_sigs, blacklist_message)

# Verify aggregate against group public key (Eq 3.33)
valid = ts.verify_aggregate(σ_star, partial_sigs, blacklist_message)
```

Prevents a single compromised RSU from unilaterally isolating a legitimate vehicle.

---

## PQC-LKH: Post-Quantum Group Re-Keying

Implemented in `client/pqc_lkh.py` using Kyber-768 at each tree node.

Reduces re-keying from `O(N)` unicast KEM operations to `O(log N)`.

**Binary tree structure (Eq 3.34):**
Each vehicle holds Kyber key pairs for all nodes on its root-to-leaf path.

**Group key encapsulation (Eq 3.35):**
```
(K_grp, c_root) = Kyber.Enc(pk_root, m),   m ←$ {0,1}^256
```

**Path refresh on isolation (Eq 3.36):**
Only the `⌈log₂ N⌉` nodes on the isolated vehicle's path are refreshed. The updated key at each node is re-encrypted under the sibling subtree's public key and broadcast.

Example for N=8: isolating V3 requires exactly `⌈log₂ 8⌉ = 3` Kyber operations, versus 7 for naïve unicast.

---

## Full Mitigation Pipeline (Algorithm 4)

`client/pqc_mitigation.py` — `PQCMitigationEngine.run_isolation(node_id, zkp_store)`

**Step 1 — ZKP Verification:**
Retrieve ZKP proof from ledger. If valid → ABORT (false positive from channel loss). If FAIL → confirm attacker.

**Step 2 — Threshold Blacklisting:**
Collect `k` Dilithium partial signatures from independent RSUs. Combine into `σ*`. Verify against group public key. If insufficient RSUs → ABORT.

**Step 3 — SDN Flow Modification:**
Controller creates FlowMod BLOCK command, signs with Dilithium `sk_c`. OpenFlow switch verifies before installing block rule.

**Step 4 — PQC-LKH Re-Keying:**
Traverse isolated vehicle's leaf-to-root path. Refresh each node's Kyber key pair. Broadcast `⌈log₂ N⌉` Dilithium-signed update messages. Issue new `K_grp` under refreshed root key.

---

## Integration Points

| Module | Interface |
|--------|-----------|
| NS-3 simulation | Vehicle events ingested via `ingestion_pipeline.py` |
| FL module | Gradient hashes committed/verified via `fl_gradient_commit.py` and `BlockchainBridge` |
| LLM module | Reads `reputation_score`, `zkp_valid`, `debsc_triggered`, `matd_corrected_trust` fields |
| Dashboard backend | REST queries against `GetRecord` / `GetHistory` chaincode methods |
| OpenFlow switches | Receive Dilithium-signed FlowMod commands from mitigation engine |

---

## Security Properties

| Threat | Mechanism | Guarantee |
|--------|-----------|-----------|
| Reputation forgery | Append-only Hyperledger ledger | Attacker cannot erase historical dropping behaviour |
| False isolation (mobility) | MATD correction + DEBSC ZKP gate | Legitimate handoff loss cannot trigger isolation alone |
| Gradient poisoning | On-chain hash commitment pre-aggregation | Tampered gradients produce hash mismatch → rejected |
| Quantum adversary (harvest-now) | CRYSTALS-Kyber (ML-KEM) + Dilithium (ML-DSA) | IND-CCA2 / EUF-CMA under Module-LWE hardness |
| Single-RSU false isolation | (k,n)-threshold Dilithium signatures | Requires k≥2 independent RSUs to agree |
| Controller compromise | Controller excluded from BFT consensus group | Cannot write to ledger or trigger mitigation |
