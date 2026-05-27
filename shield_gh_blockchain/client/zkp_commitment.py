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
                               observed_n_fwd: int,
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
