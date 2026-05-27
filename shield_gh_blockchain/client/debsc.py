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
    BENIGN                 = "BENIGN"
    RATE_LIMIT             = "RATE_LIMIT"
    REQUIRE_ZKP            = "REQUIRE_ZKP_PER_BATCH"
    ISOLATED               = "ISOLATED"
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
                 theta_R: float = 0.40,   # reputation deficit threshold
                 lambda1: int   = 3,      # rate-limit threshold
                 lambda2: int   = 6,      # ZKP-per-batch threshold
                 ws_size: int   = 10):    # suspicion window size
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
                "node_id":            nid,
                "reputation_score":   round(state.reputation_score, 4),
                "reputation_deficit": round(1 - state.reputation_score, 4),
                "suspicion_level":    sum(state.suspicion_window),
                "isolation_status":   state.isolation_status.value,
                "debsc_triggered":    state.isolation_status == IsolationDecision.ISOLATED,
            })
        return result
