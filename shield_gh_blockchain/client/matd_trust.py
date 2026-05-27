"""
MATD Trust Scoring — Implements Eq 3.4, 3.5, 3.16, 3.17, 3.18
Mobility-Aware Trust Decay for SHIELD-GH Blockchain module.
"""

import math
from dataclasses import dataclass, field
from typing import List, Dict

# ── Calibrated constants (tune from NS-3 benign runs) ────────────────────────
LAMBDA_S    = 0.010   # mobility decay coefficient
DELTA_T     = 1.0     # observation slot duration (seconds)
RSU_R       = 300.0   # RSU coverage radius (metres)
DELTA_THO   = 0.30    # average handoff transition duration (seconds)
RHO_MAX     = 0.15    # worst-case handoff loss rate (calibrated from simulation)
ALPHA_PRIOR = 1.0     # Beta distribution prior — forwarding successes
BETA_PRIOR  = 1.0     # Beta distribution prior — forwarding failures


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
        node_id   = event["node_id"]
        n_rx      = event["packets_received"]
        n_fwd     = event["packets_forwarded"]
        n_drop    = n_rx - n_fwd
        speed     = event["speed_kmh"]
        timestamp = event["timestamp"]

        raw_trust    = compute_instantaneous_trust(n_fwd, n_drop)
        matd_trust   = compute_matd_trust(n_fwd, n_drop, speed)
        pdr_raw      = n_fwd / n_rx if n_rx > 0 else 1.0
        pdr_corr     = compute_corrected_pdr(pdr_raw, speed)
        handoff_loss = compute_handoff_loss_rate(speed)

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
            "pdr_raw":            round(pdr_raw,      4),
            "pdr_corrected":      round(pdr_corr,     4),
            "handoff_loss_rate":  round(handoff_loss,  4),
            "raw_trust":          round(raw_trust,     4),
            "matd_trust":         round(matd_trust,    4),
            "reputation_score":   round(reputation,    4),
            "reputation_deficit": round(1 - reputation, 4),
            "total_interactions": len(self.histories[node_id].matd_scores),
            "speed_kmh":          speed,
            "rsu_id":             event.get("rsu_id", "RSU_01"),
            "is_handoff":         event.get("is_handoff", False),
        }
