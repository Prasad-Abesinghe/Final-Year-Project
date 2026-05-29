"""
SHIELD-GH LLM — Event Tokenisation  (Section 3.6.3)

Converts vehicle_event.jsonl rows or simulation_dataset.csv rows into
structured text sequences that DistilBERT can classify.

Design principle: text tokens must encode the TEMPORAL PATTERN of dropping:
  S1 (full-rate)   → consistently PDR_VLOW + DROP_HEAVY tokens
  S2 (intermittent)→ alternating PDR_HIGH/PDR_VLOW tokens every ~10 s
  S3 (target-spec) → PDR_VLOW only for specific SRC_N tokens

Example output sequence (10 events, [SEP]-joined):
  NODE3 T2.9 PDR_VLOW DROP_HEAVY SPD_MED RSU2 HAND_N SRC1 RX30 FWD14 [SEP]
  NODE3 T3.9 PDR_VLOW DROP_HEAVY SPD_MED RSU2 HAND_N SRC1 RX28 FWD13 [SEP] ...
"""

import json
import pandas as pd
from pathlib import Path
from typing import List, Dict
import sys

# Allow standalone use and package import
sys.path.insert(0, str(Path(__file__).parent.parent))
from model.model_config import WINDOW_SIZE, LABEL2ID, LABELS


# ── Token helpers ──────────────────────────────────────────────────────────────

def _pdr_bucket(pdr: float) -> str:
    if pdr >= 0.90: return "PDR_HIGH"
    if pdr >= 0.75: return "PDR_MED"
    if pdr >= 0.55: return "PDR_LOW"
    return "PDR_VLOW"


def _speed_bucket(kmh: float) -> str:
    if kmh >= 80: return "SPD_FAST"
    if kmh >= 50: return "SPD_MED"
    return "SPD_SLOW"


def _drop_token(n_rx: int, n_fwd: int) -> str:
    if n_rx == 0: return "DROP_NONE"
    ratio = (n_rx - n_fwd) / n_rx
    if ratio >= 0.60: return "DROP_HEAVY"
    if ratio >= 0.30: return "DROP_MED"
    if ratio >= 0.10: return "DROP_LIGHT"
    return "DROP_NONE"


def event_to_token(ev: dict) -> str:
    """
    One vehicle event dict → one structured text token string.

    Format:
        NODE{id} T{time:.1f} {pdr_bucket} {drop_token} {spd_bucket}
        RSU{n} {HAND_Y/N} SRC{src} RX{rx} FWD{fwd}
    """
    n_rx  = int(ev.get("packets_received",  0))
    n_fwd = int(ev.get("packets_forwarded", 0))
    rsu   = str(ev.get("rsu_id", "RSU_01")).replace("RSU_0", "RSU").replace("RSU_", "RSU")
    src   = int(ev.get("src_vehicle", 0))
    hand  = "HAND_Y" if ev.get("is_handoff", False) else "HAND_N"

    return (
        f"NODE{ev['node_id']} "
        f"T{float(ev['timestamp']):.1f} "
        f"{_pdr_bucket(float(ev['pdr']))} "
        f"{_drop_token(n_rx, n_fwd)} "
        f"{_speed_bucket(float(ev['speed_kmh']))} "
        f"{rsu} {hand} SRC{src} RX{n_rx} FWD{n_fwd}"
    )


def _csv_row_to_token(row) -> str:
    """simulation_dataset.csv row → text token (used when JSONL not available)."""
    drop_r = 1.0 - float(row["pdr_mean"])
    drop_t = ("DROP_HEAVY" if drop_r >= 0.60 else
              "DROP_MED"   if drop_r >= 0.30 else
              "DROP_NONE")
    rsu = str(row["rsu_id"]).replace("RSU_0", "RSU").replace("RSU_", "RSU")
    hand = "HAND_Y" if int(row["is_handoff"]) else "HAND_N"
    kl   = float(row.get("kl_divergence", 0))
    ac   = float(row.get("autocorr_peak", 0))

    return (
        f"NODE{int(row['node_id'])} "
        f"T{float(row['window_start']):.1f} "
        f"{_pdr_bucket(float(row['pdr_mean']))} "
        f"{drop_t} "
        f"{_speed_bucket(float(row['speed_kmh']))} "
        f"{rsu} {hand} "
        f"KL{kl:.2f} AC{ac:.2f}"
    )


# ── Sequence builders ──────────────────────────────────────────────────────────

def build_sequences_from_events(events: List[dict],
                                window: int = WINDOW_SIZE) -> List[dict]:
    """
    Slide a window over events sorted by timestamp for one node.
    Each window → one text sequence. Label = last event's ground_truth_label.
    """
    if len(events) < window:
        return []
    events_sorted = sorted(events, key=lambda x: x["timestamp"])
    sequences = []
    for i in range(len(events_sorted) - window + 1):
        win     = events_sorted[i: i + window]
        text    = " [SEP] ".join(event_to_token(e) for e in win)
        label   = win[-1].get("ground_truth_label", "BENIGN")
        sequences.append({
            "text":         text,
            "label":        label,
            "label_id":     LABEL2ID.get(label, 0),
            "node_id":      win[0]["node_id"],
            "window_start": win[0]["timestamp"],
            "window_end":   win[-1]["timestamp"],
            "n_events":     window,
        })
    return sequences


def build_sequences_from_jsonl(jsonl_path: str,
                                window: int = WINDOW_SIZE) -> List[dict]:
    """Load vehicle_event.jsonl and return all sliding-window sequences."""
    by_node: Dict[int, list] = {}
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            by_node.setdefault(int(ev["node_id"]), []).append(ev)
    all_seqs = []
    for evs in by_node.values():
        all_seqs.extend(build_sequences_from_events(evs, window))
    return all_seqs


def build_dataset_from_csv(csv_path: str,
                            window: int = WINDOW_SIZE) -> List[dict]:
    """
    Build sequences from simulation_dataset.csv (FL mock dataset).
    Used when the JSONL event file is not available.
    """
    df = pd.read_csv(csv_path)
    sequences = []
    for node_id in df["node_id"].unique():
        node_df = df[df["node_id"] == node_id].sort_values("window_start").reset_index(drop=True)
        for i in range(len(node_df) - window + 1):
            win   = node_df.iloc[i: i + window]
            text  = " [SEP] ".join(_csv_row_to_token(win.iloc[j]) for j in range(window))
            label = str(win.iloc[-1]["ground_truth_label"])
            sequences.append({
                "text":         text,
                "label":        label,
                "label_id":     LABEL2ID.get(label, 0),
                "node_id":      int(node_id),
                "window_start": float(win.iloc[0]["window_start"]),
                "window_end":   float(win.iloc[-1]["window_end"]),
                "n_events":     window,
            })
    return sequences


if __name__ == "__main__":
    # Quick smoke test
    test_ev = {"node_id": 3, "timestamp": 2.96, "packets_received": 30,
               "packets_forwarded": 14, "pdr": 0.467, "speed_kmh": 72.4,
               "rsu_id": "RSU_02", "is_handoff": False, "src_vehicle": 1,
               "ground_truth_label": "S1_DP_FR"}
    print("Token:", event_to_token(test_ev))
