#!/usr/bin/env python3
"""
Run the full SHIELD-GH blockchain pipeline in mock mode.
No Hyperledger Fabric installation required.

Usage:
    python run_mock_pipeline.py                     # uses built-in synthetic events
    python run_mock_pipeline.py path/to/events.jsonl  # uses your NS-3 output
"""

import sys
import os
import json
import random
import argparse
from pathlib import Path

# Allow importing client modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from matd_trust import MATDEngine
from zkp_commitment import ZKPStore, simulate_zkp_verification
from debsc import DEBSC, IsolationDecision
from mock_ledger import MockLedger, MockFabricChaincode

OUTPUT_DIR = Path(__file__).parent.parent / "output" / "bc_records"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# -- Synthetic event generator (no NS-3 needed) -------------------------------

def generate_synthetic_events(n_benign: int = 5, n_attacker: int = 2,
                               events_per_node: int = 15) -> list:
    """
    Generate a realistic mix of benign, handoff, and attacker vehicle events.
    Used when no NS-3 / real data file is provided.
    """
    events = []
    timestamp = 0.0

    # Benign vehicles — high PDR, variable speed
    for node_id in range(1, n_benign + 1):
        for _ in range(events_per_node):
            speed    = random.uniform(40, 120)
            n_rx     = random.randint(25, 50)
            n_fwd    = int(n_rx * random.uniform(0.85, 1.0))
            is_hoff  = random.random() < 0.15
            if is_hoff:
                n_fwd = int(n_fwd * random.uniform(0.60, 0.80))  # temporary handoff dip
            events.append({
                "node_id":           node_id,
                "timestamp":         round(timestamp, 4),
                "packets_received":  n_rx,
                "packets_forwarded": n_fwd,
                "pdr":               round(n_fwd / n_rx, 4),
                "speed_kmh":         round(speed, 1),
                "rsu_id":            f"RSU_0{(node_id % 3) + 1}",
                "is_handoff":        is_hoff,
                "src_vehicle":       node_id,
                "dst_vehicle":       (node_id % n_benign) + 1,
            })
            timestamp += random.uniform(0.3, 1.2)

    # Grey-hole attacker vehicles — low PDR, commits dishonest count
    for node_id in range(100, 100 + n_attacker):
        for i in range(events_per_node):
            speed   = random.uniform(50, 90)
            n_rx    = random.randint(25, 50)
            n_fwd   = int(n_rx * random.uniform(0.30, 0.50))  # actual forwarded (low)
            events.append({
                "node_id":           node_id,
                "timestamp":         round(timestamp, 4),
                "packets_received":  n_rx,
                "packets_forwarded": n_fwd,
                "pdr":               round(n_fwd / n_rx, 4),
                "speed_kmh":         round(speed, 1),
                "rsu_id":            "RSU_02",
                "is_handoff":        False,
                "src_vehicle":       node_id,
                "dst_vehicle":       1,
                "_is_attacker":      True,       # flag for ZKP dishonesty injection
            })
            timestamp += random.uniform(0.3, 1.2)

    random.shuffle(events)
    return events


# -- Main pipeline -------------------------------------------------------------

def run_pipeline(events: list, use_pqc: bool = True) -> list:
    matd   = MATDEngine()
    zkp    = ZKPStore()
    debsc  = DEBSC(theta_R=0.40, lambda1=3, lambda2=6)
    ledger = MockLedger()
    chain  = MockFabricChaincode(ledger)

    pqc_engine = None
    if use_pqc:
        try:
            from pqc_mitigation import PQCMitigationEngine
            pqc_engine = PQCMitigationEngine(n_rsus=3, k_threshold=2)
            print("[PQC] CRYSTALS-Dilithium + Kyber loaded successfully")
        except ImportError:
            print("[PQC] oqs not installed — skipping PQC steps (pip install oqs)")

    records = {}
    isolated_nodes = set()

    print(f"\nProcessing {len(events)} events...\n")

    for ev in events:
        node_id    = ev["node_id"]
        n_fwd      = ev["packets_forwarded"]
        n_rx       = ev["packets_received"]
        is_attacker = ev.get("_is_attacker", False)

        # ZKP: attackers commit a dishonest (inflated) count
        committed_fwd = int(n_rx * 0.90) if is_attacker else n_fwd
        zkp.vehicle_commit(node_id, committed_fwd)
        zkp.rsu_report_observed(node_id, n_fwd)

        # Also reflect on mock Fabric chaincode
        chain.commit_forwarding_proof(node_id, committed_fwd)

        # MATD trust scoring
        trust_record = matd.process_event(ev)
        rep_score    = trust_record["reputation_score"]

        # ZKP verification
        zkp_valid = zkp.verify_proof(node_id)

        # DEBSC evaluation
        decision = debsc.evaluate(node_id, rep_score, zkp_valid)

        # Mirror on mock Fabric
        chain.submit_forwarding_event(
            node_id, ev["timestamp"], n_fwd, n_rx,
            ev["speed_kmh"], ev.get("rsu_id", "RSU_01"), ev.get("is_handoff", False)
        )

        # PQC mitigation on isolation
        mitigation = None
        if decision == IsolationDecision.ISOLATED and node_id not in isolated_nodes:
            isolated_nodes.add(node_id)
            if pqc_engine:
                mitigation = pqc_engine.run_isolation(node_id, zkp)
                print(f"  [ISOLATION] Node {node_id}: {mitigation.get('action')}")
            else:
                mitigation = {"action": "NODE_ISOLATED", "pqc": "skipped"}
                print(f"  [ISOLATION] Node {node_id}: isolated (PQC skipped)")

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


def write_records(records: list):
    for rec in records:
        path = OUTPUT_DIR / f"bc_record_{rec['node_id']}.json"
        with open(path, "w") as f:
            json.dump(rec, f, indent=2)

    print(f"\n{'-'*55}")
    print(f"{'Node':<8} {'Rep':>6} {'ZKP':>6} {'MATD':>6} {'Decision'}")
    print(f"{'-'*55}")
    for rec in sorted(records, key=lambda r: r["node_id"]):
        flag = " <- ATTACKER" if rec["debsc_triggered"] else ""
        print(f"{rec['node_id']:<8} {rec['reputation_score']:>6.3f} "
              f"{'OK' if rec['zkp_valid'] else 'FAIL':>6} "
              f"{rec['matd_corrected_trust']:>6.3f}  "
              f"{rec['isolation_status']}{flag}")
    print(f"{'-'*55}")
    print(f"\n[DONE] {len(records)} bc_record files -> {OUTPUT_DIR}")


def main():
    parser = argparse.ArgumentParser(description="SHIELD-GH Blockchain Mock Pipeline")
    parser.add_argument("events_file", nargs="?", help="Path to vehicle_events.jsonl")
    parser.add_argument("--no-pqc", action="store_true", help="Skip PQC steps")
    args = parser.parse_args()

    if args.events_file:
        with open(args.events_file) as f:
            events = [json.loads(line) for line in f if line.strip()]
        print(f"[INPUT] Loaded {len(events)} events from {args.events_file}")
    else:
        events = generate_synthetic_events(n_benign=5, n_attacker=2, events_per_node=12)
        print(f"[INPUT] Generated {len(events)} synthetic events (5 benign + 2 attackers)")

    print("=== SHIELD-GH Blockchain Mock Mode ===")
    records = run_pipeline(events, use_pqc=not args.no_pqc)
    write_records(records)


if __name__ == "__main__":
    main()
