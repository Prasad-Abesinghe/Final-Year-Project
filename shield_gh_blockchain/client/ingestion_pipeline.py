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
        zkp_valid = zkp.verify_proof(node_id)

        # DEBSC evaluation
        decision = debsc.evaluate(node_id, rep_score, zkp_valid)

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
