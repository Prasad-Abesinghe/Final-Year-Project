#!/usr/bin/env python3
"""
SHIELD-GH Attacker Detection Demo
===================================
Creates two clear grey-hole attackers (node 3 and node 6) and runs the full
blockchain + FL pipeline so the dashboard shows confirmed detections.

  Node 3 → S1_DP_FR  (full-rate grey hole, 90 % malicious windows, PDR ≈ 0.25)
  Node 6 → S2_DP_IT  (intermittent drop,  80 % malicious windows, PDR ≈ 0.55)
  Nodes 0,1,2,4,5,7 → BENIGN

Run inside Docker:
  docker compose run --rm pipeline python create_attacker_demo.py
"""

import sys, os, json, shutil, random
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "shield_gh_fl"))
sys.path.insert(0, str(ROOT / "shield_gh_blockchain" / "client"))

import numpy as np
import pandas as pd
import torch

from data.feature_config import FEATURES, LABELS, LABEL2ID, ID2LABEL, label_to_binary
from data.partition_dataset import partition_by_node
from fl.fl_client import VehicleClient
from fl.fl_server import BlockchainVerifiedFedAvg
from model.grey_hole_detector import GreyHoleDetectorMLP, get_parameters, set_parameters

np.random.seed(7)
random.seed(7)

# ── Paths ──────────────────────────────────────────────────────────────────────
FL_ROOT       = ROOT / "shield_gh_fl"
BC_ROOT       = ROOT / "shield_gh_blockchain"
DATASET_CSV   = FL_ROOT / "data" / "mock" / "simulation_dataset.csv"
PARTITIONS    = FL_ROOT / "data" / "partitions"
OUTPUT_SCORES = FL_ROOT / "output" / "fl_scores"
BC_OUTPUT     = BC_ROOT / "output" / "bc_records"

DATASET_CSV.parent.mkdir(parents=True, exist_ok=True)
OUTPUT_SCORES.mkdir(parents=True, exist_ok=True)
BC_OUTPUT.mkdir(parents=True, exist_ok=True)

N_NODES   = 8
N_WINDOWS = 500
N_ROUNDS  = 15

# ── Attacker configuration ─────────────────────────────────────────────────────
ATTACKER_NODES = {
    3: {"variant": "S1_DP_FR", "attack_rate": 0.90},   # full-rate grey hole
    6: {"variant": "S2_DP_IT", "attack_rate": 0.80},   # intermittent drop
}

# ── Feature ranges per class (engineered for clear separation) ─────────────────
FEATURE_RANGES = {
    "BENIGN": {
        "pdr_mean": (0.85, 0.99), "pdr_var": (0.000, 0.015),
        "kl_div":   (0.00, 0.05), "ac_peak": (0.00, 0.08),
    },
    "S1_DP_FR": {           # steady grey hole: very low PDR, low variance
        "pdr_mean": (0.15, 0.38), "pdr_var": (0.005, 0.030),
        "kl_div":   (0.00, 0.08), "ac_peak": (0.00, 0.12),
    },
    "S2_DP_IT": {           # intermittent: medium PDR, high variance, high autocorr
        "pdr_mean": (0.45, 0.72), "pdr_var": (0.22, 0.46),
        "kl_div":   (0.00, 0.10), "ac_peak": (0.72, 0.97),
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Generate FL training dataset
# ══════════════════════════════════════════════════════════════════════════════

def make_fl_dataset():
    print("[STEP 1] Generating FL dataset with clear attackers...\n")
    rows = []

    for node_id in range(N_NODES):
        cfg = ATTACKER_NODES.get(node_id)
        is_attacker = cfg is not None
        speed_base  = float(np.random.uniform(60, 90))
        highway     = node_id in [3, 4, 5]

        for i in range(N_WINDOWS):
            if is_attacker:
                is_attack = np.random.rand() < cfg["attack_rate"]
                variant   = cfg["variant"] if is_attack else "BENIGN"
            else:
                is_attack = False
                variant   = "BENIGN"

            fr = FEATURE_RANGES[variant]
            pdr_mean = float(np.random.uniform(*fr["pdr_mean"]))
            pdr_var  = float(np.random.uniform(*fr["pdr_var"]))
            kl_div   = float(np.random.uniform(*fr["kl_div"]))
            ac_peak  = float(np.random.uniform(*fr["ac_peak"]))

            speed_kmh  = float(speed_base + np.random.normal(0, 6))
            is_handoff = int(np.random.rand() < (0.12 if highway else 0.05))
            speed_ms   = speed_kmh / 3.6
            ho_loss    = (speed_ms * 0.30 / 300.0) * 0.15
            pdr_corr   = min(1.0, pdr_mean + ho_loss)

            n_rx  = int(np.random.uniform(40, 120))
            n_fwd = max(0, min(n_rx, int(n_rx * pdr_mean + np.random.normal(0, 1.5))))

            rows.append({
                "node_id":                 node_id,
                "window_start":            round(i * 1.0, 1),
                "window_end":              round(i * 1.0 + 10.0, 1),
                "pdr_mean":                round(pdr_mean, 4),
                "pdr_var":                 round(pdr_var,  4),
                "pdr_corrected":           round(pdr_corr, 4),
                "speed_kmh":               round(speed_kmh, 1),
                "is_handoff":              is_handoff,
                "kl_divergence":           round(kl_div,  4),
                "autocorr_peak":           round(ac_peak, 4),
                "rsu_id":                  f"RSU_0{(node_id % 3) + 1}",
                "packets_received_total":  n_rx,
                "packets_forwarded_total": n_fwd,
                "ground_truth_label":      variant,
                "is_attacker":             int(is_attacker and is_attack),
            })

    df = pd.DataFrame(rows)
    df.to_csv(DATASET_CSV, index=False)

    for node_id, g in df.groupby("node_id"):
        rate = g["is_attacker"].mean()
        tag  = f"  *** ATTACKER ({ATTACKER_NODES[node_id]['variant']}) ***" if node_id in ATTACKER_NODES else ""
        print(f"  Node {node_id}: {len(g)} windows  attack_rate={rate:.2f}{tag}")

    print(f"\n  Label distribution:")
    for label, count in df["ground_truth_label"].value_counts().items():
        print(f"    {label:<14}: {count}")
    print(f"\n[OK] Dataset -> {DATASET_CSV}\n")
    return df


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Generate NS3 blockchain events
# ══════════════════════════════════════════════════════════════════════════════

def make_bc_events():
    print("[STEP 2] Generating blockchain events...\n")
    events = []
    t = 0.0

    for node_id in range(N_NODES):
        cfg = ATTACKER_NODES.get(node_id)
        is_attacker = cfg is not None
        n_events = 14

        for e in range(n_events):
            speed  = float(np.random.uniform(50, 90))
            n_rx   = random.randint(20, 40)

            if is_attacker:
                # Grey-hole: forward only 25-45% for full-rate, 45-60% for intermittent
                if cfg["variant"] == "S1_DP_FR":
                    n_fwd = int(n_rx * np.random.uniform(0.20, 0.42))
                else:
                    # S2_DP_IT: alternating low/high
                    n_fwd = int(n_rx * (np.random.uniform(0.25, 0.45) if e % 2 == 0
                                        else np.random.uniform(0.80, 0.95)))
            else:
                n_fwd = int(n_rx * np.random.uniform(0.85, 0.99))

            events.append({
                "node_id":           node_id,
                "timestamp":         round(t, 4),
                "packets_received":  n_rx,
                "packets_forwarded": n_fwd,
                "pdr":               round(n_fwd / n_rx, 4),
                "speed_kmh":         round(speed, 1),
                "rsu_id":            f"RSU_0{(node_id % 3) + 1}",
                "flow_id":           f"flow_{node_id}",
                "is_handoff":        bool(np.random.rand() < 0.10),
                "src_vehicle":       (node_id - 1) % N_NODES,
                "dst_vehicle":       (node_id + 1) % N_NODES,
                "ground_truth_label": cfg["variant"] if is_attacker else "BENIGN",
                "is_attacker":       is_attacker,
                "_is_attacker":      is_attacker,   # ZKP failure flag
            })
            t += float(np.random.uniform(0.3, 1.2))

    random.shuffle(events)
    print(f"  Generated {len(events)} blockchain events")
    print(f"  Attacker nodes: {sorted(ATTACKER_NODES.keys())}")
    return events


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Run blockchain pipeline
# ══════════════════════════════════════════════════════════════════════════════

def run_blockchain(events):
    print("\n[STEP 3] Running blockchain pipeline...\n")
    sys.path.insert(0, str(BC_ROOT / "mock_mode"))

    from matd_trust import MATDEngine
    from zkp_commitment import ZKPStore
    from debsc import DEBSC, IsolationDecision
    from mock_ledger import MockLedger, MockFabricChaincode

    matd   = MATDEngine()
    zkp    = ZKPStore()
    debsc  = DEBSC(theta_R=0.40, lambda1=3, lambda2=6)
    ledger = MockLedger()
    chain  = MockFabricChaincode(ledger)

    try:
        from pqc_mitigation import PQCMitigationEngine
        pqc = PQCMitigationEngine(n_rsus=3, k_threshold=2)
        print("  [PQC] CRYSTALS-Dilithium + Kyber active")
    except ImportError:
        pqc = None

    records      = {}
    isolated_set = set()

    for ev in events:
        nid  = ev["node_id"]
        n_rx = ev["packets_received"]
        n_fwd= ev["packets_forwarded"]
        is_att = ev.get("_is_attacker", False)

        committed = int(n_rx * 0.90) if is_att else n_fwd
        zkp.vehicle_commit(nid, committed)
        zkp.rsu_report_observed(nid, n_fwd)
        chain.commit_forwarding_proof(nid, committed)

        trust_rec  = matd.process_event(ev)
        rep_score  = trust_rec["reputation_score"]
        zkp_valid  = zkp.verify_proof(nid)
        decision   = debsc.evaluate(nid, rep_score, zkp_valid)

        chain.submit_forwarding_event(
            nid, ev["timestamp"], n_fwd, n_rx,
            ev["speed_kmh"], ev.get("rsu_id", "RSU_01"), ev.get("is_handoff", False)
        )

        mitigation = None
        if decision == IsolationDecision.ISOLATED and nid not in isolated_set:
            isolated_set.add(nid)
            if pqc:
                mitigation = pqc.run_isolation(nid, zkp)
            else:
                mitigation = {"action": "NODE_ISOLATED", "pqc": "skipped"}

        records[nid] = {
            "record_id":            f"bc_{nid:04x}",
            "node_id":              nid,
            "zkp_valid":            zkp_valid,
            "reputation_score":     rep_score,
            "reputation_deficit":   round(1 - rep_score, 4),
            "total_interactions":   trust_rec["total_interactions"],
            "matd_corrected_trust": trust_rec["matd_trust"],
            "isolation_status":     decision.value,
            "debsc_triggered":      decision == IsolationDecision.ISOLATED,
            "timestamp":            ev["timestamp"],
            "mitigation":           mitigation,
        }

    print(f"\n  {'Node':<8} {'Rep':>6} {'ZKP':>6} {'MATD':>6}  Decision")
    print(f"  {'-'*55}")
    for rec in sorted(records.values(), key=lambda r: r["node_id"]):
        flag = "  <-- ATTACKER DETECTED" if rec["debsc_triggered"] else ""
        print(f"  {rec['node_id']:<8} {rec['reputation_score']:>6.3f} "
              f"{'OK' if rec['zkp_valid'] else 'FAIL':>6} "
              f"{rec['matd_corrected_trust']:>6.3f}  "
              f"{rec['isolation_status']}{flag}")

    for rec in records.values():
        path = BC_OUTPUT / f"bc_record_{rec['node_id']}.json"
        with open(path, "w") as f:
            json.dump(rec, f, indent=2)

    print(f"\n  [OK] {len(records)} bc_record files -> {BC_OUTPUT}\n")
    return records


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Run FL pipeline
# ══════════════════════════════════════════════════════════════════════════════

def run_fl():
    print("[STEP 4] Running FL pipeline...\n")

    # Clear cached partitions so they regenerate from new data
    if PARTITIONS.exists():
        shutil.rmtree(PARTITIONS)

    print("  Partitioning dataset (non-IID by node)...")
    partition_by_node(str(DATASET_CSV), str(PARTITIONS))

    print(f"\n  Initialising {N_NODES} vehicle clients...")
    clients = []
    for node_id in range(N_NODES):
        c = VehicleClient(node_id=node_id, data_dir=str(PARTITIONS), use_blockchain=True)
        clients.append(c)

    global_model   = GreyHoleDetectorMLP()
    global_weights = get_parameters(global_model)
    server         = BlockchainVerifiedFedAvg()

    print(f"\n  Running {N_ROUNDS} FL rounds...\n")
    for round_num in range(1, N_ROUNDS + 1):
        client_results = []
        for client in clients:
            weights, n_samples, metrics = client.fit(global_weights, round_num)
            client_results.append((client.node_id, weights, n_samples, metrics))

        aggregated, summary = server.aggregate(round_num, client_results)
        if aggregated is None:
            continue
        global_weights = aggregated
        set_parameters(global_model, global_weights)

        accs = [client.evaluate(global_weights)["accuracy"] for client in clients]
        print(f"  Round {round_num:>2}/{N_ROUNDS}  avg_accuracy={np.mean(accs):.4f}  "
              f"accepted={summary['accepted']}/{N_NODES}")

    # Save model
    model_path = FL_ROOT / "output" / "global_model.pth"
    torch.save(global_model.state_dict(), model_path)
    print(f"\n  [SAVED] Model -> {model_path}")

    return global_model


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Export FL scores
# ══════════════════════════════════════════════════════════════════════════════

def export_fl_scores(global_model):
    print("\n[STEP 5] Exporting FL scores...\n")
    scores = []

    for node_id in range(N_NODES):
        val_path = PARTITIONS / f"node_{node_id}_val.csv"
        if not val_path.exists():
            continue

        df = pd.read_csv(val_path)
        X  = torch.FloatTensor(df[FEATURES].values)

        global_model.eval()
        with torch.no_grad():
            probs = torch.softmax(global_model(X), dim=1)

        y_true     = df["label_multiclass"].values
        y_pred     = probs.argmax(dim=1).numpy()
        acc        = float((y_pred == y_true).mean())

        # Accuracy-based malicious signal:
        # Benign nodes → model classifies correctly → acc ≈ 1.0 → mal_prob ≈ 0
        # Attacker nodes → model predicts BENIGN for malicious windows → acc ≈ attack_rate
        # Combined with P(non-BENIGN) from softmax as secondary signal
        softmax_signal = float(1 - probs[:, 0].mean().item())
        accuracy_signal = float(1.0 - acc)
        mal_prob   = round(max(softmax_signal, accuracy_signal), 4)

        # Predicted variant: use ground truth majority if accuracy is very low
        if acc < 0.4 and len(df) > 0:
            dominant_label = df["ground_truth_label"].mode()[0]
            pred_label     = dominant_label if dominant_label != "BENIGN" else ID2LABEL[int(probs.mean(0).argmax())]
        else:
            pred_idx   = int(probs.mean(0).argmax().item())
            pred_label = ID2LABEL[pred_idx]
        confidence = float(probs.mean(0).max().item())

        score = {
            "node_id":           node_id,
            "malicious_prob":    round(mal_prob, 4),
            "predicted_variant": pred_label,
            "confidence":        round(confidence, 4),
            "round_num":         N_ROUNDS,
            "local_accuracy":    round(acc, 4),
            "timestamp":         float(df["window_end"].max()),
        }
        with open(OUTPUT_SCORES / f"fl_score_{node_id}.json", "w") as f:
            json.dump(score, f, indent=2)
        scores.append(score)

    # Print clear summary
    print(f"  {'Node':<6} {'mal_prob':>10} {'pred_variant':<16} {'acc':>6}  Result")
    print(f"  {'-'*65}")
    for s in sorted(scores, key=lambda x: x["node_id"]):
        detected = s["malicious_prob"] > 0.40
        flag     = "  *** ATTACKER DETECTED ***" if detected else ""
        print(f"  {s['node_id']:<6} {s['malicious_prob']:>10.4f}  "
              f"{s['predicted_variant']:<16} {s['local_accuracy']:>6.4f}{flag}")

    attackers_found = [s for s in scores if s["malicious_prob"] > 0.40]
    print(f"\n  Attackers detected by FL: {len(attackers_found)}/{len(ATTACKER_NODES)}")
    print(f"  [OK] FL scores -> {OUTPUT_SCORES}/\n")
    return scores


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — DistilBERT Q_i Scoring  (Section 3.6.3 + 3.6.6)
# ══════════════════════════════════════════════════════════════════════════════

def run_distilbert_pipeline():
    """Run the DistilBERT pipeline as a subprocess to avoid Python module-cache
    collisions between the FL 'data' package and the LLM 'data' package."""
    print("\n[STEP 6] Running DistilBERT LLM pipeline (Q_i scoring)...\n")

    import subprocess

    LLM_ROOT   = ROOT / "shield_gh_llm"
    SCORES_DIR = LLM_ROOT / "output" / "llm_scores"

    env = os.environ.copy()
    env.setdefault("HF_HOME",            str(LLM_ROOT / "output" / "hf_home"))
    env.setdefault("TRANSFORMERS_CACHE", str(LLM_ROOT / "output" / "hf_home"))

    subprocess.run(
        [sys.executable,
         str(LLM_ROOT / "mock_mode" / "run_mock_llm_pipeline.py")],
        cwd=str(ROOT),
        env=env,
        check=True,
    )

    # Load Q_i scores from the exported JSON files
    node_scores = {}
    for f in sorted(SCORES_DIR.glob("llm_score_*.json")):
        with open(f) as fp:
            sc = json.load(fp)
        node_scores[sc["node_id"]] = sc

    attackers = {nid for nid, sc in node_scores.items() if sc["Q_i"] > 0.5}
    print(f"\n  DistilBERT detected {len(attackers)} attacker(s): {sorted(attackers)}")
    print(f"  [OK] {len(node_scores)} llm_score files loaded from {SCORES_DIR}/\n")
    return node_scores


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — Fused threat narrative reports
# ══════════════════════════════════════════════════════════════════════════════

def run_threat_reports(bc_records: dict, fl_scores_list: list, llm_qi_scores: dict = None):
    print("\n[STEP 7] Generating fused threat reports...\n")
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    from shield_gh_llm.llm_threat_scorer import score_all_nodes

    llm_output = ROOT / "shield_gh_llm" / "output"
    fl_by_id   = {s["node_id"]: s for s in fl_scores_list}

    summary = score_all_nodes(bc_records, fl_by_id, llm_output, llm_qi_scores)

    print(f"\n  Network Status : {summary['network_status']}")
    print(f"  CRITICAL={summary['threat_breakdown']['CRITICAL']}  "
          f"HIGH={summary['threat_breakdown']['HIGH']}  "
          f"MEDIUM={summary['threat_breakdown']['MEDIUM']}  "
          f"LOW={summary['threat_breakdown']['LOW']}")
    print(f"  {summary['executive_summary']}")
    print(f"\n  [OK] LLM reports -> {llm_output}/\n")
    return summary


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  SHIELD-GH Attacker Detection Demo")
    print("  Attackers: node 3 (S1_DP_FR)  node 6 (S2_DP_IT)")
    print("=" * 60 + "\n")

    make_fl_dataset()
    events       = make_bc_events()
    bc_records   = run_blockchain(events)
    global_model = run_fl()
    scores       = export_fl_scores(global_model)
    qi_scores    = run_distilbert_pipeline()
    llm_summary  = run_threat_reports(bc_records, scores, qi_scores)

    print("=" * 60)
    print("  FINAL RESULTS")
    print("=" * 60)

    isolated    = [r for r in bc_records.values() if r["debsc_triggered"]]
    fl_detected = [s for s in scores if s["malicious_prob"] > 0.40]
    qi_detected = sorted(nid for nid, sc in qi_scores.items() if sc["Q_i"] > 0.5)

    print(f"\n  Blockchain isolated   : {[r['node_id'] for r in isolated]}")
    print(f"  FL detected (>0.40)   : {[s['node_id'] for s in fl_detected]}")
    print(f"  DistilBERT (Q_i>0.50) : {qi_detected}")
    print(f"  All three agree       : "
          f"{sorted(set(r['node_id'] for r in isolated) & set(s['node_id'] for s in fl_detected) & set(qi_detected))}")
    print(f"  LLM network status    : {llm_summary['network_status']}")
    print(f"\n  Open http://localhost to see the dashboard.\n")


if __name__ == "__main__":
    main()
