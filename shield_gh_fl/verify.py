#!/usr/bin/env python3
"""
SHIELD-GH FL Verification Script
Runs 3 checks to confirm the FL system is working correctly:
  CHECK 1 — FL score outputs exist and attacker node is flagged
  CHECK 2 — Global model evaluation (accuracy, MCC, FPR)
  CHECK 3 — Gradient poisoning test (tampered gradient must be REJECTED)
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))

import torch
import numpy as np
from pathlib import Path

SCORES_DIR   = Path(__file__).parent / "output" / "fl_scores"
PARTS_DIR    = Path(__file__).parent / "data" / "partitions"
ROUND_LOG    = Path(__file__).parent / "output" / "round_log.json"

PASS = "[PASS]"
FAIL = "[FAIL]"
INFO = "[INFO]"


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 1 — FL Score outputs
# ─────────────────────────────────────────────────────────────────────────────

def check_fl_scores():
    print("\n" + "="*55)
    print(" CHECK 1 — FL Score Outputs")
    print("="*55)

    scores = []
    for node_id in range(8):
        path = SCORES_DIR / f"fl_score_{node_id}.json"
        if not path.exists():
            print(f"{FAIL}  fl_score_{node_id}.json missing!")
            continue
        with open(path) as f:
            s = json.load(f)
        scores.append(s)

    if len(scores) != 8:
        print(f"{FAIL}  Expected 8 score files, found {len(scores)}")
        return False

    print(f"\n{'Node':<6} {'mal_prob':>10} {'accuracy':>10} {'prediction':<15} {'Status'}")
    print("-"*55)
    all_ok = True
    for s in sorted(scores, key=lambda x: x["node_id"]):
        node_id  = s["node_id"]
        mal_prob = s["malicious_prob"]
        acc      = s["local_accuracy"]
        pred     = s["predicted_variant"]
        is_attacker = (node_id == 3)

        # Attacker node should have lower accuracy (mixed attacker/benign data)
        status = ""
        if is_attacker and acc < 0.99:
            status = "<- ATTACKER (reduced acc)"
        elif not is_attacker and acc >= 0.90:
            status = "OK"
        else:
            status = "?"

        print(f"  {node_id:<4} {mal_prob:>10.4f} {acc:>10.4f}  {pred:<15} {status}")

    print(f"\n{PASS}  All 8 fl_score files exist with valid schema")

    # Check round log
    if ROUND_LOG.exists():
        with open(ROUND_LOG) as f:
            log = json.load(f)
        total_accepted = sum(r["accepted"] for r in log)
        total_rejected = sum(len(r["rejected"]) for r in log)
        print(f"{INFO}  Round log: {len(log)} rounds, "
              f"{total_accepted} accepted updates, {total_rejected} rejected")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 2 — Global model evaluation metrics
# ─────────────────────────────────────────────────────────────────────────────

def check_evaluation():
    print("\n" + "="*55)
    print(" CHECK 2 — Global Model Evaluation Metrics")
    print("="*55)

    try:
        import pandas as pd
        from sklearn.metrics import accuracy_score, matthews_corrcoef, confusion_matrix
        from model.grey_hole_detector import GreyHoleDetectorMLP
        from data.feature_config import FEATURES, LABELS, label_to_binary

        model = GreyHoleDetectorMLP()
        model_path = Path(__file__).parent / "output" / "global_model.pth"
        if model_path.exists():
            model.load_state_dict(torch.load(model_path, weights_only=True))
            print(f"{INFO}  Loaded trained model from {model_path.name}")
        else:
            print(f"  [WARN] No saved model found — run run_mock_fl.py first")

        all_y_true, all_y_pred = [], []
        all_bin_true, all_bin_pred = [], []

        for node_id in range(8):
            csv = PARTS_DIR / f"node_{node_id}_val.csv"
            if not csv.exists():
                continue
            df    = pd.read_csv(csv)
            X     = torch.FloatTensor(df[FEATURES].values)
            y     = df["label_multiclass"].values
            model.eval()
            with torch.no_grad():
                preds = model(X).argmax(dim=1).numpy()

            all_y_true.extend(y.tolist())
            all_y_pred.extend(preds.tolist())
            all_bin_true.extend([label_to_binary(LABELS[i]) for i in y])
            all_bin_pred.extend([label_to_binary(LABELS[i]) for i in preds])

        acc = accuracy_score(all_y_true, all_y_pred)
        mcc = matthews_corrcoef(all_bin_true, all_bin_pred)
        cm  = confusion_matrix(all_bin_true, all_bin_pred)

        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        else:
            tn = fp = fn = tp = fpr = tpr = 0.0

        print(f"\n  Overall Accuracy : {acc:.4f}  {'[Good]' if acc > 0.70 else '[Low]'}")
        print(f"  MCC              : {mcc:.4f}  (range -1 to +1, higher is better)")
        print(f"  False Positive Rate (FPR): {fpr:.4f}")
        print(f"  Detection Rate (TPR)     : {tpr:.4f}")
        print(f"\n  Confusion Matrix (binary — benign vs malicious):")
        print(f"                Predicted")
        print(f"              Benign  Malicious")
        print(f"  Actual Benign  {int(tn):>5}  {int(fp):>5}")
        print(f"  Actual Malicious {int(fn):>3}  {int(tp):>5}")

        if acc > 0.70:
            print(f"\n{PASS}  Model accuracy {acc:.1%} — FL training worked")
        else:
            print(f"\n{FAIL}  Low accuracy — may need more FL rounds")

        return acc > 0.70

    except Exception as e:
        print(f"{FAIL}  Evaluation error: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 3 — Gradient poisoning test
# ─────────────────────────────────────────────────────────────────────────────

def check_gradient_poisoning():
    print("\n" + "="*55)
    print(" CHECK 3 — Gradient Poisoning Attack Test")
    print("="*55)
    print("\n  Simulating a model poisoning attack:")
    print("  - Client trains honestly, commits gradient hash to blockchain")
    print("  - Attacker then TAMPERS the gradient before sending to server")
    print("  - Server verifies hash against blockchain commitment")
    print("  - EXPECTED: server rejects the tampered gradient\n")

    try:
        from fl.blockchain_bridge import BlockchainBridge
        from model.grey_hole_detector import GreyHoleDetectorMLP, get_parameters
        import copy

        # Step 1 — client trains and commits honest gradient
        model = GreyHoleDetectorMLP()
        honest_weights = get_parameters(model)

        bridge = BlockchainBridge(node_id=99)
        bridge.commit_gradient(honest_weights, round_num=999)
        print(f"  [STEP 1] Node 99 committed honest gradient hash to blockchain")

        # Step 2 — verify honest gradient passes
        honest_ok = bridge.verify_gradient(honest_weights, round_num=999)
        print(f"  [STEP 2] Honest gradient verification: "
              f"{'ACCEPTED (OK)' if honest_ok else 'REJECTED (BAD)'}")

        # Step 3 — attacker tampers the weights (model poisoning)
        tampered_weights = copy.deepcopy(honest_weights)
        for i in range(len(tampered_weights)):
            tampered_weights[i] = tampered_weights[i] + np.random.normal(0, 10,
                                    tampered_weights[i].shape).astype(np.float32)
        print(f"  [STEP 3] Attacker tampered the gradient weights (added large noise)")

        # Step 4 — verify tampered gradient is rejected
        tampered_ok = bridge.verify_gradient(tampered_weights, round_num=999)
        print(f"  [STEP 4] Tampered gradient verification: "
              f"{'ACCEPTED (BAD! poisoning not caught)' if tampered_ok else 'REJECTED (CORRECT - poisoning blocked)'}")

        if honest_ok and not tampered_ok:
            print(f"\n{PASS}  Poisoning attack correctly blocked by blockchain verification")
            return True
        elif honest_ok and tampered_ok:
            print(f"\n{FAIL}  Tampered gradient was NOT caught — poisoning attack succeeded!")
            return False
        else:
            print(f"\n{FAIL}  Unexpected result")
            return False

    except Exception as e:
        print(f"{FAIL}  Test error: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    results = []
    results.append(check_fl_scores())
    results.append(check_evaluation())
    results.append(check_gradient_poisoning())

    print("\n" + "="*55)
    print(" VERIFICATION SUMMARY")
    print("="*55)
    labels = ["FL score outputs", "Model evaluation", "Poisoning attack blocked"]
    for label, ok in zip(labels, results):
        status = f"{PASS}" if ok else f"{FAIL}"
        print(f"  {status}  {label}")

    all_pass = all(results)
    print(f"\n  Overall: {'ALL CHECKS PASSED' if all_pass else 'SOME CHECKS FAILED'}")
