#!/usr/bin/env python3
"""
SHIELD-GH LLM Pipeline — Mock Mode  (Section 3.6.3 + 3.6.6)

Full pipeline on mock data (no NS-3 or GPU required):
  Step 1  Build HuggingFace training dataset from simulation_dataset.csv
  Step 2  Fine-tune DistilBERT edge model (CPU, ~5-10 min)
  Step 3  Run two-tier batch inference on all 8 nodes
  Step 4  Export llm_score_{node_id}.json
  Step 5  Evaluate accuracy, MCC, FPR on test set

Usage:
    python run_mock_llm_pipeline.py          # fast mode (150 steps)
    python run_mock_llm_pipeline.py --full   # full mode (300 steps)
"""

import sys
import os
import argparse
from pathlib import Path

# Project root on sys.path
ROOT     = Path(__file__).parent.parent.parent
LLM_ROOT = ROOT / "shield_gh_llm"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(LLM_ROOT))

# HuggingFace cache inside the llm_output volume (persists between runs)
HF_HOME = str(LLM_ROOT / "output" / "hf_home")
os.environ.setdefault("HF_HOME", HF_HOME)
os.environ.setdefault("TRANSFORMERS_CACHE", HF_HOME)

from data.build_training_data import build_hf_dataset
from model.train_edge_llm import train_edge_model
from inference.threat_scorer import ThreatScorer
from inference.batch_inference import score_all_nodes, export_scores
from evaluation.evaluate_llm import evaluate


# ── Paths ─────────────────────────────────────────────────────────────────────

DATASET_CSV  = ROOT / "shield_gh_fl" / "data" / "mock" / "simulation_dataset.csv"
HF_DS_PATH   = str(LLM_ROOT / "output" / "hf_dataset")
EDGE_PATH    = str(LLM_ROOT / "output" / "models" / "edge_llm")
SCORES_DIR   = LLM_ROOT / "output" / "llm_scores"


def ensure_dataset():
    """Generate simulation_dataset.csv if it doesn't exist yet."""
    if not DATASET_CSV.exists():
        print("[SETUP] simulation_dataset.csv not found — generating from FL module...")
        fl_data_dir = str(ROOT / "shield_gh_fl" / "data")
        if fl_data_dir not in sys.path:
            sys.path.insert(0, fl_data_dir)
        from generate_mock_dataset import main as gen_data
        gen_data()
        if not DATASET_CSV.exists():
            raise FileNotFoundError(f"Could not generate dataset at {DATASET_CSV}")
        print(f"[SETUP] Dataset ready: {DATASET_CSV}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true",
                        help="Full mode: 300 training steps (slower, more accurate)")
    args = parser.parse_args()
    fast_mode = not args.full

    print("=" * 60)
    print(" SHIELD-GH LLM Pipeline (DistilBERT Sequence Classifier)")
    print(f" Mode: {'FAST (150 steps)' if fast_mode else 'FULL (300 steps)'}")
    print("=" * 60 + "\n")

    # ── Step 1: Training data ─────────────────────────────────────────────────
    print("[STEP 1] Building training dataset...\n")
    ensure_dataset()
    build_hf_dataset(
        data_source=str(DATASET_CSV),
        output_dir=HF_DS_PATH,
        max_per_class=300 if fast_mode else 500,
    )
    print()

    # ── Step 2: Fine-tune DistilBERT ─────────────────────────────────────────
    print("[STEP 2] Fine-tuning DistilBERT edge model...\n")
    train_results = train_edge_model(
        dataset_path=HF_DS_PATH,
        output_path=EDGE_PATH,
        fast_mode=fast_mode,
    )
    print()

    # ── Step 3: Batch inference ───────────────────────────────────────────────
    print("[STEP 3] Running two-tier batch inference...\n")
    scorer      = ThreatScorer(llm_root=LLM_ROOT)
    node_scores = score_all_nodes(str(DATASET_CSV), scorer)
    export_scores(node_scores, SCORES_DIR)
    print()

    # ── Step 4: Evaluation ────────────────────────────────────────────────────
    print("[STEP 4] Evaluating model on test set...\n")
    eval_results = evaluate(LLM_ROOT, model_path=EDGE_PATH, dataset_path=HF_DS_PATH)
    print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print("=" * 60)
    print(" RESULTS")
    print("=" * 60)
    print(f"\n  Accuracy : {eval_results['accuracy']:.4f}")
    print(f"  MCC      : {eval_results['mcc']:.4f}")
    print(f"  FPR      : {eval_results['fpr']:.4f}  "
          f"({'PASS' if eval_results['fpr'] < 0.15 else 'WARN'} — target < 0.15)")
    print(f"\n  Node Q_i scores:")
    for nid, sc in sorted(node_scores.items()):
        flag = "  *** ATTACKER ***" if sc["Q_i"] > 0.5 else ""
        print(f"    Node {nid}: Q_i={sc['Q_i']:.4f}  label={sc['label']}{flag}")
    print(f"\n  [DONE] llm_score files → {SCORES_DIR}/\n")


if __name__ == "__main__":
    main()
