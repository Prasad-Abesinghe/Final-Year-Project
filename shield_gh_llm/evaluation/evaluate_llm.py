"""
SHIELD-GH LLM — Evaluation  (Section 3.6.6)

Computes accuracy, MCC, per-variant F1, FPR, and confusion matrix
on the held-out test set. Run after training.
"""

import sys
import json
import numpy as np
from pathlib import Path

import torch
from datasets import load_from_disk
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import (
    accuracy_score, matthews_corrcoef, classification_report,
    confusion_matrix, f1_score,
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from model.model_config import LABELS, EDGE_MODEL_PATH, MAX_SEQ_LENGTH


def evaluate(
    llm_root: Path,
    model_path: str = None,
    dataset_path: str = None,
) -> dict:
    model_path   = model_path   or str(llm_root / EDGE_MODEL_PATH)
    dataset_path = dataset_path or str(llm_root / "output" / "hf_dataset")

    print(f"[Eval] Model:   {model_path}")
    print(f"[Eval] Dataset: {dataset_path}")

    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model     = AutoModelForSequenceClassification.from_pretrained(model_path)
    model.eval()

    test_ds = load_from_disk(dataset_path)["test"]
    texts   = test_ds["text"]
    y_true  = np.array(test_ds["labels"])
    y_pred  = []

    for text in texts:
        inputs = tokenizer(text, return_tensors="pt",
                           truncation=True, max_length=MAX_SEQ_LENGTH)
        with torch.no_grad():
            logits = model(**inputs).logits
        y_pred.append(int(logits.argmax().item()))

    y_pred = np.array(y_pred)

    # Binary metrics (benign vs malicious)
    y_true_bin = (y_true > 0).astype(int)
    y_pred_bin = (y_pred > 0).astype(int)
    cm_bin     = confusion_matrix(y_true_bin, y_pred_bin)
    tn, fp, fn, tp = cm_bin.ravel() if cm_bin.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    results = {
        "accuracy":          float(accuracy_score(y_true, y_pred)),
        "mcc":               float(matthews_corrcoef(y_true_bin, y_pred_bin)),
        "f1_binary":         float(f1_score(y_true_bin, y_pred_bin,
                                            average="binary", zero_division=0)),
        "fpr":               round(fpr, 4),
        "tpr_recall":        round(tpr, 4),
        "true_positives":    int(tp),
        "false_positives":   int(fp),
        "true_negatives":    int(tn),
        "false_negatives":   int(fn),
        "n_test_samples":    len(y_true),
    }

    print(f"\n{'='*50}")
    print(" LLM Evaluation Results")
    print(f"{'='*50}")
    print(f"  Accuracy:   {results['accuracy']:.4f}")
    print(f"  MCC:        {results['mcc']:.4f}")
    print(f"  F1 (binary):{results['f1_binary']:.4f}")
    print(f"  FPR:        {results['fpr']:.4f}  (target < 0.15)")
    print(f"  TPR/Recall: {results['tpr_recall']:.4f}")
    print(f"\n  Per-variant classification report:\n")
    present_ids   = sorted(set(y_true.tolist()) | set(y_pred.tolist()))
    present_names = [LABELS[i] for i in present_ids if i < len(LABELS)]
    print(classification_report(y_true, y_pred,
                                labels=present_ids,
                                target_names=present_names,
                                zero_division=0))

    # Save results
    out_path = Path(model_path) / "eval_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  [OK] Results → {out_path}")

    return results


if __name__ == "__main__":
    ROOT = Path(__file__).parent.parent.parent
    evaluate(ROOT / "shield_gh_llm")
