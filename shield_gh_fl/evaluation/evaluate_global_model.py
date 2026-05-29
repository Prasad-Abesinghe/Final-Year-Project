#!/usr/bin/env python3
"""Evaluate trained global model — accuracy, MCC, FPR per attack variant."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import torch
import pandas as pd
import numpy as np
from sklearn.metrics import (accuracy_score, matthews_corrcoef,
                              confusion_matrix, classification_report)
from pathlib import Path

from model.grey_hole_detector import GreyHoleDetectorMLP, set_parameters
from data.feature_config import FEATURES, LABELS, ID2LABEL, label_to_binary

DATA_DIR = Path(__file__).parent.parent / "data" / "partitions"


def evaluate_all_nodes(model: GreyHoleDetectorMLP, data_dir: Path = DATA_DIR) -> dict:
    all_y_true, all_y_pred = [], []
    all_y_bin_true, all_y_bin_pred = [], []

    for node_id in range(8):
        csv = data_dir / f"node_{node_id}_val.csv"
        if not csv.exists():
            continue
        df = pd.read_csv(csv)
        X  = torch.FloatTensor(df[FEATURES].values)
        y  = df["label_multiclass"].values

        model.eval()
        with torch.no_grad():
            preds = model(X).argmax(dim=1).numpy()

        all_y_true.extend(y.tolist())
        all_y_pred.extend(preds.tolist())

        y_bin    = [label_to_binary(LABELS[i]) for i in y]
        pred_bin = [label_to_binary(LABELS[i]) for i in preds]
        all_y_bin_true.extend(y_bin)
        all_y_bin_pred.extend(pred_bin)

    acc = accuracy_score(all_y_true, all_y_pred)
    mcc = matthews_corrcoef(all_y_bin_true, all_y_bin_pred)
    cm  = confusion_matrix(all_y_bin_true, all_y_bin_pred)

    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    else:
        fpr, tpr = 0.0, 0.0

    print(f"\n=== Global Model Evaluation ===")
    print(f"Accuracy : {acc:.4f}")
    print(f"MCC      : {mcc:.4f}")
    print(f"FPR      : {fpr:.4f}")
    print(f"TPR (DR) : {tpr:.4f}")
    print(f"\n{classification_report(all_y_true, all_y_pred, target_names=LABELS, zero_division=0)}")

    return {"accuracy": acc, "mcc": mcc, "fpr": fpr, "tpr": tpr}


if __name__ == "__main__":
    model = GreyHoleDetectorMLP()
    evaluate_all_nodes(model)
