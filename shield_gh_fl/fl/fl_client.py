"""
Vehicle FL Client — local training logic (Eq 3.20).
One instance per vehicle node. Trains on local data only (no raw data shared).
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import torch
import torch.nn as nn
import pandas as pd
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path

from model.grey_hole_detector import GreyHoleDetectorMLP, get_parameters, set_parameters
from data.feature_config import FEATURES, LABEL2ID
from fl.blockchain_bridge import BlockchainBridge


class VehicleClient:
    """
    Vehicle node FL client. Trains locally (Eq 3.20) and commits
    gradient hash to blockchain before returning weights (Eq 3.22).
    """

    def __init__(self, node_id: int, data_dir: str, use_blockchain: bool = True):
        self.node_id    = node_id
        self.blockchain = BlockchainBridge(node_id) if use_blockchain else None
        self.model      = GreyHoleDetectorMLP()

        train_path = Path(data_dir) / f"node_{node_id}_train.csv"
        val_path   = Path(data_dir) / f"node_{node_id}_val.csv"

        self.train_loader = self._make_loader(train_path)
        self.val_loader   = self._make_loader(val_path)
        self.n_train      = sum(len(b[0]) for b in self.train_loader)

    def _make_loader(self, csv_path: Path, batch_size: int = 32) -> DataLoader:
        df = pd.read_csv(csv_path)
        X  = torch.FloatTensor(df[FEATURES].values)
        y  = torch.LongTensor(df["label_multiclass"].values)
        return DataLoader(TensorDataset(X, y), batch_size=batch_size, shuffle=True)

    def fit(self, global_weights: list, round_num: int) -> tuple:
        """
        Eq 3.20 — Local training for 3 epochs.
        Returns (updated_weights, n_samples, metrics).
        Commits gradient hash to blockchain before returning.
        """
        set_parameters(self.model, global_weights)

        optimizer = torch.optim.Adam(self.model.parameters(), lr=1e-3, weight_decay=1e-4)
        loss_fn   = nn.CrossEntropyLoss()
        self.model.train()

        total_loss, n_batches = 0.0, 0
        for _ in range(3):
            for X_batch, y_batch in self.train_loader:
                optimizer.zero_grad()
                loss = loss_fn(self.model(X_batch), y_batch)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
                n_batches  += 1

        updated_weights = get_parameters(self.model)

        # Eq 3.22 — commit gradient hash to blockchain BEFORE returning
        if self.blockchain:
            self.blockchain.commit_gradient(updated_weights, round_num)

        metrics = {
            "node_id":    self.node_id,
            "train_loss": round(total_loss / max(n_batches, 1), 4),
        }
        return updated_weights, self.n_train, metrics

    def evaluate(self, global_weights: list) -> dict:
        """Evaluate global model on this node's local validation set."""
        set_parameters(self.model, global_weights)
        self.model.eval()

        loss_fn = nn.CrossEntropyLoss()
        total_loss = correct = total = 0

        with torch.no_grad():
            for X_batch, y_batch in self.val_loader:
                logits = self.model(X_batch)
                total_loss += loss_fn(logits, y_batch).item()
                preds       = logits.argmax(dim=1)
                correct    += (preds == y_batch).sum().item()
                total      += len(y_batch)

        return {
            "node_id":  self.node_id,
            "accuracy": round(correct / max(total, 1), 4),
            "loss":     round(total_loss / max(len(self.val_loader), 1), 4),
            "n_val":    total,
        }
