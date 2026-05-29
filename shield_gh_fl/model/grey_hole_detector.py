"""
Grey Hole Detector — PyTorch MLP for per-window classification.
Input:  7 features per window
Output: 7 class probabilities (BENIGN + 6 attack variants)
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'data'))

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from feature_config import N_FEATURES, N_CLASSES


class GreyHoleDetectorMLP(nn.Module):
    """
    Multi-layer perceptron for grey hole detection.
    Local model trained at each Flower client (Eq 3.20).
    """

    def __init__(self, n_features: int = N_FEATURES,
                 n_classes: int = N_CLASSES,
                 hidden: list = None):
        super().__init__()
        if hidden is None:
            hidden = [64, 32, 16]
        layers = []
        in_dim = n_features
        for h in hidden:
            layers += [nn.Linear(in_dim, h), nn.BatchNorm1d(h), nn.ReLU(), nn.Dropout(0.3)]
            in_dim = h
        layers.append(nn.Linear(in_dim, n_classes))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            return F.softmax(self.forward(x), dim=-1)

    def malicious_probability(self, x: torch.Tensor) -> float:
        """Returns P(malicious) = 1 - P(BENIGN) — used as ŷ_FL score."""
        proba = self.predict_proba(x)
        return float(1.0 - proba[:, 0].mean().item())


def get_parameters(model: nn.Module) -> list:
    """Extract model parameters as list of numpy arrays (Flower format)."""
    return [p.data.cpu().numpy() for p in model.parameters()]


def set_parameters(model: nn.Module, parameters: list) -> None:
    """Set model parameters from list of numpy arrays."""
    for p, w in zip(model.parameters(), parameters):
        p.data = torch.tensor(np.array(w), dtype=torch.float32)
