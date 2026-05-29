"""
SHIELD-GH LLM — Threat Scorer  (Eq 3.23 + Eq 3.15)

Q_i(t) = softmax(LLM(x_i^(t); θ))_{malicious}
       = 1 - P(BENIGN | sequence)

Two-tier routing (Eq 3.15):
  confidence(edge) >= ε_u  →  use EDGE result
  confidence(edge) <  ε_u  →  escalate to CLOUD tier
"""

import sys
import time
import json
from pathlib import Path
from typing import Optional

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification

sys.path.insert(0, str(Path(__file__).parent.parent))
from model.model_config import (
    LABELS, ID2LABEL, MAX_SEQ_LENGTH, CLOUD_SEQ_LENGTH, EPSILON_U,
    EDGE_MODEL_PATH, CLOUD_MODEL_PATH,
)


class ThreatScorer:
    """
    Two-tier LLM threat scorer.
    Implements Eq 3.15 (edge/cloud routing) and Eq 3.23 (Q_i computation).
    """

    def __init__(
        self,
        llm_root:         Path,
        epsilon_u:        float = EPSILON_U,
    ):
        self.epsilon_u = epsilon_u
        edge_path  = str(llm_root / EDGE_MODEL_PATH)
        cloud_path = str(llm_root / CLOUD_MODEL_PATH)

        print(f"[LLM Scorer] Loading edge model from {edge_path} ...")
        self.edge_tok   = AutoTokenizer.from_pretrained(edge_path)
        self.edge_model = AutoModelForSequenceClassification.from_pretrained(edge_path)
        self.edge_model.eval()

        if Path(cloud_path).exists():
            print(f"[LLM Scorer] Loading cloud model from {cloud_path} ...")
            self.cloud_tok   = AutoTokenizer.from_pretrained(cloud_path)
            self.cloud_model = AutoModelForSequenceClassification.from_pretrained(cloud_path)
            self.cloud_model.eval()
            self._cloud_from_edge = False
        else:
            # Reuse edge model with longer context as cloud tier
            self.cloud_tok   = self.edge_tok
            self.cloud_model = self.edge_model
            self._cloud_from_edge = True

    def _infer(self, text: str, model, tokenizer, max_length: int) -> dict:
        t0     = time.time()
        inputs = tokenizer(text, return_tensors="pt",
                           truncation=True, padding=True, max_length=max_length)
        with torch.no_grad():
            logits = model(**inputs).logits
        probs   = F.softmax(logits, dim=-1).squeeze()
        latency = (time.time() - t0) * 1000
        return {"probs": probs, "latency_ms": latency}

    def score(self, text_sequence: str, node_id: int, timestamp: float = 0.0) -> dict:
        """
        Compute Q_i(t) for one text sequence.

        Returns a dict matching the llm_score_{node_id}.json schema:
          node_id, Q_i, label, confidence, tier_used, softmax_probs,
          window_events, timestamp
        """
        # Edge tier inference
        edge = self._infer(text_sequence, self.edge_model, self.edge_tok, MAX_SEQ_LENGTH)
        edge_conf = float(edge["probs"].max().item())

        # Eq 3.15 — routing
        if edge_conf >= self.epsilon_u:
            probs   = edge["probs"]
            tier    = "EDGE"
            latency = edge["latency_ms"]
        else:
            cloud = self._infer(text_sequence, self.cloud_model, self.cloud_tok, CLOUD_SEQ_LENGTH)
            probs   = cloud["probs"]
            tier    = "CLOUD"
            latency = edge["latency_ms"] + cloud["latency_ms"]

        # Eq 3.23 — Q_i = 1 - P(BENIGN)
        Q_i      = float(1.0 - probs[0].item())   # index 0 = BENIGN
        pred_idx = int(probs.argmax().item())
        label    = ID2LABEL[pred_idx]
        conf     = float(probs[pred_idx].item())

        softmax_dict = {LABELS[i]: round(float(probs[i].item()), 4)
                        for i in range(len(LABELS))}

        return {
            "node_id":       node_id,
            "Q_i":           round(Q_i, 4),
            "label":         label,
            "confidence":    round(conf, 4),
            "tier_used":     tier,
            "latency_ms":    round(latency, 2),
            "softmax_probs": softmax_dict,
            "window_events": text_sequence.count("[SEP]") + 1,
            "timestamp":     timestamp,
        }
