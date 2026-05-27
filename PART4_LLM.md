# PART 4 — LLM Implementation
## SHIELD-GH · Fine-tuned Sequence Classifier · Two-Tier Edge/Cloud Detection
**Owner:** H.E. Kularathna (EG/2021/4619)
**Tools:** HuggingFace Transformers, DistilBERT, PyTorch, Python 3.10+
**Input:** `vehicle_event.jsonl` from NS-3 / mock, `bc_record_{id}.json` from Blockchain
**Output:** `llm_score_{node_id}.json` per evaluation window

---

## What This Module Does

This module implements the **semantic detection layer** of SHIELD-GH (Section 3.6.3, 3.6.6). It:

1. **Tokenises** forwarding log sequences into text — converting numeric event streams into language model input (sliding window of events → one text sequence)
2. **Fine-tunes** DistilBERT as a sequence classifier to detect grey hole attack variants from forwarding behaviour patterns
3. **Implements** the two-tier inference pipeline: edge tier (fast, less accurate) routes low-confidence cases to cloud tier (Eq 3.15)
4. **Produces** the semantic threat score `Q_i(t)` = P(malicious | sequence) for the Fusion Engine (Eq 3.23)
5. **Exports** `llm_score_{node_id}.json` consumed by the Fusion Engine

Can be developed entirely with mock data. The tokenisation format is the most critical thing to get right — the quality of text sequences determines model performance.

---

## Shared Data Contract

### Input: `vehicle_event.jsonl` (from NS-3 / mock)
```json
{"node_id": 3, "timestamp": 2.9638, "packets_received": 30,
 "packets_forwarded": 14, "pdr": 0.4667, "speed_kmh": 72.4,
 "rsu_id": "RSU_02", "is_handoff": false, "src_vehicle": 1,
 "ground_truth_label": "S1_DP_FR"}
```

### Output: `llm_score_{node_id}.json`
```json
{
  "node_id": 3,
  "Q_i": 0.8924,
  "label": "S1_DP_FR",
  "confidence": 0.8924,
  "tier_used": "EDGE",
  "softmax_probs": {
    "BENIGN": 0.1076, "S1_DP_FR": 0.7841, "S2_DP_IT": 0.0321,
    "S3_DP_TS": 0.0298, "S4_CP_FR": 0.0241, "S5_CP_IT": 0.0143, "S6_CP_TS": 0.0080
  },
  "window_events": 10,
  "timestamp": 5.1102
}
```

---

## Directory Structure to Create

```
shield_gh_llm/
├── data/
│   ├── tokenize_logs.py              # convert event JSONL → text sequences
│   ├── build_training_data.py        # build HuggingFace dataset
│   └── augment_sequences.py          # data augmentation for rare variants
├── model/
│   ├── train_edge_llm.py             # fine-tune DistilBERT (edge tier)
│   ├── train_cloud_llm.py            # fine-tune larger BERT (cloud tier, optional)
│   └── model_config.py               # model names, hyperparameters, label maps
├── inference/
│   ├── threat_scorer.py              # Qi(t) computation — Eq 3.23
│   ├── two_tier_router.py            # edge/cloud routing — Eq 3.15
│   └── batch_inference.py            # score all nodes, export JSON files
├── evaluation/
│   ├── evaluate_llm.py               # accuracy, MCC, confusion matrix
│   └── latency_benchmark.py          # measure edge vs cloud inference time
├── mock_mode/
│   ├── generate_mock_sequences.py    # generate text sequences without NS-3
│   └── run_mock_llm_pipeline.py      # full pipeline on mock data
├── output/
│   ├── llm_scores/                   # llm_score_{node_id}.json files
│   └── models/
│       ├── edge_llm/                 # saved DistilBERT edge model
│       └── cloud_llm/                # saved BERT cloud model
└── requirements.txt
```

---

## Step 1 — Environment Setup

```bash
python3 -m venv venv_llm
source venv_llm/bin/activate

pip install transformers==4.40.0 datasets==2.18.0 \
            torch torchvision accelerate evaluate \
            scikit-learn pandas numpy

# Verify
python -c "from transformers import AutoTokenizer; print('Transformers OK')"
```

### requirements.txt
```
transformers>=4.40.0
datasets>=2.18.0
torch>=2.0.0
accelerate>=0.27.0
evaluate>=0.4.0
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
```

---

## Step 2 — Model Configuration

### File: `model/model_config.py`

```python
"""
Model names, hyperparameters, and label configuration.
All other files import from here — change model here and it propagates everywhere.
"""

# ── Label definitions ──────────────────────────────────────────────────────────
LABELS = ["BENIGN", "S1_DP_FR", "S2_DP_IT", "S3_DP_TS",
          "S4_CP_FR", "S5_CP_IT", "S6_CP_TS"]
N_CLASSES = len(LABELS)
LABEL2ID  = {l: i for i, l in enumerate(LABELS)}
ID2LABEL  = {i: l for i, l in enumerate(LABELS)}

# ── Model identifiers ──────────────────────────────────────────────────────────
EDGE_MODEL_NAME   = "distilbert-base-uncased"   # fast, ~66M params — edge RSU
CLOUD_MODEL_NAME  = "bert-base-uncased"          # larger, ~110M params — cloud

# ── Paths ──────────────────────────────────────────────────────────────────────
EDGE_MODEL_PATH   = "output/models/edge_llm"
CLOUD_MODEL_PATH  = "output/models/cloud_llm"

# ── Tokenisation ───────────────────────────────────────────────────────────────
MAX_SEQ_LENGTH    = 128    # tokens per sequence (edge)
CLOUD_SEQ_LENGTH  = 256    # longer context for cloud tier
WINDOW_SIZE       = 10     # events per classification sequence

# ── Training hyperparameters ───────────────────────────────────────────────────
EDGE_LEARNING_RATE  = 2e-5
EDGE_BATCH_SIZE     = 16
EDGE_NUM_EPOCHS     = 5
EDGE_WARMUP_RATIO   = 0.1
EDGE_WEIGHT_DECAY   = 0.01

# ── Inference ─────────────────────────────────────────────────────────────────
EPSILON_U           = 0.85    # Eq 3.15 — route to cloud if edge confidence < this
```

---

## Step 3 — Tokenisation

### File: `data/tokenize_logs.py`

This is the most critical file. The text format must be expressive enough for the model to learn attack patterns.

```python
"""
Convert vehicle_event.jsonl to text sequences for LLM input.
Each sequence = WINDOW_SIZE consecutive events for one node → one classification input.

Design principle: the text must encode the temporal pattern of dropping behaviour
so the LLM can distinguish:
  - S1 (fixed-rate): consistently low PDR across all tokens
  - S2 (intermittent): alternating HIGH_PDR and LOW_PDR tokens
  - S3 (target-specific): low PDR only for specific SRC tags
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Optional
from model.model_config import WINDOW_SIZE, LABEL2ID, LABELS


def pdr_bucket(pdr: float) -> str:
    """Convert PDR to readable bucket token — helps model learn thresholds."""
    if pdr >= 0.90: return "PDR_HIGH"
    if pdr >= 0.75: return "PDR_MED"
    if pdr >= 0.55: return "PDR_LOW"
    return "PDR_VLOW"


def speed_bucket(speed_kmh: float) -> str:
    if speed_kmh >= 80: return "SPD_FAST"
    if speed_kmh >= 50: return "SPD_MED"
    return "SPD_SLOW"


def drop_count_token(n_rx: int, n_fwd: int) -> str:
    """Explicit drop count helps model detect fixed-rate pattern."""
    dropped = n_rx - n_fwd
    if n_rx == 0: return "DROP_NONE"
    ratio = dropped / n_rx
    if ratio >= 0.60: return "DROP_HEAVY"
    if ratio >= 0.30: return "DROP_MED"
    if ratio >= 0.10: return "DROP_LIGHT"
    return "DROP_NONE"


def event_to_token(ev: dict) -> str:
    """
    Convert one vehicle event dict to a structured text token string.
    Format designed to be parseable by BERT tokenizer with semantic meaning.

    Example output:
    "NODE3 T2.96 PDR_VLOW DROP_HEAVY SPD_FAST RSU2 HAND_N SRC1 RX30 FWD14"
    """
    n_rx  = ev.get("packets_received", 0)
    n_fwd = ev.get("packets_forwarded", 0)
    rsu   = ev.get("rsu_id", "RSU_01").replace("RSU_0", "RSU").replace("RSU_", "RSU")
    src   = ev.get("src_vehicle", 0)
    hand  = "HAND_Y" if ev.get("is_handoff", False) else "HAND_N"

    return (
        f"NODE{ev['node_id']} "
        f"T{ev['timestamp']:.1f} "
        f"{pdr_bucket(ev['pdr'])} "
        f"{drop_count_token(n_rx, n_fwd)} "
        f"{speed_bucket(ev['speed_kmh'])} "
        f"{rsu} "
        f"{hand} "
        f"SRC{src} "
        f"RX{n_rx} "
        f"FWD{n_fwd}"
    )


def build_sequences_from_events(events: List[dict],
                                  window: int = WINDOW_SIZE) -> List[dict]:
    """
    Slide a window over sorted events for one node and build sequences.
    Each sequence covers WINDOW events with [SEP] as delimiter.

    The label is taken from the LAST event in the window (most recent verdict).
    """
    if len(events) < window:
        return []

    events_sorted = sorted(events, key=lambda x: x["timestamp"])
    sequences     = []

    for i in range(len(events_sorted) - window + 1):
        win_evs    = events_sorted[i:i+window]
        tokens     = [event_to_token(e) for e in win_evs]
        text_seq   = " [SEP] ".join(tokens)
        label      = win_evs[-1].get("ground_truth_label", "BENIGN")
        node_id    = win_evs[0]["node_id"]

        sequences.append({
            "text":        text_seq,
            "label":       label,
            "label_id":    LABEL2ID.get(label, 0),
            "node_id":     node_id,
            "window_start":win_evs[0]["timestamp"],
            "window_end":  win_evs[-1]["timestamp"],
            "n_events":    window,
        })
    return sequences


def build_sequences_from_jsonl(jsonl_path: str,
                                window: int = WINDOW_SIZE) -> List[dict]:
    """Load a vehicle_event.jsonl file and return all sequences."""
    events_by_node: Dict[int, List] = {}
    with open(jsonl_path) as f:
        for line in f:
            ev = json.loads(line.strip())
            events_by_node.setdefault(ev["node_id"], []).append(ev)

    all_seqs = []
    for node_id, evs in events_by_node.items():
        seqs = build_sequences_from_events(evs, window)
        all_seqs.extend(seqs)
    return all_seqs


def build_dataset_from_csv(csv_path: str, window: int = WINDOW_SIZE) -> List[dict]:
    """
    Alternative: build sequences from simulation_dataset.csv
    (used when JSONL is not available but feature CSV is).
    Each row becomes a single-event token; windows are reconstructed.
    """
    df = pd.read_csv(csv_path)
    sequences = []

    for node_id in df["node_id"].unique():
        node_df = df[df["node_id"] == node_id].sort_values("window_start")
        for i in range(len(node_df) - window + 1):
            win = node_df.iloc[i:i+window]
            tokens = []
            for _, row in win.iterrows():
                drop_r = 1 - row["pdr_mean"]
                tok = (
                    f"NODE{int(row['node_id'])} "
                    f"T{row['window_start']:.1f} "
                    f"{pdr_bucket(row['pdr_mean'])} "
                    f"{'DROP_HEAVY' if drop_r>=0.60 else 'DROP_MED' if drop_r>=0.30 else 'DROP_NONE'} "
                    f"{speed_bucket(row['speed_kmh'])} "
                    f"{row['rsu_id'].replace('RSU_0','RSU')} "
                    f"{'HAND_Y' if row['is_handoff'] else 'HAND_N'} "
                    f"KL{row['kl_divergence']:.2f} "
                    f"AC{row['autocorr_peak']:.2f}"
                )
                tokens.append(tok)
            text_seq = " [SEP] ".join(tokens)
            label    = win.iloc[-1]["ground_truth_label"]
            sequences.append({
                "text": text_seq, "label": label,
                "label_id": LABEL2ID.get(label, 0),
                "node_id": node_id,
                "window_start": win.iloc[0]["window_start"],
                "window_end":   win.iloc[-1]["window_end"],
            })
    return sequences


if __name__ == "__main__":
    # Test tokenisation on a few events
    test_events = [
        {"node_id":3, "timestamp":2.96, "packets_received":30, "packets_forwarded":14,
         "pdr":0.467, "speed_kmh":72.4, "rsu_id":"RSU_02", "is_handoff":False,
         "src_vehicle":1, "ground_truth_label":"S1_DP_FR"},
        {"node_id":3, "timestamp":3.96, "packets_received":28, "packets_forwarded":13,
         "pdr":0.464, "speed_kmh":72.1, "rsu_id":"RSU_02", "is_handoff":False,
         "src_vehicle":1, "ground_truth_label":"S1_DP_FR"},
    ]
    for ev in test_events:
        print(event_to_token(ev))
```

---

## Step 4 — Build Training Dataset

### File: `data/build_training_data.py`

```python
#!/usr/bin/env python3
"""
Build HuggingFace dataset from event logs or CSV.
Handles class imbalance, train/val/test splits, and saves to disk.
"""

import json
import glob
import pandas as pd
from datasets import Dataset, DatasetDict, ClassLabel, Value, Features
from pathlib import Path
from collections import Counter
from tokenize_logs import build_sequences_from_jsonl, build_dataset_from_csv
from model.model_config import LABELS, LABEL2ID, N_CLASSES


def build_hf_dataset(data_sources: list, output_dir: str = "output/hf_dataset",
                     test_size: float = 0.15, val_size: float = 0.15) -> DatasetDict:
    """
    Load sequences from all data sources, build balanced HuggingFace DatasetDict.

    data_sources: list of file paths (.jsonl or .csv)
    """
    all_sequences = []

    for source in data_sources:
        print(f"  Loading: {source}")
        if source.endswith(".jsonl"):
            seqs = build_sequences_from_jsonl(source)
        elif source.endswith(".csv"):
            seqs = build_dataset_from_csv(source)
        else:
            continue
        all_sequences.extend(seqs)
        print(f"    → {len(seqs)} sequences")

    print(f"\nTotal sequences: {len(all_sequences)}")

    # Check class balance
    label_counts = Counter(s["label"] for s in all_sequences)
    print("Label distribution:")
    for label in LABELS:
        print(f"  {label:15s}: {label_counts.get(label, 0):5d}")

    # Upsample minority classes (simple replication)
    max_count = max(label_counts.values())
    balanced  = []
    for label in LABELS:
        label_seqs = [s for s in all_sequences if s["label"] == label]
        if not label_seqs: continue
        n_needed = max_count - len(label_seqs)
        balanced.extend(label_seqs)
        if n_needed > 0:
            # Upsample with slight jitter in numeric values
            import random, copy
            for _ in range(n_needed):
                s = copy.deepcopy(random.choice(label_seqs))
                balanced.append(s)

    print(f"\nBalanced dataset: {len(balanced)} sequences")

    # Build HuggingFace Dataset
    df = pd.DataFrame(balanced)[["text", "label_id", "node_id"]]
    df = df.rename(columns={"label_id": "labels"})
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

    # Split
    n      = len(df)
    n_test = int(n * test_size)
    n_val  = int(n * val_size)
    n_train= n - n_test - n_val

    train_df = df.iloc[:n_train]
    val_df   = df.iloc[n_train:n_train+n_val]
    test_df  = df.iloc[n_train+n_val:]

    dataset_dict = DatasetDict({
        "train": Dataset.from_pandas(train_df, preserve_index=False),
        "validation": Dataset.from_pandas(val_df, preserve_index=False),
        "test": Dataset.from_pandas(test_df, preserve_index=False),
    })
    dataset_dict.save_to_disk(output_dir)
    print(f"\n[OK] Dataset saved to {output_dir}")
    print(f"  Train: {len(train_df)}  Val: {len(val_df)}  Test: {len(test_df)}")
    return dataset_dict


if __name__ == "__main__":
    # Try real data first, fall back to mock CSV
    sources = (glob.glob("../shield_gh_ns3/output/vehicle_events/*.jsonl") or
               glob.glob("../../shield_gh_ns3/mock_data/output/*.jsonl") or
               ["../shield_gh_fl/data/mock/simulation_dataset.csv"])
    build_hf_dataset(sources)
```

---

## Step 5 — Fine-Tune Edge LLM (DistilBERT)

### File: `model/train_edge_llm.py`

```python
#!/usr/bin/env python3
"""
Fine-tune DistilBERT for grey hole attack classification.
This is the EDGE model — fast inference for RSU-side detection.
"""

import torch
import numpy as np
from pathlib import Path
from datasets import load_from_disk
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
    DataCollatorWithPadding,
)
from sklearn.metrics import accuracy_score, matthews_corrcoef, f1_score
import evaluate
import sys
sys.path.insert(0, "..")
from model.model_config import (EDGE_MODEL_NAME, EDGE_MODEL_PATH, LABELS,
                                 LABEL2ID, ID2LABEL, N_CLASSES,
                                 MAX_SEQ_LENGTH, EDGE_LEARNING_RATE,
                                 EDGE_BATCH_SIZE, EDGE_NUM_EPOCHS,
                                 EDGE_WARMUP_RATIO, EDGE_WEIGHT_DECAY)

OUTPUT_DIR = Path(EDGE_MODEL_PATH)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_and_tokenize(dataset_path: str = "output/hf_dataset"):
    tokenizer = AutoTokenizer.from_pretrained(EDGE_MODEL_NAME)

    def tokenize_fn(examples):
        return tokenizer(
            examples["text"],
            truncation=True,
            padding=False,          # DataCollator handles padding
            max_length=MAX_SEQ_LENGTH,
        )

    # Load or build dataset
    if Path(dataset_path).exists():
        dataset = load_from_disk(dataset_path)
    else:
        print(f"[WARN] Dataset not found at {dataset_path}. Run build_training_data.py first.")
        raise FileNotFoundError(dataset_path)

    tokenized = dataset.map(tokenize_fn, batched=True,
                            remove_columns=["text", "node_id"])
    return tokenized, tokenizer


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    # Binary (benign vs malicious)
    labels_bin = (labels > 0).astype(int)
    preds_bin  = (preds  > 0).astype(int)

    acc   = accuracy_score(labels, preds)
    mcc   = matthews_corrcoef(labels_bin, preds_bin)
    f1    = f1_score(labels_bin, preds_bin, average="binary", zero_division=0)
    fp    = int(((preds_bin == 1) & (labels_bin == 0)).sum())
    tn    = int(((preds_bin == 0) & (labels_bin == 0)).sum())
    fpr   = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {"accuracy": acc, "mcc": mcc, "f1": f1, "fpr": fpr}


def train_edge_model(dataset_path: str = "output/hf_dataset"):
    print(f"=== Training Edge LLM ({EDGE_MODEL_NAME}) ===")

    tokenized_dataset, tokenizer = load_and_tokenize(dataset_path)

    model = AutoModelForSequenceClassification.from_pretrained(
        EDGE_MODEL_NAME,
        num_labels=N_CLASSES,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    collator = DataCollatorWithPadding(tokenizer=tokenizer)

    args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        num_train_epochs=EDGE_NUM_EPOCHS,
        learning_rate=EDGE_LEARNING_RATE,
        per_device_train_batch_size=EDGE_BATCH_SIZE,
        per_device_eval_batch_size=EDGE_BATCH_SIZE * 2,
        weight_decay=EDGE_WEIGHT_DECAY,
        warmup_ratio=EDGE_WARMUP_RATIO,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="mcc",
        greater_is_better=True,
        logging_steps=50,
        save_total_limit=2,
        report_to="none",         # disable wandb
        dataloader_num_workers=2,
        fp16=torch.cuda.is_available(),  # use mixed precision if GPU available
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=tokenized_dataset["train"],
        eval_dataset=tokenized_dataset["validation"],
        tokenizer=tokenizer,
        data_collator=collator,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    print(f"Training on {len(tokenized_dataset['train'])} sequences...")
    trainer.train()

    # Final evaluation on test set
    test_results = trainer.evaluate(tokenized_dataset["test"])
    print(f"\n=== Test Set Results ===")
    for k, v in test_results.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")

    # Save final model
    trainer.save_model(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    print(f"\n[OK] Edge model saved to {OUTPUT_DIR}")
    return test_results


if __name__ == "__main__":
    train_edge_model()
```

---

## Step 6 — Threat Scorer (Eq 3.23)

### File: `inference/threat_scorer.py`

```python
"""
LLM Threat Scorer — implements Eq 3.23.
Q_i(t) = softmax(LLM(x_i^(t); θ))_{malicious}
"""

import torch
import torch.nn.functional as F
import json
import time
from typing import Union, List
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification

import sys
sys.path.insert(0, "..")
from model.model_config import (EDGE_MODEL_PATH, CLOUD_MODEL_PATH,
                                 LABELS, ID2LABEL, MAX_SEQ_LENGTH,
                                 CLOUD_SEQ_LENGTH, EPSILON_U)


class ThreatScorer:
    """
    Two-tier LLM threat scorer implementing Eq 3.15 and 3.23.
    """

    def __init__(self, edge_model_path: str = EDGE_MODEL_PATH,
                 cloud_model_path: str = CLOUD_MODEL_PATH,
                 epsilon_u: float = EPSILON_U):
        self.epsilon_u = epsilon_u

        print(f"[LLM] Loading edge model from {edge_model_path}...")
        self.edge_tokenizer = AutoTokenizer.from_pretrained(edge_model_path)
        self.edge_model     = AutoModelForSequenceClassification.from_pretrained(edge_model_path)
        self.edge_model.eval()

        # Cloud model: load if path exists, otherwise reuse edge model with larger context
        if Path(cloud_model_path).exists():
            print(f"[LLM] Loading cloud model from {cloud_model_path}...")
            self.cloud_tokenizer = AutoTokenizer.from_pretrained(cloud_model_path)
            self.cloud_model     = AutoModelForSequenceClassification.from_pretrained(cloud_model_path)
            self.cloud_model.eval()
        else:
            print(f"[LLM] Cloud model not found — using edge model for cloud tier too")
            self.cloud_tokenizer = self.edge_tokenizer
            self.cloud_model     = self.edge_model

    def _infer(self, text: str, model, tokenizer, max_length: int) -> dict:
        """Run one forward pass, return logits and timing."""
        t0     = time.time()
        inputs = tokenizer(text, return_tensors="pt",
                           truncation=True, padding=True,
                           max_length=max_length)
        with torch.no_grad():
            logits = model(**inputs).logits

        probs   = F.softmax(logits, dim=-1).squeeze()
        latency = (time.time() - t0) * 1000  # ms
        return {"probs": probs, "latency_ms": latency}

    def score(self, text_sequence: str, node_id: int,
              timestamp: float = 0.0) -> dict:
        """
        Eq 3.23 — Compute threat score Q_i(t).
        Eq 3.15 — Route to cloud if edge confidence < ε_u.

        Args:
            text_sequence: tokenised event sequence from tokenize_logs.py
            node_id:       vehicle identifier
            timestamp:     current simulation time

        Returns:
            dict matching llm_score_{node_id}.json schema
        """
        # Edge tier inference
        edge_out = self._infer(text_sequence, self.edge_model,
                               self.edge_tokenizer, MAX_SEQ_LENGTH)
        edge_probs = edge_out["probs"]
        edge_conf  = edge_probs.max().item()

        # Eq 3.15 — routing decision
        if edge_conf >= self.epsilon_u:
            probs    = edge_probs
            tier     = "EDGE"
            latency  = edge_out["latency_ms"]
        else:
            # Escalate to cloud tier with longer context
            cloud_out = self._infer(text_sequence, self.cloud_model,
                                    self.cloud_tokenizer, CLOUD_SEQ_LENGTH)
            probs   = cloud_out["probs"]
            tier    = "CLOUD"
            latency = edge_out["latency_ms"] + cloud_out["latency_ms"]

        # Eq 3.23 — Q_i = 1 - P(BENIGN)
        Q_i      = 1.0 - probs[0].item()   # index 0 = BENIGN
        pred_idx = probs.argmax().item()
        label    = ID2LABEL[pred_idx]
        conf     = probs[pred_idx].item()

        softmax_dict = {LABELS[i]: round(probs[i].item(), 4)
                        for i in range(len(LABELS))}

        result = {
            "node_id":      node_id,
            "Q_i":          round(Q_i, 4),
            "label":        label,
            "confidence":   round(conf, 4),
            "tier_used":    tier,
            "latency_ms":   round(latency, 2),
            "softmax_probs":softmax_dict,
            "window_events":text_sequence.count("[SEP]") + 1,
            "timestamp":    timestamp,
        }
        return result
```

---

## Step 7 — Batch Inference Over All Nodes

### File: `inference/batch_inference.py`

```python
#!/usr/bin/env python3
"""
Run LLM inference on all nodes in a simulation run and export llm_score files.
"""

import json
import glob
from pathlib import Path
from collections import defaultdict
import sys
sys.path.insert(0, "..")

from data.tokenize_logs import build_sequences_from_jsonl, build_dataset_from_csv
from inference.threat_scorer import ThreatScorer

OUTPUT_DIR = Path("output/llm_scores")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def score_all_nodes(data_source: str, scorer: ThreatScorer) -> dict:
    """
    Load sequences for all nodes from a data source, run inference,
    return per-node aggregated scores.
    """
    if data_source.endswith(".jsonl"):
        sequences = build_sequences_from_jsonl(data_source)
    else:
        sequences = build_dataset_from_csv(data_source)

    # Group sequences by node
    by_node = defaultdict(list)
    for seq in sequences:
        by_node[seq["node_id"]].append(seq)

    node_scores = {}

    for node_id, seqs in sorted(by_node.items()):
        # Score the last 5 windows (most recent behaviour)
        recent_seqs = sorted(seqs, key=lambda x: x["window_end"])[-5:]
        all_q = []

        for seq in recent_seqs:
            result = scorer.score(seq["text"], node_id, seq["window_end"])
            all_q.append(result["Q_i"])

        # Aggregate: use max Q_i (worst-case) for final score
        best_result = scorer.score(recent_seqs[-1]["text"], node_id,
                                   recent_seqs[-1]["window_end"])
        best_result["Q_i"] = round(max(all_q), 4)  # max over recent windows
        node_scores[node_id] = best_result

        print(f"  Node {node_id}: Q_i={best_result['Q_i']:.4f}  "
              f"label={best_result['label']}  tier={best_result['tier_used']}  "
              f"latency={best_result['latency_ms']:.1f}ms")

    return node_scores


def export_scores(node_scores: dict):
    for node_id, score in node_scores.items():
        out_path = OUTPUT_DIR / f"llm_score_{node_id}.json"
        with open(out_path, "w") as f:
            json.dump(score, f, indent=2)
    print(f"\n[OK] Scores written to {OUTPUT_DIR}/")


def main():
    print("=== SHIELD-GH LLM Batch Inference ===\n")

    scorer = ThreatScorer()

    # Find data source
    sources = (glob.glob("../../shield_gh_ns3/output/vehicle_events/*.jsonl") or
               glob.glob("../../shield_gh_ns3/mock_data/output/S1*.jsonl") or
               glob.glob("../../shield_gh_fl/data/mock/simulation_dataset.csv"))

    if not sources:
        print("[ERROR] No data source found. Run generate_mock_events.py first.")
        return

    source = sources[0]
    print(f"Data source: {source}\n")
    scores = score_all_nodes(source, scorer)
    export_scores(scores)


if __name__ == "__main__":
    main()
```

---

## Step 8 — Mock Pipeline (No Training Needed First)

### File: `mock_mode/run_mock_llm_pipeline.py`

```python
#!/usr/bin/env python3
"""
Run the full LLM pipeline on mock data.
Step 1: Build training dataset from mock CSV
Step 2: Fine-tune edge model (5 epochs, ~10 min on CPU)
Step 3: Run batch inference and export llm_score files
"""

import subprocess
import sys
from pathlib import Path

steps = [
    ("Build HF dataset",     "python ../data/build_training_data.py"),
    ("Train edge LLM",       "python ../model/train_edge_llm.py"),
    ("Run batch inference",  "python ../inference/batch_inference.py"),
]

print("=== SHIELD-GH LLM Mock Pipeline ===\n")
for name, cmd in steps:
    print(f"[STEP] {name}")
    print(f"  Running: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"  [FAIL] Step failed. Fix errors above and re-run.")
        sys.exit(1)
    print(f"  [OK] Done\n")

print("=== Pipeline complete ===")
print("Check output/llm_scores/ for llm_score_{id}.json files")
```

---

## Step 9 — Evaluation

### File: `evaluation/evaluate_llm.py`

```python
#!/usr/bin/env python3
"""Evaluate fine-tuned LLM: accuracy, MCC, per-variant F1, FPR."""

import torch
import numpy as np
import pandas as pd
from pathlib import Path
from datasets import load_from_disk
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import (accuracy_score, matthews_corrcoef,
                              classification_report, confusion_matrix)
import sys
sys.path.insert(0, "..")
from model.model_config import EDGE_MODEL_PATH, LABELS, MAX_SEQ_LENGTH


def evaluate(model_path: str = EDGE_MODEL_PATH,
             dataset_path: str = "output/hf_dataset"):
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model     = AutoModelForSequenceClassification.from_pretrained(model_path)
    model.eval()

    dataset   = load_from_disk(dataset_path)["test"]
    texts     = dataset["text"]
    y_true    = dataset["labels"]
    y_pred    = []

    for text in texts:
        inputs  = tokenizer(text, return_tensors="pt",
                            truncation=True, max_length=MAX_SEQ_LENGTH)
        with torch.no_grad():
            logits = model(**inputs).logits
        y_pred.append(logits.argmax().item())

    y_pred = np.array(y_pred)
    y_true = np.array(y_true)

    # Binary metrics
    y_true_bin = (y_true > 0).astype(int)
    y_pred_bin = (y_pred > 0).astype(int)
    cm         = confusion_matrix(y_true_bin, y_pred_bin)
    tn, fp, fn, tp = cm.ravel() if cm.shape==(2,2) else (0,0,0,0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("=== LLM Evaluation Results ===")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print(f"MCC:      {matthews_corrcoef(y_true_bin, y_pred_bin):.4f}")
    print(f"FPR:      {fpr:.4f}")
    print(f"\nPer-variant report:\n")
    print(classification_report(y_true, y_pred, target_names=LABELS, zero_division=0))


if __name__ == "__main__":
    evaluate()
```

---

## Step 10 — Latency Benchmark

### File: `evaluation/latency_benchmark.py`

```python
#!/usr/bin/env python3
"""Measure edge vs cloud tier inference latency (M4 metric)."""

import torch, time, statistics, sys
sys.path.insert(0, "..")
from inference.threat_scorer import ThreatScorer
from data.tokenize_logs import event_to_token

def benchmark(n_trials: int = 100):
    scorer = ThreatScorer()

    # Build a test sequence
    test_events = [
        {"node_id":3,"timestamp":float(t),"packets_received":30,
         "packets_forwarded":14,"pdr":0.467,"speed_kmh":72.4,
         "rsu_id":"RSU_02","is_handoff":False,"src_vehicle":1}
        for t in range(10)
    ]
    seq = " [SEP] ".join(event_to_token(e) for e in test_events)

    edge_latencies = []
    for _ in range(n_trials):
        t0 = time.time()
        scorer._infer(seq, scorer.edge_model, scorer.edge_tokenizer, 128)
        edge_latencies.append((time.time()-t0)*1000)

    print("=== Latency Benchmark ===")
    print(f"Edge tier ({n_trials} trials):")
    print(f"  Mean:   {statistics.mean(edge_latencies):.2f} ms")
    print(f"  Median: {statistics.median(edge_latencies):.2f} ms")
    print(f"  P95:    {sorted(edge_latencies)[int(0.95*n_trials)]:.2f} ms")
    print(f"  Budget: 1000ms (safety-critical) — {'PASS' if statistics.mean(edge_latencies)<1000 else 'FAIL'}")

if __name__ == "__main__":
    benchmark()
```

---

## Completion Checklist

- [ ] `mock_mode/run_mock_llm_pipeline.py` completes without errors
- [ ] `output/models/edge_llm/` contains `config.json`, `pytorch_model.bin`, `tokenizer.json`
- [ ] Test accuracy > 65% on mock data (this is a minimum — real NS-3 data will be higher)
- [ ] `output/llm_scores/llm_score_{0..7}.json` all exist with correct schema
- [ ] Node 3 (attacker) should have higher `Q_i` than nodes 0–2 when running on S1 attack data
- [ ] Edge latency benchmark shows mean < 500ms (well within 1s vehicular budget)
- [ ] FPR < 0.15 — legitimate nodes should not be falsely flagged
- [ ] Two-tier routing test: manually set `EPSILON_U = 1.0` → all cases escalate to CLOUD tier

---

## Files to Hand Off

| File | Used By |
|------|---------|
| `output/llm_scores/llm_score_{id}.json` | Fusion Engine |
| `data/tokenize_logs.py` | NS-3 member can use this to verify token format |
| `output/models/edge_llm/` | Integration testing |
