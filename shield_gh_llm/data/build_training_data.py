"""
SHIELD-GH LLM — Training Dataset Builder

Loads event sequences from JSONL or CSV, balances classes,
splits into train/val/test, and saves as a HuggingFace DatasetDict.
"""

import sys
import random
import copy
from pathlib import Path
from collections import Counter
from typing import List

from datasets import Dataset, DatasetDict

sys.path.insert(0, str(Path(__file__).parent.parent))
from data.tokenize_logs import build_sequences_from_jsonl, build_dataset_from_csv
from model.model_config import LABELS, LABEL2ID, N_CLASSES


def build_hf_dataset(
    data_source: str,
    output_dir: str,
    test_size: float = 0.15,
    val_size: float  = 0.15,
    max_per_class: int = 500,
    seed: int = 42,
) -> DatasetDict:
    """
    Build a balanced HuggingFace DatasetDict from a JSONL or CSV source.

    max_per_class caps training size for fast CPU training.
    """
    random.seed(seed)

    print(f"  Loading sequences from: {data_source}")
    if data_source.endswith(".jsonl"):
        seqs = build_sequences_from_jsonl(data_source)
    else:
        seqs = build_dataset_from_csv(data_source)

    print(f"  Raw sequences: {len(seqs)}")

    # Class distribution
    counts = Counter(s["label"] for s in seqs)
    print("  Label distribution:")
    for lbl in LABELS:
        print(f"    {lbl:<14}: {counts.get(lbl, 0):5d}")

    # Group by label
    by_label = {lbl: [s for s in seqs if s["label"] == lbl] for lbl in LABELS}

    # Cap majority classes + upsample minority classes to max_per_class
    balanced = []
    for lbl in LABELS:
        lbl_seqs = by_label[lbl]
        if not lbl_seqs:
            continue
        if len(lbl_seqs) > max_per_class:
            lbl_seqs = random.sample(lbl_seqs, max_per_class)
        elif len(lbl_seqs) < max_per_class:
            # Upsample by repeating with random selection
            needed = max_per_class - len(lbl_seqs)
            lbl_seqs = lbl_seqs + [copy.deepcopy(random.choice(lbl_seqs))
                                    for _ in range(needed)]
        balanced.extend(lbl_seqs)

    random.shuffle(balanced)
    print(f"\n  Balanced dataset: {len(balanced)} sequences "
          f"({max_per_class} per class × {N_CLASSES} classes)")

    # Extract as plain Python lists — avoids pandas-to-Arrow encoding edge cases
    # in datasets 4.x / pyarrow 24.x.
    texts  = [str(s["text"])      for s in balanced]
    labels = [int(s["label_id"])  for s in balanced]

    # Split indices
    n       = len(texts)
    n_test  = int(n * test_size)
    n_val   = int(n * val_size)
    n_train = n - n_test - n_val

    def _make_split(t, l):
        return Dataset.from_dict({"text": t, "labels": l})

    dataset = DatasetDict({
        "train":      _make_split(texts[:n_train],             labels[:n_train]),
        "validation": _make_split(texts[n_train:n_train+n_val], labels[n_train:n_train+n_val]),
        "test":       _make_split(texts[n_train+n_val:],        labels[n_train+n_val:]),
    })
    dataset.save_to_disk(output_dir)

    print(f"  Train: {n_train}  Val: {n_val}  Test: {n_test}")
    print(f"  [OK] Dataset saved → {output_dir}")
    return dataset
