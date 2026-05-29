"""
SHIELD-GH LLM — Edge Model Fine-Tuning  (Section 3.6.3)

Fine-tunes DistilBERT as a 7-class grey-hole attack classifier.
The trained model is the EDGE tier of the two-tier inference pipeline.
"""

import sys
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from model.model_config import (
    EDGE_MODEL_NAME, LABELS, LABEL2ID, ID2LABEL, N_CLASSES,
    MAX_SEQ_LENGTH, EDGE_LEARNING_RATE, EDGE_BATCH_SIZE,
    EDGE_NUM_EPOCHS, EDGE_WARMUP_STEPS, EDGE_WEIGHT_DECAY, EDGE_MAX_STEPS,
)

import torch
from datasets import load_from_disk
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)
from sklearn.metrics import accuracy_score, matthews_corrcoef, f1_score


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    # Binary: benign (0) vs malicious (1+)
    labels_bin = (labels > 0).astype(int)
    preds_bin  = (preds  > 0).astype(int)

    acc = accuracy_score(labels, preds)
    mcc = matthews_corrcoef(labels_bin, preds_bin)
    f1  = f1_score(labels_bin, preds_bin, average="binary", zero_division=0)

    fp  = int(((preds_bin == 1) & (labels_bin == 0)).sum())
    tn  = int(((preds_bin == 0) & (labels_bin == 0)).sum())
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {"accuracy": acc, "mcc": mcc, "f1": f1, "fpr": fpr}


def train_edge_model(
    dataset_path: str,
    output_path:  str,
    fast_mode:    bool = False,
) -> dict:
    """
    Fine-tune DistilBERT on the pre-built HuggingFace dataset.

    fast_mode=True: fewer steps, no early stopping — for CPU demo runs.
    Returns test-set evaluation metrics.
    """
    print(f"[LLM Train] Loading dataset from {dataset_path} ...")
    dataset   = load_from_disk(dataset_path)
    tokenizer = AutoTokenizer.from_pretrained(EDGE_MODEL_NAME)

    def tokenize_fn(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            padding=False,
            max_length=MAX_SEQ_LENGTH,
        )

    print(f"[LLM Train] Tokenising {len(dataset['train'])} train / "
          f"{len(dataset['validation'])} val sequences ...")
    tokenized = dataset.map(tokenize_fn, batched=True, remove_columns=["text"])
    collator  = DataCollatorWithPadding(tokenizer=tokenizer)

    model = AutoModelForSequenceClassification.from_pretrained(
        EDGE_MODEL_NAME,
        num_labels=N_CLASSES,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    # Training arguments — optimised for CPU with fast_mode flag
    n_steps    = min(EDGE_MAX_STEPS, 150) if fast_mode else EDGE_MAX_STEPS
    eval_steps = max(50, n_steps // 4)

    args = TrainingArguments(
        output_dir=output_path,
        max_steps=n_steps,
        learning_rate=EDGE_LEARNING_RATE,
        per_device_train_batch_size=EDGE_BATCH_SIZE,
        per_device_eval_batch_size=EDGE_BATCH_SIZE * 2,
        weight_decay=EDGE_WEIGHT_DECAY,
        warmup_steps=EDGE_WARMUP_STEPS,
        eval_strategy="steps",
        eval_steps=eval_steps,
        save_strategy="steps",
        save_steps=eval_steps,
        load_best_model_at_end=True,
        metric_for_best_model="mcc",
        greater_is_better=True,
        logging_steps=50,
        save_total_limit=1,
        report_to="none",
        fp16=torch.cuda.is_available(),
        dataloader_num_workers=0,   # 0 avoids multiprocessing issues in Docker
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        processing_class=tokenizer,
        data_collator=collator,
        compute_metrics=compute_metrics,
    )

    n_train = len(tokenized["train"])
    print(f"[LLM Train] Starting training — model={EDGE_MODEL_NAME}  "
          f"steps={n_steps}  batch={EDGE_BATCH_SIZE}  "
          f"device={'GPU' if torch.cuda.is_available() else 'CPU'}")
    trainer.train()

    # Evaluate on held-out test set
    test_results = trainer.evaluate(tokenized["test"])
    print(f"\n[LLM Train] Test results:")
    for k, v in test_results.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")

    # Save final model + tokenizer
    Path(output_path).mkdir(parents=True, exist_ok=True)
    trainer.save_model(output_path)
    tokenizer.save_pretrained(output_path)
    print(f"[LLM Train] Model saved → {output_path}")

    return test_results
