"""
SHIELD-GH LLM — Model Configuration
All hyperparameters, label maps, and paths in one place.
Every other module imports from here.
"""

# ── Labels ────────────────────────────────────────────────────────────────────

LABELS    = ["BENIGN", "S1_DP_FR", "S2_DP_IT", "S3_DP_TS",
             "S4_CP_FR", "S5_CP_IT", "S6_CP_TS"]
N_CLASSES = len(LABELS)
LABEL2ID  = {l: i for i, l in enumerate(LABELS)}
ID2LABEL  = {i: l for i, l in enumerate(LABELS)}

# ── Model identifiers ─────────────────────────────────────────────────────────

EDGE_MODEL_NAME  = "distilbert-base-uncased"   # ~66M params — edge RSU tier
CLOUD_MODEL_NAME = "bert-base-uncased"          # ~110M params — cloud tier

# ── Paths (relative to shield_gh_llm/) ───────────────────────────────────────

EDGE_MODEL_PATH  = "output/models/edge_llm"
CLOUD_MODEL_PATH = "output/models/cloud_llm"
HF_DATASET_PATH  = "output/hf_dataset"
LLM_SCORES_PATH  = "output/llm_scores"

# ── Tokenisation ──────────────────────────────────────────────────────────────

MAX_SEQ_LENGTH   = 128    # tokens per sequence — edge tier
CLOUD_SEQ_LENGTH = 256    # longer context for cloud tier
WINDOW_SIZE      = 10     # events per sliding window → one text sequence

# ── Training (edge model) ─────────────────────────────────────────────────────

EDGE_LEARNING_RATE = 2e-5
EDGE_BATCH_SIZE    = 8
EDGE_NUM_EPOCHS    = 3     # kept low for CPU training
EDGE_WARMUP_STEPS  = 30    # transformers 5.x uses warmup_steps (not warmup_ratio)
EDGE_WEIGHT_DECAY  = 0.01
EDGE_MAX_STEPS     = 300   # hard cap — use whichever limit is reached first

# ── Inference ────────────────────────────────────────────────────────────────

EPSILON_U = 0.85    # Eq 3.15 — route to cloud if edge confidence < ε_u
