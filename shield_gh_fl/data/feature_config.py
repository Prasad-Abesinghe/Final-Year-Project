"""
Shared feature configuration for FL module.
All feature names must match simulation_dataset.csv column names exactly.
"""

FEATURES = [
    "pdr_mean",        # Eq 3.1 — mean PDR over window
    "pdr_var",         # Eq 3.3 — PDR variance
    "pdr_corrected",   # Eq 3.5 — MATD-corrected PDR
    "speed_kmh",       # vehicle speed (mobility signal)
    "is_handoff",      # 1 if RSU handoff occurred in window
    "kl_divergence",   # Eq 3.8 — per-source PDR non-uniformity (S3 signal)
    "autocorr_peak",   # Eq 3.7 — periodicity of drop pattern (S2 signal)
]

N_FEATURES = len(FEATURES)

LABELS = ["BENIGN", "S1_DP_FR", "S2_DP_IT", "S3_DP_TS",
          "S4_CP_FR", "S5_CP_IT", "S6_CP_TS"]
N_CLASSES = len(LABELS)
LABEL2ID  = {l: i for i, l in enumerate(LABELS)}
ID2LABEL  = {i: l for i, l in enumerate(LABELS)}


def label_to_binary(label: str) -> int:
    return 0 if label == "BENIGN" else 1
