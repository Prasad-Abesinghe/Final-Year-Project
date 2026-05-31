# SHIELD-GH LLM Module Architecture

## Overview

The LLM module forms the **Intelligence Layer** of SHIELD-GH. It fuses evidence from the blockchain trust layer (ZKP proofs, MATD reputation, DEBSC status) and the federated learning layer (malicious probability, predicted attack variant) into a structured, human-readable threat assessment for each vehicle node.

The module operates in two modes:
- **Template mode** (default): deterministic rule-based narrative generation using pre-defined templates per threat level. Requires no API key and runs entirely offline.
- **LLM mode** (when `ANTHROPIC_API_KEY` is set): calls `claude-haiku-4-5-20251001` to generate richer, contextually-aware threat assessments from structured evidence prompts.

In both modes, the same numeric threat score computation, threat level classification, and evidence fusion logic are used. The LLM mode only differs in the natural-language narrative output.

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| LLM provider | Anthropic Claude (`claude-haiku-4-5-20251001`) — via `anthropic` Python SDK |
| DistilBERT scorer | HuggingFace `transformers` — fine-tuned DistilBERT for Q_i semantic scores |
| Template engine | Python string formatting + deterministic seeded randomness |
| Inference runtime | Local CPU inference (DistilBERT); API calls (Claude Haiku) |
| Training | HuggingFace Trainer API (`model/train_edge_llm.py`) |
| Output format | JSON per node (`llm_report_{node_id}.json`) + network summary (`llm_summary.json`) |

---

## Module Directory Structure

```
shield_gh_llm/
├── llm_threat_scorer.py          # Main scoring + narrative generation module
├── model/
│   ├── model_config.py           # DistilBERT model configuration
│   ├── train_edge_llm.py         # Fine-tuning script (HuggingFace Trainer)
│   └── __init__.py
├── inference/
│   ├── threat_scorer.py          # DistilBERT inference wrapper (Q_i generation)
│   └── batch_inference.py        # Batch scoring across all nodes
├── data/
│   └── (forwarding log sequences for fine-tuning)
├── evaluation/
│   └── (accuracy, F1 evaluation scripts)
└── mock_mode/
    └── (standalone simulation data)
```

---

## Core Module: `llm_threat_scorer.py`

### Attack Variant Reference (`VARIANT_INFO`)

Seven attack signatures are defined and referenced throughout narrative generation:

| ID | Name | Plane | Pattern |
|----|------|-------|---------|
| S1_DP_FR | Data-Plane Full-Rate Grey Hole | data | steady |
| S2_DP_IT | Data-Plane Intermittent Grey Hole | data | intermittent |
| S3_DP_TS | Data-Plane Target-Specific Drop | data | selective |
| S4_CP_FR | Control-Plane Full-Rate FlowMod Injection | control | steady |
| S5_CP_IT | Control-Plane Intermittent FlowMod Injection | control | intermittent |
| S6_CP_TS | Control-Plane Target-Specific FlowMod | control | selective |
| BENIGN | Normal Vehicle | n/a | normal |

### Threat Score Computation

```python
def compute_threat_score(bc: dict, fl: dict, llm: dict = None) -> float
```

**With Q_i (DistilBERT semantic score available):**
```
score = 0.25 · (1 - R_i)   [blockchain reputation deficit]
      + 0.30 · P(malicious) [FL malicious probability]
      + 0.15 · zkp_penalty  [0 if ZKP valid, 1 if ZKP failed]
      + 0.30 · Q_i          [DistilBERT semantic threat score]
```

**Without Q_i (template mode fallback):**
```
score = 0.35 · (1 - R_i)
      + 0.45 · P(malicious)
      + 0.20 · zkp_penalty
```

### Threat Level Classification

```python
def score_to_level(threat_score: float, debsc_triggered: bool) -> str
```

| Condition | Level |
|-----------|-------|
| `debsc_triggered = True`  OR  `score ≥ 0.75` | CRITICAL |
| `score ≥ 0.50` | HIGH |
| `score ≥ 0.25` | MEDIUM |
| `score < 0.25` | LOW |

DEBSC triggered (i.e., on-chain isolation already enacted) overrides the numeric score and always yields CRITICAL.

---

## Two-Tier Inference Architecture (Eq 3.15)

The paper describes a two-tier edge-cloud LLM design:

**Tier 1 — Edge LLM at RSU:**
A quantised, fine-tuned lightweight model (DistilBERT or 4-bit quantised Mistral-7B) processes short blockchain log windows `x_i^(t)` at the RSU. Produces a binary preliminary verdict and semantic threat score `Q_i`.

**Tier 2 — Cloud LLM escalation (Eq 3.15):**
```
Use Tier 2 = 1[max_c softmax(LLM_edge(x_i))_c < ε_u]
```
When edge model confidence falls below threshold `ε_u`, the input is escalated to the full-size cloud model (Claude Haiku) for a richer, contextualised assessment.

In the current implementation:
- Template mode = Tier 1 (deterministic, zero latency)
- LLM mode with `claude-haiku-4-5-20251001` = Tier 2 (API-based, richer narrative)

### LLM Threat Score (Eq 3.23)

The DistilBERT model produces:
```
Q_i(t) = softmax(LLM(x_i^(t); θ))_malicious
```
The malicious-class softmax probability is extracted as `Q_i`. Higher `Q_i` = stronger semantic evidence of grey hole behaviour from the forwarding log sequence.

---

## DistilBERT Edge Model

### Model Configuration (`model/model_config.py`)

- Base model: `distilbert-base-uncased`
- Task: sequence classification (7 classes: BENIGN + 6 attack variants)
- Input: tokenised blockchain forwarding log windows (PDR sequences, drop events, speed, RSU handoff flags)
- Fine-tuning: HuggingFace Trainer (`model/train_edge_llm.py`)

### Inference (`inference/threat_scorer.py`)

```python
threat_scorer = ThreatScorer(model_path="model/")
Q_i = threat_scorer.score(forwarding_log_sequence)  # returns float ∈ [0, 1]
variant = threat_scorer.classify(forwarding_log_sequence)  # returns variant ID string
```

The edge model processes short windows (typically 20–50 forwarding events) and outputs both a semantic threat score and a predicted attack variant.

---

## Template-Mode Narrative Generation

When no API key is present, deterministic narratives are generated from pre-defined templates keyed by threat level. `random.Random(node_id)` ensures deterministic but varied output for the same node across runs.

**Narrative templates** cover four threat levels (CRITICAL / HIGH / MEDIUM / LOW) with multiple variants per level. Each template cites specific evidence values:
- ZKP proof status (FAILED / PASSED)
- MATD reputation score and threshold comparison
- FL malicious probability
- Number of monitored interactions
- DEBSC isolation status
- Attack variant name

**Attack pattern descriptions** per variant describe the technical mechanism:
- S1: steady 85-90% packet drop
- S2: ~10-second on/off cycle exploiting time-averaged metrics
- S3: per-source selective drop (KL-divergence signal)
- S4: continuous malicious FlowMod injection
- S5: periodic FlowMod injection to evade signature detection
- S6: target-specific FlowMod affecting only designated vehicle flows

**Recommended actions** per level:
- CRITICAL: Immediate DEBSC isolation + PQC LKH re-keying + RSU cluster alert
- HIGH: Submit for DEBSC review + increase polling frequency to 0.5s
- MEDIUM: Increase sampling rate + register as DEBSC candidate
- LOW: Standard MATD tracking continues

---

## LLM Mode — Claude Haiku Integration

When `ANTHROPIC_API_KEY` is set, `_llm_report()` constructs a structured evidence prompt and calls `claude-haiku-4-5-20251001`.

### System Prompt

```
You are a cybersecurity analyst for SHIELD-GH, a grey-hole attack detection and
mitigation system for Software-Defined Vehicular Networks (SDVN). You produce
concise, technically precise threat assessments from cryptographic proof results,
trust-score evidence, and federated learning predictions. Write in formal
professional prose. Never use markdown formatting in your response.
```

### User Prompt Structure

The prompt passes all numeric evidence values in a structured block:

```
EVIDENCE:
- ZKP Forwarding Proof: FAILED (dishonest ZKP commitment)
- Blockchain Reputation Score: 0.2134  (DEBSC isolation threshold: 0.40)
- MATD Corrected Trust: 0.1987
- Total Monitored Interactions: 23
- FL Malicious Probability: 0.9231
- FL Predicted Attack Variant: S1_DP_FR — consistently drops 85–90% of packets
- FL Local Model Accuracy on Node Data: 0.9143
- DEBSC Decision: ISOLATED
- Computed Threat Score: 0.8812
- Threat Level: CRITICAL

ATTACK VARIANT REFERENCE:
[all 7 variant descriptions]

Respond with ONLY a valid JSON object — no markdown, no preamble:
{
  "narrative": "...",
  "attack_pattern": "...",
  "recommended_action": "...",
  "confidence_assessment": "..."
}
```

The model returns a JSON object with four fields. The module parses and merges these with the numeric evidence fields to produce the final report.

**Fallback:** If the API call fails (network error, rate limit, key not set), the module silently falls back to template mode and records the error type in `generated_by`.

---

## Output Format

### Per-Node Report (`llm_report_{node_id}.json`)

```json
{
  "node_id": 3,
  "threat_level": "CRITICAL",
  "threat_score": 0.8812,
  "attack_variant": "S1_DP_FR",
  "attack_plane": "data",
  "attack_pattern_label": "Data-Plane Full-Rate Grey Hole",
  "narrative": "Vehicle node 3 has been definitively confirmed as a grey-hole attacker ...",
  "attack_pattern": "Full-rate data-plane grey hole: the node receives packets ...",
  "recommended_action": "ISOLATE IMMEDIATELY — trigger DEBSC smart contract ...",
  "confidence_assessment": "High confidence: ZKP failed, MATD reputation 0.213 (below threshold 0.40), FL malicious probability 92.3%.",
  "evidence": {
    "zkp_failed": true,
    "reputation_score": 0.2134,
    "reputation_deficit": 0.7866,
    "matd_corrected_trust": 0.1987,
    "malicious_probability": 0.9231,
    "fl_predicted_variant": "S1_DP_FR",
    "fl_confidence": 0.9231,
    "fl_local_accuracy": 0.9143,
    "total_interactions": 23,
    "debsc_triggered": true
  },
  "generated_by": "claude-haiku-4-5-20251001",
  "generated_at": "2026-05-31T09:00:00Z"
}
```

### Network Summary (`llm_summary.json`)

```json
{
  "network_status": "COMPROMISED",
  "total_nodes": 5,
  "threats_detected": 1,
  "threat_breakdown": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 4 },
  "attacker_nodes": [3],
  "executive_summary": "One vehicle node (node 3, S1_DP_FR) has been confirmed ...",
  "scoring_mode": "llm",
  "generated_at": "2026-05-31T09:00:00Z"
}
```

**Network status values:**
- `SECURE` — no CRITICAL or HIGH nodes detected
- `COMPROMISED` — exactly one confirmed attacker
- `UNDER ATTACK` — multiple confirmed attackers (coordinates PQC re-keying across all RSU clusters)

---

## Fusion Integration (Eq 3.24)

The LLM module contributes `Q_i(t)` to the full-mode detection decision:

```
ŷ_i(t) = 1[μ₁·S_total(v_i) + μ₂·Q_i(t) + μ₃·(1 - R_i(t)) > θ_det]
```

Where:
- `μ₁ + μ₂ + μ₃ = 1` (fusion weights optimised on validation set)
- `S_total` = max binary signature score (from lightweight rule-based detector)
- `Q_i(t)` = DistilBERT semantic threat score for node i at time t
- `(1 - R_i(t))` = blockchain reputation deficit

The LLM layer is engaged when the lightweight signatures do not fire or when edge model confidence falls below `ε_u`. For high-confidence lightweight detections (e.g., clear fixed-rate attacks), the rule-based path dominates and LLM inference is skipped to meet latency requirements.

---

## Integration Points

| Module | Interface |
|--------|-----------|
| Blockchain | Reads `reputation_score`, `reputation_deficit`, `matd_corrected_trust`, `zkp_valid`, `debsc_triggered`, `total_interactions` from ledger records |
| FL module | Reads `fl_score_{round}.json`: `malicious_prob`, `predicted_variant`, `confidence`, `local_accuracy`, `round_num` |
| Dashboard backend | `main.py` calls `score_all_nodes()`, serves results via REST |
| NS-3 simulation | Forwarding log sequences sourced from simulation output |

---

## Latency Design

The two-tier design minimises average inference latency:

| Path | Latency | Coverage |
|------|---------|----------|
| Template mode (Tier 1) | < 1 ms | All cases (no API) |
| Edge DistilBERT (Tier 1) | 20–80 ms | High-confidence cases at RSU |
| Claude Haiku API (Tier 2) | 200–800 ms | Ambiguous / borderline cases only |

The full-mode detection pipeline (including LLM) satisfies the latency budget for safety-critical vehicular applications because the majority of decisions are resolved at the edge tier without cloud escalation.
