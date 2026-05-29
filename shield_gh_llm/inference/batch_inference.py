"""
SHIELD-GH LLM — Batch Inference

Scores all nodes from the simulation dataset and exports
llm_score_{node_id}.json files consumed by the Fusion Engine.
"""

import sys
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from data.tokenize_logs import build_dataset_from_csv, build_sequences_from_jsonl
from inference.threat_scorer import ThreatScorer


def score_all_nodes(
    data_source: str,
    scorer: ThreatScorer,
    n_recent_windows: int = 5,
) -> Dict[int, dict]:
    """
    Score all nodes found in data_source.
    Uses the last n_recent_windows windows per node and keeps the max Q_i.
    """
    if data_source.endswith(".jsonl"):
        sequences = build_sequences_from_jsonl(data_source)
    else:
        sequences = build_dataset_from_csv(data_source)

    by_node: Dict[int, List] = defaultdict(list)
    for seq in sequences:
        by_node[seq["node_id"]].append(seq)

    node_scores = {}
    for node_id, seqs in sorted(by_node.items()):
        recent = sorted(seqs, key=lambda x: x["window_end"])[-n_recent_windows:]
        q_values = []
        for seq in recent:
            result = scorer.score(seq["text"], node_id, seq["window_end"])
            q_values.append(result["Q_i"])

        # Use last window's result but report max Q_i (worst-case)
        best = scorer.score(recent[-1]["text"], node_id, recent[-1]["window_end"])
        best["Q_i"] = round(max(q_values), 4)
        node_scores[node_id] = best

        flag = "  *** ATTACKER ***" if best["Q_i"] > 0.5 else ""
        print(f"  Node {node_id:>2}: Q_i={best['Q_i']:.4f}  "
              f"label={best['label']:<14}  tier={best['tier_used']:<5}  "
              f"lat={best['latency_ms']:.0f}ms{flag}")

    return node_scores


def export_scores(node_scores: Dict[int, dict], output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    for node_id, score in node_scores.items():
        path = output_dir / f"llm_score_{node_id}.json"
        with open(path, "w") as f:
            json.dump(score, f, indent=2)
    print(f"\n[LLM Batch] Scores → {output_dir}/")
