#!/usr/bin/env python3
"""
SHIELD-GH LLM Threat Scoring — Mock Mode Runner

Reads bc_record_*.json (blockchain output) and fl_score_*.json (FL output),
then calls the LLM threat scorer to produce per-node threat reports.

Usage:
    python run_mock_llm.py
    ANTHROPIC_API_KEY=sk-ant-... python run_mock_llm.py
"""

import sys
import os
import json
from pathlib import Path

# Project root on sys.path so shield_gh_llm is importable
ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from shield_gh_llm.llm_threat_scorer import score_all_nodes

BC_DIR     = ROOT / "shield_gh_blockchain" / "output" / "bc_records"
FL_DIR     = ROOT / "shield_gh_fl"         / "output" / "fl_scores"
OUTPUT_DIR = ROOT / "shield_gh_llm"        / "output"


def _load_dir(directory: Path, pattern: str, id_key: str) -> dict:
    records = {}
    for path in sorted(directory.glob(pattern)):
        try:
            data = json.loads(path.read_text())
            records[data[id_key]] = data
        except Exception as exc:
            print(f"  [WARN] Skipping {path.name}: {exc}")
    return records


def main():
    print("=== SHIELD-GH LLM Threat Scoring ===\n")

    if not BC_DIR.exists() or not any(BC_DIR.glob("bc_record_*.json")):
        print("[ERROR] No blockchain records found. Run the blockchain pipeline first.")
        print(f"        Expected: {BC_DIR}/bc_record_*.json")
        sys.exit(1)

    if not FL_DIR.exists() or not any(FL_DIR.glob("fl_score_*.json")):
        print("[ERROR] No FL scores found. Run the FL pipeline first.")
        print(f"        Expected: {FL_DIR}/fl_score_*.json")
        sys.exit(1)

    bc_records = _load_dir(BC_DIR, "bc_record_*.json", "node_id")
    fl_scores  = _load_dir(FL_DIR,  "fl_score_*.json",  "node_id")

    print(f"[INPUT] {len(bc_records)} BC records  |  {len(fl_scores)} FL scores\n")

    summary = score_all_nodes(bc_records, fl_scores, OUTPUT_DIR)

    print(f"\n{'='*55}")
    print(f"  Network Status : {summary['network_status']}")
    print(f"  Threats        : CRITICAL={summary['threat_breakdown']['CRITICAL']}  "
          f"HIGH={summary['threat_breakdown']['HIGH']}  "
          f"MEDIUM={summary['threat_breakdown']['MEDIUM']}  "
          f"LOW={summary['threat_breakdown']['LOW']}")
    print(f"  Attacker nodes : {summary['attacker_nodes']}")
    print(f"{'='*55}")
    print(f"\n  {summary['executive_summary']}\n")
    print(f"[DONE] Reports -> {OUTPUT_DIR}/\n")


if __name__ == "__main__":
    main()
