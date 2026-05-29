"""
Blockchain bridge for FL module.
Interfaces with Part 2's fl_gradient_commit.py.
In integration mode: imports directly from shield_gh_blockchain/client/.
In standalone mode:  uses a file-based mock ledger.
"""

import hashlib
import json
import numpy as np
from pathlib import Path

# ── Try to import from Part 2 blockchain module ───────────────────────────────
try:
    import sys
    _bc_path = str(Path(__file__).parent.parent.parent / "shield_gh_blockchain" / "client")
    sys.path.insert(0, _bc_path)
    from fl_gradient_commit import commit_gradient as bc_commit
    from fl_gradient_commit import verify_gradient as bc_verify
    BLOCKCHAIN_AVAILABLE = True
    print("[FL] Using live blockchain module from Part 2")
except ImportError:
    BLOCKCHAIN_AVAILABLE = False
    print("[FL] Blockchain module not found — using file-based mock ledger")

MOCK_LEDGER_PATH = Path(__file__).parent.parent / "output" / "mock_ledger.json"


def _load_ledger() -> dict:
    if MOCK_LEDGER_PATH.exists():
        with open(MOCK_LEDGER_PATH) as f:
            return json.load(f)
    return {}


def _save_ledger(ledger: dict):
    MOCK_LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MOCK_LEDGER_PATH, "w") as f:
        json.dump(ledger, f, indent=2)


def _hash_weights(weights: list) -> str:
    serialized = json.dumps(
        [w.tolist() if hasattr(w, "tolist") else w for w in weights],
        sort_keys=True
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


class BlockchainBridge:
    def __init__(self, node_id: int):
        self.node_id = node_id

    def commit_gradient(self, weights: list, round_num: int) -> str:
        if BLOCKCHAIN_AVAILABLE:
            return bc_commit(weights, self.node_id, round_num)
        ledger = _load_ledger()
        h = _hash_weights(weights)
        ledger[f"grad_{self.node_id}_{round_num}"] = h
        _save_ledger(ledger)
        print(f"  [BC] Committed  node={self.node_id} round={round_num} hash={h[:16]}...")
        return h

    def verify_gradient(self, weights: list, round_num: int) -> bool:
        if BLOCKCHAIN_AVAILABLE:
            return bc_verify(weights, self.node_id, round_num)
        ledger = _load_ledger()
        key = f"grad_{self.node_id}_{round_num}"
        if key not in ledger:
            return False
        return _hash_weights(weights) == ledger[key]
