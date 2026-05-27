"""
Blockchain-verified FL gradient integrity — Eq 3.22.
The FL module calls these functions to commit and verify gradient hashes.
"""

import hashlib
import json
from typing import Any

# ── Simulated on-chain ledger (replace with Fabric SDK calls in production) ──
_ledger: dict = {}


def commit_gradient(gradient_weights: Any, node_id: int, round_num: int) -> str:
    """
    Called by FL vehicle client BEFORE submitting gradient to aggregator.
    Stores hash on blockchain so aggregator can verify integrity.

    Eq 3.22: Accept(Δw_i) = 1[ H_BC(Δw_i) = Hash(Δw_i) ]

    Args:
        gradient_weights: list of numpy arrays (model parameters)
        node_id:          vehicle identifier
        round_num:        FL round number

    Returns:
        commitment_hash: hex string stored on blockchain
    """
    if hasattr(gradient_weights, '__iter__'):
        serialized = json.dumps(
            [arr.tolist() if hasattr(arr, 'tolist') else arr
             for arr in gradient_weights],
            sort_keys=True
        ).encode()
    else:
        serialized = str(gradient_weights).encode()

    key      = f"grad_{node_id}_{round_num}"
    hash_val = hashlib.sha256(serialized).hexdigest()
    _ledger[key] = hash_val
    print(f"[BLOCKCHAIN] Committed gradient: node={node_id} round={round_num} hash={hash_val[:16]}...")
    return hash_val


def verify_gradient(gradient_weights: Any, node_id: int, round_num: int) -> bool:
    """
    Called by FL aggregator to verify gradient was not tampered with.
    Returns False if gradient was poisoned or hash mismatches.
    """
    key = f"grad_{node_id}_{round_num}"
    if key not in _ledger:
        print(f"[BLOCKCHAIN] No commitment found for node={node_id} round={round_num} — rejecting")
        return False

    if hasattr(gradient_weights, '__iter__'):
        serialized = json.dumps(
            [arr.tolist() if hasattr(arr, 'tolist') else arr
             for arr in gradient_weights],
            sort_keys=True
        ).encode()
    else:
        serialized = str(gradient_weights).encode()

    actual_hash = hashlib.sha256(serialized).hexdigest()
    expected    = _ledger[key]
    match       = (actual_hash == expected)
    if not match:
        print(f"[BLOCKCHAIN] GRADIENT MISMATCH node={node_id} round={round_num} — POISONING DETECTED")
    return match
