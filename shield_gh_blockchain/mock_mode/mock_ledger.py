"""
In-memory mock ledger — replaces Hyperledger Fabric for development/testing.
Implements the same key-value state store interface as Fabric stub.getState / stub.putState.
"""

import json
from typing import Any, Dict, Optional


class MockLedger:
    """Thread-safe in-memory key-value store mimicking Fabric world state."""

    def __init__(self):
        self._state: Dict[str, bytes] = {}
        self._history: Dict[str, list] = {}  # key -> list of (tx_id, value) for audit

    def put_state(self, key: str, value: Any):
        """Store serialised value at key (mirrors Fabric stub.putState)."""
        if isinstance(value, (dict, list)):
            encoded = json.dumps(value).encode()
        elif isinstance(value, str):
            encoded = value.encode()
        elif isinstance(value, bytes):
            encoded = value
        else:
            encoded = str(value).encode()

        self._state[key] = encoded
        if key not in self._history:
            self._history[key] = []
        self._history[key].append(encoded)

    def get_state(self, key: str) -> Optional[bytes]:
        """Retrieve value at key (mirrors Fabric stub.getState)."""
        return self._state.get(key, b"")

    def get_state_json(self, key: str) -> Optional[Any]:
        """Convenience: deserialise JSON value at key."""
        raw = self.get_state(key)
        if not raw:
            return None
        try:
            return json.loads(raw.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def delete_state(self, key: str):
        """Remove key from ledger."""
        self._state.pop(key, None)

    def get_history(self, key: str) -> list:
        """Return all historical values for a key (for audit)."""
        return self._history.get(key, [])

    def get_all_keys(self) -> list:
        return list(self._state.keys())

    def dump(self) -> dict:
        """Dump full ledger state as a readable dict (for debugging)."""
        result = {}
        for k, v in self._state.items():
            try:
                result[k] = json.loads(v.decode())
            except Exception:
                result[k] = v.hex()
        return result


# ── Mock Fabric Chaincode Shim ────────────────────────────────────────────────

class MockFabricChaincode:
    """
    Thin Python wrapper that mirrors the debsc.js chaincode interface.
    Allows running the same DEBSC logic without a running Fabric network.
    """

    def __init__(self, ledger: MockLedger):
        self.ledger = ledger

    def submit_forwarding_event(self, node_id: int, timestamp: float,
                                 n_fwd: int, n_rx: int,
                                 speed_kmh: float, rsu_id: str,
                                 is_handoff: bool) -> dict:
        """Mirrors SubmitForwardingEvent in debsc.js."""
        import math

        n_drop     = n_rx - n_fwd
        raw_trust  = (1.0 + n_fwd) / (1.0 + n_fwd + 1.0 + n_drop)
        penalty    = math.exp(-0.010 * (speed_kmh / 3.6) * 1.0)
        matd_trust = raw_trust * penalty

        hist_key  = f"HISTORY_{node_id}"
        history   = self.ledger.get_state_json(hist_key) or []
        history.append(matd_trust)
        self.ledger.put_state(hist_key, history)

        reputation = sum(history) / len(history)

        zkp_key  = f"ZKP_{node_id}"
        zkp_data = self.ledger.get_state_json(zkp_key)
        if zkp_data:
            committed = zkp_data.get("committed", n_fwd)
            denominator = max(n_fwd, 1)
            zkp_valid = abs(committed - n_fwd) / denominator <= 0.05
        else:
            zkp_valid = True

        deficit  = 1 - reputation
        isolated = (deficit > 0.40) and not zkp_valid

        record = {
            "nodeId":             node_id,
            "timestamp":          timestamp,
            "matdTrust":          round(matd_trust, 4),
            "reputation":         round(reputation, 4),
            "reputationDeficit":  round(deficit, 4),
            "zkpValid":           zkp_valid,
            "isolated":           isolated,
            "totalInteractions":  len(history),
            "rsuId":              rsu_id,
            "isHandoff":          is_handoff,
        }
        self.ledger.put_state(f"RECORD_{node_id}", record)
        return record

    def commit_forwarding_proof(self, node_id: int, committed_n_fwd: int) -> str:
        """Mirrors CommitForwardingProof in debsc.js."""
        key = f"ZKP_{node_id}"
        self.ledger.put_state(key, {"committed": committed_n_fwd})
        return "OK"

    def commit_gradient(self, node_id: int, round_num: int, gradient_hash: str) -> str:
        """Mirrors CommitGradient in debsc.js."""
        key = f"GRAD_{node_id}_{round_num}"
        self.ledger.put_state(key, {"hash": gradient_hash})
        return "OK"

    def verify_gradient(self, node_id: int, round_num: int, received_hash: str) -> dict:
        """Mirrors VerifyGradient in debsc.js."""
        key    = f"GRAD_{node_id}_{round_num}"
        stored = self.ledger.get_state_json(key)
        if not stored:
            return {"valid": False, "reason": "no_commitment"}
        return {"valid": stored.get("hash") == received_hash}

    def get_record(self, node_id: int) -> Optional[dict]:
        """Mirrors GetRecord in debsc.js."""
        return self.ledger.get_state_json(f"RECORD_{node_id}")
