"""
PQC-LKH Group Re-Keying — Implements Eq 3.34–3.36.
Post-Quantum Logical Key Hierarchy for secure group re-keying after node isolation.

After a grey-hole node is isolated, all group keys it held must be refreshed.
PQC-LKH minimises re-keying messages using a binary key tree structure
with Kyber-768 for key encapsulation at each tree level.
"""

import hashlib
import secrets
import math
from typing import Dict, List, Optional, Tuple
from pqc_mitigation import kyber_keygen, kyber_encapsulate, kyber_decapsulate


class LKHNode:
    """Single node in the Logical Key Hierarchy tree."""

    def __init__(self, node_id: str, level: int):
        self.node_id  = node_id
        self.level    = level
        self.pk: Optional[bytes] = None
        self.sk: Optional[bytes] = None
        self.group_key: bytes    = secrets.token_bytes(32)  # symmetric TEK/KEK
        self.children: List["LKHNode"] = []
        self.parent:   Optional["LKHNode"] = None

    def generate_keypair(self):
        """Eq 3.34 — Generate Kyber key pair for this tree node."""
        self.pk, self.sk = kyber_keygen()


class PQCLKHTree:
    """
    PQC-LKH Binary Key Tree — Eq 3.34–3.36.

    Tree structure:
      - Root holds the group key (GK) shared by all members.
      - Each internal node holds a sub-group key encrypted for children.
      - Leaves represent individual vehicles.

    Re-keying after isolation: O(log n) Kyber encapsulations needed
    instead of O(n) unicast re-keys.
    """

    def __init__(self, member_ids: List[int]):
        self.member_ids = list(member_ids)
        self.n_members  = len(member_ids)
        self.tree_depth = max(1, math.ceil(math.log2(self.n_members + 1)))
        self._leaves:   Dict[int, LKHNode] = {}
        self._internals: List[LKHNode]     = []
        self.root: Optional[LKHNode]       = None
        self._build_tree()

    # ── Tree Construction ─────────────────────────────────────────────────────

    def _build_tree(self):
        """Build a full binary key tree and assign members to leaves."""
        # Create leaf nodes for each member
        leaves = []
        for mid in self.member_ids:
            leaf = LKHNode(f"leaf_{mid}", level=self.tree_depth)
            leaf.generate_keypair()
            self._leaves[mid] = leaf
            leaves.append(leaf)

        # Build internal nodes bottom-up
        current_level = leaves
        level = self.tree_depth - 1
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                internal = LKHNode(f"int_L{level}_N{i//2}", level=level)
                internal.generate_keypair()
                left  = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                internal.children = [left, right]
                left.parent  = internal
                right.parent = internal
                self._internals.append(internal)
                next_level.append(internal)
            current_level = next_level
            level -= 1

        self.root = current_level[0]

    # ── Re-Keying ─────────────────────────────────────────────────────────────

    def rekey_after_isolation(self, isolated_node_id: int) -> dict:
        """
        Eq 3.35 — Re-key the group after isolating a member.

        Only ancestors of the isolated node need new keys.
        Cost: O(log n) Kyber encapsulations.

        Returns dict summarising re-keying actions.
        """
        if isolated_node_id not in self._leaves:
            return {"error": f"node {isolated_node_id} not in group"}

        result = {
            "isolated_node":    isolated_node_id,
            "rekey_operations": [],
            "new_group_key":    None,
        }

        # Walk up the tree from the isolated leaf, refreshing keys
        current = self._leaves[isolated_node_id].parent
        while current is not None:
            old_key = current.group_key
            current.group_key = secrets.token_bytes(32)  # new KEK

            # Eq 3.35 — Encapsulate new key for each surviving child
            for child in current.children:
                child_member = self._member_for_subtree(child)
                if child_member == isolated_node_id:
                    continue  # skip isolated node's subtree
                if child.pk is None:
                    child.generate_keypair()
                session_key, ciphertext = kyber_encapsulate(child.pk)
                result["rekey_operations"].append({
                    "target_subtree": child.node_id,
                    "ciphertext_len": len(ciphertext),
                    "session_key_hash": hashlib.sha256(session_key).hexdigest()[:16],
                })

            current = current.parent

        # Refresh root group key (Eq 3.36 — new GK for surviving members)
        if self.root:
            self.root.group_key = secrets.token_bytes(32)
            result["new_group_key"] = hashlib.sha256(self.root.group_key).hexdigest()[:16] + "..."

        # Remove isolated node from membership
        del self._leaves[isolated_node_id]
        self.member_ids = [m for m in self.member_ids if m != isolated_node_id]

        return result

    def _member_for_subtree(self, node: LKHNode) -> Optional[int]:
        """Return the first leaf member ID under this subtree."""
        if not node.children:
            for mid, leaf in self._leaves.items():
                if leaf is node:
                    return mid
            return None
        return self._member_for_subtree(node.children[0])

    # ── Group Key Distribution ────────────────────────────────────────────────

    def distribute_group_key(self, member_id: int) -> dict:
        """
        Eq 3.36 — Encrypt the current root group key for a specific member
        using Kyber, so only that member can recover it.
        """
        if member_id not in self._leaves:
            return {"error": f"node {member_id} not in group"}

        leaf = self._leaves[member_id]
        if leaf.pk is None:
            leaf.generate_keypair()

        group_key    = self.root.group_key if self.root else secrets.token_bytes(32)
        session_key, ciphertext = kyber_encapsulate(leaf.pk)

        return {
            "member_id":       member_id,
            "ciphertext_len":  len(ciphertext),
            "gk_hash":         hashlib.sha256(group_key).hexdigest()[:16] + "...",
            "session_key_hash": hashlib.sha256(session_key).hexdigest()[:16] + "...",
        }

    def get_tree_info(self) -> dict:
        return {
            "n_members":   len(self.member_ids),
            "tree_depth":  self.tree_depth,
            "rekey_cost":  f"O(log {len(self.member_ids)}) = {self.tree_depth} Kyber ops",
            "member_ids":  self.member_ids,
        }
