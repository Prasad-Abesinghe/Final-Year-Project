"""
Post-Quantum Cryptographic Mitigation — CRYSTALS-Kyber + Dilithium.
Implements Eq 3.25–3.33.
Requires: pip install oqs
"""

import oqs
import json
import hashlib
import secrets
from typing import List, Tuple, Dict


# ── CRYSTALS-Kyber KEM — Eq 3.25–3.26 ───────────────────────────────────────

def kyber_keygen() -> Tuple[bytes, bytes]:
    """Generate a Kyber-768 key pair (pk, sk)."""
    with oqs.KeyEncapsulation("Kyber768") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


def kyber_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
    """
    Eq 3.25 — Encapsulate a fresh session key under recipient's public key.
    Returns (session_key K, ciphertext c).
    """
    with oqs.KeyEncapsulation("Kyber768") as kem:
        ciphertext, session_key = kem.encap_secret(pk)
    return session_key, ciphertext


def kyber_decapsulate(sk: bytes, ciphertext: bytes, pk: bytes) -> bytes:
    """
    Eq 3.26 — Recover session key K from ciphertext using private key sk.
    """
    with oqs.KeyEncapsulation("Kyber768", secret_key=sk) as kem:
        session_key = kem.decap_secret(ciphertext)
    return session_key


# ── CRYSTALS-Dilithium Signatures — Eq 3.27–3.28 ────────────────────────────

def dilithium_keygen() -> Tuple[bytes, bytes]:
    """Generate a Dilithium3 (ML-DSA) signing key pair (pk, sk)."""
    with oqs.Signature("Dilithium3") as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
    return pk, sk


def dilithium_sign(sk: bytes, message: bytes) -> bytes:
    """
    Eq 3.27 — Sign a flow modification command with Dilithium private key.
    σ = Dilithium.Sign(sk_c, M)
    """
    with oqs.Signature("Dilithium3", secret_key=sk) as signer:
        signature = signer.sign(message)
    return signature


def dilithium_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """
    Eq 3.28 — Verify Dilithium signature. Returns True if valid.
    b = Dilithium.Verify(pk_c, M, σ) ∈ {0, 1}
    """
    try:
        with oqs.Signature("Dilithium3") as verifier:
            return verifier.verify(message, signature, pk)
    except Exception:
        return False


# ── Threshold Signatures — Eq 3.31–3.33 ─────────────────────────────────────

class ThresholdSignatureScheme:
    """
    (k, n)-threshold signature scheme for collective blacklisting.
    Simulation: k individual Dilithium signatures aggregated.
    Production: use BLS threshold signatures for compact aggregation.
    """

    def __init__(self, k: int, n: int):
        self.k = k  # minimum co-signers
        self.n = n  # total RSUs
        self.rsu_keys = []
        for _ in range(n):
            pk, sk = dilithium_keygen()
            self.rsu_keys.append({"pk": pk, "sk": sk})
        combined = b"".join(kp["pk"] for kp in self.rsu_keys)
        self.group_pk = hashlib.sha256(combined).digest()

    def partial_sign(self, rsu_idx: int, message: bytes) -> bytes:
        """Eq 3.31 — RSU j produces partial signature over blacklist message."""
        sk = self.rsu_keys[rsu_idx]["sk"]
        return dilithium_sign(sk, message)

    def combine_signatures(self, partial_sigs: List[bytes], message: bytes) -> bytes:
        """
        Eq 3.32 — Combine k partial signatures into aggregate σ*.
        Simulation: concatenate and hash (production: BLS aggregation).
        """
        if len(partial_sigs) < self.k:
            raise ValueError(f"Need {self.k} signatures, got {len(partial_sigs)}")
        combined   = b"".join(partial_sigs[:self.k])
        sigma_star = hashlib.sha256(combined + message).digest()
        return sigma_star

    def verify_aggregate(self, sigma_star: bytes,
                         partial_sigs: List[bytes], message: bytes) -> bool:
        """
        Eq 3.33 — Verify aggregate signature against group public key.
        Returns True only if k valid partial signatures exist.
        """
        if len(partial_sigs) < self.k:
            return False
        valid_count = 0
        for i, sig in enumerate(partial_sigs[:self.k]):
            pk = self.rsu_keys[i]["pk"]
            if dilithium_verify(pk, message, sig):
                valid_count += 1
        if valid_count < self.k:
            return False
        expected = hashlib.sha256(b"".join(partial_sigs[:self.k]) + message).digest()
        return sigma_star == expected


# ── Full PQC Mitigation Pipeline ─────────────────────────────────────────────

class PQCMitigationEngine:
    """
    Algorithm 4 (PQC-Mit) — Full post-quantum mitigation pipeline.
    Called when DEBSC confirms ISOLATED verdict.
    """

    def __init__(self, n_rsus: int = 3, k_threshold: int = 2):
        self.ts       = ThresholdSignatureScheme(k=k_threshold, n=n_rsus)
        self.ctrl_pk, self.ctrl_sk = dilithium_keygen()
        self.n_rsus   = n_rsus
        self.k        = k_threshold

    def run_isolation(self, node_id: int, zkp_store) -> dict:
        """
        Full Algorithm 4 execution.
        Returns dict summarising mitigation actions taken.
        """
        result = {"node_id": node_id, "steps": []}

        # Step 1 — ZKP verification (Eq 3.30)
        zkp_valid = zkp_store.verify_proof(node_id)
        if zkp_valid:
            return {"node_id": node_id, "action": "ABORT_FALSE_POSITIVE",
                    "reason": "ZKP proof valid — statistical detection was false positive"}
        result["steps"].append({"step": 1, "name": "ZKP_VERIFICATION",
                                 "result": "FAIL — confirmed attacker"})

        # Step 2 — Threshold-signed blacklisting (Eq 3.31–3.33)
        blacklist_msg = json.dumps({"isolate": node_id,
                                    "reason": "grey_hole_confirmed"}).encode()
        partial_sigs  = [self.ts.partial_sign(i, blacklist_msg)
                         for i in range(self.n_rsus)]
        sigma_star    = self.ts.combine_signatures(partial_sigs[:self.k], blacklist_msg)
        sig_valid     = self.ts.verify_aggregate(sigma_star, partial_sigs, blacklist_msg)

        if not sig_valid:
            return {"node_id": node_id, "action": "ABORT_INSUFFICIENT_SIGNATURES",
                    "reason": f"Only {len(partial_sigs)} RSUs — need {self.k}"}
        result["steps"].append({"step": 2, "name": "THRESHOLD_SIGNING",
                                 "result": f"sigma* valid ({self.k}/{self.n_rsus} RSUs)"})

        # Step 3 — SDN flow modification (Eq 3.27–3.28)
        flowmod_cmd = json.dumps({"action": "BLOCK", "target_node": node_id,
                                   "priority": 65535}).encode()
        flowmod_sig = dilithium_sign(self.ctrl_sk, flowmod_cmd)
        verified    = dilithium_verify(self.ctrl_pk, flowmod_cmd, flowmod_sig)
        result["steps"].append({"step": 3, "name": "FLOWMOD_SIGN",
                                 "result": f"Dilithium signature valid={verified}",
                                 "flowmod": flowmod_cmd.decode()})

        result["action"]         = "NODE_ISOLATED"
        result["sigma_star_hex"] = sigma_star.hex()[:32] + "..."
        return result
