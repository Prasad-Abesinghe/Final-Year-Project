"""
OQS simulation layer for SHIELD-GH FYP.

Provides the same interface as the real liboqs-python package, but uses
standard cryptography primitives as stand-ins:
  - Signature("Dilithium3")     -> Ed25519  (both are lattice/modern EUF-CMA schemes)
  - KeyEncapsulation("Kyber768") -> X25519 ECDH  (both are IND-CCA2 KEMs)

This lets the full PQC pipeline run on any machine without compiling liboqs.
In a production deployment, replace this file with: pip install liboqs-python
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
import hashlib
import os


class Signature:
    """
    Simulates oqs.Signature("Dilithium3") using Ed25519.
    Supports context-manager usage: with oqs.Signature("Dilithium3") as s:
    """

    def __init__(self, alg_name: str, secret_key: bytes = None):
        self.alg_name = alg_name
        self._sk_bytes = secret_key
        self._private_key = None
        self._public_key_bytes = None

        if secret_key is not None:
            self._private_key = Ed25519PrivateKey.from_private_bytes(secret_key[:32])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def generate_keypair(self) -> bytes:
        """Generate a new key pair. Returns public key bytes."""
        self._private_key = Ed25519PrivateKey.generate()
        pub = self._private_key.public_key()
        self._public_key_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return self._public_key_bytes

    def export_secret_key(self) -> bytes:
        """Return private key bytes (32 bytes seed)."""
        if self._private_key is None:
            raise RuntimeError("No key generated yet")
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, message: bytes) -> bytes:
        """Sign message. Returns 64-byte Ed25519 signature."""
        if self._private_key is None:
            raise RuntimeError("No private key loaded")
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature. Returns True if valid."""
        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key[:32])
            pub.verify(signature[:64], message)
            return True
        except Exception:
            return False


class KeyEncapsulation:
    """
    Simulates oqs.KeyEncapsulation("Kyber768") using X25519 ECDH.
    Supports context-manager usage: with oqs.KeyEncapsulation("Kyber768") as kem:
    """

    def __init__(self, alg_name: str, secret_key: bytes = None):
        self.alg_name = alg_name
        self._sk_bytes = secret_key
        self._private_key = None

        if secret_key is not None:
            self._private_key = X25519PrivateKey.from_private_bytes(secret_key[:32])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def generate_keypair(self) -> bytes:
        """Generate a new key pair. Returns public key bytes (32 bytes)."""
        self._private_key = X25519PrivateKey.generate()
        pub = self._private_key.public_key()
        return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def export_secret_key(self) -> bytes:
        """Return private key bytes."""
        if self._private_key is None:
            raise RuntimeError("No key generated yet")
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def encap_secret(self, public_key_bytes: bytes):
        """
        Encapsulate a session key under recipient's public key.
        Returns (ciphertext, session_key) — mirrors liboqs API.
        """
        ephemeral_sk = X25519PrivateKey.generate()
        recipient_pk = X25519PublicKey.from_public_bytes(public_key_bytes[:32])

        shared = ephemeral_sk.exchange(recipient_pk)
        session_key = hashlib.sha256(shared).digest()

        eph_pub = ephemeral_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ciphertext = eph_pub + os.urandom(32)  # pad to Kyber-like size

        return ciphertext, session_key

    def decap_secret(self, ciphertext: bytes) -> bytes:
        """
        Recover session key from ciphertext using private key.
        Returns session_key bytes.
        """
        if self._private_key is None:
            raise RuntimeError("No private key loaded")
        eph_pub_bytes = ciphertext[:32]
        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        shared = self._private_key.exchange(eph_pub)
        return hashlib.sha256(shared).digest()


def get_enabled_sig_mechanisms():
    return ["Dilithium3 (simulated)", "Ed25519", "Falcon-512 (simulated)"]


def get_enabled_kem_mechanisms():
    return ["Kyber768 (simulated)", "X25519", "NTRU (simulated)"]
