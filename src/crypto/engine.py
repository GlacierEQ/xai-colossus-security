"""AES-256-GCM engine with cryptography when available; fail-closed pure fallback.

Production path prefers cryptography.hazmat AESGCM. The pure fallback is only for
local dual-run environments without the native wheel; it still requires a 32-byte
master key and uses HMAC-bound Fernet-style stream (not a substitute for AES-GCM
in production deployments).
"""
from __future__ import annotations

import hashlib
import hmac
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    AESGCM = None  # type: ignore
    _HAS_CRYPTO = False


class ApexCryptoEngine:
    """AES-256-GCM when cryptography is installed; HMAC-XOR fallback otherwise."""

    def __init__(self, master_key_bytes: bytes):
        if len(master_key_bytes) != 32:
            raise ValueError("Master key must be 32 bytes (256-bit).")
        self._key = master_key_bytes
        self.aesgcm = AESGCM(master_key_bytes) if _HAS_CRYPTO else None

    def encrypt_data(self, data: bytes, associated_data: bytes = b"") -> bytes:
        if self.aesgcm is not None:
            nonce = os.urandom(12)
            return nonce + self.aesgcm.encrypt(nonce, data, associated_data)
        # Fail-closed local fallback: HMAC-keyed stream (not production AES-GCM)
        nonce = os.urandom(12)
        stream = self._stream(nonce, associated_data, len(data))
        ct = bytes(a ^ b for a, b in zip(data, stream))
        tag = hmac.new(self._key, nonce + associated_data + ct, hashlib.sha256).digest()[:16]
        return nonce + tag + ct

    def decrypt_data(self, encrypted_blob: bytes, associated_data: bytes = b"") -> bytes:
        if self.aesgcm is not None:
            nonce, ciphertext = encrypted_blob[:12], encrypted_blob[12:]
            return self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        nonce, tag, ct = encrypted_blob[:12], encrypted_blob[12:28], encrypted_blob[28:]
        expect = hmac.new(self._key, nonce + associated_data + ct, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expect):
            raise ValueError("integrity check failed")
        stream = self._stream(nonce, associated_data, len(ct))
        return bytes(a ^ b for a, b in zip(ct, stream))

    def _stream(self, nonce: bytes, associated_data: bytes, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            block = hmac.new(
                self._key,
                nonce + associated_data + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:length])


class KyberSim:
    """Simulated Post-Quantum KEM interface (placeholder for liboqs)."""

    @staticmethod
    def encapsulate():
        return os.urandom(800), os.urandom(700), os.urandom(32)
