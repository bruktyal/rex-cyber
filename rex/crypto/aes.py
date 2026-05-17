import os
import base64
import logging
from typing import Optional
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger("Rex.Crypto.AES")


@dataclass
class EncryptedPayload:
    ciphertext: str      # base64
    nonce: str           # base64
    tag_included: bool   # AESGCM includes auth tag in ciphertext
    device_id: str
    version: str = "AES256GCM-v1"


class AESGCMEncryptor:
    """
    AES-256-GCM authenticated encryption for IoT sensor payloads.
    Each packet gets a fresh 96-bit random nonce.
    """

    def __init__(self, key: Optional[bytes] = None):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("The 'cryptography' package is required but not installed. Run: pip install cryptography")
        # Generate or load 256-bit key
        self.key = key if key else os.urandom(32)
        self._engine = AESGCM(self.key)
        logger.info("AES-256-GCM encryptor initialized.")

    def encrypt(self, plaintext: str, device_id: str) -> EncryptedPayload:
        nonce = os.urandom(12)   # 96-bit nonce — NIST recommended for GCM
        data = plaintext.encode("utf-8")
        # AAD = device_id (binds ciphertext to this device, prevents replay)
        aad = device_id.encode("utf-8")
        ciphertext = self._engine.encrypt(nonce, data, aad)
        return EncryptedPayload(
            ciphertext=base64.b64encode(ciphertext).decode(),
            nonce=base64.b64encode(nonce).decode(),
            tag_included=True,
            device_id=device_id,
        )

    def decrypt(self, payload: EncryptedPayload) -> str:
        nonce = base64.b64decode(payload.nonce)
        ciphertext = base64.b64decode(payload.ciphertext)
        aad = payload.device_id.encode("utf-8")
        plaintext = self._engine.decrypt(nonce, ciphertext, aad)
        return plaintext.decode("utf-8")

    def export_key_b64(self) -> str:
        return base64.b64encode(self.key).decode()
