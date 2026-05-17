import base64
import logging

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger("Rex.Crypto.Keys")


class X25519KeyExchange:
    """
    ECDH key exchange using Curve25519 for secure device onboarding.
    Allows IoT gateways to dynamically negotiate session keys with devices.
    """

    def __init__(self, key_info: bytes = b"Rex-IoT-Session-Key"):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("The 'cryptography' package is required but not installed. Run: pip install cryptography")
        self._private_key = X25519PrivateKey.generate()
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.key_info = key_info
        logger.info("X25519 key pair generated for secure device onboarding.")

    def get_public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode()

    def derive_shared_key(self, peer_public_key_b64: str) -> bytes:
        """Derive a 256-bit shared AES key from peer's public key."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_bytes = base64.b64decode(peer_public_key_b64)
        peer_key = X25519PublicKey.from_public_bytes(peer_bytes)
        shared_secret = self._private_key.exchange(peer_key)
        
        # HKDF to derive a proper cryptographically strong 256-bit AES key
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.key_info,
        ).derive(shared_secret)
        return derived
