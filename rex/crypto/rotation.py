import os
import time
import logging
from typing import Optional, Dict

logger = logging.getLogger("Rex.Crypto.Rotation")


class KeyRotationManager:
    """
    Manages periodic key rotation for secure, long-running IoT networks.
    Ensures session keys expire and are rotated securely on a configured schedule.
    """

    def __init__(self, rotation_interval_seconds: int = 86400):
        self.rotation_interval = rotation_interval_seconds
        self._keys: Dict[str, dict] = {}  # device_id -> {"key": bytes, "issued_at": float}
        self._rotation_count = 0

    def issue_key(self, device_id: str) -> bytes:
        """Issue a fresh, cryptographically secure 256-bit key for a device."""
        key = os.urandom(32)
        self._keys[device_id] = {"key": key, "issued_at": time.time()}
        logger.info(f"New AES-256 session key issued for device: {device_id}")
        return key

    def get_key(self, device_id: str) -> Optional[bytes]:
        """Retrieve key for the given device if it has not expired yet."""
        if device_id not in self._keys:
            return None
        entry = self._keys[device_id]
        age = time.time() - entry["issued_at"]
        if age > self.rotation_interval:
            logger.warning(f"Session key expired for device {device_id}. Rotation is required.")
            return None
        return entry["key"]

    def rotate_key(self, device_id: str) -> bytes:
        """Force manual rotation and issue a new key."""
        self._rotation_count += 1
        logger.info(f"[Key Rotation #{self._rotation_count}] Force rotating key for device {device_id}")
        return self.issue_key(device_id)

    def needs_rotation(self, device_id: str) -> bool:
        """Check if the device's key has exceeded the allowed rotation interval."""
        if device_id not in self._keys:
            return True
        age = time.time() - self._keys[device_id]["issued_at"]
        return age > self.rotation_interval
