import time
import logging
import threading
from typing import Dict, List

logger = logging.getLogger("Rex.Monitor.RateLimit")


class DeviceRateLimiter:
    """
    Sliding-window rate limiter to detect flooding / DoS attacks.
    Maintains a thread-safe window of recent packet timestamps per device.
    """

    def __init__(self, max_rate: int = 100):
        self.max_rate = max_rate
        self._windows: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, device_id: str) -> bool:
        now = time.time()
        with self._lock:
            if device_id not in self._windows:
                self._windows[device_id] = []
            
            # Keep timestamps within the last 1.0 second
            window = [t for t in self._windows[device_id] if now - t < 1.0]
            window.append(now)
            self._windows[device_id] = window
            
            if len(window) > self.max_rate:
                logger.warning(f"[RATE LIMIT] Device {device_id} exceeded allowed limit of {self.max_rate} pkts/sec.")
                return False
            return True
