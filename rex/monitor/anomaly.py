import logging
from typing import Optional, Dict, List

logger = logging.getLogger("Rex.Monitor.Anomaly")


class AnomalyDetector:
    """
    Statistical anomaly detection using a rolling window of past metrics.
    Flagging values exceeding a specified number of standard deviations (z-score).
    """

    def __init__(self, window_size: int = 50, z_threshold: float = 3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self._history: Dict[str, List[float]] = {}

    def record(self, device_id: str, value: float) -> Optional[float]:
        """
        Record a reading and return its Z-score if anomalous, else None.
        """
        key = device_id
        if key not in self._history:
            self._history[key] = []
        self._history[key].append(value)
        
        # Enforce rolling window size
        if len(self._history[key]) > self.window_size:
            self._history[key].pop(0)
            
        history = self._history[key]
        if len(history) < 10:  # Need baseline history before checking anomalies
            return None
            
        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        stddev = variance ** 0.5
        
        if stddev == 0:
            return None
            
        z_score = abs((value - mean) / stddev)
        return z_score if z_score > self.z_threshold else None
