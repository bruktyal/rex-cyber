import queue
import logging
from datetime import datetime
from typing import List, Dict, Any, Union
from enum import Enum
from dataclasses import dataclass, asdict

logger = logging.getLogger("Rex.Monitor.Alert")


class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class SecurityAlert:
    alert_id: str
    device_id: str
    threat_level: str
    description: str
    timestamp: str
    action_taken: str
    region: str


class AlertManager:
    """
    Generates, logs, and queues security alerts for the SOC Dashboard.
    """

    def __init__(self):
        self.alert_queue: queue.Queue = queue.Queue()
        self._counter = 0

    def raise_alert(
        self,
        device_id: str,
        threat_level: ThreatLevel,
        description: str,
        action: str,
        region: str = "Unknown",
    ) -> SecurityAlert:
        self._counter += 1
        alert = SecurityAlert(
            alert_id=f"REX-ALERT-{self._counter:05d}",
            device_id=device_id,
            threat_level=threat_level.name,
            description=description,
            timestamp=datetime.utcnow().isoformat() + "Z",
            action_taken=action,
            region=region,
        )
        self.alert_queue.put(alert)
        logger.error(
            f"[ALERT {alert.alert_id}] [{alert.threat_level}] {device_id}: {description}"
        )
        return alert

    def flush_alerts(self) -> List[SecurityAlert]:
        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get_nowait())
        return alerts
