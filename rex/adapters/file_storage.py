import os
import json
import logging
from typing import Dict, Any, List
from rex.adapters.base import StorageBackend

logger = logging.getLogger("Rex.Adapters.FileStorage")


class FileStorageBackend(StorageBackend):
    """
    Default zero-dependency local filesystem storage adapter.
    Persists data as structured line-delimited JSON files.
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.packets_file = os.path.join(data_dir, "packets.jsonl")
        self.alerts_file = os.path.join(data_dir, "alerts.jsonl")
        os.makedirs(data_dir, exist_ok=True)
        logger.info(f"Local file storage backend initialized at: {data_dir}")

    def save_packet(self, device_id: str, packet: Dict[str, Any]) -> None:
        try:
            entry = {"device_id": device_id, "timestamp": os.path.getmtime(self.packets_file) if os.path.exists(self.packets_file) else 0.0, "data": packet}
            with open(self.packets_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to save packet to local storage: {e}")

    def save_alert(self, alert: Dict[str, Any]) -> None:
        try:
            with open(self.alerts_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
        except Exception as e:
            logger.error(f"Failed to save alert to local storage: {e}")

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        if not os.path.exists(self.alerts_file):
            return []
        
        alerts = []
        try:
            with open(self.alerts_file, "r", encoding="utf-8") as f:
                # Read from bottom of the file up to limit
                lines = f.readlines()
                for line in reversed(lines[-limit:]):
                    if line.strip():
                        alerts.append(json.loads(line.strip()))
        except Exception as e:
            logger.error(f"Failed to read alerts from local storage: {e}")
        return alerts
