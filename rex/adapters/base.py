from abc import ABC, abstractmethod
from typing import Dict, Any, List, Union


class StorageBackend(ABC):
    """
    Abstract Base Class for pluggable storage backends in the Rex framework.
    Allows users to store device packets, security alerts, and logs in their preferred system
    (e.g., local files, PostgreSQL, SQLite, InfluxDB).
    """

    @abstractmethod
    def save_packet(self, device_id: str, packet: Dict[str, Any]) -> None:
        """Persist an incoming verified sensor packet."""
        pass

    @abstractmethod
    def save_alert(self, alert: Dict[str, Any]) -> None:
        """Persist a security threat alert raised by the engines."""
        pass

    @abstractmethod
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent security alerts."""
        pass


class BrokerBackend(ABC):
    """
    Abstract Base Class for pluggable message brokers in the Rex framework.
    Allows ingestion of sensor packets and publishing of security events/alerts
    via preferred brokers (e.g., MQTT, AMQP/RabbitMQ, Kafka, AWS IoT).
    """

    @abstractmethod
    def publish(self, topic: str, payload: Union[str, bytes]) -> None:
        """Publish a message to a specific topic."""
        pass

    @abstractmethod
    def subscribe(self, topic: str, callback: callable) -> None:
        """Subscribe to a topic and execute callback upon message reception."""
        pass
