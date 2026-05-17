import logging
from typing import Optional, Union
from rex.adapters.base import BrokerBackend

try:
    import paho.mqtt.client as mqtt
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False

logger = logging.getLogger("Rex.Adapters.MQTT")


class MQTTBrokerAdapter(BrokerBackend):
    """
    MQTT Broker Adapter using the popular paho-mqtt client library.
    If 'paho-mqtt' is not installed, it gracefully switches to a mock/dry-run mode
    allowing the system to start up and demonstrate pipeline logic safely.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 1883,
        client_id: str = "rex-iot-gateway",
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        self.host = host
        self.port = port
        self.client_id = client_id
        
        self.connected = False
        self._client = None

        if PAHO_AVAILABLE:
            try:
                self._client = mqtt.Client(client_id=client_id)
                if username and password:
                    self._client.username_pw_set(username, password)
                
                self._client.on_connect = self._on_connect
                self._client.on_disconnect = self._on_disconnect
                
                logger.info(f"MQTT Client configured for {host}:{port} with ClientID: {client_id}")
            except Exception as e:
                logger.error(f"Failed to initialize Paho MQTT client: {e}. Defaulting to mock mode.")
                self._client = None
        else:
            logger.warning(
                "Package 'paho-mqtt' not detected. Defaulting to simulated MQTT client. "
                "To resolve, run: pip install paho-mqtt"
            )

    def connect(self):
        if self._client:
            try:
                # Start loop thread in background
                self._client.connect(self.host, self.port, keepalive=60)
                self._client.loop_start()
            except Exception as e:
                logger.error(f"Failed to connect to MQTT broker at {self.host}:{self.port} - {e}")
        else:
            logger.info(f"[SIMULATOR] Connected to virtual MQTT broker at {self.host}:{self.port}")
            self.connected = True

    def disconnect(self):
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
        else:
            logger.info("[SIMULATOR] Disconnected from virtual MQTT broker.")
            self.connected = False

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            logger.info(f"Successfully connected to MQTT Broker at {self.host}:{self.port}")
        else:
            logger.error(f"MQTT Connection failed with return code: {rc}")

    def _on_disconnect(self, client, userdata, rc):
        self.connected = False
        logger.warning(f"MQTT Client disconnected from broker with return code: {rc}")

    def publish(self, topic: str, payload: Union[str, bytes]) -> None:
        if self._client and self.connected:
            try:
                self._client.publish(topic, payload, qos=1)
                logger.debug(f"Published message to topic '{topic}'")
            except Exception as e:
                logger.error(f"Failed to publish MQTT message to topic '{topic}': {e}")
        else:
            payload_str = payload.decode() if isinstance(payload, bytes) else payload
            logger.info(f"[SIMULATOR MQTT PUBLISH] Topic: '{topic}' | Payload: {payload_str[:80]}")

    def subscribe(self, topic: str, callback: callable) -> None:
        if self._client:
            try:
                def _wrapped_on_message(client, userdata, msg):
                    callback(msg.topic, msg.payload)
                
                self._client.subscribe(topic)
                self._client.on_message = _wrapped_on_message
                logger.info(f"Subscribed to MQTT topic '{topic}'")
            except Exception as e:
                logger.error(f"Failed to subscribe to MQTT topic '{topic}': {e}")
        else:
            logger.info(f"[SIMULATOR MQTT SUBSCRIBE] Subscribed to simulated topic '{topic}'")
            # In mock mode, we register subscriptions to verify setup logic
            self._mock_callback = callback
