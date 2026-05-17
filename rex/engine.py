import time
import logging
import hashlib
import hmac
from typing import Dict, Any, Optional, Union

from rex.config import RexConfig
from rex.core.gateway import CppGatewayBridge, ProcessResult
from rex.crypto.aes import AESGCMEncryptor
from rex.crypto.rotation import KeyRotationManager
from rex.nids.engine import RexNIDS
from rex.monitor.anomaly import AnomalyDetector
from rex.monitor.rate_limiter import DeviceRateLimiter
from rex.monitor.validator import SensorRangeValidator
from rex.monitor.alert import AlertManager, ThreatLevel, SecurityAlert

logger = logging.getLogger("Rex.Engine")


# Default master key bytes matching C++ REX_MASTER_KEY
REX_MASTER_KEY_BYTES = bytes([
    0xE5, 0x1A, 0x4B, 0x8C, 0xD2, 0x6F, 0x93, 0x07,
    0xAB, 0x3E, 0x12, 0x5D, 0x74, 0xC8, 0x29, 0xF6,
    0x0D, 0xE7, 0x41, 0x9A, 0xBB, 0x53, 0x6E, 0x28,
    0x14, 0x97, 0xC0, 0x35, 0xF2, 0x8D, 0x4A, 0x61,
])


class RexEngine:
    """
    The main coordinator class for the Rex IoT Security Framework.
    Binds the C++ performance-critical pipeline with modular Python-based NIDS,
    cryptography key rotation, anomaly detection, and range validation.
    """

    def __init__(self, config: Optional[RexConfig] = None):
        self.config = config if config is not None else RexConfig()
        
        # Initialize the logging level
        logging.getLogger("Rex").setLevel(self.config.log_level)

        # ── C++ Core Bridge ───────────────────────────────────────
        self.cpp_bridge = CppGatewayBridge()
        self.use_cpp = self.config.use_cpp_engine and self.cpp_bridge.is_available
        if self.use_cpp:
            logger.info("Using C++ Core Engine for high-speed packet processing.")
        else:
            logger.warning("C++ Core Engine is not active. Running in Pure Python Mode.")

        # ── Subsystems ────────────────────────────────────────────
        self.nids = RexNIDS(allowed_cidr=self.config.allowed_cidr)
        self.crypto_rotation = KeyRotationManager(
            rotation_interval_seconds=self.config.key_rotation_hours * 3600
        )
        self.anomaly_detector = AnomalyDetector(
            window_size=self.config.anomaly_window_size,
            z_threshold=self.config.anomaly_threshold
        )
        self.rate_limiter = DeviceRateLimiter(max_rate=self.config.max_packet_rate)
        self.range_validator = SensorRangeValidator()
        self.alert_manager = AlertManager()

        self._stats = {"processed": 0, "rejected": 0, "alerts": 0}
        logger.info("Rex Security Engine fully initialized and operational.")

    def serialize_packet(
        self,
        device_id: str,
        region: str,
        location: str,
        sensor_type: Union[str, int],
        value: float,
        timestamp_ms: int,
        sequence_number: int,
        flags: int = 0
    ) -> bytes:
        import struct
        dev_bytes = device_id.encode("utf-8")[:31].ljust(32, b"\x00")
        reg_bytes = region.encode("utf-8")[:31].ljust(32, b"\x00")
        loc_bytes = location.encode("utf-8")[:63].ljust(64, b"\x00")
        stype_int = self._convert_sensor_type_to_int(sensor_type)
        
        # Binary struct format: 32s 32s 64s B f Q I B (146 bytes total payload for HMAC)
        return struct.pack("<32s32s64sBfQIB",
            dev_bytes,
            reg_bytes,
            loc_bytes,
            stype_int,
            value,
            timestamp_ms,
            sequence_number,
            flags
        )

    def validate_packet(
        self,
        device_id: str,
        region: str,
        location: str,
        sensor_type: Union[str, int],
        value: float,
        sequence_number: int,
        timestamp_ms: Optional[int] = None,
        flags: int = 0,
        hmac_signature: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Main entry point for validating a sensor packet.
        Routes validation to C++ core if enabled, or executes the modular Python fallback.
        """
        self._stats["processed"] += 1
        t_ms = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)

        # ── Case A: C++ Accelerated Path ─────────────────────────────────────
        if self.use_cpp:
            sensor_type_int = self._convert_sensor_type_to_int(sensor_type)
            c_res = self.cpp_bridge.validate_packet(
                device_id=device_id,
                region=region,
                location=location,
                sensor_type=sensor_type_int,
                value=value,
                timestamp_ms=t_ms,
                sequence_number=sequence_number,
                flags=flags,
                hmac_bytes=hmac_signature
            )
            
            if c_res == ProcessResult.OK:
                # Still check statistical anomalies in Python layer
                z_score = self.anomaly_detector.record(device_id, value)
                if z_score is not None:
                    alert = self.alert_manager.raise_alert(
                        device_id, ThreatLevel.MEDIUM,
                        f"Statistical anomaly detected (z-score={z_score:.2f}) on '{sensor_type}' field.",
                        "Alert flagged to dashboard",
                        region
                    )
                    self._stats["alerts"] += 1
                    return {"status": "ANOMALY", "reason": "z_score_deviation", "alert": alert}
                return {"status": "OK", "source": "C++"}
            
            # Map C++ error codes to alerts
            self._stats["rejected"] += 1
            if c_res == ProcessResult.AUTH_FAIL:
                alert = self.alert_manager.raise_alert(
                    device_id, ThreatLevel.HIGH,
                    "C++ Engine: Invalid HMAC signature detected.",
                    "Packet discarded; threat logged", region
                )
                self._stats["alerts"] += 1
                return {"status": "REJECTED", "reason": "auth_failure", "alert": alert}
            
            elif c_res == ProcessResult.RATE_LIMITED:
                alert = self.alert_manager.raise_alert(
                    device_id, ThreatLevel.HIGH,
                    "C++ Engine: Flooding detected (rate limit exceeded).",
                    "Throttling applied", region
                )
                self._stats["alerts"] += 1
                return {"status": "THROTTLED", "reason": "rate_limited", "alert": alert}
                
            elif c_res == ProcessResult.OUT_OF_RANGE:
                alert = self.alert_manager.raise_alert(
                    device_id, ThreatLevel.MEDIUM,
                    f"C++ Engine: Value {value} was physically out of range.",
                    "Packet quarantined", region
                )
                self._stats["alerts"] += 1
                return {"status": "QUARANTINED", "reason": "range_violation", "alert": alert}
                
            elif c_res == ProcessResult.REPLAY:
                alert = self.alert_manager.raise_alert(
                    device_id, ThreatLevel.HIGH,
                    "C++ Engine: Replay attack detected.",
                    "Dropped duplicate sequence or old timestamp", region
                )
                self._stats["alerts"] += 1
                return {"status": "REJECTED", "reason": "replay_attack", "alert": alert}

        # ── Case B: Pure Python Fallback Path ───────────────────────────────
        else:
            # 1. Signature Verification (HMAC-SHA256)
            if hmac_signature:
                payload = self.serialize_packet(device_id, region, location, sensor_type, value, t_ms, sequence_number, flags)
                secret_bytes = REX_MASTER_KEY_BYTES
                expected_mac = hmac.new(secret_bytes, payload, hashlib.sha256).digest()
                if not hmac.compare_digest(expected_mac, hmac_signature):
                    self._stats["rejected"] += 1
                    alert = self.alert_manager.raise_alert(
                        device_id, ThreatLevel.HIGH,
                        "Python Engine: Invalid HMAC signature.",
                        "Packet dropped", region
                    )
                    self._stats["alerts"] += 1
                    return {"status": "REJECTED", "reason": "auth_failure", "alert": alert}

            # 2. Rate Limiting
            if not self.rate_limiter.is_allowed(device_id):
                self._stats["rejected"] += 1
                alert = self.alert_manager.raise_alert(
                    device_id, ThreatLevel.HIGH,
                    "Python Engine: Rate limit exceeded.",
                    "Dropped", region
                )
                self._stats["alerts"] += 1
                return {"status": "THROTTLED", "reason": "rate_limited", "alert": alert}

            # 3. Range Verification
            if not self.range_validator.validate(sensor_type, value):
                self._stats["rejected"] += 1
                alert = self.alert_manager.raise_alert(
                    device_id, ThreatLevel.MEDIUM,
                    f"Python Engine: Physical range violation on '{sensor_type}' reading: {value}",
                    "Quarantined", region
                )
                self._stats["alerts"] += 1
                return {"status": "QUARANTINED", "reason": "range_violation", "alert": alert}

            # 4. Statistical Anomaly
            z_score = self.anomaly_detector.record(device_id, value)
            if z_score is not None:
                alert = self.alert_manager.raise_alert(
                    device_id, ThreatLevel.MEDIUM,
                    f"Python Engine: Anomaly detected (z={z_score:.2f}).",
                    "Dashboard alert triggered", region
                )
                self._stats["alerts"] += 1
                return {"status": "ANOMALY", "reason": "z_score_deviation", "alert": alert}

            return {"status": "OK", "source": "Python"}

    def _convert_sensor_type_to_int(self, sensor_type: Union[str, int]) -> int:
        if isinstance(sensor_type, int):
            return sensor_type
        # Basic mapping for known strings
        mapping = {
            "soil_moisture": 1,
            "temperature": 2,
            "humidity": 3,
            "irrigation_valve": 4,
            "weather_station": 5,
        }
        return mapping.get(str(sensor_type).lower(), 99)

    def get_stats(self) -> dict:
        return dict(self._stats)
