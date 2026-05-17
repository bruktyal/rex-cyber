"""
Rex IoT Security Framework
==========================
A C++-accelerated, pluggable IoT security framework.

Quick Start::

    from rex import RexEngine, RexConfig

    config = RexConfig(secret_key="my-secret")
    engine = RexEngine(config)
    result = engine.validate_packet(
        device_id="SENSOR-001", region="Zone-A",
        sensor_type="temperature", value=27.5, sequence=1
    )
    print(result.status)  # "OK"
"""

from rex.config import RexConfig
from rex.engine import RexEngine

__version__ = "0.1.0"
__all__ = ["RexConfig", "RexEngine"]
