"""
Rex Framework Configuration
============================
Type-safe, environment-driven configuration using pydantic-settings.
Can be loaded from environment variables or a .env file.

Usage::

    from rex.config import RexConfig

    # From env vars / defaults
    config = RexConfig()

    # Fully custom
    config = RexConfig(
        secret_key="my-secret",
        max_packet_rate=200,
        anomaly_threshold=2.5,
        allowed_cidr="192.168.1.0/24",
    )
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class RexConfig(BaseSettings):
    """
    Central configuration for the Rex IoT Security Framework.
    All fields can be overridden via environment variables prefixed with REX_.

    Example env vars:
        REX_SECRET_KEY=mysecret
        REX_MAX_PACKET_RATE=200
        REX_ANOMALY_THRESHOLD=2.5
        REX_LOG_DIR=logs/
    """

    # ── Authentication ─────────────────────────────────────────────
    secret_key: str = Field(
        default="REX_IOT_SECURITY_SECRET_2024",
        description="HMAC-SHA256 master secret. Always override in production!",
    )

    # ── Rate Limiting ──────────────────────────────────────────────
    max_packet_rate: int = Field(
        default=100,
        gt=0,
        description="Maximum packets per second per device (DoS threshold).",
    )

    # ── Anomaly Detection ──────────────────────────────────────────
    anomaly_threshold: float = Field(
        default=3.0,
        gt=0,
        description="Z-score threshold above which a reading is flagged as anomalous.",
    )
    anomaly_window_size: int = Field(
        default=50,
        gt=1,
        description="Number of samples in the rolling anomaly detection window.",
    )

    # ── Replay Attack Prevention ───────────────────────────────────
    replay_window_ms: int = Field(
        default=30_000,
        gt=0,
        description="Timestamp freshness window in milliseconds (default: 30 seconds).",
    )

    # ── Network / NIDS ─────────────────────────────────────────────
    allowed_cidr: str = Field(
        default="10.50.0.0/16",
        description="Allowed IoT subnet in CIDR notation. Packets outside are flagged.",
    )

    # ── Key Rotation ───────────────────────────────────────────────
    key_rotation_hours: int = Field(
        default=24,
        gt=0,
        description="Hours before a device session key is flagged for rotation.",
    )

    # ── Logging / Storage ──────────────────────────────────────────
    log_dir: str = Field(
        default="data/logs",
        description="Directory where logs and reports are written.",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging verbosity: DEBUG | INFO | WARNING | ERROR",
    )

    # ── C++ Engine ─────────────────────────────────────────────────
    use_cpp_engine: bool = Field(
        default=True,
        description="If True, use the C++ shared library for packet validation.",
    )

    class Config:
        env_prefix = "REX_"
        env_file = ".env"
        case_sensitive = False
