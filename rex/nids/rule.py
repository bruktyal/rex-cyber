import time
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum


class RuleAction(Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"
    LOG   = "LOG"


@dataclass
class IDS_Rule:
    rule_id: str
    name: str
    description: str
    action: RuleAction
    protocol: Optional[str] = None         # "TCP", "UDP", "ICMP", None = any
    src_ip: Optional[str] = None           # CIDR or single IP, None = any
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    payload_pattern: Optional[str] = None  # Regex pattern to match payload content
    severity: int = 2                      # 1 = Low, 2 = Medium, 3 = High, 4 = Critical


@dataclass
class NetworkPacket:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    payload: str = ""
    timestamp: float = field(default_factory=time.time)
    device_id: str = ""


@dataclass
class IDS_Alert:
    rule_id: str
    rule_name: str
    action: str
    packet: NetworkPacket
    timestamp: str
    severity: int
    region: str = "default"
