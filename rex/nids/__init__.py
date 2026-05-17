"""
Rex Network Intrusion Detection System
======================================
Rule-based packet analysis and port-scan detection.
"""

from rex.nids.rule import IDS_Rule, RuleAction, NetworkPacket, IDS_Alert
from rex.nids.engine import RexNIDS
from rex.nids.default_rules import REX_DEFAULT_RULES

__all__ = [
    "IDS_Rule",
    "RuleAction",
    "NetworkPacket",
    "IDS_Alert",
    "RexNIDS",
    "REX_DEFAULT_RULES",
]
