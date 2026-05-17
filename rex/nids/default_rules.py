from typing import List
from rex.nids.rule import IDS_Rule, RuleAction

REX_DEFAULT_RULES: List[IDS_Rule] = [
    IDS_Rule(
        rule_id="REX-001",
        name="SSH Brute Force Attempt",
        description="Multiple SSH connection attempts from a single source IP",
        action=RuleAction.BLOCK,
        protocol="TCP",
        dst_port=22,
        severity=3,
    ),
    IDS_Rule(
        rule_id="REX-002",
        name="MQTT Broker Unauthorized Access",
        description="MQTT connection attempt on a non-standard port (rogue broker warning)",
        action=RuleAction.ALERT,
        protocol="TCP",
        dst_port=1884,
        severity=3,
    ),
    IDS_Rule(
        rule_id="REX-003",
        name="Malformed MQTT CONNECT Payload",
        description="MQTT payload containing standard SQL/Command injection attempts",
        action=RuleAction.BLOCK,
        protocol="TCP",
        payload_pattern=r"(CONNECT|PUBLISH).*(\bDROP\b|\bDELETE\b|;--|<script)",
        severity=4,
    ),
    IDS_Rule(
        rule_id="REX-004",
        name="Port Scan Detected",
        description="Triggered by NIDS tracker for rapid sequential port accesses",
        action=RuleAction.ALERT,
        severity=2,
    ),
    IDS_Rule(
        rule_id="REX-005",
        name="Unauthorized External IP Communication",
        description="IoT device attempting to talk to addresses outside allowed subnets",
        action=RuleAction.ALERT,
        dst_ip="0.0.0.0/0",  # Triggers fallback evaluation in engine
        severity=3,
    ),
    IDS_Rule(
        rule_id="REX-006",
        name="CoAP Amplification Attack",
        description="Large response from UDP port 5683 (potential amplification vector)",
        action=RuleAction.BLOCK,
        protocol="UDP",
        src_port=5683,
        severity=4,
    ),
    IDS_Rule(
        rule_id="REX-007",
        name="Default Credential Attempt",
        description="Common default device credentials (e.g. admin:admin) matched in payload",
        action=RuleAction.BLOCK,
        payload_pattern=r"(admin:admin|root:root|guest:guest|password:1234|admin:1234)",
        severity=4,
    ),
    IDS_Rule(
        rule_id="REX-008",
        name="Firmware Update Injection",
        description="Unencrypted/unsigned firmware upload signature detected over HTTP",
        action=RuleAction.BLOCK,
        protocol="TCP",
        dst_port=80,
        payload_pattern=r"(firmware|update|flash|OTA).*\.bin",
        severity=4,
    ),
]
