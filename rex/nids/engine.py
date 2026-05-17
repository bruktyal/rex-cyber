import re
import time
import logging
import ipaddress
from typing import List, Dict, Optional
from rex.nids.rule import IDS_Rule, IDS_Alert, NetworkPacket, RuleAction
from rex.nids.default_rules import REX_DEFAULT_RULES

logger = logging.getLogger("Rex.NIDS")


class RexNIDS:
    """
    Rex Network Intrusion Detection System.
    Evaluates packet streams against a configurable list of active detection rules.
    """

    def __init__(self, rules: Optional[List[IDS_Rule]] = None, allowed_cidr: str = "10.50.0.0/16"):
        self.rules = rules if rules is not None else REX_DEFAULT_RULES
        self.allowed_cidr = allowed_cidr
        self._alerts: List[IDS_Alert] = []
        self._port_scan_tracker: Dict[str, List[tuple]] = {}
        self._blocked_ips: set = set()
        logger.info(f"Rex NIDS Engine initialized with {len(self.rules)} rules. Network range: {allowed_cidr}")

    def analyze(self, packet: NetworkPacket) -> List[IDS_Alert]:
        """Evaluate a packet against all configured security rules."""
        triggered = []

        # Skip already-blocked IPs for performance
        if packet.src_ip in self._blocked_ips:
            logger.debug(f"Packet from blocked source IP {packet.src_ip} silently dropped.")
            return []

        # Track and detect potential port scans
        self._track_port_scan(packet)

        for rule in self.rules:
            if self._matches(rule, packet):
                alert = IDS_Alert(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    action=rule.action.value,
                    packet=packet,
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    severity=rule.severity,
                )
                self._alerts.append(alert)
                triggered.append(alert)
                logger.warning(
                    f"[{rule.action.value}] {rule.rule_id} | {rule.name} | "
                    f"src={packet.src_ip}:{packet.src_port} "
                    f"dst={packet.dst_ip}:{packet.dst_port}"
                )
                if rule.action == RuleAction.BLOCK:
                    self._blocked_ips.add(packet.src_ip)

        return triggered

    def _matches(self, rule: IDS_Rule, pkt: NetworkPacket) -> bool:
        if rule.protocol and rule.protocol != pkt.protocol.upper():
            return False
        if rule.dst_port and rule.dst_port != pkt.dst_port:
            return False
        if rule.src_port and rule.src_port != pkt.src_port:
            return False

        # Custom logic for external IP subnet rule (e.g. REX-005)
        if rule.rule_id == "REX-005":
            try:
                # Alert if destination IP is external (not in our allowed private range)
                dst_addr = ipaddress.ip_address(pkt.dst_ip)
                allowed_net = ipaddress.ip_network(self.allowed_cidr)
                if dst_addr not in allowed_net and not dst_addr.is_private:
                    return True
            except ValueError:
                pass
            return False

        if rule.src_ip:
            try:
                if ipaddress.ip_address(pkt.src_ip) not in ipaddress.ip_network(rule.src_ip):
                    return False
            except ValueError:
                pass

        if rule.payload_pattern:
            if not re.search(rule.payload_pattern, pkt.payload, re.IGNORECASE):
                return False

        return True

    def _track_port_scan(self, pkt: NetworkPacket):
        """Heuristic check: >15 unique ports scanned in 5 seconds flags a scanning alert."""
        src = pkt.src_ip
        now = time.time()
        if src not in self._port_scan_tracker:
            self._port_scan_tracker[src] = []
        self._port_scan_tracker[src].append((pkt.dst_port, now))
        
        # Prune old tracked events outside the 5s window
        self._port_scan_tracker[src] = [
            (p, t) for p, t in self._port_scan_tracker[src] if now - t < 5.0
        ]
        
        unique_ports = {p for p, _ in self._port_scan_tracker[src]}
        if len(unique_ports) > 15:
            logger.warning(f"[PORT SCAN] Host {src} accessed {len(unique_ports)} unique ports in 5 seconds.")

    def get_alerts(self) -> List[IDS_Alert]:
        return list(self._alerts)

    def get_blocked_ips(self) -> set:
        return set(self._blocked_ips)

    def summary(self) -> dict:
        return {
            "total_alerts": len(self._alerts),
            "blocked_ips": len(self._blocked_ips),
            "rules_loaded": len(self.rules),
            "critical_alerts": sum(1 for a in self._alerts if a.severity == 4),
        }
