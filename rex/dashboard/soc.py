import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from rex.dashboard.report import RexReport

logger = logging.getLogger("Rex.Dashboard")


@dataclass
class DeviceStatus:
    device_id: str
    region: str
    sensor_type: str
    last_seen: str
    status: str          # ONLINE, OFFLINE, COMPROMISED, QUARANTINED
    alert_count: int
    last_value: float


class SOCDashboard:
    """
    Rex Security Operations Center Dashboard.
    Aggregates device availability states, security events, compliance reports, and mitigation recommendations.
    """

    def __init__(self, log_dir: str = "data/logs"):
        self.log_dir = log_dir
        self._devices: Dict[str, DeviceStatus] = {}
        self._events: List[Dict] = []
        self._report_counter = 0
        self.compliance_history: List[Dict] = []  # Stores [{'timestamp': ..., 'score': ...}]
        self._start_time = datetime.utcnow()
        logger.info("Rex SOC Dashboard initialized.")

    def register_device(self, device_id: str, region: str, sensor_type: str):
        self._devices[device_id] = DeviceStatus(
            device_id=device_id,
            region=region,
            sensor_type=sensor_type,
            last_seen=datetime.utcnow().isoformat() + "Z",
            status="ONLINE",
            alert_count=0,
            last_value=0.0,
        )
        logger.info(f"Device registered: {device_id} | Region: {region} | Type: {sensor_type}")

    def update_device(self, device_id: str, value: float, status: str = "ONLINE"):
        if device_id in self._devices:
            self._devices[device_id].last_seen = datetime.utcnow().isoformat() + "Z"
            self._devices[device_id].last_value = value
            self._devices[device_id].status = status

    def log_event(self, event: Dict[str, Any]):
        event["logged_at"] = datetime.utcnow().isoformat() + "Z"
        self._events.append(event)
        device_id = event.get("device_id")
        if device_id and device_id in self._devices:
            self._devices[device_id].alert_count += 1
            if event.get("threat_level") in ("HIGH", "CRITICAL"):
                self._devices[device_id].status = "COMPROMISED"

    def get_threat_summary(self) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for ev in self._events:
            threat = ev.get("threat_level", "NONE")
            summary[threat] = summary.get(threat, 0) + 1
        return summary

    def generate_report(self) -> RexReport:
        self._report_counter += 1
        now = datetime.utcnow()
        threats = self.get_threat_summary()
        online = sum(1 for d in self._devices.values() if d.status == "ONLINE")
        critical = threats.get("CRITICAL", 0) + threats.get("HIGH", 0)

        # Compliance score: Deduct for critical alerts and offline devices
        total = len(self._devices) or 1
        score = max(0.0, 100.0 - (critical * 5) - ((total - online) / total * 20))
        self.compliance_history.append({
            "timestamp": now.isoformat() + "Z",
            "score": round(score, 2)
        })

        report = RexReport(
            report_id=f"REX-RPT-{self._report_counter:04d}",
            generated_at=now.isoformat() + "Z",
            period_start=self._start_time.isoformat() + "Z",
            period_end=now.isoformat() + "Z",
            total_devices=total,
            online_devices=online,
            total_alerts=len(self._events),
            critical_alerts=critical,
            blocked_ips=0,
            regions_covered=list({d.region for d in self._devices.values()}),
            top_threats=[{"level": k, "count": v} for k, v in sorted(
                threats.items(), key=lambda x: x[1], reverse=True
            )],
            recommendations=self._generate_recommendations(score, critical, online, total),
            compliance_score=round(score, 2),
        )
        return report

    def _generate_recommendations(self, score: float, critical: int, online: int, total: int) -> List[str]:
        recs = []
        if critical > 0:
            recs.append(
                f"URGENT: {critical} High/Critical threat events are active. Request security review."
            )
        if online < total:
            recs.append(
                f"{total - online} device(s) are offline. Validate cellular/LoRa connection states."
            )
        if score < 70:
            recs.append("Conduct emergency architecture audit of all edge nodes.")
        recs.append("Rotate edge node session HMAC keys on a strict 24-hour cycle.")
        recs.append("Ensure firmware validation scores are within Rex-approved margins.")
        return recs

    def print_dashboard(self):
        """Render a CLI monitoring report layout."""
        report = self.generate_report()
        print("\n" + "=" * 62)
        print("  REX SECURITY OPERATIONS CENTER — GLOBAL MONITORING")
        print(f"  Report ID : {report.report_id}")
        print(f"  Generated : {report.generated_at[:19]} UTC")
        print("=" * 62)
        print(f"  Devices       : {report.online_devices}/{report.total_devices} ONLINE")
        print(f"  Total Alerts  : {report.total_alerts}")
        print(f"  Critical/High : {report.critical_alerts}")
        print(f"  Regions/Zones : {', '.join(report.regions_covered) or 'None registered'}")
        print(f"  Compliance    : {report.compliance_score:.1f} / 100")
        if len(self.compliance_history) > 1:
            print(f"  Last 5 Scores : {[s['score'] for s in self.compliance_history[-5:]]}")
        print("-" * 62)
        print("  Threat Level Summary:")
        for t in report.top_threats:
            bar = "#" * min(t["count"], 20)
            print(f"    {t['level']:10s} {bar} ({t['count']})")
        print("-" * 62)
        print("  Mitigation Steps & Recommendations:")
        for i, rec in enumerate(report.recommendations, 1):
            # Wrap long line layouts
            words = rec.split()
            line, lines = "", []
            for w in words:
                if len(line) + len(w) + 1 > 52:
                    lines.append(line)
                    line = w
                else:
                    line = (line + " " + w).strip()
            if line:
                lines.append(line)
            print(f"    {i}. {lines[0]}")
            for continuation in lines[1:]:
                print(f"       {continuation}")
        print("=" * 62 + "\n")

    def export_json(self, filepath: Optional[str] = None):
        if filepath is None:
            filepath = os.path.join(self.log_dir, "rex_report.json")
        report = self.generate_report()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(asdict(report), f, indent=2)
        logger.info(f"Compliance report exported to: {filepath}")
