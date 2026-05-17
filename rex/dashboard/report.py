from typing import List, Dict
from dataclasses import dataclass


@dataclass
class RexReport:
    report_id: str
    generated_at: str
    period_start: str
    period_end: str
    total_devices: int
    online_devices: int
    total_alerts: int
    critical_alerts: int
    blocked_ips: int
    regions_covered: List[str]
    top_threats: List[Dict]
    recommendations: List[str]
    compliance_score: float  # 0-100
