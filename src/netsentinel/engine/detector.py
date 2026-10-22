"""Detection orchestrator: flows -> suspicious events -> report."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import DetectionConfig, Settings
from ..features.beacon import detect_beacons
from ..features.dns import detect_dga, detect_dns_tunneling, detect_nxdomain_storm
from ..features.exfil import detect_exfiltration
from ..features.scan import detect_scans
from ..models import Flow, SuspiciousEvent

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class DetectionReport:
    events: List[SuspiciousEvent] = field(default_factory=list)
    flows_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flows_count": self.flows_count,
            "events_found": len(self.events),
            "events": [e.to_dict() for e in self.events],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def by_type(self, event_type: str) -> List[SuspiciousEvent]:
        return [e for e in self.events if e.event_type == event_type]


def detect(flows: List[Flow], cfg: Optional[DetectionConfig] = None) -> DetectionReport:
    """Run every detection heuristic over the flow list."""
    cfg = cfg or Settings.load().detection
    events: List[SuspiciousEvent] = []
    events.extend(detect_beacons(flows, cfg))
    events.extend(detect_dga(flows, cfg))
    events.extend(detect_nxdomain_storm(flows, cfg))
    events.extend(detect_dns_tunneling(flows, cfg))
    events.extend(detect_scans(flows, cfg))
    events.extend(detect_exfiltration(flows, cfg))

    events.sort(key=lambda e: (_SEVERITY_ORDER.get(e.severity, 0), e.event_type))
    events.reverse()
    return DetectionReport(events=events, flows_count=len(flows))
