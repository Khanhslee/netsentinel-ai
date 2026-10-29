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
from ..models import Flow, SuspiciousEvent, stable_hash

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class DetectionReport:
    events: List[SuspiciousEvent] = field(default_factory=list)
    flows_count: int = 0
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flows_count": self.flows_count,
            "events_found": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "stats": self.stats,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def by_type(self, event_type: str) -> List[SuspiciousEvent]:
        return [e for e in self.events if e.event_type == event_type]


def compute_flow_stats(flows: List[Flow]) -> Dict[str, Any]:
    """Aggregate capture-level metrics for the dashboards/reports (KPIs)."""
    packets = sum(f.src_packets + f.dst_packets for f in flows)
    bytes_out = sum(f.src_bytes for f in flows)
    bytes_in = sum(f.dst_bytes for f in flows)
    times = [f.start_time for f in flows if f.start_time]
    ends = [f.end_time or f.start_time for f in flows if f.end_time or f.start_time]
    start = min(times, default=0.0)
    end = max(ends, default=start)
    src_ips = {f.src_ip for f in flows}
    dst_ips = {f.dst_ip for f in flows}
    dns_flows = [f for f in flows if f.dns_qname]
    return {
        "flows": len(flows),
        "packets": packets,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "total_bytes": bytes_out + bytes_in,
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "unique_hosts": len(src_ips | dst_ips),
        "dns_flows": len(dns_flows),
        "capture_start": start,
        "capture_end": end,
        "capture_duration_sec": round(max(0.0, end - start), 2),
    }


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

    # Stable evidence identities allow repeated offline analyses to be compared.
    for event in events:
        evidence = event.to_dict()
        evidence.pop("event_id", None)
        event.event_id = stable_hash(json.dumps(evidence, sort_keys=True))

    events.sort(key=lambda e: (_SEVERITY_ORDER.get(e.severity, 0), e.event_type))
    events.reverse()
    return DetectionReport(
        events=events,
        flows_count=len(flows),
        stats=compute_flow_stats(flows),
    )
