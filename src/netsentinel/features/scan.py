"""Port-scan detection (TCP SYN scans and UDP sweeps)."""
from __future__ import annotations

from typing import List

from ..config import DetectionConfig
from ..mitre import mitre_for
from ..models import Flow, SuspiciousEvent
from .flows import group_by


def detect_scans(flows: List[Flow], cfg: DetectionConfig) -> List[SuspiciousEvent]:
    """Detect many distinct ports probed by a single host against a target."""
    mitre = mitre_for("port_scan")
    events: List[SuspiciousEvent] = []

    # TCP SYN scans: track flows that carry a SYN flag.
    syn_flows = [f for f in flows if f.proto == "tcp" and "S" in f.tcp_flags]
    events.extend(_scan_events(syn_flows, cfg, mitre, "SYN"))

    # UDP sweeps: no SYN flag exists, so flag distinct-destination-port volume.
    udp_flows = [f for f in flows if f.proto == "udp" and f.src_packets > 0]
    events.extend(_scan_events(udp_flows, cfg, mitre, "UDP"))

    return events


def _scan_events(candidate: List[Flow], cfg: DetectionConfig, mitre: dict, kind: str) -> List[SuspiciousEvent]:
    events: List[SuspiciousEvent] = []
    groups = group_by(candidate, key_fn=lambda f: (f.src_ip, f.dst_ip))
    for (src_ip, dst_ip), members in groups:
        ports = {f.dst_port for f in members}
        if len(ports) < cfg.scan_min_ports:
            continue
        times = [f.start_time for f in members]
        span = (max(times) - min(times)) if len(times) > 1 else 0.0
        if span > cfg.scan_window_seconds:
            continue
        events.append(
            SuspiciousEvent(
                event_type="port_scan",
                severity="high",
                description=(
                    f"{src_ip} probed {len(ports)} ports on {dst_ip} "
                    f"({kind}) within {span:.1f}s, indicating network reconnaissance."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                iocs=[src_ip],
                features={
                    "kind": kind,
                    "distinct_ports": len(ports),
                    "ports": sorted(ports)[:50],
                    "time_span": round(span, 2),
                },
                mitre_technique=mitre.get("technique_id", ""),
            )
        )
    return events
