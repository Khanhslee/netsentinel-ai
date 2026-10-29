"""Port-scan detection (TCP SYN scans and UDP sweeps)."""
from __future__ import annotations

from typing import List

from ..config import DetectionConfig
from ..mitre import kill_chain_stage_for, mitre_for
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
        packets = sum(max(1, f.src_packets) for f in members)
        window = max(span, 1e-6)
        ordered = sorted(t for t in times if t)
        first_seen, last_seen = (ordered[0], ordered[-1]) if ordered else (0.0, 0.0)
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
                iocs=[src_ip, dst_ip],
                features={
                    "kind": kind,
                    "distinct_ports": len(ports),
                    "ports": sorted(ports)[:50],
                    "time_span": round(span, 2),
                    # --- forensic evidence (Phase 2) -------------------------
                    "packets_sent": packets,
                    "packets_per_second": round(packets / window, 2),
                    "ports_per_second": round(len(ports) / window, 2),
                    "unique_src_ports": len({f.src_port for f in members}),
                    "port_range": {
                        "min": min(ports),
                        "max": max(ports),
                    },
                    "well_known_ports_hit": sum(1 for p in ports if p < 1024),
                    "scan_window_limit_sec": cfg.scan_window_seconds,
                    "threshold_ports": cfg.scan_min_ports,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                },
                mitre_technique=mitre.get("technique_id", ""),
                mitre_tactic=mitre.get("tactic", ""),
                kill_chain_stage=kill_chain_stage_for("port_scan"),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )
    return events
