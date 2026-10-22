"""Beacon / C2 detection: repeated connections at a near-constant cadence."""
from __future__ import annotations

from typing import List

from ..config import DetectionConfig
from ..mitre import mitre_for
from ..models import Flow, SuspiciousEvent
from .flows import group_by, interarrival_stats


def detect_beacons(flows: List[Flow], cfg: DetectionConfig) -> List[SuspiciousEvent]:
    """Detect periodic outbound beacons by inter-arrival jitter analysis."""
    events: List[SuspiciousEvent] = []
    mitre = mitre_for("beacon")

    groups = group_by(flows, key_fn=lambda f: (f.src_ip, f.dst_ip, f.dst_port, f.proto))
    for (src_ip, dst_ip, dst_port, proto), members in groups:
        times = [f.start_time for f in members]
        mean, std, count = interarrival_stats(times)
        if count + 1 < cfg.beacon_min_connections:
            continue
        if mean <= 0 or mean < cfg.beacon_min_interval:
            continue

        jitter = std / mean
        if jitter > cfg.beacon_jitter_ratio:
            continue

        severity = _beacon_severity(jitter)
        events.append(
            SuspiciousEvent(
                event_type="beacon",
                severity=severity,
                description=(
                    f"{src_ip} maintained {count + 1} {proto.upper()} connections to "
                    f"{dst_ip}:{dst_port} at a mean interval of {mean:.1f}s "
                    f"(jitter {jitter:.3f}), consistent with C2 beaconing."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                iocs=[dst_ip, f"{dst_ip}:{dst_port}"],
                features={
                    "proto": proto,
                    "connections": count + 1,
                    "mean_interval": round(mean, 3),
                    "std_interval": round(std, 3),
                    "jitter_ratio": round(jitter, 4),
                },
                mitre_technique=mitre.get("sub_technique_id") or mitre.get("technique_id", ""),
            )
        )
    return events


def _beacon_severity(jitter: float) -> str:
    if jitter <= 0.02:
        return "critical"
    if jitter <= 0.05:
        return "high"
    if jitter <= 0.1:
        return "medium"
    return "low"
