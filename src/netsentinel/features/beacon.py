"""Beacon / C2 detection: repeated connections at a near-constant cadence."""
from __future__ import annotations

import statistics
from typing import List

from ..config import DetectionConfig
from ..mitre import kill_chain_stage_for, mitre_for
from ..models import Flow, SuspiciousEvent
from .flows import coefficient_of_variation, group_by, interarrival_stats


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

        ordered = sorted(t for t in times if t > 0)
        deltas = [b - a for a, b in zip(ordered, ordered[1:])]
        first_seen, last_seen = (ordered[0], ordered[-1]) if ordered else (0.0, 0.0)

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
                    # --- forensic evidence (Phase 2) -------------------------
                    "coefficient_of_variation": coefficient_of_variation(mean, std),
                    "mean_delta_t_sec": round(mean, 3),
                    "std_delta_t_sec": round(std, 3),
                    "median_delta_t_sec": round(statistics.median(deltas), 3) if deltas else 0.0,
                    "min_delta_t_sec": round(min(deltas), 3) if deltas else 0.0,
                    "max_delta_t_sec": round(max(deltas), 3) if deltas else 0.0,
                    "jitter_pct": round(jitter * 100, 2),
                    "periodicity_score": round(max(0.0, 1.0 - jitter), 4),
                    "observation_window_sec": round(last_seen - first_seen, 2),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "destination": f"{dst_ip}:{dst_port}",
                },
                mitre_technique=mitre.get("sub_technique_id") or mitre.get("technique_id", ""),
                mitre_tactic=mitre.get("tactic", ""),
                kill_chain_stage=kill_chain_stage_for("beacon"),
                first_seen=first_seen,
                last_seen=last_seen,
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
