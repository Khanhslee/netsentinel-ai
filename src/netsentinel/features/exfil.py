"""Data exfiltration detection: large asymmetric outbound transfers."""
from __future__ import annotations

from typing import List

from ..config import DetectionConfig
from ..mitre import mitre_for
from ..models import Flow, SuspiciousEvent


def detect_exfiltration(flows: List[Flow], cfg: DetectionConfig) -> List[SuspiciousEvent]:
    """Flag large outbound flows with little to no return traffic (exfil signal)."""
    mitre = mitre_for("exfiltration")
    events: List[SuspiciousEvent] = []

    for f in flows:
        if f.proto not in ("tcp", "udp"):
            continue
        if f.src_bytes < cfg.exfil_min_bytes:
            continue
        ratio = f.src_bytes / max(1, f.dst_bytes)
        if ratio < cfg.exfil_upload_ratio:
            continue
        events.append(
            SuspiciousEvent(
                event_type="exfiltration",
                severity="high" if f.src_bytes >= cfg.exfil_min_bytes * 10 else "medium",
                description=(
                    f"{f.src_ip} transferred {f.src_bytes:,} bytes to {f.dst_ip}:{f.dst_port} "
                    f"while receiving only {f.dst_bytes:,} bytes back (ratio {ratio:.0f}:1), "
                    f"a potential data exfiltration channel."
                ),
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                dst_port=f.dst_port,
                iocs=[f.dst_ip, f"{f.dst_ip}:{f.dst_port}"],
                features={
                    "proto": f.proto,
                    "dst_port": f.dst_port,
                    "src_bytes": f.src_bytes,
                    "dst_bytes": f.dst_bytes,
                    "upload_ratio": round(ratio, 1),
                },
                mitre_technique=mitre.get("technique_id", ""),
            )
        )
    return events
