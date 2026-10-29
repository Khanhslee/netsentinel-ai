"""Data exfiltration detection: large asymmetric outbound transfers."""
from __future__ import annotations

from typing import List

from ..config import DetectionConfig
from ..mitre import kill_chain_stage_for, mitre_for
from ..models import Flow, SuspiciousEvent
from .flows import safe_div, throughput


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
                    # --- forensic evidence (Phase 2) -------------------------
                    "upload_download_ratio": round(ratio, 2),
                    "ratio_denominator_bytes": max(1, f.dst_bytes),
                    "download_observed": f.dst_bytes > 0,
                    "ratio_note": "upload / max(1, download); no reply bytes means a guarded ratio, not measured infinity",
                    "download_upload_ratio": round(
                        safe_div(f.dst_bytes, max(1, f.src_bytes)), 3
                    ),
                    "bytes_out": f.src_bytes,
                    "bytes_in": f.dst_bytes,
                    "total_bytes": f.total_bytes,
                    "src_packets": f.src_packets,
                    "dst_packets": f.dst_packets,
                    "duration_sec": round(f.duration, 3),
                    "throughput_bps": throughput(f.src_bytes, f.duration),
                    "avg_packet_size": round(
                        safe_div(f.src_bytes, max(1, f.src_packets)), 1
                    ),
                    "threshold_bytes": cfg.exfil_min_bytes,
                    "threshold_ratio": cfg.exfil_upload_ratio,
                    "first_seen": f.start_time,
                    "last_seen": f.end_time or f.start_time,
                },
                mitre_technique=mitre.get("technique_id", ""),
                mitre_tactic=mitre.get("tactic", ""),
                kill_chain_stage=kill_chain_stage_for("exfiltration"),
                first_seen=f.start_time,
                last_seen=f.end_time or f.start_time,
            )
        )
    return events
