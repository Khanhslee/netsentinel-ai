"""Core data models shared across the NetSentinel pipeline."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Flow:
    """An origin-oriented session or DNS observation with directional counters."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # "tcp" | "udp" | "icmp" | ...
    src_bytes: int = 0
    dst_bytes: int = 0
    src_packets: int = 0
    dst_packets: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    tcp_flags: str = ""
    # Optional DNS metadata (populated when the flow carries DNS traffic)
    dns_qname: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_rcode: Optional[int] = None
    dns_is_query: Optional[bool] = None

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def total_bytes(self) -> int:
        return self.src_bytes + self.dst_bytes

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto)

    def merge(self, other: "Flow") -> "Flow":
        """Merge `other` into this flow (same 5-tuple)."""
        self.src_bytes += other.src_bytes
        self.dst_bytes += other.dst_bytes
        self.src_packets += other.src_packets
        self.dst_packets += other.dst_packets
        self.start_time = min(self.start_time, other.start_time) if self.start_time else other.start_time
        self.end_time = max(self.end_time, other.end_time)
        if other.tcp_flags:
            self.tcp_flags = other.tcp_flags
        if other.dns_qname:
            self.dns_qname = other.dns_qname
            self.dns_qtype = other.dns_qtype
            self.dns_rcode = other.dns_rcode
            self.dns_is_query = other.dns_is_query
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "src_bytes": self.src_bytes,
            "dst_bytes": self.dst_bytes,
            "src_packets": self.src_packets,
            "dst_packets": self.dst_packets,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "tcp_flags": self.tcp_flags,
            "dns_qname": self.dns_qname,
            "dns_qtype": self.dns_qtype,
            "dns_rcode": self.dns_rcode,
            "dns_is_query": self.dns_is_query,
        }


@dataclass
class SuspiciousEvent:
    """A suspicious behaviour surfaced by one of the detection heuristics."""

    event_type: str  # beacon | dga | nxdomain_storm | dns_tunneling | port_scan | exfiltration
    severity: str  # low | medium | high | critical
    description: str
    src_ip: str
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    iocs: List[str] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: str = ""
    mitre_tactic: str = ""
    kill_chain_stage: str = ""
    #: Epoch seconds of the first/last contributing flow (0.0 when unknown).
    first_seen: float = 0.0
    last_seen: float = 0.0
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def timestamp(self) -> float:
        """Sort key for the correlation timeline."""
        return self.first_seen or self.last_seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "iocs": self.iocs,
            "features": self.features,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "kill_chain_stage": self.kill_chain_stage,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def stable_hash(text: str) -> str:
    """Return a short stable hash used for YARA/rule identifiers."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
