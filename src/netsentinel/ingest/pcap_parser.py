"""PCAP parsing (via scapy) -> list of unidirectional Flow objects.

This module is deliberately lazy about importing scapy so that other parts of
the pipeline (and the test suite) keep working even if scapy is not installed.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..models import Flow

DNS_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY",
}


def read_packets(path) -> list:
    """Read packets from a pcap/pcapng file into a list (uses scapy)."""
    from scapy.all import rdpcap  # type: ignore

    return list(rdpcap(str(path)))


def parse_pcap(path) -> List[Flow]:
    """Parse a pcap/pcapng file and aggregate packets into flows."""
    return aggregate_packets(read_packets(path))


def aggregate_packets(packets) -> List[Flow]:
    """Aggregate raw packets (any scapy-compatible iterable) into flows."""
    flows: Dict[tuple, Flow] = {}
    order: List[tuple] = []

    for pkt in packets:
        flow = _packet_to_flow(pkt)
        if flow is None:
            continue
        key = flow.key
        if key in flows:
            flows[key].merge(flow)
        else:
            flows[key] = flow
            order.append(key)
    return [flows[k] for k in order]


def _packet_to_flow(pkt) -> Optional[Flow]:
    """Convert a single packet into a Flow, or None if it has no IP layer."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    src_ip = str(ip.src)
    dst_ip = str(ip.dst)
    proto_num = int(ip.proto)
    ts = float(getattr(pkt, "time", 0.0) or 0.0)

    src_port = 0
    dst_port = 0
    proto = str(proto_num)
    tcp_flags = ""
    payload_bytes = 0

    if pkt.haslayer(TCP):
        proto = "tcp"
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = str(getattr(tcp, "flags", "") or "")
        payload_bytes = _payload_len(tcp)
    elif pkt.haslayer(UDP):
        proto = "udp"
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        payload_bytes = _payload_len(udp)
    elif pkt.haslayer(ICMP):
        proto = "icmp"
        payload_bytes = _payload_len(ip)

    flow = Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        src_bytes=payload_bytes,
        src_packets=1,
        start_time=ts,
        end_time=ts,
        tcp_flags=tcp_flags,
    )

    dns_qname, dns_qtype, dns_rcode, dns_is_query = _extract_dns(pkt)
    flow.dns_qname = dns_qname
    flow.dns_qtype = dns_qtype
    flow.dns_rcode = dns_rcode
    flow.dns_is_query = dns_is_query
    return flow


def _payload_len(layer) -> int:
    try:
        return int(len(layer.payload))
    except Exception:
        return 0


def _extract_dns(pkt) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[bool]]:
    """Extract (qname, qtype, rcode, is_query) from a DNS layer if present."""
    try:
        from scapy.layers.dns import DNS  # type: ignore

        if not pkt.haslayer(DNS):
            return None, None, None, None
        dns = pkt[DNS]
        qname: Optional[str] = None
        qtype: Optional[str] = None
        if getattr(dns, "qd", None) and len(dns.qd) > 0:
            q = dns.qd[0]
            qname = _decode_qname(getattr(q, "qname", None))
            qt = getattr(q, "qtype", None)
            if qt is not None:
                qtype = DNS_TYPE_NAMES.get(int(qt), str(qt))
        is_query = bool(int(getattr(dns, "qr", 0)) == 0)
        rcode = int(getattr(dns, "rcode", 0))
        return qname, qtype, rcode, is_query
    except Exception:
        return None, None, None, None


def _decode_qname(raw) -> Optional[str]:
    """Decode a DNS qname (dotted string or wire-format length-prefixed labels)."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw.rstrip(".")
    if not isinstance(raw, bytes):
        return str(raw).rstrip(".")

    labels: List[str] = []
    i, n = 0, len(raw)
    while i < n:
        length = raw[i]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            break  # compression pointer - not followed inline
        i += 1
        if i + length > n:
            break
        labels.append(raw[i : i + length].decode("utf-8", errors="replace"))
        i += length
    if labels:
        return ".".join(labels)
    return raw.decode("utf-8", errors="replace").rstrip(".")
