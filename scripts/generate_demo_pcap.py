"""Generate a synthetic demo PCAP containing benign + malicious traffic.

The malicious patterns exercise every detector in NetSentinel:
  - beacon      : periodic C2 connections (every 60 s)
  - dga         : high-entropy algorithmic domains queried by one host
  - nxdomain    : NXDOMAIN responses for those domains
  - dns_tunnel  : long-label TXT queries to a single tunnel domain
  - port_scan   : rapid SYN sweep across many ports
  - exfil       : large asymmetric outbound transfer

Usage:
    python scripts/generate_demo_pcap.py [output.pcap]
"""
from __future__ import annotations

import random
import string
import sys

DNS_SERVER = "8.8.8.8"


def dga_name(seed: int) -> str:
    """Generate a DGA-style registered domain (one random label + a TLD)."""
    rng = random.Random(seed)
    label = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(12, 16)))
    tld = rng.choice(["com", "net", "org", "info"])
    return f"{label}.{tld}"


def build_packets() -> list:
    from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP  # type: ignore

    packets = []

    def add(pkt, t: float):
        pkt.time = t
        packets.append(pkt)

    # -- benign: normal DNS + a little web traffic -------------------------
    for i in range(3):
        add(
            IP(src=f"10.0.0.{i + 1}", dst=DNS_SERVER)
            / UDP(sport=20000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"host{i}.example.com")),
            t=1.0 + i,
        )
    for i in range(2):
        add(
            IP(src="10.0.0.20", dst="93.184.216.34")
            / TCP(sport=20040 + i, dport=80, flags="S"),
            t=2.0 + i,
        )

    # -- 1) beacon: 10.0.0.5 -> 203.0.113.10:8080 every 60 s ---------------
    for i in range(10):
        add(
            IP(src="10.0.0.5", dst="203.0.113.10")
            / TCP(sport=40000 + i, dport=8080, flags="S"),
            t=100.0 + i * 60.0,
        )

    # -- 2) port scan: 10.0.0.7 -> 10.0.0.50 ports 1..40 -------------------
    for i, port in enumerate(range(1, 41)):
        add(
            IP(src="10.0.0.7", dst="10.0.0.50")
            / TCP(sport=50000 + i, dport=port, flags="S"),
            t=200.0 + i * 0.1,
        )

    # -- 3) DGA + 4) NXDOMAIN: 10.0.0.6 queries high-entropy domains --------
    for i in range(15):
        domain = dga_name(i)
        add(
            IP(src="10.0.0.6", dst=DNS_SERVER)
            / UDP(sport=30000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain)),
            t=300.0 + i,
        )
        # NXDOMAIN response for the same query
        add(
            IP(src=DNS_SERVER, dst="10.0.0.6")
            / UDP(sport=53, dport=30000 + i)
            / DNS(qr=1, rcode=3, qd=DNSQR(qname=domain)),
            t=300.0 + i + 0.05,
        )

    # -- 5) DNS tunneling: 10.0.0.8 -> long-label TXT queries ---------------
    rng = random.Random(42)
    for i in range(12):
        label = "".join(rng.choices(string.ascii_lowercase + string.digits, k=30))
        domain = f"{label}.tunnel.evil"
        add(
            IP(src="10.0.0.8", dst=DNS_SERVER)
            / UDP(sport=31000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype="TXT")),
            t=400.0 + i,
        )

    # -- 6) exfiltration: 10.0.0.9 -> 198.51.100.5:443 huge upload ----------
    # Split into 25 x 60 KB segments (a single TCP segment must stay < 65535 B).
    for i in range(25):
        add(
            IP(src="10.0.0.9", dst="198.51.100.5")
            / TCP(sport=32000, dport=443, flags="PA")
            / Raw(load=b"A" * 60_000),
            t=500.0 + i * 0.01,
        )

    return packets


def main() -> int:
    from scapy.all import wrpcap  # type: ignore

    output = sys.argv[1] if len(sys.argv) > 1 else "data/demo.pcap"
    packets = build_packets()
    wrpcap(output, packets)
    print(f"Wrote {len(packets)} packets to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
