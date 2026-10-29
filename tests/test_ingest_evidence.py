"""Preserve measurements needed by the forensic detector metadata."""
import pytest

from netsentinel.config import DetectionConfig
from netsentinel.features.dns import detect_nxdomain_storm
from netsentinel.ingest.flow_parser import flows_from_dicts
from netsentinel.models import Flow


def test_pcap_reverse_bytes_and_repeated_dns_are_preserved():
    pytest.importorskip("scapy")
    from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP
    from netsentinel.ingest.pcap_parser import aggregate_packets

    packets = [IP(src="10.0.0.1", dst="203.0.113.1") / TCP(sport=5000, dport=443) / Raw(b"A" * 100),
               IP(src="203.0.113.1", dst="10.0.0.1") / TCP(sport=443, dport=5000) / Raw(b"B" * 50)]
    dns = IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=3000, dport=53) / DNS(qd=DNSQR(qname="example.test"))
    flows = aggregate_packets(packets + [dns, dns.copy()])
    assert len(flows) == 3
    assert (flows[0].src_bytes, flows[0].dst_bytes) == (100, 50)
    assert flows[0].src_packets + flows[0].dst_packets == 2
    assert sum(bool(f.dns_qname) for f in flows) == 2


def test_flow_metadata_duration_and_nxdomain_ratio_use_all_responses():
    flow = flows_from_dicts([{"src": "10.0.0.1", "dst": "10.0.0.2", "ts": 100, "duration": 5}])[0]
    assert flow.duration == 5
    responses = [Flow("8.8.8.8", "10.0.0.6", 53, 3000+i, "udp", dns_qname=f"host{i}.example.test",
                      dns_rcode=3 if i < 10 else 0, dns_is_query=False) for i in range(20)]
    evidence = detect_nxdomain_storm(responses, DetectionConfig())[0].features
    assert evidence["nxdomain_ratio"] == 0.5
