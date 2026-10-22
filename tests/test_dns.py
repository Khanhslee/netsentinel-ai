"""Unit tests for DNS anomaly detection."""
from netsentinel.config import DetectionConfig
from netsentinel.features.dns import (
    detect_dga,
    detect_dns_tunneling,
    detect_nxdomain_storm,
)
from netsentinel.models import Flow


def _dns_flow(src, qname, qtype="A", rcode=0, is_query=True):
    return Flow(
        src_ip=src,
        dst_ip="8.8.8.8",
        src_port=30000,
        dst_port=53,
        proto="udp",
        dns_qname=qname,
        dns_qtype=qtype,
        dns_rcode=rcode,
        dns_is_query=is_query,
    )


def test_detects_high_entropy_domains():
    cfg = DetectionConfig()
    flows = [_dns_flow("10.0.0.6", f"qwzxev-krtbnm-{i}jhd.com") for i in range(5)]
    events = detect_dga(flows, cfg)
    assert len(events) == 1
    assert events[0].event_type == "dga"
    assert events[0].src_ip == "10.0.0.6"


def test_ignores_low_entropy_domains():
    cfg = DetectionConfig()
    flows = [_dns_flow("10.0.0.1", "www.example.com")]
    assert detect_dga(flows, cfg) == []


def test_detects_nxdomain_storm():
    cfg = DetectionConfig()
    flows = []
    for i in range(15):
        # NXDOMAIN responses attributed to the querying host via dst_ip.
        flows.append(
            Flow(
                src_ip="8.8.8.8",
                dst_ip="10.0.0.6",
                src_port=53,
                dst_port=30000 + i,
                proto="udp",
                dns_qname=f"qzx-{i}abcd.bank.example",
                dns_qtype="A",
                dns_rcode=3,
                dns_is_query=False,
            )
        )
    events = detect_nxdomain_storm(flows, cfg)
    assert len(events) == 1
    assert events[0].event_type == "nxdomain_storm"
    assert events[0].src_ip == "10.0.0.6"


def test_detects_dns_tunneling():
    cfg = DetectionConfig()
    flows = [
        _dns_flow("10.0.0.8", "a" * 30 + ".tunnel.evil", qtype="TXT")
        for _ in range(10)
    ]
    events = detect_dns_tunneling(flows, cfg)
    assert len(events) == 1
    assert events[0].event_type == "dns_tunneling"
