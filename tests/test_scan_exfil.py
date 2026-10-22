"""Unit tests for port-scan and exfiltration detection."""
from netsentinel.config import DetectionConfig
from netsentinel.features.exfil import detect_exfiltration
from netsentinel.features.scan import detect_scans
from netsentinel.models import Flow


def test_detects_syn_scan():
    cfg = DetectionConfig()
    flows = [
        Flow(
            src_ip="10.0.0.7",
            dst_ip="10.0.0.50",
            src_port=50000 + i,
            dst_port=i + 1,
            proto="tcp",
            start_time=10.0 + i * 0.1,
            end_time=10.0 + i * 0.1,
            tcp_flags="S",
        )
        for i in range(30)
    ]
    events = detect_scans(flows, cfg)
    assert len(events) == 1
    assert events[0].event_type == "port_scan"
    assert events[0].features["distinct_ports"] == 30


def test_no_scan_for_single_port():
    cfg = DetectionConfig()
    flows = [
        Flow(
            src_ip="10.0.0.7",
            dst_ip="10.0.0.50",
            src_port=50000 + i,
            dst_port=80,
            proto="tcp",
            tcp_flags="S",
        )
        for i in range(10)
    ]
    assert detect_scans(flows, cfg) == []


def test_detects_exfiltration():
    cfg = DetectionConfig(exfil_min_bytes=1_000_000, exfil_upload_ratio=10.0)
    flows = [
        Flow(
            src_ip="10.0.0.9",
            dst_ip="198.51.100.5",
            src_port=32000,
            dst_port=443,
            proto="tcp",
            src_bytes=2_000_000,
            dst_bytes=100,
            src_packets=1000,
            tcp_flags="PA",
        )
    ]
    events = detect_exfiltration(flows, cfg)
    assert len(events) == 1
    assert events[0].event_type == "exfiltration"
    assert events[0].dst_ip == "198.51.100.5"
