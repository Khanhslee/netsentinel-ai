"""Unit tests for beacon detection."""
from netsentinel.config import DetectionConfig
from netsentinel.features.beacon import detect_beacons
from netsentinel.models import Flow


def _flow(src_port, start_time):
    return Flow(
        src_ip="10.0.0.5",
        dst_ip="203.0.113.10",
        src_port=src_port,
        dst_port=8080,
        proto="tcp",
        start_time=start_time,
        end_time=start_time,
        tcp_flags="S",
    )


def test_detects_periodic_beacon():
    cfg = DetectionConfig()
    flows = [_flow(40000 + i, 100.0 + i * 60.0) for i in range(10)]
    events = detect_beacons(flows, cfg)
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "beacon"
    assert e.dst_ip == "203.0.113.10"
    assert e.dst_port == 8080
    assert e.features["jitter_ratio"] <= 0.15


def test_ignores_irregular_connections():
    cfg = DetectionConfig()
    times = [100.0, 105.0, 120.0, 150.0, 400.0]
    flows = [_flow(40000 + i, t) for i, t in enumerate(times)]
    assert detect_beacons(flows, cfg) == []


def test_ignores_too_few_connections():
    cfg = DetectionConfig()
    flows = [_flow(40000 + i, 100.0 + i * 60.0) for i in range(3)]
    assert detect_beacons(flows, cfg) == []
