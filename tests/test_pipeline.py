"""End-to-end integration test: generate a demo PCAP and run the full pipeline."""
import os
import sys
import tempfile

import pytest

scapy = pytest.importorskip("scapy")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from netsentinel.ingest.pcap_parser import parse_pcap  # noqa: E402
from netsentinel.pipeline import analyze_flows  # noqa: E402
from generate_demo_pcap import build_packets  # noqa: E402


def test_full_pipeline_on_demo_pcap():
    packets = build_packets()
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        from scapy.all import wrpcap

        wrpcap(tmp.name, packets)
        tmp_path = tmp.name

    try:
        flows = parse_pcap(tmp_path)
        assert len(flows) > 0

        result = analyze_flows(flows, use_llm=False)
        types = {e.event_type for e in result.report.events}

        assert "beacon" in types
        assert "port_scan" in types
        assert "dga" in types
        assert "nxdomain_storm" in types
        assert "dns_tunneling" in types
        assert "exfiltration" in types

        # Every event must produce a playbook and assessment.
        assert len(result.assessments) == len(result.report.events)
        assert len(result.playbooks) == len(result.report.events)
    finally:
        os.unlink(tmp_path)
