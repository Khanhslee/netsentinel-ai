"""Tests for Suricata/YARA rule and playbook generation."""
from netsentinel.models import SuspiciousEvent
from netsentinel.response import generate_playbook, generate_suricata_rules, generate_yara_rule


def _event():
    return SuspiciousEvent(
        event_type="dns_tunneling",
        severity="high",
        description="long TXT queries to a single domain",
        src_ip="10.0.0.8",
        iocs=["a" * 30 + ".tunnel.evil"],
        mitre_technique="T1071.004",
    )


def test_suricata_rule_for_domain():
    rules = generate_suricata_rules(_event())
    assert len(rules) >= 1
    assert 'dns.query' in rules[0]
    assert "tunnel.evil" in rules[0]


def test_yara_rule_contains_string():
    rule = generate_yara_rule(_event())
    assert rule.startswith("rule NetSentinel_")
    assert "tunnel.evil" in rule
    assert "condition:" in rule


def test_playbook_has_steps():
    pb = generate_playbook(_event())
    assert pb["mitre_technique"] == "T1071.004"
    assert pb["steps"]
    assert pb["steps"][0]["order"] == 1
