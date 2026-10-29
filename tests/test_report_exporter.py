"""Reports preserve evidence and keep untrusted telemetry inert."""
from netsentinel.response.report_exporter import (
    _md, export_html_report, export_markdown_report, isolation_commands,
    render_html_report, render_markdown_report,
)
from netsentinel.response.suricata import build_rule_set, write_ruleset
from netsentinel.response.yara import generate_yara_rule
from netsentinel.models import SuspiciousEvent


def _report(description="Synthetic repeated queries"):
    return {
        "flows_count": 20, "stats": {"packets": 42, "total_bytes": 8192},
        "events": [{"event": {"event_type": "dns_tunneling", "src_ip": "10.0.0.8",
            "severity": "high", "description": description, "iocs": ["tunnel.example"],
            "features": {"shannon_entropy": 4.6, "query_count": 20}},
            "assessment": {"threat_summary": description, "confidence_score": .8,
                           "reasoning_source": "offline-deterministic",
                           "recommended_actions": ["Validate originating process"]}}],
        "suricata_rules": ['alert dns any any -> any 53 (dns.query; content:"tunnel.example"; sid:9000001;)'],
        "yara_rules": ['rule test { strings: $a = "tunnel.example" condition: $a }'],
    }


def test_reports_export_empty_and_complete_evidence(tmp_path):
    data = _report()
    md = export_markdown_report(data, tmp_path / "nested" / "incident.md").read_text(encoding="utf-8")
    document = export_html_report(data, tmp_path / "incident.html").read_text(encoding="utf-8")
    assert "4.6" in md and "4.6" in document
    assert "42" in document and "20" in document
    assert "offline-deterministic" in md and "Offline deterministic analysis" in document
    assert "data-copy=" in document and "netsh advfirewall" in document
    assert '<html lang="en">' in document and 'src="https://' not in document
    empty = render_html_report({"events": [], "stats": {}})
    assert "No suspicious events detected" in empty
    assert "No correlated campaigns" in render_markdown_report({"events": []})


def test_report_escapes_untrusted_telemetry_and_shell_targets():
    attack = '</pre><script>alert("xss")</script><img src=x onerror=alert(1)> | [bad](javascript:alert(1))'
    data = _report(attack)
    data["events"][0]["event"]["src_ip"] = "1.2.3.4; curl attacker"
    data["events"][0]["event"]["iocs"].append(attack)
    data["suricata_rules"].append(attack)
    document = render_html_report(data, title=attack)
    md = render_markdown_report(data, title=attack)
    assert '<script>alert' not in document and '<img src=x' not in document
    assert document.count("<script>") == 1  # Only the static copy-button implementation.
    assert "&lt;script&gt;" in document
    narrative = md.split("## Suricata rules")[0]
    assert '<img src=x' not in narrative and '[bad](javascript:' not in narrative
    assert "curl attacker" not in isolation_commands(data)


def test_markdown_preserves_addresses_decimals_and_escapes_list_marker():
    assert _md("10.0.0.5") == "10.0.0.5"
    assert _md("0.97") == "0.97"
    assert _md("60.0") == "60.0"
    assert _md("1. untrusted list marker") == "1\\. untrusted list marker"
    assert _md("- untrusted list marker") == "\\- untrusted list marker"


def test_rule_set_dedup_sids_and_safe_yara(tmp_path):
    event = SuspiciousEvent(event_type="dns_tunneling", severity="high", description="test",
                            src_ip="10.0.0.8", iocs=["tunnel.example"], mitre_technique="T1071.004")
    other = SuspiciousEvent(event_type="port_scan", severity="high", description="test",
                            src_ip="10.0.0.9", dst_ip="10.0.0.10")
    rules = build_rule_set([event, event, other])
    assert len(rules) == 2
    assert "sid:9000001;" in rules[0] and "sid:9000002;" in rules[1]
    assert "dns.query; content:" in rules[0] and "flow:stateless;" in rules[1]
    other.features["kind"] = "UDP"
    assert build_rule_set([other])[0].startswith("alert udp ")
    assert "flags:S" not in build_rule_set([other])[0]
    other.src_ip = "invalid; injected"
    assert build_rule_set([other]) == []
    domain_event = SuspiciousEvent(event_type="dga", severity="high", description="test",
                                  src_ip="10.0.0.8", iocs=["one.example", "two.example"])
    grouped = build_rule_set([domain_event])
    assert len(grouped) == 1 and "one\\.example|two\\.example" in grouped[0]
    assert write_ruleset(tmp_path / "rules.rules", [event]).exists()
    event.iocs.append('bad"\\\n\x00value')
    event.severity = 'high"\nrule Injected'
    yara = generate_yara_rule(event)
    assert 'author = "NetSentinel AI - Meta Muse Wonder"' in yara
    assert 'mitre_attck = "T1071.004"' in yara and "date =" in yara
    assert '\\x0a' in yara and '\\x00' in yara
    assert '\nrule Injected' not in yara
    second = SuspiciousEvent(event_type=event.event_type, severity=event.severity,
                             description=event.description, src_ip=event.src_ip, iocs=event.iocs)
    assert generate_yara_rule(second).splitlines()[0] != yara.splitlines()[0]
