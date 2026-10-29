"""Navigator 4.5 layers map observed behaviours once per technique/tactic."""
import json

from netsentinel.response.mitre_navigator import export_mitre_layer, generate_mitre_layer


def test_navigator_v45_mappings_and_deduplication(tmp_path):
    kinds = ["beacon", "port_scan", "dga", "nxdomain_storm", "dns_tunneling", "exfiltration"]
    data = {"events": [{"event": {"event_type": kind, "severity": "high", "src_ip": "10.0.0.8",
                                  "description": f"Observed {kind}"}} for kind in kinds]}
    layer = generate_mitre_layer(data)
    assert layer["versions"] == {"attack": "15", "navigator": "4.9.1", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1071.001", "T1046", "T1568.002", "T1071.004", "T1041"}
    assert all(t["score"] == 80 and t["color"] == "#ef4444" for t in layer["techniques"])
    dga = next(t for t in layer["techniques"] if t["techniqueID"] == "T1568.002")
    assert "DGA" in dga["comment"] and "NXDOMAIN_STORM" in dga["comment"]
    assert json.loads(export_mitre_layer(data, tmp_path / "layer.json").read_text(encoding="utf-8")) == layer


def test_navigator_empty_and_unknown_events_are_valid():
    layer = generate_mitre_layer({"events": [{"event_type": "unknown", "mitre_technique": "INVALID"}]})
    assert layer["techniques"] == []
    assert generate_mitre_layer({"events": []})["techniques"] == []
