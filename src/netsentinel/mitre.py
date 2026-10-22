"""Lightweight MITRE ATT&CK knowledge base used for event enrichment.

Kept dependency-free so detection, LLM reasoning and response generation all
share the same mapping. Augment with the full STIX export for production use.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# event_type -> ATT&CK mapping (technique, sub-technique, tactic + guidance).
EVENT_MITRE: Dict[str, Dict[str, Any]] = {
    "beacon": {
        "technique_id": "T1071",
        "sub_technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Repeated, periodic outbound connections consistent with C2 beaconing.",
        "mitigation": [
            "Block the destination IP/domain and port at the perimeter firewall/proxy.",
            "Isolate the source host and inspect for additional persistence or implants.",
            "Hunt for outbound connections on the same cadence across the fleet.",
            "Enable egress filtering and DNS/Domain fronting inspection.",
        ],
    },
    "dga": {
        "technique_id": "T1568",
        "sub_technique_id": "T1568.002",
        "name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "description": "High-entropy, algorithmically generated domain names indicate DGA-based C2 fallback.",
        "mitigation": [
            "Sinkhole the affected domains via DNS and block via proxy category.",
            "Deploy a DGA detection rule/model on the recursive resolver.",
            "Identify and remediate the implant on the source host.",
            "Monitor NXDOMAIN response volume for the same hosts.",
        ],
    },
    "nxdomain_storm": {
        "technique_id": "T1568",
        "sub_technique_id": "T1568.002",
        "name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "description": "A burst of failed (NXDOMAIN) lookups under one domain family suggests DGA probing.",
        "mitigation": [
            "Add the parent/sinkhole domain to the DNS blocklist.",
            "Correlate NXDOMAIN volume with endpoint process telemetry.",
            "Alert analysts on sustained NXDOMAIN storms from a single host.",
        ],
    },
    "dns_tunneling": {
        "technique_id": "T1071",
        "sub_technique_id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "description": "Repeated, unusually long or TXT-type DNS queries to one domain can encode tunnelled data.",
        "mitigation": [
            "Enforce DNS filtering and rate-limit queries per host.",
            "Block the tunnel domain and pivot to sinkholing.",
            "Inspect originating process for DNS tunneling tooling.",
            "Flag long query names / high TXT query volume via IDS.",
        ],
    },
    "port_scan": {
        "technique_id": "T1046",
        "sub_technique_id": "",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Rapid probing of many ports on a target indicates reconnaissance/scanning.",
        "mitigation": [
            "Block/quarantine the scanning host.",
            "Review exposed services on the targeted host for further attacks.",
            "Tune IDS thresholds to alert on horizontal/vertical scans.",
        ],
    },
    "exfiltration": {
        "technique_id": "T1041",
        "sub_technique_id": "",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Large asymmetric outbound transfer with little return traffic may indicate data exfiltration.",
        "mitigation": [
            "Block the destination immediately and inspect the host.",
            "Verify whether the transfer matches a known business process.",
            "Enable DLP and egress volume alerting.",
        ],
    },
}


def mitre_for(event_type: str) -> Dict[str, Any]:
    """Return the MITRE mapping for an event type (empty dict if unknown)."""
    return EVENT_MITRE.get(event_type, {})


def technique_label(info: Dict[str, Any]) -> str:
    sub = info.get("sub_technique_id") or ""
    return f"{info.get('technique_id', '')}" + (f" ({sub})" if sub else "")
