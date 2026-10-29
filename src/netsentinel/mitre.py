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


# ---------------------------------------------------------------------------
# Kill-chain model
# ---------------------------------------------------------------------------
#: Lockheed-Martin kill-chain stages in attack order. Used by the correlator to
#: turn a bag of events into an ordered attack narrative.
KILL_CHAIN_STAGES: tuple = (
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
)

#: event_type -> kill-chain stage
EVENT_KILL_CHAIN: Dict[str, str] = {
    "port_scan": "Reconnaissance",
    "dga": "Command and Control",
    "nxdomain_storm": "Command and Control",
    "beacon": "Command and Control",
    "dns_tunneling": "Command and Control",
    "exfiltration": "Actions on Objectives",
}

#: Canonical ATT&CK tactic slugs (Navigator uses lower-case, dash-separated).
_NAVIGATOR_TACTICS = {
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}


def mitre_for(event_type: str) -> Dict[str, Any]:
    """Return the MITRE mapping for an event type (empty dict if unknown)."""
    return EVENT_MITRE.get(event_type, {})


def technique_id_for(event_type: str) -> str:
    """Preferred technique id (sub-technique when available)."""
    info = mitre_for(event_type)
    return info.get("sub_technique_id") or info.get("technique_id", "")


def tactic_for(event_type: str) -> str:
    return mitre_for(event_type).get("tactic", "")


def kill_chain_stage_for(event_type: str) -> str:
    return EVENT_KILL_CHAIN.get(event_type, "Exploitation")


def kill_chain_order(stage: str) -> int:
    """Position of a stage in the kill chain (unknown stages sort last)."""
    try:
        return KILL_CHAIN_STAGES.index(stage)
    except ValueError:
        return len(KILL_CHAIN_STAGES)


def navigator_tactic(tactic: str) -> str:
    """Convert a human tactic name into its ATT&CK Navigator slug."""
    return _NAVIGATOR_TACTICS.get(tactic, tactic.strip().lower().replace(" ", "-"))


def tactic_description(event_type: str) -> str:
    info = mitre_for(event_type)
    return f"{info.get('technique_id', '')} {info.get('name', '')}".strip()


def technique_label(info: Dict[str, Any]) -> str:
    sub = info.get("sub_technique_id") or ""
    return f"{info.get('technique_id', '')}" + (f" ({sub})" if sub else "")
