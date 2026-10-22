"""Incident-response playbook generation."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..mitre import mitre_for
from ..models import SuspiciousEvent
from ..llm.schemas import ThreatAssessment


def generate_playbook(
    event: SuspiciousEvent,
    assessment: Optional[ThreatAssessment] = None,
) -> Dict[str, Any]:
    """Build a mitigation playbook for a suspicious event."""
    mitre = mitre_for(event.event_type) or {}
    mitre_id = (
        mitre.get("sub_technique_id")
        or mitre.get("technique_id")
        or event.mitre_technique
        or ""
    )
    steps: List[str] = []
    if assessment and assessment.recommended_actions:
        steps = list(assessment.recommended_actions)
    else:
        steps = list(mitre.get("mitigation", []))

    return {
        "event_id": event.event_id,
        "title": f"Mitigation playbook - {event.event_type.replace('_', ' ').title()}",
        "priority": (assessment.severity if assessment else None) or event.severity,
        "affected_host": event.src_ip,
        "destination": (f"{event.dst_ip}:{event.dst_port}" if event.dst_ip else None),
        "mitre_technique": mitre_id,
        "technique_name": mitre.get("name", ""),
        "tactic": mitre.get("tactic", ""),
        "iocs": event.iocs,
        "steps": [{"order": i + 1, "action": s} for i, s in enumerate(steps)],
    }
