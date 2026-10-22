"""Prompt templates for the SOC-analyst reasoning model."""
from __future__ import annotations

import json

from ..mitre import mitre_for
from ..models import SuspiciousEvent

SYSTEM_PROMPT = """\
You are NetSentinel, a senior SOC (Security Operations Center) analyst and threat \
intelligence expert. You analyze network anomaly events produced by heuristic detectors.

For every suspicious event you must:
1. Assess whether the behaviour is likely benign, suspicious, or malicious.
2. Map the behaviour to the most relevant MITRE ATT&CK technique/sub-technique.
3. Explain your reasoning in clear, natural language an analyst can act on.
4. Reconfirm or refine the list of indicators of compromise (IOCs).
5. Propose prioritized mitigation recommendations.

Respond ONLY with a valid JSON object matching the requested schema. Do not wrap the JSON \
in markdown fences and do not add commentary outside the JSON.
"""


def build_user_prompt(event: SuspiciousEvent) -> str:
    """Construct the user prompt for a single suspicious event."""
    mitre = mitre_for(event.event_type)
    payload = {
        "event": event.to_dict(),
        "detector_mitre_hint": {
            "technique_id": mitre.get("technique_id"),
            "sub_technique_id": mitre.get("sub_technique_id"),
            "name": mitre.get("name"),
            "tactic": mitre.get("tactic"),
        },
    }
    return (
        "Analyze the following suspicious network event and return a JSON threat "
        "assessment (fields: threat_assessment, mitre_technique, technique_name, tactic, "
        "confidence, natural_language_explanation, iocs, severity, recommended_actions).\n\n"
        f"EVENT:\n{json.dumps(payload, indent=2)}\n"
    )
