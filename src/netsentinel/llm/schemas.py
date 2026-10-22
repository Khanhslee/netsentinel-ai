"""Structured output schemas for AI threat reasoning."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..mitre import mitre_for
from ..models import SuspiciousEvent


class ThreatAssessment(BaseModel):
    """The structured verdict an LLM returns for one suspicious event."""

    threat_assessment: str = Field(
        description="One-paragraph overall assessment of the threat."
    )
    mitre_technique: str = Field(
        description="Primary MITRE ATT&CK technique/sub-technique ID, e.g. T1071.001."
    )
    technique_name: str = Field(default="", description="Human-readable technique name.")
    tactic: str = Field(default="", description="ATT&CK tactic, e.g. Command and Control.")
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Analyst confidence from 0.0 to 1.0."
    )
    natural_language_explanation: str = Field(
        default="", description="Plain-language reasoning for the analyst."
    )
    iocs: List[str] = Field(
        default_factory=list, description="Indicators of compromise extracted/reconfirmed."
    )
    severity: str = Field(default="medium", description="low | medium | high | critical")
    recommended_actions: List[str] = Field(
        default_factory=list, description="Prioritized mitigation steps."
    )

    @classmethod
    def from_event(cls, event: SuspiciousEvent) -> "ThreatAssessment":
        """Deterministic local fallback when the model API is unavailable."""
        mitre = mitre_for(event.event_type)
        explanation = (
            f"{event.description} This maps to MITRE ATT&CK "
            f"{mitre.get('sub_technique_id') or mitre.get('technique_id', event.mitre_technique)} "
            f"({mitre.get('name', 'unknown technique')})."
        )
        return cls(
            threat_assessment=(
                f"Automated heuristic surfaced a '{event.event_type}' event from "
                f"{event.src_ip}. Local (offline) reasoning applied; no LLM enrichment available."
            ),
            mitre_technique=event.mitre_technique
            or mitre.get("sub_technique_id")
            or mitre.get("technique_id", ""),
            technique_name=mitre.get("name", ""),
            tactic=mitre.get("tactic", ""),
            confidence=0.6,
            natural_language_explanation=explanation,
            iocs=list(event.iocs),
            severity=event.severity,
            recommended_actions=list(mitre.get("mitigation", [])),
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


def assessment_prompt_schema() -> Dict[str, Any]:
    """Return a JSON schema summary to embed in the LLM prompt."""
    return ThreatAssessment.model_json_schema()
