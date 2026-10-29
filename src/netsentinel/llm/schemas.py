"""Structured output schemas for AI threat reasoning.

The Meta Muse models are asked for a strict JSON object. Everything is validated
through Pydantic so a hallucinated/partial response can never break the
pipeline. Legacy field names (``threat_assessment``, ``mitre_technique``,
``tactic``, ``confidence``) are still accepted and exposed as aliases so older
call sites and tests keep working.
"""
from __future__ import annotations

import re
import ipaddress
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from ..mitre import kill_chain_stage_for, mitre_for, technique_id_for
from ..models import SuspiciousEvent

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$")


class IOCBundle(BaseModel):
    """Typed indicators of compromise (IPs, domains, hashes, JA3, user agents)."""

    ip_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    ja3: List[str] = Field(default_factory=list)
    user_agents: List[str] = Field(default_factory=list)

    model_config = {"extra": "forbid", "strict": True}

    @classmethod
    def from_iocs(cls, iocs: List[str]) -> "IOCBundle":
        return cls(
            ip_addresses=[i for i in iocs if _is_ip(i)],
            domains=[i for i in iocs if _DOMAIN_RE.match(i) and not _is_ip(i)],
            hashes=[i for i in iocs if _HASH_RE.match(i)],
            ja3=[],
            user_agents=[],
        )

    @property
    def total(self) -> int:
        return (
            len(self.ip_addresses)
            + len(self.domains)
            + len(self.hashes)
            + len(self.ja3)
            + len(self.user_agents)
        )

    def to_dict(self) -> Dict[str, List[str]]:
        return self.model_dump()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class AssessmentOutput(BaseModel):
    """Required, strict wire contract; provenance is assigned by the client."""

    threat_summary: str = Field(min_length=1)
    kill_chain_stage: Literal[
        "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
        "Installation", "Command and Control", "Actions on Objectives",
    ]
    mitre_tactic: str = Field(min_length=1)
    mitre_technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    technique_name: str = Field(min_length=1)
    confidence_score: float = Field(ge=0.0, le=1.0)
    iocs: List[str]
    ioc_details: IOCBundle
    root_cause_analysis: str = Field(min_length=1)
    recommended_actions: List[str] = Field(min_length=1)
    severity: Literal["low", "medium", "high", "critical"]
    natural_language_explanation: str = Field(min_length=1)

    model_config = {"extra": "forbid", "strict": True}


class TriageOutput(BaseModel):
    """Strict batch item, keyed only by a detector-supplied event identifier."""

    event_id: str = Field(min_length=1)
    priority: int = Field(ge=1, le=5)
    is_noise: bool
    confidence_score: float = Field(ge=0.0, le=1.0)
    kill_chain_stage: str = Field(min_length=1)
    rationale: str = Field(min_length=1)

    model_config = {"extra": "forbid", "strict": True}


class TriageBatchOutput(BaseModel):
    verdicts: List[TriageOutput]
    model_config = {"extra": "forbid", "strict": True}


def strict_response_format(schema_model: type[BaseModel]) -> Dict[str, Any]:
    """Meta strict schemas require all properties and closed nested objects."""
    schema = schema_model.model_json_schema()

    def close_objects(node: Any) -> None:
        if isinstance(node, dict):
            node.pop("default", None)
            if node.get("type") == "object":
                node["additionalProperties"] = False
                node["required"] = list(node.get("properties", {}))
            for value in node.values():
                close_objects(value)
        elif isinstance(node, list):
            for value in node:
                close_objects(value)

    close_objects(schema)
    return {"type": "json_schema", "json_schema": {
        "name": schema_model.__name__, "strict": True, "schema": schema,
    }}


class TriageVerdict(BaseModel):
    """Tier-1 (Muse Spark) fast classification of a single event."""

    event_id: str = ""
    event_type: str = ""
    priority: int = Field(default=3, ge=1, le=5, description="1 = lowest, 5 = urgent")
    is_noise: bool = Field(default=False, description="True when likely benign/false positive")
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    kill_chain_stage: str = ""
    rationale: str = ""
    model: str = ""
    requested_model: str = ""
    source: str = "offline-deterministic"
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ThreatAssessment(BaseModel):
    """The structured verdict a model returns for one suspicious event."""

    threat_summary: str = Field(
        default="", description="One-paragraph overall assessment of the threat."
    )
    kill_chain_stage: str = Field(
        default="Command and Control",
        description="Kill-chain stage, e.g. Reconnaissance or Actions on Objectives.",
    )
    mitre_tactic: str = Field(default="", description="ATT&CK tactic name.")
    mitre_technique_id: str = Field(
        default="", description="Primary ATT&CK technique/sub-technique, e.g. T1071.001."
    )
    technique_name: str = Field(default="", description="Human-readable technique name.")
    confidence_score: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Analyst confidence from 0.0 to 1.0."
    )
    iocs: List[str] = Field(
        default_factory=list, description="Indicators of compromise extracted/reconfirmed."
    )
    ioc_details: IOCBundle = Field(
        default_factory=IOCBundle, description="Typed IOC breakdown (IPs/domains/hashes/JA3)."
    )
    root_cause_analysis: str = Field(
        default="", description="Technical root-cause explanation of the observed behaviour."
    )
    recommended_actions: List[str] = Field(
        default_factory=list, description="Prioritized mitigation/containment steps."
    )
    severity: str = Field(default="medium", description="low | medium | high | critical")
    natural_language_explanation: str = Field(
        default="", description="Plain-language reasoning for the analyst."
    )
    # -- provenance --------------------------------------------------------
    model: str = Field(default="offline-deterministic", description="Model that produced it.")
    requested_model: str = Field(default="", description="Requested API model, including fallback.")
    reasoning_source: str = Field(
        default="offline-deterministic",
        description="meta-model-api | offline-deterministic",
    )
    latency_ms: float = Field(default=0.0, description="Reasoning latency in milliseconds.")

    model_config = {"populate_by_name": True, "extra": "ignore"}

    @model_validator(mode="before")
    @classmethod
    def _normalise_legacy_keys(cls, data: Any) -> Any:
        """Accept legacy/alias keys produced by older prompts or callers."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        aliases = {
            "threat_assessment": "threat_summary",
            "mitre_technique": "mitre_technique_id",
            "tactic": "mitre_tactic",
            "confidence": "confidence_score",
        }
        for old, new in aliases.items():
            if old in data and (new not in data or data[new] is None or data[new] == ""):
                data[new] = data.pop(old)
        if "ioc_details" not in data:
            iocs = data.get("iocs") or []
            if isinstance(iocs, list):
                data["ioc_details"] = IOCBundle.from_iocs([str(i) for i in iocs]).model_dump()
        return data


    # -- backwards-compatible aliases --------------------------------------
    @property
    def threat_assessment(self) -> str:
        return self.threat_summary

    @property
    def mitre_technique(self) -> str:
        return self.mitre_technique_id

    @property
    def tactic(self) -> str:
        return self.mitre_tactic

    @property
    def confidence(self) -> float:
        return self.confidence_score

    # -- construction ------------------------------------------------------
    @classmethod
    def from_event(
        cls, event: SuspiciousEvent, model: str = "offline-deterministic"
    ) -> "ThreatAssessment":
        """Deterministic local fallback when the model API is unavailable."""
        from .offline import OfflineReasoningEngine  # deferred to avoid a cycle

        return OfflineReasoningEngine().assess(event, model=model)

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        data.update(
            {
                # legacy keys kept in the serialised payload for compatibility
                "threat_assessment": self.threat_summary,
                "mitre_technique": self.mitre_technique_id,
                "tactic": self.mitre_tactic,
                "confidence": self.confidence_score,
            }
        )
        return data


def assessment_prompt_schema() -> Dict[str, Any]:
    """Return a JSON schema summary to embed in the LLM prompt."""
    return ThreatAssessment.model_json_schema()


_LEGACY = {
    "mitre_technique_id": "mitre_technique",
    "mitre_tactic": "tactic",
    "threat_summary": "threat_assessment",
    "confidence_score": "confidence",
}


def coerce_assessment(
    payload: Dict[str, Any],
    event: Optional[SuspiciousEvent] = None,
    model: str = "offline-deterministic",
    source: str = "meta-model-api",
) -> ThreatAssessment:
    """Validate a model payload, repairing missing fields from the event heuristics."""
    fallback = ThreatAssessment.from_event(event) if event else ThreatAssessment()
    data = dict(payload or {})

    # Fill anything the model omitted (or returned blank) from the heuristics.
    for field_name in (
        "mitre_technique_id",
        "mitre_tactic",
        "technique_name",
        "kill_chain_stage",
        "severity",
    ):
        if not data.get(field_name) and not data.get(_LEGACY.get(field_name, "")):
            data[field_name] = getattr(fallback, field_name)
    if not data.get("threat_summary") and not data.get("threat_assessment"):
        data["threat_summary"] = fallback.threat_summary
    if not data.get("root_cause_analysis"):
        data["root_cause_analysis"] = fallback.root_cause_analysis
    if not data.get("recommended_actions"):
        data["recommended_actions"] = list(fallback.recommended_actions)
    if not data.get("iocs") and event is not None:
        data["iocs"] = list(event.iocs)
    data["model"] = model
    data["requested_model"] = model
    data["reasoning_source"] = source

    try:
        assessment = ThreatAssessment.model_validate(data)
    except Exception:
        assessment = fallback
        assessment.requested_model = model
        assessment.reasoning_source = "offline-deterministic"

    if event is not None:
        assessment = _merge_with_event(assessment, event)
    if not assessment.ioc_details.total:
        assessment.ioc_details = IOCBundle.from_iocs(assessment.iocs)
    return assessment


def _merge_with_event(
    assessment: ThreatAssessment, event: SuspiciousEvent
) -> ThreatAssessment:
    """Ensure the model's verdict retains detector IOCs and MITRE fallback."""
    # A model may explain evidence, but cannot introduce unobserved indicators
    # into automated response artifacts. Retain all detector indicators.
    observed = list(dict.fromkeys(event.iocs))
    assessment.iocs = observed
    assessment.ioc_details = event_ioc_bundle(event)
    if not assessment.mitre_technique_id:
        assessment.mitre_technique_id = event.mitre_technique or technique_id_for(
            event.event_type
        )
    if not assessment.mitre_tactic:
        assessment.mitre_tactic = event.mitre_tactic or mitre_for(event.event_type).get(
            "tactic", ""
        )
    if not assessment.technique_name:
        assessment.technique_name = mitre_for(event.event_type).get("name", "")
    if not assessment.kill_chain_stage:
        assessment.kill_chain_stage = event.kill_chain_stage or kill_chain_stage_for(
            event.event_type
        )
    if assessment.severity not in ("low", "medium", "high", "critical"):
        assessment.severity = event.severity
    return assessment


def event_ioc_bundle(event: SuspiciousEvent) -> IOCBundle:
    """Classify only indicators present in the input telemetry."""
    bundle = IOCBundle.from_iocs(list(dict.fromkeys(event.iocs)))
    for address in (event.src_ip, event.dst_ip):
        if address and _is_ip(address) and address not in bundle.ip_addresses:
            bundle.ip_addresses.append(address)
    for key, target in (("ja3", bundle.ja3), ("user_agent", bundle.user_agents),
                        ("user_agents", bundle.user_agents), ("hashes", bundle.hashes)):
        raw = event.features.get(key, [])
        values = [raw] if isinstance(raw, str) else raw
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str) and value and value not in target:
                    target.append(value)
    return bundle
