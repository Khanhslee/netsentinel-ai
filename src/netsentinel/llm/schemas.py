"""Structured output schemas for AI threat reasoning.

The Meta Muse models are asked for a JSON object, but their responses are never
trusted to be exactly on-schema: reasoning models routinely rename keys, use
``command_and_control`` instead of ``Command and Control``, wrap the JSON in
markdown fences, emit a percentage instead of a 0-1 confidence, or drop fields
entirely once their token budget is spent. A partial answer must never break the
pipeline, therefore:

* every field of every *response* model is optional with a sensible default,
* unknown/extra keys are ignored instead of rejected,
* a ``mode="before"`` validator normalises legacy names, casing, numbers and
  string/list mismatches,
* nothing here raises when the model drifts; the caller repairs the remaining
  gaps from the deterministic heuristics.

Legacy field names (``threat_assessment``, ``mitre_technique``, ``tactic``,
``confidence``) are still accepted and exposed as aliases so older call sites
and tests keep working.
"""
from __future__ import annotations

import re
import ipaddress
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, Field, model_validator

from ..mitre import (
    KILL_CHAIN_STAGES,
    kill_chain_stage_for,
    mitre_for,
    technique_id_for,
)
from ..models import SuspiciousEvent

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$")
_TECHNIQUE_RE = re.compile(r"\bT?\d{4}(?:\.\d{3})?\b")
#: Tolerant spellings -> canonical kill-chain stage.
_STAGE_ALIASES: Dict[str, str] = {
    "recon": "Reconnaissance",
    "reconnaissance": "Reconnaissance",
    "reconnaisance": "Reconnaissance",
    "weaponization": "Weaponization",
    "weaponisation": "Weaponization",
    "delivery": "Delivery",
    "exploitation": "Exploitation",
    "exploit": "Exploitation",
    "installation": "Installation",
    "install": "Installation",
    "persistence": "Installation",
    "commandandcontrol": "Command and Control",
    "commandcontrol": "Command and Control",
    "c2": "Command and Control",
    "cnc": "Command and Control",
    "cc": "Command and Control",
    "actionsonobjectives": "Actions on Objectives",
    "actiononobjectives": "Actions on Objectives",
    "actiononobjective": "Actions on Objectives",
    "objectives": "Actions on Objectives",
    "exfiltration": "Actions on Objectives",
    "exfil": "Actions on Objectives",
    "impact": "Actions on Objectives",
}

#: Tolerant spellings -> canonical severity.
_SEVERITY_ALIASES: Dict[str, str] = {
    "informational": "low", "info": "low", "low": "low", "minor": "low",
    "medium": "medium", "moderate": "medium", "med": "medium",
    "high": "high", "severe": "high", "major": "high",
    "critical": "critical", "crit": "critical", "urgent": "critical",
}


def _key(value: Any) -> str:
    """Lower-case alphanumeric key used for tolerant alias lookups."""
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def normalise_kill_chain_stage(value: Any) -> str:
    """Map any model spelling of a kill-chain stage onto a canonical label.

    Returns ``""`` when the value cannot be recognised, so the caller can fill
    it from the deterministic detector heuristics instead of failing.
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    text = value.strip()
    if text in KILL_CHAIN_STAGES:
        return text
    alias = _STAGE_ALIASES.get(_key(text))
    if alias:
        return alias
    # Last resort: a canonical stage name embedded in a longer sentence.
    for stage in KILL_CHAIN_STAGES:
        if _key(stage) in _key(text):
            return stage
    return ""


def normalise_severity(value: Any, default: str = "") -> str:
    """Map any model spelling of a severity onto low/medium/high/critical."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (
            "critical" if value >= 9 else
            "high" if value >= 7 else
            "medium" if value >= 4 else
            "low"
        )
    return _SEVERITY_ALIASES.get(_key(value), default)


def normalise_technique_id(value: Any) -> str:
    """Extract a ``T####[.###]`` technique id from arbitrary model text."""
    if not isinstance(value, str):
        value = str(value or "")
    match = _TECHNIQUE_RE.search(value.upper())
    if not match:
        return ""
    token = match.group(0)
    return token if token.startswith("T") else f"T{token}"


def coerce_confidence(value: Any, default: float = 0.5) -> float:
    """Accept ``0.9``, ``"0.9"``, ``"90%"`` or ``90`` and clamp to 0.0-1.0."""
    amount: Optional[float] = None
    if isinstance(value, bool):
        amount = 1.0 if value else 0.0
    elif isinstance(value, (int, float)):
        amount = float(value)
        if 1.0 < amount <= 100.0:  # models often answer in percent
            amount = amount / 100.0
    elif isinstance(value, str):
        text = value.strip()
        percent = "%" in text
        try:
            amount = float(text.rstrip("%").strip())
        except ValueError:
            lowered = _key(text)
            for word, score in (
                ("critical", 0.95), ("veryhigh", 0.9), ("high", 0.8),
                ("medium", 0.55), ("moderate", 0.55), ("low", 0.3),
                ("none", 0.05),
            ):
                if word in lowered:
                    amount = score
                    break
        else:
            if percent or amount > 1.0:
                amount = amount / 100.0
    if amount is None or amount != amount:  # None / NaN
        return default
    return round(min(1.0, max(0.0, amount)), 4)


def _looks_like_indicator(value: str) -> bool:
    """True for an IP, domain, hash, URL or ``ip:port`` style indicator."""
    text = value.strip()
    if not text:
        return False
    if _is_ip(text) or _HASH_RE.match(text):
        return True
    if text.lower().startswith(("http://", "https://")):
        return True
    if re.match(r"^[0-9a-fA-F:.]{3,}:\d{1,5}$", text):
        return True
    return bool(_DOMAIN_RE.match(text))


def coerce_str_list(value: Any) -> List[str]:
    """Flatten a string/list/dict produced by a model into a list of strings."""
    if value is None or isinstance(value, bool):
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if "\n" in text or ";" in text:
            parts = re.split(r"[\n;]+", text)
        elif "," in text:
            candidates = [part.strip() for part in text.split(",") if part.strip()]
            # Only split a comma list when every part is an indicator;
            # "Block 1.2.3.4, then isolate the host" must stay one action.
            parts = (
                candidates
                if len(candidates) > 1 and all(_looks_like_indicator(c) for c in candidates)
                else [text]
            )
        else:
            parts = [text]
        return [part.strip(" -\t") for part in parts if part.strip(" -\t")]
    if isinstance(value, dict):
        items: List[str] = []
        for item in value.values():
            items.extend(coerce_str_list(item))
        return list(dict.fromkeys(items))
    if isinstance(value, Iterable):
        items = []
        for item in value:
            if isinstance(item, (str, dict, list, tuple, set)):
                items.extend(coerce_str_list(item))
            elif isinstance(item, (int, float)) and not isinstance(item, bool):
                items.append(str(item))
        return list(dict.fromkeys(item for item in items if item))
    return []


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Interpret truthy model output (``true``, ``"yes"``, ``"noise"``)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = _key(value)
        if lowered in ("true", "yes", "y", "1", "noise", "benign"):
            return True
        if lowered in ("false", "no", "n", "0", "signal", "interesting"):
            return False
    return default


def _coerce_priority(value: Any, default: int = 3) -> int:
    """Clamp priority into 1-5, accepting ``"high"``/``"P2"``/``"4"`` too."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(min(5, max(1, round(value))))
    if isinstance(value, str):
        lowered = _key(value)
        for word, score in (
            ("critical", 5), ("urgent", 5), ("p1", 5), ("high", 4), ("p2", 4),
            ("medium", 3), ("moderate", 3), ("p3", 3), ("low", 2), ("p4", 2),
            ("informational", 1), ("info", 1), ("p5", 1),
        ):
            if word in lowered:
                return score
        match = re.search(r"\d", lowered)
        if match:
            return int(min(5, max(1, int(match.group(0)))))
    return default


def _text_of(data: Dict[str, Any], *keys: str) -> str:
    """First non-empty string among ``keys`` (models rename text fields a lot)."""
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return ""


def _coerce_ioc_details(value: Any, iocs: Any = None) -> IOCBundle:
    """Normalise ``ioc_details`` into an :class:`IOCBundle`."""
    if isinstance(value, IOCBundle):
        return value
    if isinstance(value, dict):
        bundle = IOCBundle.model_validate(value)
        if bundle.total:
            return bundle
    return IOCBundle.from_iocs(coerce_str_list(value) or coerce_str_list(iocs))


class IOCBundle(BaseModel):
    """Typed indicators of compromise (IPs, domains, hashes, JA3, user agents)."""

    ip_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    ja3: List[str] = Field(default_factory=list)
    user_agents: List[str] = Field(default_factory=list)

    #: Tolerant: models send scalars, comma-separated strings or unknown keys.
    model_config = {"extra": "ignore", "strict": False}

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: Any) -> Any:
        if isinstance(data, IOCBundle):
            return data
        if not isinstance(data, dict):
            return cls.from_iocs(coerce_str_list(data)).model_dump()
        return {
            name: coerce_str_list(data.get(name))
            for name in ("ip_addresses", "domains", "hashes", "ja3", "user_agents")
        }

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
    """Lenient wire contract for the Tier-2 assessment.

    Every field is optional with a default so a truncated, renamed or
    partially-hallucinated model response still parses; the client fills the
    remaining gaps from the deterministic heuristics in
    :func:`coerce_assessment`.
    """

    threat_summary: str = ""
    kill_chain_stage: str = ""
    mitre_tactic: str = ""
    mitre_technique_id: str = ""
    technique_name: str = ""
    confidence_score: float = 0.5
    iocs: List[str] = Field(default_factory=list)
    ioc_details: IOCBundle = Field(default_factory=IOCBundle)
    root_cause_analysis: str = ""
    recommended_actions: List[str] = Field(default_factory=list)
    severity: str = ""
    natural_language_explanation: str = ""

    model_config = {"extra": "ignore", "strict": False}

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: Any) -> Any:
        """Coerce whatever the model returned into an on-contract dict."""
        if isinstance(data, AssessmentOutput):
            return data.model_dump()
        if data is None:
            return {}
        if isinstance(data, str):
            return {"threat_summary": data.strip()}
        if not isinstance(data, dict):
            return {}
        data = dict(data)
        # A nested wrapper (``{"assessment": {...}}``) is common enough to unwrap.
        for wrapper in ("assessment", "threat_assessment", "analysis", "result"):
            inner = data.get(wrapper)
            if isinstance(inner, dict):
                merged = {key: value for key, value in data.items() if key != wrapper}
                merged.update(inner)
                data = merged
                break

        iocs = coerce_str_list(
            data.get("iocs") or data.get("indicators_of_compromise")
            or data.get("indicators")
        )
        return {
            "threat_summary": _text_of(
                data, "threat_summary", "threat_assessment", "summary", "overview",
            ),
            "kill_chain_stage": normalise_kill_chain_stage(
                data.get("kill_chain_stage") or data.get("kill_chain")
                or data.get("stage") or data.get("phase")
            ),
            "mitre_tactic": _text_of(
                data, "mitre_tactic", "tactic", "attack_tactic", "mitre_tactics",
            ),
            "mitre_technique_id": normalise_technique_id(
                data.get("mitre_technique_id") or data.get("mitre_technique")
                or data.get("technique_id") or data.get("technique")
            ),
            "technique_name": _text_of(
                data, "technique_name", "technique", "attack_technique",
                "mitre_technique_name",
            ),
            "confidence_score": coerce_confidence(
                data.get("confidence_score", data.get("confidence"))
            ),
            "iocs": iocs,
            "ioc_details": _coerce_ioc_details(
                data.get("ioc_details") or data.get("ioc_bundle"), iocs
            ),
            "root_cause_analysis": _text_of(
                data, "root_cause_analysis", "root_cause", "rca", "cause",
            ),
            "recommended_actions": coerce_str_list(
                data.get("recommended_actions") or data.get("mitigations")
                or data.get("actions") or data.get("containment")
            ),
            "severity": normalise_severity(data.get("severity")),
            "natural_language_explanation": _text_of(
                data, "natural_language_explanation", "explanation", "reasoning",
                "rationale", "analyst_notes",
            ),
        }


class TriageOutput(BaseModel):
    """Lenient batch item, keyed only by a detector-supplied event identifier."""

    event_id: str = ""
    priority: int = Field(default=3, description="1 = lowest, 5 = urgent")
    is_noise: bool = False
    confidence_score: float = 0.5
    kill_chain_stage: str = ""
    rationale: str = ""

    model_config = {"extra": "ignore", "strict": False}

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: Any) -> Any:
        if isinstance(data, TriageOutput):
            return data.model_dump()
        if not isinstance(data, dict):
            return {}
        return {
            "event_id": _text_of(data, "event_id", "eventId", "id", "event"),
            "priority": _coerce_priority(data.get("priority")),
            "is_noise": _coerce_bool(
                data.get("is_noise", data.get("noise", data.get("benign"))), False
            ),
            "confidence_score": coerce_confidence(
                data.get("confidence_score", data.get("confidence"))
            ),
            "kill_chain_stage": normalise_kill_chain_stage(
                data.get("kill_chain_stage") or data.get("kill_chain")
                or data.get("stage")
            ),
            "rationale": _text_of(
                data, "rationale", "reason", "reasoning", "explanation", "summary",
            ),
        }


class TriageBatchOutput(BaseModel):
    """Lenient wrapper accepting the verdict list under any plausible key."""

    verdicts: List[TriageOutput] = Field(default_factory=list)

    model_config = {"extra": "ignore", "strict": False}

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: Any) -> Any:
        if isinstance(data, TriageBatchOutput):
            return data
        if isinstance(data, list):
            return {"verdicts": data}
        if not isinstance(data, dict):
            return {"verdicts": []}
        for key in ("verdicts", "triage", "results", "events", "items", "data",
                    "classifications"):
            value = data.get(key)
            if isinstance(value, list):
                return {"verdicts": value}
            if isinstance(value, dict):
                return {"verdicts": [value]}
        if "event_id" in data:
            return {"verdicts": [data]}
        return {"verdicts": []}


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

    model_config = {"extra": "ignore", "strict": False}

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: Any) -> Any:
        """Clamp model-supplied priorities/confidences instead of rejecting them."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if "priority" in data:
            data["priority"] = _coerce_priority(data["priority"])
        if "confidence_score" in data:
            data["confidence_score"] = coerce_confidence(data["confidence_score"])
        if "is_noise" in data:
            data["is_noise"] = _coerce_bool(data["is_noise"], False)
        stage = normalise_kill_chain_stage(data.get("kill_chain_stage"))
        if stage or not data.get("kill_chain_stage"):
            data["kill_chain_stage"] = stage
        return data

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
    """Validate a model payload, repairing missing fields from the event heuristics.

    This never raises: whatever the model produced is normalised through
    :class:`AssessmentOutput` (casing, aliases, numbers, string/list shapes) and
    every remaining gap is filled from the deterministic expert engine.
    """
    fallback = ThreatAssessment.from_event(event) if event else ThreatAssessment()
    data = dict(payload or {})
    try:
        # Normalise key names/values exactly like the wire schema does.
        data = AssessmentOutput.model_validate(data).model_dump()
    except Exception:  # noqa: BLE001 - normalisation must never break the pipeline
        pass

    # Fill anything the model omitted (or returned blank) from the heuristics.
    model_summary = str(data.get("threat_summary") or data.get("threat_assessment") or "")
    for field_name in (
        "mitre_technique_id",
        "mitre_tactic",
        "technique_name",
        "kill_chain_stage",
        "severity",
    ):
        if not data.get(field_name) and not data.get(_LEGACY.get(field_name, "")):
            data[field_name] = getattr(fallback, field_name)
    if not data.get("root_cause_analysis"):
        data["root_cause_analysis"] = fallback.root_cause_analysis
    if not data.get("recommended_actions"):
        data["recommended_actions"] = list(fallback.recommended_actions)
    if not data.get("natural_language_explanation"):
        # Prefer the model's own summary over the heuristic explanation.
        data["natural_language_explanation"] = (
            model_summary or fallback.natural_language_explanation
        )
    if not model_summary:
        data["threat_summary"] = (
            data["natural_language_explanation"] or fallback.threat_summary
        )
    if not data.get("iocs") and event is not None:
        data["iocs"] = list(event.iocs)
    data["model"] = model
    data["requested_model"] = model
    data["reasoning_source"] = source

    try:
        assessment = ThreatAssessment.model_validate(data)
    except Exception:  # noqa: BLE001 - keep the model's text instead of discarding it
        assessment = ThreatAssessment()
        for name, value in data.items():
            if name in ThreatAssessment.model_fields:
                try:
                    setattr(assessment, name, value)
                except Exception:  # noqa: BLE001 - skip a single unusable field
                    continue
        if assessment.reasoning_source != source:
            assessment.reasoning_source = source

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
