"""End-to-end pipeline: ingest -> detect -> reason -> respond."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .config import Settings
from .engine.detector import DetectionReport, detect
from .engine.correlator import CorrelationReport, correlate_events
from .ingest import parse_csv, parse_json, parse_pcap, parse_zeek_conn
from .llm.client import MetaModelClient
from .llm.schemas import ThreatAssessment
from .models import Flow
from .response import generate_playbook, generate_yara_rule
from .response.suricata import build_rule_set

_EXT_HANDLERS = {
    ".pcap": parse_pcap,
    ".pcapng": parse_pcap,
    ".json": parse_json,
    ".csv": parse_csv,
    ".log": parse_zeek_conn,
    ".conn": parse_zeek_conn,
}


def load_flows(path) -> List[Flow]:
    """Load flows from a file based on its extension."""
    suffix = Path(path).suffix.lower()
    handler = _EXT_HANDLERS.get(suffix)
    if handler is None:
        raise ValueError(f"Unsupported file type: '{suffix}' (supported: {sorted(_EXT_HANDLERS)})")
    return handler(path)


@dataclass
class AnalysisResult:
    report: DetectionReport
    assessments: List[ThreatAssessment] = field(default_factory=list)
    suricata_rules: List[str] = field(default_factory=list)
    yara_rules: List[str] = field(default_factory=list)
    playbooks: List[dict] = field(default_factory=list)
    llm_available: bool = False
    correlation: CorrelationReport = field(default_factory=CorrelationReport)
    routing: dict = field(default_factory=dict)
    source_path: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def vulnerabilities_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self.report.events:
            counts[e.severity] = counts.get(e.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "schema_version": "2.0",
            "generated_at": self.generated_at,
            "source_path": self.source_path,
            "flows_count": self.report.flows_count,
            "stats": self.report.stats,
            "severity_counts": self.vulnerabilities_by_severity(),
            "llm_available": self.llm_available,
            "routing": self.routing,
            "correlation": self.correlation.to_dict(),
            "campaigns": [c.to_dict() for c in self.correlation.campaigns],
            "events": [
                {
                    "event": e.to_dict(),
                    "assessment": a.to_dict(),
                    "playbook": p,
                }
                for e, a, p in zip(self.report.events, self.assessments, self.playbooks)
            ],
            "suricata_rules": self.suricata_rules,
            "yara_rules": self.yara_rules,
        }


def analyze_flows(
    flows: List[Flow],
    settings: Optional[Settings] = None,
    use_llm: bool = True,
) -> AnalysisResult:
    """Run the full pipeline over a list of flows."""
    settings = settings or Settings.load()
    report = detect(flows, settings.detection)

    correlation = correlate_events(report.events)
    client = MetaModelClient(settings.meta)
    assessments = (
        client.analyze_events(
            report.events, campaigns=[c.to_dict() for c in correlation.campaigns]
        )
        if use_llm else [ThreatAssessment.from_event(event) for event in report.events]
    )
    suricata_rules = build_rule_set(report.events)
    yara_rules = list(dict.fromkeys(generate_yara_rule(event) for event in report.events))
    playbooks = [generate_playbook(event, assessment)
                 for event, assessment in zip(report.events, assessments)]
    routing = client.routing_summary()
    if not use_llm:
        routing = {**routing, "mode": "offline-deterministic",
                   "fallback_reason": "Offline mode requested"}

    return AnalysisResult(
        report=report,
        assessments=assessments,
        suricata_rules=suricata_rules,
        yara_rules=yara_rules,
        playbooks=playbooks,
        llm_available=use_llm and any(a.reasoning_source == "meta-model-api" for a in assessments),
        correlation=correlation,
        routing=routing,
    )


def analyze_path(
    path,
    settings: Optional[Settings] = None,
    use_llm: bool = True,
) -> AnalysisResult:
    """Load flows from file path and run the full pipeline."""
    flows = load_flows(path)
    result = analyze_flows(flows, settings=settings, use_llm=use_llm)
    result.source_path = Path(path).as_posix()
    return result
