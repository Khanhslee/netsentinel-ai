"""End-to-end pipeline: ingest -> detect -> reason -> respond."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .config import Settings
from .engine.detector import DetectionReport, detect
from .ingest import parse_csv, parse_json, parse_pcap, parse_zeek_conn
from .llm.client import LlamaClient
from .llm.schemas import ThreatAssessment
from .models import Flow
from .response import generate_playbook, generate_suricata_rules, generate_yara_rule

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

    def vulnerabilities_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self.report.events:
            counts[e.severity] = counts.get(e.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "flows_count": self.report.flows_count,
            "llm_available": self.llm_available,
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

    client = LlamaClient(settings.llama)
    assessments: List[ThreatAssessment] = []
    suricata_rules: List[str] = []
    yara_rules: List[str] = []
    playbooks: List[dict] = []

    for event in report.events:
        assessment = (
            client.analyze_event(event) if use_llm else ThreatAssessment.from_event(event)
        )
        assessments.append(assessment)
        suricata_rules.extend(generate_suricata_rules(event))
        yara_rules.append(generate_yara_rule(event))
        playbooks.append(generate_playbook(event, assessment))

    return AnalysisResult(
        report=report,
        assessments=assessments,
        suricata_rules=suricata_rules,
        yara_rules=yara_rules,
        playbooks=playbooks,
        llm_available=client.available() and use_llm,
    )


def analyze_path(
    path,
    settings: Optional[Settings] = None,
    use_llm: bool = True,
) -> AnalysisResult:
    """Load flows from file path and run the full pipeline."""
    flows = load_flows(path)
    return analyze_flows(flows, settings=settings, use_llm=use_llm)
