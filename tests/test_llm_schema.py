"""Tests for the LLM schema + JSON extraction + offline fallback."""
from netsentinel.llm.client import _extract_json
from netsentinel.llm.schemas import ThreatAssessment
from netsentinel.models import SuspiciousEvent
from netsentinel.pipeline import analyze_flows


def _event():
    return SuspiciousEvent(
        event_type="beacon",
        severity="high",
        description="periodic C2 beacon",
        src_ip="10.0.0.5",
        dst_ip="203.0.113.10",
        dst_port=8080,
        iocs=["203.0.113.10", "203.0.113.10:8080"],
        mitre_technique="T1071.001",
    )


def test_from_event_fallback():
    a = ThreatAssessment.from_event(_event())
    assert a.mitre_technique == "T1071.001"
    assert a.iocs == ["203.0.113.10", "203.0.113.10:8080"]
    assert a.severity == "high"
    assert a.recommended_actions  # populated from MITRE table


def test_extract_json_plain():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced():
    text = '```json\n{"threat_assessment": "x"}\n```'
    assert _extract_json(text)["threat_assessment"] == "x"


def test_pipeline_offline_end_to_end():
    result = analyze_flows([], use_llm=False)
    assert result.report.flows_count == 0
    assert result.assessments == []
