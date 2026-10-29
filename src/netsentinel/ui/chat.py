"""Grounded local answers for the Chainlit and terminal SOC copilot."""
from __future__ import annotations

import json
import re
from typing import Optional

from ..pipeline import AnalysisResult


def answer_query(result: Optional[AnalysisResult], query: str) -> str:
    """Answer commands locally and provide a useful fallback for free-form chat."""
    q = query.strip().lower()
    if result is None:
        return "Run the full demo or upload a PCAP / flow file to begin your investigation."
    events = result.report.events
    if q in ("help", "?", "trợ giúp"):
        return (
            "**Investigation commands**\n"
            "- `summary` — capture and severity overview\n"
            "- `events` / `beacons` — list findings\n"
            "- `explain <n>` — evidence and MITRE reasoning for a finding\n"
            "- `kill-chain` — correlated campaign hypotheses\n"
            "- `evidence` / `iocs` — forensic metrics and observables\n"
            "- `rules` / `playbook <n>` — review detection and response artifacts\n\n"
            "Ask a free-form question for Muse Wonder reasoning when the API is available."
        )
    if q in ("summary", "tóm tắt", "overview", "tong quan"):
        sev = result.vulnerabilities_by_severity()
        counts = ", ".join(f"{key}={value}" for key, value in sev.items()) or "none"
        return (
            f"**Flows:** {result.report.flows_count:,} · **Findings:** {len(events)}\n"
            f"**Severity:** {counts}\n"
            f"**Reasoning:** {'Meta Model API' if result.llm_available else 'offline deterministic expert engine'}"
        )
    if any(term in q for term in ("kill-chain", "kill chain", "killchain", "correlation", "chiến dịch")):
        return correlation_summary(result)
    if q in ("iocs", "ioc", "indicators", "observables"):
        iocs = sorted({ioc for event in events for ioc in event.iocs})
        return "**Observed IOCs**\n\n" + "\n".join(f"- {_safe(ioc)}" for ioc in iocs) if iocs else "No IOCs were observed."
    if q in ("metrics", "evidence", "forensics", "forensic"):
        return "\n\n".join(
            f"**[{i}] {event.event_type.upper()}**\n\n{_fenced(json.dumps(event.features, indent=2, default=str), 'json')}"
            for i, event in enumerate(events, 1)
        ) or "No forensic findings were detected."
    if "beacon" in q:
        matches = [event for event in events if event.event_type == "beacon"]
        return "\n".join(
            f"- {_safe(event.src_ip or 'unknown')} → {_safe(event.dst_ip or 'unknown')}:{event.dst_port} ({event.severity})"
            for event in matches
        ) or "No beacon findings were detected."
    if q in ("events", "sự kiện", "su kien", "list") or q.startswith("list "):
        return "\n".join(
            f"[{i}] {event.event_type.upper()} ({event.severity}) {_safe(event.src_ip or 'unknown')}"
            + (f" → {_safe(event.dst_ip)}" if event.dst_ip else "")
            for i, event in enumerate(events, 1)
        ) or "No suspicious events were detected."
    if any(term in q for term in ("explain", "giải thích", "giai thich")):
        idx = _extract_index(q)
        if idx is None or not 1 <= idx <= len(events):
            return f"Choose a finding from 1 to {len(events)}. Use `events` to see the list."
        event = events[idx - 1]
        assessment = result.assessments[idx - 1]
        explanation = assessment.natural_language_explanation or event.description
        root_cause = getattr(assessment, "root_cause_analysis", "")
        return (
            f"**[{idx}] {event.event_type.upper()} ({event.severity})**\n"
            f"**MITRE ATT&CK:** {_safe(assessment.mitre_technique)} — {_safe(assessment.technique_name)}\n\n"
            f"{_safe(explanation)}\n\n{_safe(root_cause)}"
        )
    if any(term in q for term in ("rule", "snort", "suricata", "yara")):
        parts = []
        if result.suricata_rules:
            parts.append("**Suricata**\n" + _fenced("\n".join(result.suricata_rules), "text"))
        if result.yara_rules:
            parts.append("**YARA**\n" + _fenced("\n\n".join(result.yara_rules), "yara"))
        return "\n\n".join(parts) or "No detection rules were generated."
    if "playbook" in q or "mitigation" in q:
        idx = _extract_index(q)
        if idx is None or not 1 <= idx <= len(events):
            return f"Choose a finding from 1 to {len(events)}."
        pb = result.playbooks[idx - 1]
        steps = "\n".join(f"{s['order']}. {_safe(s['action'])}" for s in pb["steps"])
        return f"**{_safe(pb['title'])}** · Priority {pb['priority']}\n\n{steps}\n\nAnalyst review is required before containment."
    if not events:
        return "No suspicious events were detected in this capture. Additional host or DNS telemetry may be needed to answer that question."
    top = max(events, key=lambda event: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(event.severity, 0))
    return (
        "**Evidence-based offline investigation**\n\n"
        f"The capture contains {len(events)} findings. The highest-priority signal is "
        f"**{top.event_type.upper()}** on **{_safe(top.src_ip or 'unknown')}**: {_safe(top.description)}\n\n"
        "These are behavioral indicators; the capture alone does not prove compromise or attribution. "
        "Use `evidence` for the measured signals, `kill-chain` for correlation, "
        "or `playbook <n>` for investigation and containment guidance. "
        "A more specific answer may require process, endpoint, or DNS resolver logs."
    )


def correlation_summary(result: AnalysisResult) -> str:
    correlation = getattr(result, "correlation", None)
    if correlation is None:
        from ..engine.correlator import correlate_events
        correlation = correlate_events(result.report.events)
    campaigns = list(correlation.campaigns)
    overview = getattr(correlation, "environment_overview", None)
    if overview is not None:
        campaigns.append(overview)
    if not campaigns:
        return "No correlated campaigns were found in the current capture."
    lines = ["## Attack kill-chain correlation", "Behavioral hypotheses grouped by endpoints and time. Validate causality with host telemetry."]
    for campaign in campaigns:
        label = "Temporal environment overview (hypothesis)" if campaign.scope == "environment" else campaign.name
        lines.extend([
            "", f"**{_safe(label)} · Risk {campaign.risk_score}/100**",
            " → ".join(_safe(stage) for stage in campaign.observed_stages),
            _safe(campaign.kill_chain_narrative),
        ])
    return "\n\n".join(lines)


def _safe(value: object) -> str:
    """Render capture-controlled strings as text in the Markdown chat surface."""
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for character in ("\\", "`", "*", "_", "[", "]", "(", ")", "#", "!"):
        text = text.replace(character, "\\" + character)
    return text


def _fenced(value: str, language: str) -> str:
    longest = max((len(match.group()) for match in re.finditer(r"`+", value)), default=2)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{value}\n{fence}"


def _extract_index(query: str) -> Optional[int]:
    for token in query.split():
        if token.isdigit():
            try:
                return int(token)
            except ValueError:
                return None
    return None
