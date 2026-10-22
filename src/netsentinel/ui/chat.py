"""Natural-language query answering over an AnalysisResult (no LLM required).

This powers both the terminal fallback chat and the Chainlit UI, giving
analysts quick answers such as "list beacons", "explain 1", or "show rules".
"""
from __future__ import annotations

from typing import List, Optional

from ..pipeline import AnalysisResult


def answer_query(result: Optional[AnalysisResult], query: str) -> str:
    """Answer a natural-language query about an analysis result."""
    q = query.strip().lower()
    if result is None:
        return "Chưa có kết quả phân tích. Hãy cung cấp file PCAP/flow trước."

    events = result.report.events

    if q in ("help", "?", "trợ giúp"):
        return (
            "Các câu lệnh:\n"
            "- summary / tóm tắt  -> tổng quan kết quả\n"
            "- events / sự kiện   -> liệt kê sự kiện\n"
            "- beacons / beacon   -> chỉ liệt kê beacon\n"
            "- explain <n>        -> giải thích sự kiện thứ n\n"
            "- rules / snort / yara -> sinh rule phát hiện\n"
            "- playbook <n>       -> bước mitigation cho sự kiện n\n"
            "- exit / thoát       -> kết thúc"
        )

    if q in ("summary", "tóm tắt", "overview", "tong quan"):
        sev = result.vulnerabilities_by_severity()
        sev_str = ", ".join(f"{k}={v}" for k, v in sev.items()) or "none"
        return (
            f"Flows: {result.report.flows_count} | Events: {len(events)} | "
            f"Severity: {sev_str} | LLM: {'on' if result.llm_available else 'offline'}"
        )

    if "beacon" in q:
        beacons = [e for e in events if e.event_type == "beacon"]
        if not beacons:
            return "Không phát hiện beacon."
        return "\n".join(f"- {e.src_ip} -> {e.dst_ip}:{e.dst_port} ({e.severity})" for e in beacons)

    if q in ("events", "sự kiện", "su kien", "list") or "list" in q:
        if not events:
            return "Không phát hiện sự kiện đáng ngờ."
        lines = []
        for i, e in enumerate(events, 1):
            lines.append(f"[{i}] {e.event_type.upper()} ({e.severity}) {e.src_ip}"
                         + (f" -> {e.dst_ip}" if e.dst_ip else ""))
        return "\n".join(lines)

    if "explain" in q or "giải thích" in q or "giai thich" in q:
        idx = _extract_index(q)
        if idx is None or idx > len(events):
            return f"Chọn chỉ số từ 1..{len(events)}. Dùng 'events' để xem danh sách."
        event = events[idx - 1]
        assessment = result.assessments[idx - 1]
        return (
            f"[{idx}] {event.event_type.upper()} ({event.severity})\n"
            f"MITRE: {assessment.mitre_technique} - {assessment.technique_name}\n"
            f"{assessment.natural_language_explanation or event.description}"
        )

    if "rule" in q or "snort" in q or "suricata" in q or "yara" in q:
        out: List[str] = []
        if result.suricata_rules:
            out.append("-- Snort/Suricata --")
            out.extend(result.suricata_rules)
        if result.yara_rules:
            out.append("-- YARA --")
            out.extend(result.yara_rules)
        return "\n".join(out) if out else "Chưa có rule nào."

    if "playbook" in q or "mitigation" in q:
        idx = _extract_index(q)
        if idx is None or idx > len(events):
            return f"Chọn chỉ số từ 1..{len(events)}."
        pb = result.playbooks[idx - 1]
        steps = "\n".join(f"{s['order']}. {s['action']}" for s in pb["steps"])
        return f"{pb['title']} (priority {pb['priority']})\n{steps}"

    return (
        "Tôi chưa hiểu câu hỏi. Gõ 'help' để xem các lệnh hỗ trợ "
        "(summary, events, beacons, explain <n>, rules, playbook <n>)."
    )


def _extract_index(query: str) -> Optional[int]:
    for token in query.split():
        if token.isdigit():
            return int(token)
    return None
