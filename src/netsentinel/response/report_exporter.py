"""Self-contained SOC incident reports with escaped, evidence-first content."""
from __future__ import annotations

import html
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..mitre import KILL_CHAIN_STAGES, kill_chain_stage_for, technique_id_for
from ._common import campaigns, event_rows, report_data

_TITLE = "NetSentinel AI Incident Report"
_METRICS = {
    "shannon_entropy": "Shannon entropy (bits/character)",
    "avg_entropy": "Mean label entropy (bits/character)",
    "cv": "Inter-arrival coefficient of variation",
    "jitter_pct": "Inter-arrival jitter (%)",
    "mean_interval": "Mean interval (seconds)",
    "mean_interval_sec": "Mean interval (seconds)",
    "std_interval": "Interval standard deviation (seconds)",
    "packets_per_second": "Packets / second",
    "ports_per_second": "Distinct ports / second",
    "distinct_ports": "Distinct destination ports",
    "upload_ratio": "Upload / download byte ratio",
    "bytes_out": "Outbound bytes", "bytes_in": "Inbound bytes",
}


def _text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value if value is not None else "—")


def _h(value: Any) -> str:
    return html.escape(_text(value), quote=True)


def _md(value: Any) -> str:
    value = html.escape(_text(value), quote=False).replace("\r", " ").replace("\n", " / ")
    value = re.sub(r"([\\`*_{}\[\]|])", r"\\\1", value)
    value = re.sub(r"^([ \t]*)([-+>#])", r"\1\\\2", value)
    # CommonMark ordered lists require whitespace after the marker. Escape
    # the punctuation, preserving IP addresses and decimal measurements.
    return re.sub(r"^([ \t]*\d{1,9})\.(?=\s)", r"\1\\.", value)


def _fence(value: str, language: str = "") -> str:
    longest = max((len(m.group()) for m in re.finditer(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{value.rstrip()}\n{fence}"


def _severity(value: Any) -> str:
    return value if value in ("critical", "high", "medium", "low", "info") else "medium"


def _iocs(rows: list[dict]) -> list[tuple[str, str]]:
    found = {}
    for row in rows:
        event, assessment = row["event"], row.get("assessment", {})
        for value in [event.get("src_ip"), event.get("dst_ip"), *event.get("iocs", []), *assessment.get("iocs", [])]:
            if not value:
                continue
            value = str(value)
            try:
                ipaddress.ip_address(value)
                kind = "IP address"
            except ValueError:
                kind = "Hash / JA3" if re.fullmatch(r"[0-9A-Fa-f]{32,64}", value) else "Domain / observed string"
            found[value] = kind
        for key, values in assessment.get("ioc_details", {}).items():
            for value in values:
                found.setdefault(str(value), key.replace("_", " ").title())
    return sorted((kind, value) for value, kind in found.items())


def isolation_commands(report: Any) -> str:
    """Return reviewable containment commands; never execute shell commands."""
    hosts = []
    for row in event_rows(report_data(report)):
        try:
            address = ipaddress.ip_address(row["event"].get("src_ip", ""))
        except ValueError:
            continue
        if str(address) not in hosts:
            hosts.append(str(address))
    if not hosts:
        return "# No valid affected IP addresses were observed."
    lines = ["# Review ownership and preserve console/management access before containment.",
             "# Linux gateway: quarantine affected hosts in the forwarding path."]
    for host in hosts:
        command = "ip6tables" if ":" in host else "iptables"
        lines.extend([f"sudo {command} -I FORWARD -s {host} -j DROP", f"sudo {command} -I FORWARD -d {host} -j DROP"])
    lines.extend(["", "# Windows: run on each affected endpoint with an elevated console.",
                  "# Blocks inbound/outbound traffic until these rules are removed.",
                  'netsh advfirewall firewall add rule name="NetSentinel-Isolate-Out" dir=out action=block remoteip=any',
                  'netsh advfirewall firewall add rule name="NetSentinel-Isolate-In" dir=in action=block remoteip=any',
                  "", "# Rollback after incident review:",
                  'netsh advfirewall firewall delete rule name="NetSentinel-Isolate-Out"',
                  'netsh advfirewall firewall delete rule name="NetSentinel-Isolate-In"'])
    for host in hosts:
        command = "ip6tables" if ":" in host else "iptables"
        lines.extend([f"sudo {command} -D FORWARD -s {host} -j DROP", f"sudo {command} -D FORWARD -d {host} -j DROP"])
    return "\n".join(lines)


def _context(report: Any) -> tuple[dict, list[dict], dict, Counter]:
    data = report_data(report)
    rows = event_rows(data)
    return data, rows, data.get("stats", {}), Counter(_severity(row["event"].get("severity")) for row in rows)


def _stage_counts(data: dict, rows: list[dict]) -> Counter:
    matrix = data.get("correlation", {}).get("kill_chain_summary", [])
    if matrix:
        return Counter({stage["stage"]: stage.get("event_count", 0) for stage in matrix})
    return Counter(row["event"].get("kill_chain_stage") or kill_chain_stage_for(row["event"].get("event_type", "")) for row in rows)


def render_markdown_report(report: Any, title: str = _TITLE) -> str:
    """Render Markdown from an AnalysisResult or its serialized dictionary."""
    data, rows, stats, severities = _context(report)
    generated = data.get("generated_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")
    sources = sorted({r.get("assessment", {}).get("reasoning_source", "offline-deterministic") for r in rows})
    lines = [f"# {_md(title)}", "", f"Generated: {_md(generated)}", "",
             "## Executive assessment", "",
             f"{len(rows)} behavioural alerts across {data.get('flows_count', stats.get('flows', 0))} network flows; "
             f"{severities['critical']} critical and {severities['high']} high. "
             "Findings are hypotheses supported by network evidence; validate with endpoint and business context.", "",
             f"**Reasoning provenance:** {_md(', '.join(sources) or 'No alerts / no model calls')}", "",
             f"**Source:** {_md(data.get('source_path', 'Flow collection'))}", "",
             "## Capture metrics", "", "| Metric | Value |", "| --- | ---: |"]
    for key, value in [("Packets", stats.get("packets", "Unavailable")), ("Flows", data.get("flows_count", stats.get("flows", 0))),
                       ("Total bytes", stats.get("total_bytes", "Unavailable")), ("Affected source hosts", len({r['event'].get('src_ip') for r in rows})),
                       ("Alerts", len(rows)), ("Critical / High", f"{severities['critical']} / {severities['high']}")]:
        lines.append(f"| {_md(key)} | {_md(value)} |")
    lines.extend(["", "## Attack kill-chain correlation", ""])
    lines.extend(["| Kill-chain stage | Observed alerts |", "| --- | ---: |"])
    stage_counts = _stage_counts(data, rows)
    lines.extend(f"| {_md(stage)} | {stage_counts[stage]} |" for stage in KILL_CHAIN_STAGES)
    lines.append("")
    grouped = campaigns(data)
    if not grouped:
        lines.append("No correlated campaigns were identified.")
    for campaign in grouped:
        lines.extend([f"### {_md(campaign.get('name', campaign.get('campaign_id', 'Campaign')))}", "",
                      f"**Scope:** {_md(campaign.get('scope', 'host'))} · **Risk:** {_md(campaign.get('risk_score', 0))}/100", "",
                      _md(campaign.get("kill_chain_narrative", campaign.get("summary", ""))), ""])
    overview = data.get("correlation", {}).get("environment_overview")
    if overview:
        lines.extend(["### Capture-wide context (unconfirmed relationship)", "",
                      _md(overview.get("kill_chain_narrative", overview.get("summary", ""))), ""])
    lines.extend(["", "## Forensic evidence & structured assessments", ""])
    if not rows:
        lines.append("No suspicious events were detected by the configured heuristics.")
    for row in rows:
        event, assessment = row["event"], row.get("assessment", {})
        kind = event.get("event_type", "unknown")
        technique = event.get("mitre_technique") or technique_id_for(kind)
        lines.extend([f"### {_md(kind.upper())} — {_md(event.get('src_ip', 'unknown'))}", "",
                      f"**Severity:** {_md(event.get('severity'))} · **ATT&CK:** {_md(technique)} · "
                      f"**Stage:** {_md(event.get('kill_chain_stage') or kill_chain_stage_for(kind))}", "",
                      _md(event.get("description", "")), "",
                      _md(assessment.get("threat_summary", assessment.get("threat_assessment", ""))), "",
                      f"**Root cause / interpretation:** {_md(assessment.get('root_cause_analysis', 'Requires analyst validation.'))}", "",
                      f"**Confidence:** {_md(assessment.get('confidence_score', assessment.get('confidence', 'Unavailable')))} · "
                      f"**Source:** {_md(assessment.get('reasoning_source', 'offline-deterministic'))}", "",
                      "| Observed feature | Value |", "| --- | --- |"])
        for key, value in event.get("features", {}).items():
            lines.append(f"| {_md(_METRICS.get(key, key.replace('_', ' ').capitalize()))} | {_md(value)} |")
        lines.extend(["", "**Recommended actions**", ""])
        for action in assessment.get("recommended_actions", []):
            lines.append(f"- {_md(action)}")
    lines.extend(["", "## Observed indicators", "", "Indicators are hunt pivots, including affected internal hosts; an indicator alone does not establish maliciousness.", "",
                  "| Type | Value |", "| --- | --- |"])
    for kind, value in _iocs(rows):
        lines.append(f"| {_md(kind)} | {_md(value)} |")
    lines.extend(["", "## Suricata rules", "", "Review and tune these IOC/behaviour watch rules before deployment.", "",
                  _fence("\n".join(data.get("suricata_rules", [])) or "# No rules generated.", "text"), "",
                  "## YARA rules", "", "Observed-string hunts for files and memory; corroborate matches with endpoint telemetry.", "",
                  _fence("\n".join(data.get("yara_rules", [])) or "// No rules generated.", "yara"), "",
                  "## Containment playbook", "", "Commands are provided for analyst review and are never executed by NetSentinel.", "",
                  _fence(isolation_commands(data), "text"), "",
                  "## Evidence limitations", "", "Network heuristics do not identify the originating process, prove compromise, or demonstrate that bytes contain sensitive data. "
                  "Campaign correlation expresses shared observable context; investigate attribution separately.", ""])
    return "\n".join(lines)


_CSS = """
:root{color-scheme:dark;--bg:#080e19;--panel:#101b2c;--line:#24344a;--text:#edf3fc;--muted:#96a9c4;--cyan:#5de4dc;--orange:#ffb15e;--red:#ff657a}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(ellipse at 80% 0%,#132c3b 0,transparent 40%),var(--bg);color:var(--text);font:15px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}.wrap{max-width:1420px;margin:auto;padding:36px 46px 64px}.eyebrow{color:var(--cyan);font-size:11px;letter-spacing:2px;font-weight:750;text-transform:uppercase}.header{display:flex;align-items:center;justify-content:space-between;gap:20px;border-bottom:1px solid var(--line);padding-bottom:26px}.brand{font-size:22px;font-weight:800;letter-spacing:-.8px}.brand span{color:var(--cyan)}.status{border:1px solid #2b5b57;background:#12302f;color:#88e2cb;padding:6px 12px;border-radius:30px;font-size:12px}.hero{padding:36px 0 22px;max-width:1050px}h1{font-size:clamp(30px,4vw,48px);line-height:1.15;letter-spacing:-1.8px;margin:12px 0 16px}h2{font-size:23px;letter-spacing:-.6px;margin:0 0 16px}h3{font-size:17px;margin:0 0 10px}p{margin:8px 0}.muted,.sub{color:var(--muted)}.sub{font-size:12px}.nav{display:flex;gap:24px;flex-wrap:wrap;font-size:13px;margin:0 0 28px}.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:22px 0 30px}.kpi,.panel{background:linear-gradient(145deg,#132033,#0d1727);border:1px solid var(--line);border-radius:12px}.kpi{padding:18px}.kpi b{display:block;font-size:30px;line-height:1.3;letter-spacing:-1px}.kpi span{font-size:12px;color:var(--muted)}.danger{color:var(--red)}.warn{color:var(--orange)}.panel{padding:25px;margin:18px 0;overflow:hidden}.section-head{display:flex;align-items:center;justify-content:space-between;gap:15px;margin-bottom:14px}.tag{display:inline-block;font-size:11px;letter-spacing:.5px;border:1px solid var(--line);padding:3px 9px;border-radius:5px;color:var(--cyan);white-space:nowrap}.tag.critical,.tag.high{color:#ff95a5;border-color:#713c4a;background:#392333}.tag.medium{color:var(--orange)}.chain{display:grid;grid-template-columns:repeat(7,minmax(125px,1fr));gap:8px;overflow-x:auto;padding-bottom:8px}.stage{min-height:100px;background:#0a1321;border:1px solid var(--line);border-radius:9px;padding:12px;color:#657b9a}.stage.on{border-color:#388982;background:linear-gradient(145deg,#153b3a,#10232d);color:var(--text)}.stage b{display:block;font-size:12px;line-height:1.5}.stage small{display:block;margin-top:8px;font-size:10px}.number{font-family:ui-monospace,monospace;color:var(--cyan);display:block;font-size:11px;margin-bottom:8px}.campaign{border-left:3px solid var(--cyan);padding:3px 16px;margin:22px 0}.campaign p{font-size:13px;color:#bbc9dc}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:12px;text-align:left}th{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:1px;padding:12px 14px;background:#0b1524}td{padding:14px;border-bottom:1px solid #1e2c41;vertical-align:top;max-width:440px;overflow-wrap:anywhere}td:first-child{padding-left:14px}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}code{color:#adefe9;font-size:12px}pre{border:1px solid var(--line);border-radius:9px;padding:20px;background:#070e19;font-size:11px;line-height:1.8;overflow:auto;max-height:480px;color:#b6d9e9;tab-size:4}button{background:#173b43;color:#a7fff2;border:1px solid #346572;border-radius:6px;padding:7px 12px;cursor:pointer;font-size:12px}button:hover{background:#23515b}.details{display:grid;grid-template-columns:1fr 1fr;gap:16px}.detail{background:#0b1423;border:1px solid var(--line);border-radius:8px;padding:18px}.detail p,.detail li{font-size:13px;color:#b9c8dc}.detail ul{padding-left:18px}.metric{display:inline-block;border:1px solid #2d4057;border-radius:4px;padding:3px 7px;margin:2px;font-size:11px;color:#bcd3e8}.empty{padding:24px;color:var(--muted);text-align:center}.footer{margin-top:28px;padding-top:20px;border-top:1px solid var(--line);font-size:11px;color:#7f94af}.pill{font-size:11px;background:#19273d;color:#b2c8e6;border-radius:5px;padding:3px 8px}.break{overflow-wrap:anywhere}.note{border-left:3px solid #607998;padding:9px 15px;color:var(--muted);font-size:12px}.scroll-top{float:right}
@media(max-width:1050px){.kpis{grid-template-columns:repeat(3,1fr)}.details{grid-template-columns:1fr}.wrap{padding:24px}.chain{grid-template-columns:repeat(7,140px)}}@media(max-width:550px){.kpis{grid-template-columns:repeat(2,1fr)}.header{align-items:flex-start;flex-direction:column}.wrap{padding:18px}.panel{padding:16px}h1{letter-spacing:-1px}.nav{gap:14px}}@media print{body{background:#fff;color:#111}.wrap{padding:0}.panel,.kpi{background:#fff;break-inside:avoid}.nav,button{display:none}pre{white-space:pre-wrap;max-height:none;color:#111}p,td,.detail p,.muted{color:#333}}
"""

_SCRIPT = """
document.querySelectorAll('[data-copy]').forEach(function(button){
  button.addEventListener('click',async function(){
    var content=document.getElementById(button.dataset.copy).textContent;
    var copied=false;
    if(navigator.clipboard&&window.isSecureContext){
      try{await navigator.clipboard.writeText(content);copied=true;}catch(error){}
    }
    if(!copied){
      var area=document.createElement('textarea');
      var previousFocus=document.activeElement;
      area.value=content;
      area.setAttribute('readonly','');
      area.style.position='fixed';
      area.style.opacity='0';
      document.body.appendChild(area);
      try{
        area.select();
        area.setSelectionRange(0,area.value.length);
        copied=document.execCommand('copy');
      }catch(error){}
      finally{
        area.remove();
        if(previousFocus&&previousFocus.focus)previousFocus.focus({preventScroll:true});
      }
    }
    button.textContent=copied?'Copied':'Select code to copy';
    setTimeout(function(){button.textContent='Copy';},2200);
  });
});
"""


def _code_panel(title: str, value: str, identifier: str, description: str) -> str:
    return (f'<section class="panel" id="{identifier}-section"><div class="section-head"><h2>{_h(title)}</h2>'
            f'<button type="button" data-copy="{identifier}">Copy</button></div><p class="sub">{_h(description)}</p>'
            f'<pre id="{identifier}">{_h(value)}</pre></section>')


def render_html_report(report: Any, title: str = _TITLE) -> str:
    """Render a portable dashboard. Every telemetry value stays in a text node."""
    data, rows, stats, severities = _context(report)
    iocs = _iocs(rows)
    grouped = campaigns(data)
    generated = data.get("generated_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")
    provenance = Counter(row.get("assessment", {}).get("reasoning_source", "offline-deterministic") for row in rows)
    mode = "Meta API + local evidence" if "meta-model-api" in provenance else "Offline deterministic analysis"
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
             f'<title>{_h(title)}</title><style>{_CSS}</style></head><body id="top"><div class="wrap">',
             '<header class="header"><div class="brand">NET<span>SENTINEL</span> <span class="pill">AI</span></div>',
             f'<span class="status">● {_h(mode)}</span></header><div class="hero"><div class="eyebrow">Security Operations / Incident Intelligence</div>',
             f'<h1>{_h(title)}</h1><p class="muted">From network signals to an evidence-backed response. Mathematical detection, attack correlation and structured SOC reasoning in one investigation.</p>',
             f'<p class="sub break">Generated {_h(generated)} &nbsp;·&nbsp; Source: {_h(data.get("source_path", "Flow collection"))}</p></div>',
             '<nav class="nav"><a href="#kill-chain">Kill chain</a><a href="#evidence">Forensic evidence</a><a href="#assessments">Assessments</a><a href="#indicators">Indicators</a><a href="#suricata-section">Rules</a><a href="#containment-section">Containment</a></nav>',
             '<div class="kpis">']
    for label, value, cls in [("Packets observed", stats.get("packets", "—"), ""),
                              ("Network flows", data.get("flows_count", stats.get("flows", 0)), ""),
                              ("Behavioural alerts", len(rows), ""), ("Critical alerts", severities["critical"], "danger"),
                              ("High alerts", severities["high"], "warn"), ("Observed indicators", len(iocs), "")]:
        display = f"{value:,}" if isinstance(value, int) else value
        parts.append(f'<div class="kpi"><span>{_h(label)}</span><b class="{cls}">{_h(display)}</b></div>')
    observed = _stage_counts(data, rows)
    parts.append('</div><section class="panel" id="kill-chain"><div class="section-head"><h2>Attack kill-chain correlation</h2><span class="tag">EVIDENCE → CONTEXT</span></div><div class="chain">')
    for i, stage in enumerate(KILL_CHAIN_STAGES, 1):
        count = observed[stage]
        parts.append(f'<div class="stage {"on" if count else ""}"><span class="number">0{i}</span><b>{_h(stage)}</b><small>{count} observed alert(s)</small></div>')
    parts.append('</div><p class="sub">Highlighted stages are observed behaviours. Unobserved stages are not inferred as completed.</p>')
    for campaign in grouped:
        parts.append(f'<article class="campaign"><h3>{_h(campaign.get("name", campaign.get("campaign_id", "Campaign")))}</h3><span class="tag">{_h(campaign.get("scope", "host"))} · RISK {_h(campaign.get("risk_score", 0))}/100</span><p>{_h(campaign.get("kill_chain_narrative", campaign.get("summary", "")))}</p></article>')
    overview = data.get("correlation", {}).get("environment_overview")
    if overview:
        parts.append(f'<article class="campaign"><h3>Capture-wide context</h3><span class="tag">UNCONFIRMED RELATIONSHIP</span><p>{_h(overview.get("kill_chain_narrative", overview.get("summary", "")))}</p></article>')
    if not grouped:
        parts.append('<p class="empty">No correlated campaigns identified.</p>')
    parts.append('</section><section class="panel" id="evidence"><div class="section-head"><h2>Forensic evidence</h2><span class="tag">MEASURED SIGNALS</span></div><div class="table-wrap"><table><thead><tr><th>Detection / host</th><th>Severity</th><th>ATT&amp;CK / stage</th><th>Observed measurements</th></tr></thead><tbody>')
    for row in rows:
        event = row["event"]
        severity = _severity(event.get("severity"))
        kind = event.get("event_type", "unknown")
        metrics = ''.join(f'<span class="metric">{_h(_METRICS.get(key, key.replace("_", " ")))}: <b>{_h(value)}</b></span>' for key, value in event.get("features", {}).items() if not isinstance(value, (dict, list)))
        technique = event.get("mitre_technique") or technique_id_for(kind)
        parts.append(f'<tr><td><b>{_h(kind.upper())}</b><br><code>{_h(event.get("src_ip"))} → {_h(event.get("dst_ip") or "DNS / multiple targets")}</code><br><span class="sub">{_h(event.get("description", ""))}</span></td><td><span class="tag {severity}">{severity.upper()}</span></td><td><code>{_h(technique)}</code><br><span class="sub">{_h(event.get("kill_chain_stage") or kill_chain_stage_for(kind))}</span></td><td>{metrics or "No additional metrics supplied."}</td></tr>')
    if not rows:
        parts.append('<tr><td colspan="4" class="empty">No suspicious events detected by the configured heuristics.</td></tr>')
    parts.append('</tbody></table></div></section><section class="panel" id="assessments"><div class="section-head"><h2>Analyst reasoning &amp; response</h2><span class="tag">STRUCTURED ASSESSMENTS</span></div><div class="details">')
    for row in rows:
        event, assessment = row["event"], row.get("assessment", {})
        actions = ''.join(f'<li>{_h(action)}</li>' for action in assessment.get("recommended_actions", []))
        parts.append(f'<article class="detail"><div class="eyebrow">{_h(event.get("event_type", "unknown"))}</div><h3>{_h(event.get("src_ip"))}</h3><p>{_h(assessment.get("threat_summary", assessment.get("threat_assessment", event.get("description", ""))))}</p><p><b>Root cause / interpretation:</b> {_h(assessment.get("root_cause_analysis", "Requires analyst validation."))}</p><p class="sub">Confidence {_h(assessment.get("confidence_score", assessment.get("confidence", "—")))} · {_h(assessment.get("reasoning_source", "offline-deterministic"))} · {_h(assessment.get("model", "local expert engine"))}</p><ul>{actions}</ul></article>')
    parts.append('</div></section><section class="panel" id="indicators"><div class="section-head"><h2>Observed indicators</h2><span class="tag">HUNT PIVOTS</span></div><p class="sub">Includes affected internal hosts and remote endpoints. Validate role and context before blocking.</p><div class="table-wrap"><table><thead><tr><th>Type</th><th>Indicator</th></tr></thead><tbody>')
    parts.extend(f'<tr><td>{_h(kind)}</td><td><code>{_h(value)}</code></td></tr>' for kind, value in iocs)
    if not iocs:
        parts.append('<tr><td colspan="2" class="empty">No indicators observed.</td></tr>')
    parts.append('</tbody></table></div></section>')
    parts.append(_code_panel("Suricata detection rules", '\n'.join(data.get("suricata_rules", [])) or "# No rules generated.", "suricata", "Compact IOC / behaviour watch rules. Validate and tune in your IDS before deployment."))
    parts.append(_code_panel("YARA indicator hunts", '\n'.join(data.get("yara_rules", [])) or "// No rules generated.", "yara", "Hunt observed strings in files and memory; corroborate with endpoint telemetry."))
    parts.append(_code_panel("Containment playbook", isolation_commands(data), "containment", "Review-only commands. Linux rules apply on the forwarding gateway; Windows rules apply locally on affected hosts. Preserve console access. NetSentinel never executes these commands."))
    parts.append('<p class="note">Evidence limits: network behaviour alone does not identify a process, prove compromise or establish the sensitivity of transferred bytes. Correlation supports investigation; attribution requires additional evidence.</p>')
    parts.append('<footer class="footer"><a class="scroll-top" href="#top">Back to top ↑</a>NETSENTINEL AI · Meta Muse Spark + Muse Wonder · ATT&amp;CK v15 · Self-contained SOC artifact</footer></div>')
    parts.append(f'<script>{_SCRIPT}</script></body></html>')
    return ''.join(parts)


def _write(path: str | Path, content: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def export_markdown_report(report: Any, path: str | Path) -> Path:
    return _write(path, render_markdown_report(report))


def export_html_report(report: Any, path: str | Path) -> Path:
    return _write(path, render_html_report(report))


render_markdown = render_markdown_report
render_html = render_html_report
