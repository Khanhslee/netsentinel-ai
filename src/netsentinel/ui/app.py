"""Chainlit SOC copilot: ``chainlit run src/netsentinel/ui/app.py``.

The CLI remains usable without the optional UI extra. Capture parsing and model
calls run in worker threads so progress remains visible during analysis.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

# Chainlit imports this entry point as a standalone module.
_SRC = Path(__file__).resolve().parents[2]
_REPO = _SRC.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

try:
    import chainlit as cl
except ImportError:  # pragma: no cover - UI is an optional extra
    cl = None

from netsentinel.config import Settings
from netsentinel.llm.client import MetaModelClient
from netsentinel.pipeline import AnalysisResult, analyze_flows, load_flows
from netsentinel.ui.chat import answer_query, correlation_summary

log = logging.getLogger(__name__)
_SUPPORTED_SUFFIXES = {".pcap", ".pcapng", ".json", ".csv", ".log", ".conn"}
_ACTION_SPECS = (
    ("run_demo", "🔍 Run Full Demo PCAP Analysis"),
    ("view_kill_chain", "🔗 View Attack Kill-Chain Correlation"),
    ("generate_rules", "🛡️ Generate Suricata & YARA Rules"),
    ("export_report", "📊 Export HTML & Markdown SOC Report"),
)


def _actions() -> list[Any]:
    return [cl.Action(name=name, payload={}, label=label) for name, label in _ACTION_SPECS]


def _welcome(settings: Settings) -> str:
    status = (
        "API key configured · connection is verified when analysis runs"
        if settings.meta.api_key
        else "Offline deterministic expert engine · no API key configured"
    )
    return (
        "# 🛡️ NetSentinel AI\n**Your evidence-driven SOC copilot**\n\n"
        "Turn network telemetry into prioritized findings, correlated attack hypotheses, "
        "and reviewable response artifacts.\n\n"
        "| Reasoning tier | Configured model |\n| --- | --- |\n"
        f"| Deep analysis & SOC copilot · Meta Muse Wonder | `{settings.meta.reasoning_model}` |\n"
        f"| Fast batch triage · Meta Muse Spark | `{settings.meta.triage_model}` |\n\n"
        f"**Status:** {status}\n\n"
        "Run the bundled six-scenario demo below, upload a PCAP or flow file, "
        "or paste a local file path. Then ask about evidence, IOCs, "
        "MITRE ATT&CK, or containment. Response commands are generated for analyst review."
    )


async def on_chat_start() -> None:
    settings = _load_settings()
    cl.user_session.set("settings", settings)
    cl.user_session.set("analysis_lock", asyncio.Lock())
    cl.user_session.set("copilot_client", MetaModelClient(settings.meta))
    await cl.Message(content=_welcome(settings), actions=_actions()).send()


async def on_message(message: Any) -> None:
    resolved = _resolve_input(message)
    if resolved:
        path, suffix_hint, display_name = resolved
        await _run_analysis(path, suffix_hint=suffix_hint, display_name=display_name)
        return
    query = (getattr(message, "content", "") or "").strip()
    if not query:
        await cl.Message(content="Upload a capture or choose **Run Full Demo PCAP Analysis**.").send()
        return
    result = cl.user_session.get("result")
    if result is None:
        await cl.Message(content=answer_query(None, query), actions=_actions()).send()
        return
    fallback = answer_query(result, query)
    simple_command = query.lower().split()[0] in {
        "help", "?", "summary", "overview", "events", "list", "beacons", "beacon",
        "explain", "rules", "suricata", "yara", "snort", "playbook", "iocs",
        "metrics", "evidence", "kill-chain", "killchain", "correlation",
    }
    routing = getattr(result, "routing", {}) or {}
    online = bool(result.llm_available) and routing.get("mode") != "offline-deterministic"
    client = cl.user_session.get("copilot_client")
    if online and not simple_command and client is not None:
        async with cl.Step(name="Muse Wonder · grounded SOC investigation", type="llm") as step:
            reply = await asyncio.to_thread(client.chat, query, _copilot_context(result), fallback_answer=fallback)
            step.output = (
                "Answered from the current capture and correlated evidence."
                if client.available()
                else "API unavailable; deterministic evidence-based answer provided."
            )
    else:
        reply = fallback
    await cl.Message(content=reply).send()


async def _run_analysis(
    path: Path, *, suffix_hint: str | None = None, display_name: str | None = None
) -> AnalysisResult | None:
    lock = cl.user_session.get("analysis_lock")
    if lock is None:
        lock = asyncio.Lock()
        cl.user_session.set("analysis_lock", lock)
    if lock.locked():
        await cl.Message(content="Analysis is running. The findings will appear when it completes.").send()
        return None
    async with lock:
        try:
            settings = cl.user_session.get("settings") or _load_settings()
            async with cl.Step(name="1 · Ingest capture and reconstruct flows", type="tool") as step:
                flows = await asyncio.to_thread(_load_capture, path, suffix_hint)
                step.output = f"Loaded {len(flows):,} flows from {display_name or path.name}."
            async with cl.Step(
                name="2 · Mathematical detection, kill-chain correlation & dual-model reasoning", type="tool"
            ) as step:
                result = await asyncio.to_thread(analyze_flows, flows, settings=settings, use_llm=True)
                if hasattr(result, "source_path"):
                    result.source_path = display_name or str(path)
                routing = getattr(result, "routing", {}) or {}
                mode = routing.get("mode", "meta-model-api" if result.llm_available else "offline-deterministic")
                step.output = f"Detected {len(result.report.events)} events. Reasoning mode: {mode}."
            async with cl.Step(name="3 · Prepare SOC response artifacts", type="tool") as step:
                cl.user_session.set("result", result)
                cl.user_session.set("copilot_client", MetaModelClient(settings.meta))
                step.output = (
                    f"{len(result.suricata_rules)} compact Suricata rules and "
                    f"{len(result.yara_rules)} YARA rules ready; SOC reports available below."
                )
            await cl.Message(content=_analysis_summary(result), actions=_actions()).send()
            return result
        except Exception as exc:  # A malformed upload must not end the chat session.
            log.warning("Capture analysis failed: %s", type(exc).__name__)
            if isinstance(exc, FileNotFoundError):
                explanation = "The capture was not found. Upload it again or run the bundled demo."
            elif isinstance(exc, PermissionError):
                explanation = "The capture cannot be read. Choose a file you have permission to open."
            else:
                explanation = "The file could not be analyzed. Use a valid PCAP, PCAPNG, JSON, CSV, or Zeek conn.log file."
            await cl.Message(content=f"⚠️ {explanation}", actions=_actions()).send()
            return None


def _load_capture(path: Path, suffix_hint: str | None = None) -> list[Any]:
    # Chainlit uploads can have extensionless UUID paths. Preserve only the
    # verified extension, never the user-provided upload filename.
    if path.suffix.lower() not in _SUPPORTED_SUFFIXES and suffix_hint in _SUPPORTED_SUFFIXES:
        with tempfile.TemporaryDirectory(prefix="netsentinel-upload-") as directory:
            staged = Path(directory) / f"capture{suffix_hint}"
            shutil.copyfile(path, staged)
            return load_flows(staged)
    return load_flows(path)


async def _ensure_result() -> AnalysisResult | None:
    result = cl.user_session.get("result")
    return result if result is not None else await _run_analysis(_REPO / "data" / "demo.pcap")


async def run_demo(_action: Any = None) -> None:
    await _run_analysis(_REPO / "data" / "demo.pcap")


async def view_kill_chain(_action: Any = None) -> None:
    result = await _ensure_result()
    if result is not None:
        async with cl.Step(name="Inspect correlated attack hypotheses", type="tool") as step:
            step.output = "Grouped findings by shared endpoints and time; causality requires investigation."
        await cl.Message(content=correlation_summary(result)).send()


async def generate_rules(_action: Any = None) -> None:
    result = await _ensure_result()
    if result is None:
        return
    async with cl.Step(name="Package deduplicated detection rules", type="tool") as step:
        suricata = "\n".join(result.suricata_rules) + "\n"
        yara = "\n\n".join(result.yara_rules) + "\n"
        step.output = f"{len(result.suricata_rules)} Suricata / {len(result.yara_rules)} YARA rules."
    await cl.Message(
        content="🛡️ **Detection rules ready.** Download and validate them against your SOC's deployment policy.",
        elements=[
            cl.File(name="suricata_netsentinel.rules", content=suricata.encode("utf-8"), display="inline"),
            cl.File(name="yara_netsentinel.yar", content=yara.encode("utf-8"), display="inline"),
        ],
    ).send()


async def export_report(_action: Any = None) -> None:
    result = await _ensure_result()
    if result is None:
        return
    from netsentinel.response.mitre_navigator import generate_mitre_layer
    from netsentinel.response.report_exporter import render_html_report, render_markdown_report

    try:
        async with cl.Step(name="Export SOC dashboard, incident report & ATT&CK layer", type="tool") as step:
            markdown, html, layer = await asyncio.gather(
                asyncio.to_thread(render_markdown_report, result),
                asyncio.to_thread(render_html_report, result),
                asyncio.to_thread(generate_mitre_layer, result),
            )
            step.output = "Self-contained HTML, Markdown, and ATT&CK Navigator layer generated."
        await cl.Message(
            content="📊 **SOC reports ready.** The HTML dashboard works offline. All containment commands require analyst review.",
            elements=[
                cl.File(name="incident_report.html", content=html.encode("utf-8"), display="inline"),
                cl.File(name="incident_report.md", content=markdown.encode("utf-8"), display="inline"),
                cl.File(name="attck_navigator_layer.json", content=json.dumps(layer, indent=2).encode("utf-8"), display="inline"),
            ],
        ).send()
    except Exception as exc:
        log.warning("SOC report export failed: %s", type(exc).__name__)
        await cl.Message(content="The report could not be exported. Your analysis and detection rules are still available.").send()


def _analysis_summary(result: AnalysisResult) -> str:
    severities = result.vulnerabilities_by_severity()
    stats = getattr(result.report, "stats", {}) or {}
    sources = {assessment.reasoning_source for assessment in result.assessments}
    mode = (
        "Meta Model API + deterministic fallback" if result.llm_available and len(sources) > 1
        else "Meta Model API" if result.llm_available
        else "Offline deterministic expert engine"
    )
    lines = [
        "## Analysis complete",
        f"**{stats.get('packets', 0):,} packets · {result.report.flows_count:,} flows · {len(result.report.events)} findings**",
        f"**Critical:** {severities.get('critical', 0)} · **High:** {severities.get('high', 0)} · **Reasoning:** {mode}",
        "", "| # | Detection | Severity | Source | ATT&CK |", "| --- | --- | --- | --- | --- |",
    ]
    for index, event in enumerate(result.report.events, 1):
        lines.append(
            f"| {index} | {event.event_type.upper()} | {event.severity.upper()} | "
            f"{_cell(event.src_ip or 'unknown')} | {_cell(event.mitre_technique or 'unmapped')} |"
        )
    lines.extend(["", "Use the actions below or ask `explain 1`, `evidence`, `iocs`, or `kill-chain`."])
    return "\n".join(lines)


def _cell(value: str) -> str:
    return str(value).replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|").replace("\n", " ")


def _copilot_context(result: AnalysisResult) -> list[str]:
    data = result.to_dict()
    correlation = data.get("correlation", {})
    fragments = [json.dumps({
        "capture_stats": data.get("stats", {}),
        "severity_counts": data.get("severity_counts", {}),
        "campaigns": [
            {key: campaign.get(key) for key in (
                "scope", "src_ips", "observed_stages", "summary", "risk_score"
            )}
            for campaign in correlation.get("campaigns", [])
        ],
        "environment_overview_is_unconfirmed": bool(correlation.get("environment_overview")),
    }, default=str)]
    for row in data.get("events", []):
        event = row["event"]
        assessment = row.get("assessment", {})
        # Full rule bodies and repeated campaign timelines otherwise consume the
        # bounded copilot context before the event evidence is reached.
        fragments.append(json.dumps({
            "event_id": event["event_id"],
            "type": event["event_type"],
            "source": event.get("src_ip"), "destination": event.get("dst_ip"),
            "severity": event.get("severity"),
            "first_seen": event.get("first_seen"), "last_seen": event.get("last_seen"),
            "evidence": {
                key: value[:5] if isinstance(value, list) else value
                for key, value in event.get("features", {}).items()
            },
            "observed_iocs": event.get("iocs", [])[:8],
            "assessment": {
                "threat_summary": str(assessment.get("threat_summary", ""))[:220],
                "root_cause_analysis": str(assessment.get("root_cause_analysis", ""))[:300],
                **{key: assessment.get(key) for key in (
                    "kill_chain_stage", "mitre_technique_id", "confidence_score"
                )},
            },
        }, default=str))
    return fragments


def _resolve_input(message: Any) -> tuple[Path, str | None, str] | None:
    for element in getattr(message, "elements", []) or []:
        raw_path = getattr(element, "path", None)
        if raw_path:
            try:
                path = Path(raw_path)
                if path.is_file():
                    name = Path(getattr(element, "name", "") or path.name).name
                    return path, Path(name).suffix.lower(), name
            except (OSError, ValueError):
                continue
    raw_text = (getattr(message, "content", "") or "").strip().strip('"').strip("'")
    if not raw_text:
        return None
    try:
        path = Path(raw_text).expanduser()
        candidates = [path] if path.is_absolute() else [Path.cwd() / path, _REPO / path]
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve(), None, candidate.name
    except (OSError, ValueError):
        pass
    return None


def _resolve_file_path(message: Any) -> str | None:
    """Legacy helper kept for the original upload interface."""
    resolved = _resolve_input(message)
    return str(resolved[0]) if resolved else None


def _load_settings() -> Settings:
    return Settings.load(_REPO / "config" / "config.yaml")


if cl is not None:  # pragma: no cover - registration is exercised by Chainlit
    cl.on_chat_start(on_chat_start)
    cl.on_message(on_message)
    cl.action_callback("run_demo")(run_demo)
    cl.action_callback("view_kill_chain")(view_kill_chain)
    cl.action_callback("generate_rules")(generate_rules)
    cl.action_callback("export_report")(export_report)
