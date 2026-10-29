"""Command-line interface for NetSentinel AI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import Settings
from .pipeline import AnalysisResult, analyze_path


def main(argv: Optional[List[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "analyze":
        try:
            settings = Settings.load(getattr(args, "config", None))
            return _run_analyze(args, settings)
        except (OSError, ValueError, ImportError) as exc:
            print(f"NetSentinel: {exc}", file=sys.stderr)
            return 2

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel AI - network anomaly detection copilot & threat analysis.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="Analyze a PCAP / flow-metadata file.")
    analyze.add_argument("path", help="Path to .pcap/.pcapng/.json/.csv/Zeek conn.log")
    analyze.add_argument("--format", choices=["text", "json"], default="text")
    analyze.add_argument("--config", help="Path to a custom YAML configuration.")
    analyze.add_argument("--output", help="Also save the structured detection JSON to this path.")
    analyze.add_argument("--report-md", help="Export a Markdown incident report.")
    analyze.add_argument("--report-html", help="Export a standalone dark-mode HTML dashboard.")
    analyze.add_argument("--mitre-layer", help="Export an ATT&CK Navigator v4.5 layer.")
    analyze.add_argument("--suricata-rules", help="Save deduplicated Suricata rules.")
    analyze.add_argument("--yara-rules", help="Save YARA rules.")
    analyze.add_argument(
        "--offline",
        action="store_true",
        help="Skip the LLM call and use local heuristic reasoning.",
    )
    analyze.add_argument(
        "--rules",
        action="store_true",
        help="Also print generated Suricata and YARA rules.",
    )
    return parser


def _run_analyze(args, settings: Settings) -> int:
    result = analyze_path(args.path, settings=settings, use_llm=not args.offline)
    from .response.report_exporter import export_html_report, export_markdown_report
    from .response.mitre_navigator import export_mitre_layer

    if args.output:
        _write_text(args.output, json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n")
    for target, exporter in ((args.report_md, export_markdown_report),
                             (args.report_html, export_html_report),
                             (args.mitre_layer, export_mitre_layer)):
        if target:
            exporter(result, target)
    if args.suricata_rules:
        from .response.suricata import generate_ruleset_document
        _write_text(args.suricata_rules, generate_ruleset_document(result.report.events))
    if args.yara_rules:
        _write_text(args.yara_rules, "\n\n".join(result.yara_rules).rstrip() + "\n")

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print(_render_text(result, show_rules=args.rules))
    return 0


def _write_text(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _render_text(result: AnalysisResult, show_rules: bool = False) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("NetSentinel AI - Analysis Report")
    lines.append("=" * 72)
    lines.append(f"Flows analysed      : {result.report.flows_count}")
    lines.append(f"Packets analysed    : {result.report.stats.get('packets', 0)}")
    lines.append(f"Suspicious events   : {len(result.report.events)}")
    lines.append(f"LLM enrichment      : {'yes' if result.llm_available else 'no (local heuristic)'}")
    lines.append(f"Correlated groups   : {len(result.correlation.campaigns)}")
    lines.append(f"Models              : {result.routing.get('tier1_model', 'muse-spark-1.3')} / "
                 f"{result.routing.get('tier2_model', 'muse-wonder-1.0')}")

    severity = result.vulnerabilities_by_severity()
    if severity:
        lines.append("Severity breakdown   : " + ", ".join(f"{k}={v}" for k, v in severity.items()))

    for i, (event, assessment) in enumerate(zip(result.report.events, result.assessments), 1):
        lines.append("")
        lines.append(f"[{i}] {event.event_type.upper()} ({event.severity.upper()})")
        lines.append(f"    MITRE : {assessment.mitre_technique} - {assessment.technique_name or 'n/a'}")
        lines.append(f"    Event : {event.description}")
        lines.append(f"    Reason: {assessment.natural_language_explanation}")
        lines.append(f"    IOCs  : {', '.join(event.iocs) if event.iocs else '-'}")

    if show_rules:
        if result.suricata_rules:
            lines.append("")
            lines.append("-" * 72)
            lines.append("Suricata rules")
            lines.append("-" * 72)
            lines.extend(result.suricata_rules)
        if result.yara_rules:
            lines.append("")
            lines.append("-" * 72)
            lines.append("YARA rules")
            lines.append("-" * 72)
            lines.extend(result.yara_rules)

    lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines)
