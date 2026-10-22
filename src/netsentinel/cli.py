"""Command-line interface for NetSentinel AI."""
from __future__ import annotations

import argparse
import json
import sys
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

    settings = Settings.load()
    if args.command == "analyze":
        return _run_analyze(args, settings)

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
    analyze.add_argument(
        "--offline",
        action="store_true",
        help="Skip the LLM call and use local heuristic reasoning.",
    )
    analyze.add_argument(
        "--rules",
        action="store_true",
        help="Also print generated Snort/Suricata and YARA rules.",
    )
    return parser


def _run_analyze(args, settings: Settings) -> int:
    result = analyze_path(args.path, settings=settings, use_llm=not args.offline)

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print(_render_text(result, show_rules=args.rules))
    return 0


def _render_text(result: AnalysisResult, show_rules: bool = False) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("NetSentinel AI - Analysis Report")
    lines.append("=" * 72)
    lines.append(f"Flows analysed      : {result.report.flows_count}")
    lines.append(f"Suspicious events   : {len(result.report.events)}")
    lines.append(f"LLM enrichment      : {'yes' if result.llm_available else 'no (local heuristic)'}")

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
            lines.append("Snort/Suricata rules")
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
