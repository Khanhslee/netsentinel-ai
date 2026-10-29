"""Compact, deduplicated Suricata 7+ IOC and behavioural watch rules.

Packet rules complement the statistical flow detectors. They do not reproduce
entropy, cadence or byte-ratio analysis, and should be tuned before deployment.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Sequence

from ..mitre import technique_id_for
from ..models import SuspiciousEvent

SID_BASE = 9_000_001
CLASSTYPE_BY_EVENT = {
    "beacon": "trojan-activity", "port_scan": "attempted-recon",
    "dga": "trojan-activity", "nxdomain_storm": "attempted-recon",
    "dns_tunneling": "trojan-activity", "exfiltration": "policy-violation",
}
_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}$")


def generate_suricata_rules(event: SuspiciousEvent, start_sid: int = SID_BASE) -> list[str]:
    return build_rule_set([event], start_sid)


def build_rule_set(events: Sequence[SuspiciousEvent], start_sid: int = SID_BASE) -> list[str]:
    """Allocate SIDs once for a capture and deduplicate identical predicates."""
    if start_sid < 1:
        raise ValueError("start_sid must be positive")
    rules, seen = [], set()
    for event in events:
        for protocol, header, match in _specs(event):
            signature = (protocol, header, match)
            if signature in seen:
                continue
            seen.add(signature)
            technique = event.mitre_technique or technique_id_for(event.event_type)
            technique = _token(technique) or "unmapped"
            kind = _token(event.event_type)
            severity = _token(event.severity)
            msg = f"NetSentinel {kind.upper()} {technique} observed IOC/behaviour watch"
            rules.append(
                f'alert {protocol} {header} (msg:"{msg}"; {match} '
                f"classtype:{CLASSTYPE_BY_EVENT.get(event.event_type, 'misc-activity')}; "
                f"metadata: mitre_technique_id {technique}, event_type {kind}, severity {severity}; "
                f"sid:{start_sid + len(rules)}; rev:1;)"
            )
    return rules


def generate_ruleset_document(events: Sequence[SuspiciousEvent], start_sid: int = SID_BASE) -> str:
    header = (
        "# NetSentinel AI | Suricata 7+ | SPDX-License-Identifier: MIT\n"
        "# Observed IOC and behavioural watch rules. Validate and tune before deployment.\n"
        "# Flow-level entropy/cadence/volume verdicts remain in the detection report.\n"
    )
    return header + "\n".join(build_rule_set(events, start_sid)) + "\n"


def write_ruleset(path: str | Path, events: Sequence[SuspiciousEvent], start_sid: int = SID_BASE) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(generate_ruleset_document(events, start_sid), encoding="utf-8")
    return target


def _specs(event: SuspiciousEvent) -> list[tuple[str, str, str]]:
    source = _ip(event.src_ip)
    if not source:
        # Invalid telemetry must not silently turn into a network-wide rule.
        return []
    target = _ip(event.dst_ip) or "any"
    port = event.dst_port if isinstance(event.dst_port, int) and 0 < event.dst_port <= 65535 else "any"
    kind = event.event_type
    if kind in ("dns_tunneling", "dga", "nxdomain_storm"):
        domains = _observed_domains(event)
        if len(domains) > 1 and kind != "dns_tunneling":
            # One exact alternation covers the observed family/domain set instead
            # of either dropping indicators or emitting one SID per domain.
            choices = "|".join(re.escape(domain) for domain in domains)
            return [("dns", f"{source} any -> any 53", (
                f'flow:to_server; dns.query; pcre:"/(?:^|\\.)(?:{choices})$/i";'
            ))]
        domain = _primary_domain(event)
        if domain:
            pattern = re.escape(domain).replace("/", r"\/")
            return [("dns", f"{source} any -> any 53", (
                f'flow:to_server; dns.query; content:"{domain}"; nocase; endswith; '
                f'pcre:"/(?:^|\\.){pattern}$/i";'
            ))]
        return [("udp", f"{source} any -> any 53", (
            "flow:to_server; dsize:>12; "
            "threshold:type both, track by_src, count 20, seconds 60;"
        ))]
    if kind == "port_scan":
        protocol = "udp" if str(event.features.get("kind", "SYN")).upper() == "UDP" else "tcp"
        flags = "flags:S; " if protocol == "tcp" else ""
        return [(protocol, f"{source} any -> {target} any", (
            f"flow:stateless; {flags}"
            "threshold:type both, track by_src, count 10, seconds 60;"
        ))]
    proto = str(event.features.get("proto", "tcp")).lower()
    proto = proto if proto in ("tcp", "udp") else "tcp"
    flow = "established,to_server" if proto == "tcp" else "to_server"
    if kind == "exfiltration":
        return [(proto, f"{source} any -> {target} {port}", (
            f"flow:{flow}; dsize:>1200; "
            "threshold:type both, track by_src, count 50, seconds 60;"
        ))]
    if kind == "beacon":
        return [(proto, f"{source} any -> {target} {port}", (
            f"flow:{flow}; threshold:type both, track by_src, count 3, seconds 600;"
        ))]
    return [("ip", f"{source} any -> {target} any", "flow:stateless;")]


def _primary_domain(event: SuspiciousEvent) -> str:
    for candidate in [event.features.get("base_domain"), event.features.get("top_family"), *event.iocs]:
        value = str(candidate or "").rstrip(".").lower()
        if _DOMAIN.fullmatch(value):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return value
    return ""


def _observed_domains(event: SuspiciousEvent) -> list[str]:
    domains = []
    for candidate in event.iocs:
        value = str(candidate).rstrip(".").lower()
        if not _DOMAIN.fullmatch(value) or value in domains:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            domains.append(value)
    return domains[:50]


def _ip(value: str | None) -> str:
    try:
        return str(ipaddress.ip_address(value or ""))
    except ValueError:
        return ""


def _token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(value))[:100]
