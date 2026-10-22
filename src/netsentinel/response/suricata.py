"""Snort/Suricata rule generation from suspicious events."""
from __future__ import annotations

import ipaddress
from typing import List

from ..models import SuspiciousEvent, stable_hash


def generate_suricata_rules(event: SuspiciousEvent) -> List[str]:
    """Generate one or more Snort/Suricata rules from event IOCs."""
    rules: List[str] = []
    sid = _sid_base(event)
    msg = _safe_msg(f"NetSentinel {event.event_type.upper()} {event.mitre_technique}".strip())

    for ioc in event.iocs:
        if _is_ip(ioc):
            rules.append(
                f'alert ip $HOME_NET any -> {ioc} any '
                f'(msg:"{msg}"; flow:established,to_server; sid:{sid}; rev:1;)'
            )
            sid += 1
        elif _is_ip_port(ioc):
            ip, port = ioc.rsplit(":", 1)
            if _is_ip(ip) and port.isdigit():
                rules.append(
                    f'alert ip $HOME_NET any -> {ip} {port} '
                    f'(msg:"{msg}"; flow:established,to_server; sid:{sid}; rev:1;)'
                )
                sid += 1
        elif _looks_like_domain(ioc):
            rules.append(
                f'alert dns $HOME_NET any -> any 53 '
                f'(msg:"{msg}"; dns.query; content:"{ioc}"; nocase; sid:{sid}; rev:1;)'
            )
            sid += 1

    if not rules:
        # Fallback: alert on the event source as a behavioural watch.
        src = event.src_ip or "any"
        rules.append(
            f'alert ip {src} any -> any any '
            f'(msg:"{msg}"; sid:{sid}; rev:1;)'
        )
    return rules


def _sid_base(event: SuspiciousEvent) -> int:
    return 1_000_000 + int(stable_hash(event.event_id), 16) % 900_000


def _safe_msg(text: str) -> str:
    return text.replace('"', "'").replace("\\", "")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_ip_port(value: str) -> bool:
    if ":" not in value:
        return False
    ip, port = value.rsplit(":", 1)
    return _is_ip(ip) and port.isdigit()


def _looks_like_domain(value: str) -> bool:
    return "." in value and not _is_ip(value) and ":" not in value
