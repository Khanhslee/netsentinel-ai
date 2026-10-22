"""YARA rule generation from suspicious events."""
from __future__ import annotations

from ..models import SuspiciousEvent, stable_hash


def generate_yara_rule(event: SuspiciousEvent) -> str:
    """Generate a YARA rule matching the event's domain/IOC strings."""
    rule_name = f"NetSentinel_{event.event_type}_{event.event_id}"

    strings = []
    condition_parts = ["any of them"]
    for ioc in event.iocs:
        if _looks_like_ascii_string(ioc) and _looks_like_domain(ioc):
            strings.append(_yara_string(f"$d{len(strings)}", ioc))
    if not strings:
        # Fall back to the source IP/port as printable strings.
        for ioc in event.iocs:
            if _looks_like_ascii_string(ioc):
                strings.append(_yara_string(f"$s{len(strings)}", ioc))
    if not strings:
        src = event.src_ip or "none"
        strings = [_yara_string("$s0", src)]
        condition_parts = ["$s0"]
        rule_name = f"{rule_name}_src"

    body = []
    for name, value in strings:
        body.append(f"        {name} = {value}")
    body.append("    condition:")
    body.append(f"        {condition_parts[0]}")

    return (
        f"rule {rule_name}\n"
        "{\n"
        "    meta:\n"
        f"        description = \"NetSentinel {event.event_type} detection\"\n"
        f"        severity = \"{event.severity}\"\n"
        f"        mitre_technique = \"{event.mitre_technique}\"\n"
        f"        author = \"NetSentinel AI\"\n"
        f"        sample_id = \"{event.event_id}\"\n"
        "    strings:\n"
        + "\n".join(body)
        + "\n}\n"
    )


def _yara_string(name: str, value: str) -> tuple:
    # YARA wants double-quote delimited ASCII with escaped quotes/backslashes.
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return name, f'"{escaped}" nocase'


def _looks_like_domain(value: str) -> bool:
    return "." in value


def _looks_like_ascii_string(value: str) -> bool:
    return all(32 <= ord(ch) < 127 for ch in value)
