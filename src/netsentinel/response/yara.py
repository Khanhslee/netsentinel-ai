"""Portable YARA rules for hunting observed indicators in files and memory.

These are indicator hunts, not malware-family signatures or packet decoders.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..mitre import technique_id_for
from ..models import SuspiciousEvent, stable_hash


def generate_yara_rule(event: SuspiciousEvent) -> str:
    """Render one syntactically safe rule, with no invented payload signatures."""
    kind = re.sub(r"[^A-Za-z0-9_]", "_", event.event_type)
    values = list(dict.fromkeys(str(i) for i in event.iocs if str(i)))
    values = values[:50] or [event.src_ip or "NetSentinel_no_observed_indicator"]
    name = f"NetSentinel_{kind}_{stable_hash(event.event_id + '|' + '|'.join(values))}"
    technique = event.mitre_technique or technique_id_for(event.event_type)
    metadata = {
        "author": "NetSentinel AI - Meta Muse Wonder",
        "description": f"Observed {event.event_type} IOC hunt; validate matches with endpoint telemetry",
        "mitre_attck": technique,
        "mitre_technique": technique,
        "date": datetime.now(timezone.utc).date().isoformat(),
        "severity": event.severity,
        "source_event": event.event_id,
    }
    lines = [f"rule {name}", "{", "    meta:"]
    lines.extend(f'        {key} = "{_escape(value)}"' for key, value in metadata.items())
    lines.append("    strings:")
    lines.extend(f'        $ioc_{i} = "{_escape(value)}" ascii nocase' for i, value in enumerate(values))
    lines.extend(["    condition:", "        any of them", "}", ""])
    return "\n".join(lines)


def _escape(value: str) -> str:
    """Encode arbitrary telemetry as UTF-8 bytes in a YARA string literal."""
    output = []
    for byte in str(value).encode("utf-8"):
        if byte == 34:
            output.append(r'\"')
        elif byte == 92:
            output.append(r"\\")
        elif 32 <= byte < 127:
            output.append(chr(byte))
        else:
            output.append(f"\\x{byte:02x}")
    return "".join(output)
