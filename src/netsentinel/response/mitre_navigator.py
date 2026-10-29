"""Export the official ATT&CK Navigator layer format 4.5 (ATT&CK v15).

Format: https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..mitre import navigator_tactic, tactic_for, technique_id_for
from ._common import event_rows, report_data

_SCORES = {"critical": 95, "high": 80, "medium": 55, "low": 30}


def generate_mitre_layer(report: Any, name: str = "NetSentinel AI — Observed Threats") -> dict:
    """Aggregate detected techniques, preserving observed evidence in comments."""
    techniques: dict[tuple[str, str], dict] = {}
    for row in event_rows(report_data(report)):
        event = row["event"]
        kind = event.get("event_type", "")
        technique = event.get("mitre_technique") or technique_id_for(kind)
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            continue
        tactic = navigator_tactic(event.get("mitre_tactic") or tactic_for(kind))
        key = (technique, tactic)
        score = _SCORES.get(event.get("severity", "medium"), 55)
        comment = f"{kind.upper()} | host {event.get('src_ip', '?')} | {event.get('description', '')}"
        if key in techniques:
            techniques[key]["score"] = max(techniques[key]["score"], score)
            techniques[key]["comment"] += "\n" + comment
        else:
            techniques[key] = {"techniqueID": technique, "tactic": tactic,
                               "score": score, "comment": comment, "enabled": True}
    for technique in techniques.values():
        technique["color"] = "#ef4444" if technique["score"] >= 80 else "#fb923c"
    return {
        "name": name,
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Observed network behaviours mapped by NetSentinel AI. Scores reflect heuristic severity, not confirmed compromise.",
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True,
                   "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": [techniques[key] for key in sorted(techniques)],
        "gradient": {"colors": ["#fb923c", "#ef4444"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "High / Critical observed behaviour", "color": "#ef4444"},
                        {"label": "Low / Medium observed behaviour", "color": "#fb923c"}],
        "metadata": [{"name": "producer", "value": "NetSentinel AI"},
                     {"name": "scoring", "value": "critical=95, high=80, medium=55, low=30"}],
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def export_mitre_layer(report: Any, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(generate_mitre_layer(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


build_mitre_layer = generate_mitre_layer
