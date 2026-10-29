"""Shared artifact normalization, without importing the pipeline."""
from __future__ import annotations

from typing import Any


def report_data(report: Any) -> dict:
    return report.to_dict() if hasattr(report, "to_dict") else dict(report)


def event_rows(data: dict) -> list[dict]:
    return [row if "event" in row else {"event": row, "assessment": {}, "playbook": {}}
            for row in data.get("events", [])]


def campaigns(data: dict) -> list[dict]:
    value = data.get("correlation", data.get("campaigns", {}))
    if isinstance(value, dict):
        return value.get("campaigns", [])
    return value if isinstance(value, list) else []
