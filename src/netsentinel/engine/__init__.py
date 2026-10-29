"""Detection orchestration: run all detectors, correlate, produce a report."""
from .correlator import (
    AttackCampaign,
    CorrelationReport,
    correlate,
    correlate_events,
)
from .detector import DetectionReport, compute_flow_stats, detect

__all__ = [
    "AttackCampaign",
    "CorrelationReport",
    "DetectionReport",
    "compute_flow_stats",
    "correlate",
    "correlate_events",
    "detect",
]
