"""Detection orchestration: run all detectors and produce a report."""
from .detector import DetectionReport, detect

__all__ = ["DetectionReport", "detect"]
