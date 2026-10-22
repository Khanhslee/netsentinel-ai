"""Centralized logging configuration for NetSentinel AI."""
import logging
import sys

_configured = False


def get_logger(name: str = "netsentinel") -> logging.Logger:
    """Return a configured logger (idempotent)."""
    global _configured
    if not _configured:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
        )
        root = logging.getLogger("netsentinel")
        root.setLevel(logging.INFO)
        root.addHandler(handler)
        root.propagate = False
        _configured = True
    return logging.getLogger(name)
