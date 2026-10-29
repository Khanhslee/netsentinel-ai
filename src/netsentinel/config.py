"""Configuration loading for NetSentinel AI.

Precedence (highest first):
  1. Environment variables (LLAMA_API_KEY, LLAMA_MODEL, ...)
  2. `config/config.yaml`
  3. Built-in defaults
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

try:
    import yaml  # type: ignore

    _HAS_YAML = True
except Exception:  # pragma: no cover - yaml is optional at import time
    _HAS_YAML = False


@dataclass
class DetectionConfig:
    beacon_min_connections: int = 5
    beacon_min_interval: float = 5.0
    beacon_jitter_ratio: float = 0.15
    dga_entropy_threshold: float = 3.4
    dga_min_length: int = 12
    nxdomain_storm_threshold: int = 10
    dns_tunnel_query_threshold: int = 8
    dns_tunnel_max_label_len: int = 20
    scan_min_ports: int = 20
    scan_window_seconds: float = 60.0
    exfil_min_bytes: int = 1_000_000
    exfil_upload_ratio: float = 10.0


@dataclass
class LlamaConfig:
    api_key: str = ""
    base_url: str = "https://api.llama.com/v1"
    model: str = "meta/llama-4-maverick-17b-128e-instruct-fp8"
    timeout: float = 60.0
    use_json_schema: bool = True


@dataclass
class Settings:
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    llama: LlamaConfig = field(default_factory=LlamaConfig)

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "Settings":
        settings = cls()

        # 1) YAML file
        data: Dict[str, Any] = {}
        if _HAS_YAML:
            path = Path(config_path) if config_path else _default_config_path()
            if path.exists():
                try:
                    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                    if isinstance(loaded, dict):
                        data = loaded
                except Exception:
                    data = {}

        det = data.get("detection") or {}
        for key in DetectionConfig.__dataclass_fields__:
            if key in det:
                setattr(settings.detection, key, det[key])

        llama = data.get("llama") or {}
        for key in LlamaConfig.__dataclass_fields__:
            if key in llama:
                setattr(settings.llama, key, llama[key])

        # 2) Environment variables
        if os.getenv("LLAMA_API_KEY"):
            settings.llama.api_key = os.environ["LLAMA_API_KEY"]
        if os.getenv("LLAMA_MODEL"):
            settings.llama.model = os.environ["LLAMA_MODEL"]
        if os.getenv("LLAMA_BASE_URL"):
            settings.llama.base_url = os.environ["LLAMA_BASE_URL"]
        if os.getenv("LLAMA_TIMEOUT"):
            try:
                settings.llama.timeout = float(os.environ["LLAMA_TIMEOUT"])
            except ValueError:
                pass

        return settings


def _default_config_path() -> Path:
    """Locate config/config.yaml relative to the repo root."""
    candidates = [
        Path.cwd() / "config" / "config.yaml",
        Path(__file__).resolve().parents[2] / "config" / "config.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]
