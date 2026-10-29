"""Configuration loading for NetSentinel AI.

Precedence (highest first):
  1. Environment variables (META_API_KEY, META_BASE_URL, META_TRIAGE_MODEL, ...)
  2. `config/config.yaml`
  3. Built-in defaults

The Meta Model API key is resolved in the following order so that the project
works unchanged with keys provisioned under any previous naming scheme:

    ``META_API_KEY`` -> ``MODEL_API_KEY`` -> ``LLAMA_API_KEY``
"""
from __future__ import annotations

import os
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

try:
    import yaml  # type: ignore

    _HAS_YAML = True
except Exception:  # pragma: no cover - yaml is optional at import time
    _HAS_YAML = False

#: Official Meta Model API endpoint (OpenAI-compatible).
DEFAULT_META_BASE_URL = "https://api.meta.ai/v1"
#: Tier 1 - low-latency batch triage model.
DEFAULT_TRIAGE_MODEL = "muse-spark-1.3"
#: Tier 2 - deep reasoning / SOC copilot model.
DEFAULT_REASONING_MODEL = "muse-wonder-1.0"

#: API key environment variables, highest priority first.
API_KEY_ENV_ORDER = ("META_API_KEY", "MODEL_API_KEY", "LLAMA_API_KEY")


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
class MetaModelConfig:
    """Dual-model routing configuration for the Meta Model API."""

    api_key: str = field(default="", repr=False)
    base_url: str = DEFAULT_META_BASE_URL
    triage_model: str = DEFAULT_TRIAGE_MODEL
    reasoning_model: str = DEFAULT_REASONING_MODEL
    timeout: float = 60.0
    max_tokens: int = 1400
    temperature: float = 0.2
    use_json_schema: bool = True
    #: When False the orchestrator skips the Tier-1 triage pass.
    enable_triage: bool = True
    triage_batch_size: int = 8

    @property
    def model(self) -> str:
        """Backwards-compatible alias for the deep-reasoning model id."""
        return self.reasoning_model

    @model.setter
    def model(self, value: str) -> None:
        self.reasoning_model = value

    def has_credentials(self) -> bool:
        return bool(self.api_key)

    def validate_base_url(self) -> str:
        """Reject embedded secrets and plaintext remote endpoints before auth."""
        parsed = urlsplit(str(self.base_url))
        local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if (not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment
                or parsed.scheme not in ("https", "http")
                or (parsed.scheme == "http" and not local)):
            raise ValueError("Meta API endpoint must use HTTPS without embedded credentials")
        return str(self.base_url)

    def safe_base_url(self) -> str:
        """Endpoint suitable for report/log output, without URL-borne secrets."""
        try:
            return self.validate_base_url()
        except (ValueError, TypeError):
            return "<invalid endpoint>"

    def routing_table(self) -> Dict[str, str]:
        """Human-readable description of the two-tier routing setup."""
        return {
            "tier1_fast_triage": self.triage_model,
            "tier2_deep_reasoning": self.reasoning_model,
            "base_url": self.safe_base_url(),
        }


#: Legacy name kept so existing imports (``from ..config import LlamaConfig``) work.
LlamaConfig = MetaModelConfig



@dataclass
class Settings:
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    meta: MetaModelConfig = field(default_factory=MetaModelConfig)

    @property
    def llama(self) -> MetaModelConfig:
        """Legacy alias - ``settings.llama`` now points at the Meta Model config."""
        return self.meta

    @llama.setter
    def llama(self, value: MetaModelConfig) -> None:
        self.meta = value

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "Settings":
        settings = cls()
        _load_dotenv()

        # 1) YAML file
        data: Dict[str, Any] = {}
        explicit_path = config_path is not None
        path = Path(config_path) if explicit_path else _default_config_path()
        if _HAS_YAML:
            try:
                contents = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                if explicit_path:
                    raise OSError("Configuration file does not exist") from None
            except OSError:
                raise OSError("Cannot read configuration file") from None
            except UnicodeError:
                raise ValueError("Configuration file must contain UTF-8 YAML") from None
            else:
                try:
                    loaded = yaml.safe_load(contents)
                except yaml.YAMLError:
                    # Parser errors can include secret-bearing YAML source lines.
                    raise ValueError("Invalid configuration YAML") from None
                if not isinstance(loaded, dict):
                    raise ValueError("Configuration YAML must contain a mapping")
                data = loaded
        elif explicit_path:
            raise ValueError("PyYAML is required to read a configuration file")

        det = data.get("detection", {})
        if not isinstance(det, dict):
            raise ValueError("Configuration section 'detection' must be a mapping")
        for key in DetectionConfig.__dataclass_fields__:
            if key in det:
                setattr(settings.detection, key, det[key])

        # `meta:` is the canonical section; `llama:` is still honoured for
        # configs created before the Meta Model API migration.
        model_cfg: Dict[str, Any] = {}
        for section in ("llama", "meta"):
            chunk = data.get(section, {})
            if not isinstance(chunk, dict):
                raise ValueError(f"Configuration section '{section}' must be a mapping")
            model_cfg.update(chunk)
        # Translate the old model setting without allowing obsolete defaults
        # to silently override the official endpoint/models after migration.
        if "model" in model_cfg and "reasoning_model" not in model_cfg:
            legacy_model = str(model_cfg["model"])
            if legacy_model.startswith("muse-"):
                model_cfg["reasoning_model"] = legacy_model
        for key in MetaModelConfig.__dataclass_fields__:
            if key in model_cfg:
                setattr(settings.meta, key, model_cfg[key])
        # 2) Environment variables (always win over YAML/defaults)
        api_key = resolve_api_key()
        if api_key:
            settings.meta.api_key = api_key

        base_url = _first_env("META_BASE_URL", "MODEL_BASE_URL", "LLAMA_BASE_URL")
        if base_url:
            settings.meta.base_url = base_url
        if "api.llama.com" in str(settings.meta.base_url):
            settings.meta.base_url = DEFAULT_META_BASE_URL

        reasoning = _first_env("META_REASONING_MODEL", "META_MODEL", "LLAMA_MODEL")
        if reasoning:
            settings.meta.reasoning_model = reasoning

        triage = _first_env("META_TRIAGE_MODEL", "META_FAST_MODEL")
        if triage:
            settings.meta.triage_model = triage

        timeout = _first_env("META_TIMEOUT", "LLAMA_TIMEOUT")
        if timeout:
            try:
                parsed_timeout = float(timeout)
            except ValueError:
                raise ValueError("META_TIMEOUT must be a finite positive number") from None
            settings.meta.timeout = parsed_timeout

        _validate_meta_config(settings.meta)

        return settings


def _validate_meta_config(config: MetaModelConfig) -> None:
    for name in ("timeout", "temperature"):
        value = getattr(config, name)
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value)):
            raise ValueError(f"Meta setting '{name}' must be a finite number")
    if config.timeout <= 0:
        raise ValueError("Meta setting 'timeout' must be positive")
    if not 0 <= config.temperature <= 2:
        raise ValueError("Meta setting 'temperature' must be between 0 and 2")
    for name in ("max_tokens", "triage_batch_size"):
        value = getattr(config, name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"Meta setting '{name}' must be a positive integer")
    for name in ("use_json_schema", "enable_triage"):
        if not isinstance(getattr(config, name), bool):
            raise ValueError(f"Meta setting '{name}' must be a boolean")



def resolve_api_key() -> str:
    """Return the first configured Meta Model API key (priority ordered)."""
    for env_name in API_KEY_ENV_ORDER:
        value = os.getenv(env_name)
        if value and value.strip():
            return value.strip()
    return ""


def _first_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return ""


def _load_dotenv() -> None:
    """Best-effort ``.env`` loading (never raises)."""
    try:
        from dotenv import find_dotenv, load_dotenv  # type: ignore

        path = find_dotenv(usecwd=True)
        if path:
            load_dotenv(path, override=False)
    except Exception:  # pragma: no cover - python-dotenv is optional
        return


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


def project_root() -> Path:
    """Best-effort repository root (contains ``data/`` and ``pyproject.toml``)."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[2], Path.cwd()):
        if (candidate / "data").exists() or (candidate / "pyproject.toml").exists():
            return candidate
    return Path.cwd()


def examples_dir() -> Path:
    return project_root() / "examples"


def demo_pcap_path() -> Path:
    return project_root() / "data" / "demo.pcap"


def resolve_project_path(raw: str | Path, *, must_exist: bool = False) -> Optional[Path]:
    """Resolve a user-supplied path against the CWD and the project root."""
    candidate = Path(raw)
    if candidate.exists():
        return candidate
    if not candidate.is_absolute():
        rooted = project_root() / candidate
        if rooted.exists():
            return rooted
    return None if must_exist else candidate
