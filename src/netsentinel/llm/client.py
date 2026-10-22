"""Meta Model API (Llama Cloud) client - OpenAI-compatible wrapper."""
from __future__ import annotations

import json
import re
from typing import List, Optional

from ..config import LlamaConfig, Settings
from ..models import SuspiciousEvent
from ..utils.logger import get_logger
from .prompts import SYSTEM_PROMPT, build_user_prompt
from .schemas import ThreatAssessment

log = get_logger(__name__)


class LlamaClient:
    """Thin wrapper around the Meta Llama Model API using the OpenAI SDK.

    Uses ``https://api.llama.com/v1`` (OpenAI-compatible) with a Bearer token.
    Falls back to deterministic local reasoning when no API key is present or
    when the request fails, so the pipeline always completes.
    """

    def __init__(self, cfg: Optional[LlamaConfig] = None):
        self.cfg = cfg or Settings.load().llama
        self._client = None

    # -- availability -------------------------------------------------------
    def available(self) -> bool:
        return bool(self.cfg.api_key)

    # -- client -------------------------------------------------------------
    def _get_client(self):
        if self._client is None:
            from openai import OpenAI  # deferred import to keep offline path light

            self._client = OpenAI(
                base_url=self.cfg.base_url,
                api_key=self.cfg.api_key,
                timeout=self.cfg.timeout,
            )
        return self._client

    # -- core ---------------------------------------------------------------
    def analyze_event(self, event: SuspiciousEvent) -> ThreatAssessment:
        """Return a threat assessment for one event (API or local fallback)."""
        if not self.available():
            log.info("No LLAMA_API_KEY set - using local heuristic assessment.")
            return ThreatAssessment.from_event(event)

        try:
            completion = self._get_client().chat.completions.create(
                model=self.cfg.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(event)},
                ],
                temperature=0.2,
                response_format={"type": "json_object"},
            )
            content = completion.choices[0].message.content or ""
            data = _extract_json(content)
            assessment = ThreatAssessment.model_validate(data)
            return _merge_with_event(assessment, event)
        except Exception as exc:  # network/auth/model errors -> offline fallback
            log.warning("LLM call failed (%s); falling back to local reasoning.", exc)
            return ThreatAssessment.from_event(event)

    def analyze_events(self, events: List[SuspiciousEvent]) -> List[ThreatAssessment]:
        return [self.analyze_event(e) for e in events]


def _extract_json(text: str) -> dict:
    """Robustly extract a JSON object from a model response."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Find the largest balanced {...} object.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass
    raise ValueError("No JSON object found in model response")


def _merge_with_event(assessment: ThreatAssessment, event: SuspiciousEvent) -> ThreatAssessment:
    """Ensure the model's verdict retains the detector's IOCs and MITRE fallback."""
    if not assessment.iocs:
        assessment.iocs = list(event.iocs)
    if not assessment.mitre_technique and event.mitre_technique:
        assessment.mitre_technique = event.mitre_technique
    if assessment.severity not in ("low", "medium", "high", "critical"):
        assessment.severity = event.severity
    return assessment
