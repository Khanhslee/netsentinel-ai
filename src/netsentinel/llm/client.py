"""Meta Model API client with two-tier routing and a deterministic fallback.

Routing architecture
--------------------
Tier 1 - ``muse-spark-1.3``   : batch flow triage (noise filtering + priority).
Tier 2 - ``muse-wonder-1.0``  : deep kill-chain / MITRE reasoning & copilot chat.

Both tiers talk to the official Meta Model API (``https://api.meta.ai/v1``) over
the OpenAI-compatible SDK. Any failure - missing key, exhausted credit, network
error or HTTP 401/403/429 - trips a per-run circuit breaker and every remaining
call is served by :class:`~netsentinel.llm.offline.OfflineReasoningEngine`, so
the pipeline always completes with a full, high-quality analysis.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..config import MetaModelConfig, Settings
from ..models import SuspiciousEvent
from ..utils.logger import get_logger
from .offline import OfflineReasoningEngine
from .prompts import (
    COPILOT_SYSTEM_PROMPT,
    SOC_SYSTEM_PROMPT,
    TRIAGE_SYSTEM_PROMPT,
    build_copilot_prompt,
    build_triage_prompt,
    build_user_prompt,
)
from .schemas import (
    ThreatAssessment,
    AssessmentOutput,
    TriageBatchOutput,
    TriageVerdict,
    coerce_assessment,
    strict_response_format,
)

log = get_logger(__name__)

#: HTTP status codes that mean "stop calling the API for this run".
FATAL_STATUS_CODES = (401, 403, 429)


@dataclass
class RoutingRecord:
    """One routing decision, kept for observability/reporting."""

    tier: str  # "tier1-triage" | "tier2-reasoning" | "copilot"
    model: str
    source: str  # "meta-model-api" | "offline-deterministic"
    latency_ms: float = 0.0
    ok: bool = True
    fallback_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier,
            "model": self.model,
            "source": self.source,
            "latency_ms": round(self.latency_ms, 2),
            "ok": self.ok,
            "fallback_reason": self.fallback_reason,
        }


class MetaModelClient:
    """Two-tier Meta Muse client with a guaranteed offline fallback."""

    def __init__(self, cfg: Optional[MetaModelConfig] = None):
        self.cfg = cfg or Settings.load().meta
        self.offline = OfflineReasoningEngine()
        self.routing_history: List[RoutingRecord] = []
        self.last_triage: List[TriageVerdict] = []
        self._client = None
        self._circuit_open_reason: str = ""
        self._campaign_context: str = ""

    # -- availability -------------------------------------------------------
    def available(self) -> bool:
        """True when the Meta Model API can be used for the next call."""
        return bool(self.cfg.api_key) and not self._circuit_open_reason

    @property
    def mode(self) -> str:
        return "meta-model-api" if self.available() else "offline-deterministic"

    @property
    def fallback_reason(self) -> str:
        if self._circuit_open_reason:
            return self._circuit_open_reason
        return "" if self.cfg.api_key else "META_API_KEY not configured"

    def routing_table(self) -> Dict[str, Any]:
        table = dict(self.cfg.routing_table())
        table.update(
            {
                "mode": self.mode,
                "api_key_configured": bool(self.cfg.api_key),
                "fallback_reason": self.fallback_reason,
            }
        )
        return table

    # -- client -------------------------------------------------------------
    def _get_client(self):
        if self._client is None:
            from openai import OpenAI  # deferred import keeps the offline path light

            self._client = OpenAI(
                base_url=self.cfg.validate_base_url(),
                api_key=self.cfg.api_key,
                timeout=self.cfg.timeout,
                max_retries=0,
            )
        return self._client

    # -- low-level call -----------------------------------------------------
    def _chat(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        json_mode: bool = True,
        schema_model=None,
    ) -> str:
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.cfg.temperature if temperature is None else temperature,
            "max_tokens": self.cfg.max_tokens if max_tokens is None else max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = (
                strict_response_format(schema_model)
                if self.cfg.use_json_schema and schema_model is not None
                else {"type": "json_object"}
            )
        completion = self._get_client().chat.completions.create(**kwargs)
        choice = completion.choices[0]
        if getattr(choice, "finish_reason", "stop") not in ("stop", None):
            raise ValueError("Incomplete model response")
        if getattr(choice.message, "refusal", None):
            raise ValueError("Model declined the analysis")
        return choice.message.content or ""

    def _record_offline(self, tier: str, model: str) -> None:
        self.routing_history.append(RoutingRecord(
            tier=tier, model=model, source="offline-deterministic",
            fallback_reason=self.fallback_reason,
        ))

    def _trip(self, tier: str, model: str, exc: Exception, started: float) -> None:
        reason = _describe_error(exc)
        self._circuit_open_reason = reason
        self.routing_history.append(
            RoutingRecord(
                tier=tier,
                model=model,
                source="offline-deterministic",
                latency_ms=(time.perf_counter() - started) * 1000,
                ok=False,
                fallback_reason=reason,
            )
        )
        log.warning(
            "Meta Model API call failed (%s); switching to deterministic expert engine.",
            reason,
        )

    # -- Tier 1: fast batch triage (muse-spark-1.3) -------------------------
    def triage_events(self, events: Sequence[SuspiciousEvent]) -> List[TriageVerdict]:
        """Classify many events in one low-latency Tier-1 call."""
        events = list(events)
        if not events:
            self.last_triage = []
            return []

        if not (self.cfg.enable_triage and self.available()):
            self._record_offline("tier1-triage", self.cfg.triage_model)
            self.last_triage = [
                self.offline.triage(e, model=self.cfg.triage_model) for e in events
            ]
            return self.last_triage

        # Bound both prompt and output growth for large captures.
        try:
            batch_size = max(1, min(32, int(self.cfg.triage_batch_size)))
        except (ValueError, TypeError, OverflowError):
            batch_size = 8
        if len(events) > batch_size:
            verdicts = []
            for offset in range(0, len(events), batch_size):
                verdicts.extend(self.triage_events(events[offset:offset + batch_size]))
            self.last_triage = verdicts
            return verdicts

        started = time.perf_counter()
        try:
            content = self._chat(
                model=self.cfg.triage_model,
                system_prompt=TRIAGE_SYSTEM_PROMPT,
                user_prompt=build_triage_prompt(events),
                temperature=0.0,
                max_tokens=self.cfg.max_tokens,
                schema_model=TriageBatchOutput,
            )
            payload = TriageBatchOutput.model_validate(_extract_json(content)).model_dump()["verdicts"]
            verdicts = _coerce_verdicts(payload, events, model=self.cfg.triage_model)
            self.routing_history.append(
                RoutingRecord(
                    tier="tier1-triage",
                    model=self.cfg.triage_model,
                    source="meta-model-api",
                    latency_ms=(time.perf_counter() - started) * 1000,
                )
            )
            self.last_triage = verdicts
            return verdicts
        except Exception as exc:  # noqa: BLE001 - fallback must catch everything
            self._trip("tier1-triage", self.cfg.triage_model, exc, started)
            self.last_triage = [
                self.offline.triage(e, model=self.cfg.triage_model) for e in events
            ]
            return self.last_triage

    # -- Tier 2: deep reasoning (muse-wonder-1.0) ---------------------------
    def analyze_event(
        self,
        event: SuspiciousEvent,
        verdict: Optional[TriageVerdict] = None,
    ) -> ThreatAssessment:
        """Return a deep threat assessment for one event (API or fallback)."""
        if not self.available():
            self._record_offline("tier2-reasoning", self.cfg.reasoning_model)
            return self.offline.assess(event, self.cfg.reasoning_model)

        started = time.perf_counter()
        try:
            content = self._chat(
                model=self.cfg.reasoning_model,
                system_prompt=SOC_SYSTEM_PROMPT,
                user_prompt=self._deep_prompt(event, verdict),
                temperature=self.cfg.temperature,
                max_tokens=self.cfg.max_tokens,
                schema_model=AssessmentOutput,
            )
            payload = AssessmentOutput.model_validate(_extract_json(content)).model_dump()
            assessment = coerce_assessment(
                payload,
                event=event,
                model=self.cfg.reasoning_model,
                source="meta-model-api",
            )
            if assessment.reasoning_source != "meta-model-api":
                raise ValueError("Invalid assessment output")
            assessment.latency_ms = round((time.perf_counter() - started) * 1000, 2)
            self.routing_history.append(
                RoutingRecord(
                    tier="tier2-reasoning",
                    model=self.cfg.reasoning_model,
                    source="meta-model-api",
                    latency_ms=assessment.latency_ms,
                )
            )
            return assessment
        except Exception as exc:  # noqa: BLE001 - fallback must catch everything
            self._trip("tier2-reasoning", self.cfg.reasoning_model, exc, started)
            return self.offline.assess(event, self.cfg.reasoning_model)

    def analyze_events(
        self,
        events: Sequence[SuspiciousEvent],
        use_triage: bool = True,
        campaigns: Sequence[Any] = (),
    ) -> List[ThreatAssessment]:
        """Triage then deep-analyse events, preserving the caller's ordering."""
        events = list(events)
        if not events:
            return []
        self._campaign_context = json.dumps([
            campaign.to_dict() if hasattr(campaign, "to_dict") else campaign
            for campaign in campaigns
        ], default=str)[:16000] if campaigns else ""

        verdicts = self.triage_events(events) if use_triage else []
        verdict_by_id = {v.event_id: v for v in verdicts}

        # Spend the expensive Tier-2 calls on the highest-priority events first.
        ordered = sorted(
            events,
            key=lambda e: -(
                verdict_by_id[e.event_id].priority
                if e.event_id in verdict_by_id
                else {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(e.severity, 3)
            ),
        )
        results: Dict[str, ThreatAssessment] = {}
        for event in ordered:
            verdict = verdict_by_id.get(event.event_id)
            if (verdict and verdict.is_noise and verdict.confidence_score >= 0.85
                    and event.severity in ("low", "medium")):
                # Save deep-model tokens, retaining the original alert and its
                # complete deterministic assessment for analyst inspection.
                self._record_offline("tier2-noise-filter", self.cfg.reasoning_model)
                results[event.event_id] = self.offline.assess(event, self.cfg.reasoning_model)
            else:
                results[event.event_id] = self.analyze_event(event, verdict=verdict)
        return [results[e.event_id] for e in events]

    def _deep_prompt(
        self, event: SuspiciousEvent, verdict: Optional[TriageVerdict]
    ) -> str:
        prompt = build_user_prompt(event)
        if self._campaign_context:
            prompt += "\nCORRELATION CONTEXT (hypotheses, not proof of causation):\n" + self._campaign_context
        if verdict is not None:
            prompt += (
                "\nTIER-1 TRIAGE CONTEXT (from the fast triage model - verify, do not "
                f"blindly trust): priority={verdict.priority}, is_noise={verdict.is_noise}, "
                f"kill_chain_stage={verdict.kill_chain_stage}, "
                f"rationale={verdict.rationale}\n"
            )
        return prompt


    # -- SOC copilot --------------------------------------------------------
    def chat(self, question: str, context: Iterable[str], fallback_answer: str = "") -> str:
        """Ask the SOC copilot (muse-wonder-1.0) a question; never raises."""
        context = list(context)
        if not self.available():
            self._record_offline("copilot", self.cfg.reasoning_model)
            return fallback_answer or self.offline.chat(question, context)
        started = time.perf_counter()
        try:
            from .prompts import summarise_context

            content = self._chat(
                model=self.cfg.reasoning_model,
                system_prompt=COPILOT_SYSTEM_PROMPT,
                user_prompt=build_copilot_prompt(question, summarise_context(context)),
                temperature=0.2,
                json_mode=False,
            )
            self.routing_history.append(
                RoutingRecord(
                    tier="copilot",
                    model=self.cfg.reasoning_model,
                    source="meta-model-api",
                    latency_ms=(time.perf_counter() - started) * 1000,
                )
            )
            return content.strip() or fallback_answer or self.offline.chat(question, context)
        except Exception as exc:  # noqa: BLE001
            self._trip("copilot", self.cfg.reasoning_model, exc, started)
            return fallback_answer or self.offline.chat(question, context)

    # -- observability ------------------------------------------------------
    def routing_summary(self) -> Dict[str, Any]:
        api_calls = sum(1 for r in self.routing_history if r.source == "meta-model-api")
        fallbacks = sum(1 for r in self.routing_history if r.source == "offline-deterministic")
        latencies = [r.latency_ms for r in self.routing_history if r.source == "meta-model-api"]
        return {
            "mode": self.mode,
            "tier1_model": self.cfg.triage_model,
            "tier2_model": self.cfg.reasoning_model,
            "base_url": self.cfg.safe_base_url(),
            "total_calls": len(self.routing_history),
            "api_calls": api_calls,
            "offline_fallbacks": fallbacks,
            "fallback_reason": self.fallback_reason,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2)
            if latencies
            else 0.0,
            "triage": [v.to_dict() for v in self.last_triage],
        }


#: Backwards-compatible alias (Phase 1 code imported ``LlamaClient``).
LlamaClient = MetaModelClient


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------
def _strip_fences(text: str) -> str:
    return re.sub(
        r"^\s*```(?:json)?\s*|\s*```\s*$", "", text.strip(), flags=re.IGNORECASE
    ).strip()


def _extract_json(text: str) -> dict:
    """Robustly extract a JSON object from a model response."""
    text = _strip_fences(text)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
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


def _extract_json_array(text: str) -> list:
    """Robustly extract a JSON array (or a wrapper object containing one)."""
    text = _strip_fences(text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("verdicts", "events", "results", "items", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data] if "event_id" in data else []
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(text[start : end + 1])
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
    raise ValueError("No JSON array found in model response")


def _describe_error(exc: Exception) -> str:
    """Human-readable reason recorded when the API is abandoned."""
    status = getattr(exc, "status_code", None)
    if status is None:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
    if status in (401, 403):
        return f"HTTP {status} authentication/permission error"
    if status == 429:
        return "HTTP 429 rate-limit or credit exhausted"
    if status:
        return f"HTTP {status} from Meta Model API"
    # Exception messages may contain request headers, keys or captured payloads.
    # Report a useful class without reflecting sensitive server/transport text.
    return f"{type(exc).__name__}: request or response validation failed"


def _coerce_verdicts(
    payload: Sequence[Any], events: Sequence[SuspiciousEvent], model: str
) -> List[TriageVerdict]:
    """Validate Tier-1 output and repair anything the model skipped."""
    by_id = {e.event_id: e for e in events}
    verdicts: Dict[str, TriageVerdict] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        event_id = str(item.get("event_id") or "")
        if event_id not in by_id or event_id in verdicts:
            raise ValueError("Triage returned an unknown or duplicate event_id")
        try:
            verdict = TriageVerdict.model_validate({**item, "event_id": event_id})
        except Exception as exc:
            raise ValueError("Invalid triage verdict") from exc
        verdict.event_type = by_id[event_id].event_type
        verdict.model = model
        verdict.requested_model = model
        verdict.source = "meta-model-api"
        verdicts[event_id] = verdict

    if set(verdicts) != set(by_id):
        raise ValueError("Triage omitted input event identifiers")
    return [verdicts[e.event_id] for e in events]
