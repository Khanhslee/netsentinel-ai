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
    TriageOutput,
    TriageVerdict,
    coerce_assessment,
    strict_response_format,
)
from ..mitre import kill_chain_stage_for

log = get_logger(__name__)

#: HTTP status codes that mean "stop calling the API for this run".
FATAL_STATUS_CODES = (401, 403, 429)
#: Hard ceiling for the retried output budget (reasoning tokens included).
MAX_OUTPUT_TOKENS = 32000
#: Timeout used for the retried call when the model was too slow the first time.
SLOW_CALL_TIMEOUT = 180.0


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
        #: ``None`` = untested, ``True``/``False`` = endpoint accepted/rejected
        #: ``response_format``. Once rejected it is never sent again this run.
        self._response_format_supported: Optional[bool] = None

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
    def _response_format(self, schema_model=None) -> Optional[Dict[str, Any]]:
        """Return the structured-output hint, or ``None`` when unsupported.

        The Meta Model API is OpenAI-compatible but not every route accepts
        ``response_format``; the first rejection disables it for the whole run
        instead of failing the analysis (the JSON is extracted from the text
        afterwards anyway).
        """
        if self._response_format_supported is False:
            return None
        if self.cfg.use_json_schema and schema_model is not None:
            try:
                return strict_response_format(schema_model)
            except Exception:  # noqa: BLE001 - fall back to plain JSON mode
                return {"type": "json_object"}
        return {"type": "json_object"}

    def _chat(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        json_mode: bool = True,
        schema_model=None,
        attempts: int = 3,
    ) -> str:
        """Call the Meta Model API and return the raw text of the reply.

        Reasoning models spend most of their output budget on hidden reasoning
        tokens, so a small ``max_tokens`` can return ``finish_reason="length"``
        with ``content=None``. Rather than raising (which used to look like a
        response-validation failure), the budget - and, on a timeout, the
        deadline - is widened and the call retried. ``response_format`` is
        dropped for the rest of the run if the endpoint rejects it, and a
        non-``stop`` finish reason or an empty answer is never an error.
        """
        budget = int(max_tokens or self.cfg.max_tokens)
        retries_left = max(1, int(attempts))
        format_dropped = not json_mode
        format_rejected = False
        slow_call = False
        while True:
            kwargs: Dict[str, Any] = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": self.cfg.temperature if temperature is None else temperature,
                "max_tokens": min(budget, MAX_OUTPUT_TOKENS),
            }
            if not format_dropped:
                response_format = self._response_format(schema_model)
                if response_format is not None:
                    kwargs["response_format"] = response_format
                else:
                    format_dropped = True
            timeout = self.cfg.timeout
            if slow_call:
                timeout = max(float(self.cfg.timeout), SLOW_CALL_TIMEOUT)
            try:
                completion = self._get_client().chat.completions.create(
                    **kwargs, timeout=timeout
                )
            except Exception as exc:  # noqa: BLE001 - classified below
                if (not format_dropped and not format_rejected
                        and _rejects_response_format(exc)):
                    # Endpoint does not support structured output: retry as text.
                    format_rejected = format_dropped = True
                    self._response_format_supported = False
                    log.warning(
                        "Meta endpoint rejected response_format (%s); retrying in "
                        "plain text mode and extracting JSON from the reply.",
                        type(exc).__name__,
                    )
                    continue
                if _status_of(exc) in FATAL_STATUS_CODES or not _is_transient(exc):
                    raise
                retries_left -= 1
                if retries_left <= 0:
                    raise
                slow_call = True
                budget = _grow_budget(budget)
                log.warning(
                    "Meta Model API call was slow or dropped (%s); retrying with "
                    "max_tokens=%d and a %ss deadline.",
                    type(exc).__name__, min(budget, MAX_OUTPUT_TOKENS),
                    int(max(float(self.cfg.timeout), SLOW_CALL_TIMEOUT)),
                )
                continue

            if not format_dropped:
                self._response_format_supported = True
            text = _response_text(completion)
            # A reasoning model can spend the entire budget on hidden reasoning:
            # empty content, or JSON cut in half, simply means "retry with more
            # room". It is never a validation error.
            incomplete = not text.strip() or (
                json_mode and not _has_json_value(text)
            )
            if not incomplete:
                return text

            retries_left -= 1
            if retries_left <= 0:
                if text.strip():
                    log.warning(
                        "Meta model reply was truncated (finish_reason=%r) and is not "
                        "valid JSON; repairing this item from the heuristics.",
                        _finish_reason(completion),
                    )
                    return text
                log.warning(
                    "Meta model returned no text (finish_reason=%r); falling back "
                    "to the deterministic expert engine for this item.",
                    _finish_reason(completion),
                )
                return ""
            slow_call = True
            budget = _grow_budget(budget)
            log.warning(
                "Meta model reply was truncated (finish_reason=%r); retrying with "
                "max_tokens=%d.",
                _finish_reason(completion), min(budget, MAX_OUTPUT_TOKENS),
            )

    def _record_offline(self, tier: str, model: str) -> None:
        self.routing_history.append(RoutingRecord(
            tier=tier, model=model, source="offline-deterministic",
            fallback_reason=self.fallback_reason,
        ))

    def _record_failure(
        self, tier: str, model: str, exc: Exception, started: float
    ) -> None:
        """Record a transport/auth failure and open the circuit breaker.

        Response *content* problems never reach here: they are repaired from
        the deterministic heuristics and leave the API enabled for other items.
        """
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

    def _record_degraded(self, tier: str, model: str, reason: str) -> None:
        """Record a locally-served item without opening the circuit breaker."""
        self.routing_history.append(
            RoutingRecord(
                tier=tier, model=model, source="offline-deterministic",
                ok=False, fallback_reason=reason,
            )
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
        except Exception as exc:  # noqa: BLE001 - fallback must catch everything
            self._record_failure("tier1-triage", self.cfg.triage_model, exc, started)
            self.last_triage = [
                self.offline.triage(e, model=self.cfg.triage_model) for e in events
            ]
            return self.last_triage

        # Model drift (renamed keys, prose, fences, missing ids) is repaired,
        # never raised: the verdicts that are usable are kept.
        verdicts = _coerce_verdicts(
            _triage_payload(content), events, model=self.cfg.triage_model
        )
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
        except Exception as exc:  # noqa: BLE001 - fallback must catch everything
            self._record_failure("tier2-reasoning", self.cfg.reasoning_model, exc, started)
            return self.offline.assess(event, self.cfg.reasoning_model)

        payload = _assessment_payload(content)
        if payload is None:
            # The API answered, but not with JSON we can use: repair silently
            # from the detector heuristics instead of abandoning the endpoint.
            self._record_degraded(
                "tier2-reasoning", self.cfg.reasoning_model,
                "model reply contained no JSON object",
            )
            log.warning(
                "Meta Model API reply for %s contained no JSON object; using the "
                "deterministic expert engine for this event.",
                event.event_id,
            )
            return self.offline.assess(event, self.cfg.reasoning_model)

        assessment = coerce_assessment(
            payload,
            event=event,
            model=self.cfg.reasoning_model,
            source="meta-model-api",
        )
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
            self._record_failure("copilot", self.cfg.reasoning_model, exc, started)
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
#: Markdown fence wrapper around a JSON block (```json ... ``` / ``` ... ```).
_FENCE_RE = re.compile(r"```[A-Za-z0-9_+-]*\s*(.*?)\s*```", re.DOTALL)
#: Greedy match = the *outermost* ``{...}`` / ``[...]`` pair in the text.
_OBJECT_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)
_ARRAY_BLOCK_RE = re.compile(r"\[.*\]", re.DOTALL)
#: Keys under which a model may nest the verdict list or the assessment.
_WRAPPER_KEYS = ("verdicts", "triage", "results", "events", "items", "data",
                 "classifications", "assessment", "threat_assessment", "analysis",
                 "result", "response")


def _strip_fences(text: str) -> str:
    """Return the payload of a ```json ... ``` block, fences removed."""
    cleaned = (text or "").strip()
    blocks = _FENCE_RE.findall(cleaned)
    for block in blocks:
        if "{" in block or "[" in block:
            return block.strip()
    if blocks:
        return blocks[0].strip()
    return re.sub(
        r"^\s*```[A-Za-z0-9_+-]*\s*|\s*```\s*$", "", cleaned, flags=re.IGNORECASE
    ).strip()


def _has_json_value(text: str) -> bool:
    """True when the reply holds a complete JSON document (never a fragment).

    A truncated reply (``finish_reason="length"``) can still contain complete
    *nested* objects - ``{"ioc_details": {...}`` cut off - so the top-level
    document is decoded from its first brace rather than scanning for any
    decodable fragment.
    """
    stripped = _strip_fences(text)
    if not stripped:
        return False
    if stripped[0] in "{[":
        try:
            _, end = json.JSONDecoder().raw_decode(stripped)
        except json.JSONDecodeError:
            return False
        tail = stripped[end:].strip()
        # Trailing prose is acceptable; stray brackets mean unbalanced output.
        return not any(char in tail for char in "{}[]")
    return _scan_json(stripped, "{", dict) is not None or _scan_json(
        stripped, "[", list
    ) is not None


def _scan_json(text: str, opener: str, expected: type) -> Optional[Any]:
    """Decode the first ``expected`` JSON value starting at any ``opener``."""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != opener:
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, expected):
            return value
    return None


def _extract_json(text: str) -> dict:
    """Robustly extract a JSON object from a model response.

    Tolerates markdown fences, prose before/after the payload and stray braces
    by falling back to the *outermost* ``{...}`` match and then to an
    incremental ``raw_decode`` scan.
    """
    text = _strip_fences(text)
    if not text:
        raise ValueError("Model response was empty")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                return item
    if text[0] in "{[":
        # The reply *is* the JSON document: if it does not decode it was cut off
        # by the token limit, and salvaging a nested fragment would silently
        # drop most of the assessment.
        raise ValueError("Model response contained truncated JSON")

    for candidate in _OBJECT_BLOCK_RE.findall(text):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    parsed = _scan_json(text, "{", dict)
    if isinstance(parsed, dict):
        return parsed

    # A bare array of one object (common for batch prompts) still carries data.
    for candidate in _ARRAY_BLOCK_RE.findall(text):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    return item
    parsed = _scan_json(text, "[", list)
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                return item
    raise ValueError("No JSON object found in model response")


def _extract_json_array(text: str) -> list:
    """Robustly extract a JSON array (or a wrapper object containing one)."""
    text = _strip_fences(text)
    if not text:
        raise ValueError("Model response was empty")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in _WRAPPER_KEYS:
            if isinstance(data.get(key), list):
                return data[key]
        return [data] if "event_id" in data else []
    for candidate in _ARRAY_BLOCK_RE.findall(text):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            return parsed
    try:
        payload = _extract_json(text)
    except ValueError:
        raise ValueError("No JSON array found in model response") from None
    for key in _WRAPPER_KEYS:
        if isinstance(payload.get(key), list):
            return payload[key]
    return [payload]


def _triage_payload(content: str) -> List[Any]:
    """Parse Tier-1 output into verdict dicts; never raises for model drift."""
    if not (content or "").strip():
        return []
    try:
        parsed = TriageBatchOutput.model_validate(_extract_json(content))
        return [item.model_dump() for item in parsed.verdicts]
    except Exception:  # noqa: BLE001 - prose / fence / bare-array variants
        pass
    try:
        raw = _extract_json_array(content)
    except Exception:  # noqa: BLE001 - nothing JSON-shaped in the reply
        return []
    items: List[Any] = []
    for item in raw:
        if isinstance(item, dict):
            items.append(TriageOutput.model_validate(item).model_dump())
    return items


def _assessment_payload(content: str) -> Optional[Dict[str, Any]]:
    """Parse Tier-2 output into a dict, or ``None`` when nothing is parseable."""
    if not (content or "").strip():
        return None
    try:
        return _extract_json(content)
    except Exception:  # noqa: BLE001 - caller repairs from the heuristics
        return None


def _content_text(value: Any) -> str:
    """Flatten a chat message ``content`` (str, list of parts or dict) to text."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        text = value.get("text")
        return text if isinstance(text, str) else ""
    if isinstance(value, (list, tuple)):
        return "".join(_content_text(part) for part in value)
    return ""


def _response_text(completion: Any) -> str:
    """Extract the answer text from a chat completion, tolerating ``None``."""
    try:
        choice = completion.choices[0]
    except (AttributeError, IndexError, KeyError, TypeError):
        return ""
    message = getattr(choice, "message", None)
    if message is None:
        return ""
    text = _content_text(getattr(message, "content", None))
    if text.strip():
        return text
    # Some reasoning endpoints expose the text elsewhere.
    for attribute in ("reasoning_content", "reasoning", "text"):
        extra = getattr(message, attribute, None)
        if isinstance(extra, str) and extra.strip():
            return extra
    extra_fields = getattr(message, "model_extra", None) or {}
    if isinstance(extra_fields, dict):
        for key in ("reasoning_content", "reasoning", "content"):
            value = extra_fields.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return text


def _finish_reason(completion: Any) -> Any:
    try:
        return completion.choices[0].finish_reason
    except (AttributeError, IndexError, KeyError, TypeError):
        return None


def _grow_budget(budget: int) -> int:
    """Widen the output budget so reasoning tokens cannot starve the JSON."""
    return min(max(int(budget) * 2, 2048), MAX_OUTPUT_TOKENS)


def _status_of(exc: Exception) -> Optional[int]:
    status = getattr(exc, "status_code", None)
    if status is None:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def _rejects_response_format(exc: Exception) -> bool:
    """True when the endpoint refused ``response_format`` / structured output."""
    message = str(exc).lower()
    if any(token in message for token in (
        "response_format", "json_schema", "json schema", "structured output",
        "unsupported parameter", "unknown parameter",
        "unrecognized request argument", "not supported",
    )):
        return True
    return _status_of(exc) in (400, 404, 415, 422)


def _is_transient(exc: Exception) -> bool:
    """True for timeout/dropped-connection faults that a retry can absorb."""
    name = type(exc).__name__.lower()
    if "timeout" in name or "connection" in name:
        return True
    return isinstance(exc, (TimeoutError, ConnectionError))


def _describe_error(exc: Exception) -> str:
    """Human-readable reason recorded when an item is served locally."""
    status = _status_of(exc)
    if status in (401, 403):
        return f"HTTP {status} authentication/permission error"
    if status == 429:
        return "HTTP 429 rate-limit or credit exhausted"
    if status:
        return f"HTTP {status} from Meta Model API"
    # Exception messages may contain request headers, keys or captured payloads.
    # Report a useful class without reflecting sensitive server/transport text.
    return f"{type(exc).__name__}: no usable model response"


def _coerce_verdicts(
    payload: Sequence[Any], events: Sequence[SuspiciousEvent], model: str
) -> List[TriageVerdict]:
    """Repair Tier-1 output: keep usable verdicts, fill the rest heuristically.

    Unknown or duplicated ``event_id`` values are dropped (the model may not
    re-assign evidence to an event it was never given), and every event the
    model skipped is triaged locally. Nothing here raises, so a partially
    malformed batch still benefits from the model instead of falling back.
    """
    offline = OfflineReasoningEngine()
    by_id = {e.event_id: e for e in events}
    verdicts: Dict[str, TriageVerdict] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        event_id = str(item.get("event_id") or item.get("eventId") or "").strip()
        event = by_id.get(event_id)
        if event is None or event_id in verdicts:
            continue
        try:
            verdict = TriageVerdict.model_validate({**item, "event_id": event_id})
        except Exception:  # noqa: BLE001 - repair this single verdict locally
            verdict = offline.triage(event, model=model)
        verdict.event_type = event.event_type
        if not verdict.kill_chain_stage:
            verdict.kill_chain_stage = event.kill_chain_stage or kill_chain_stage_for(
                event.event_type
            )
        if not verdict.rationale:
            verdict.rationale = event.description
        verdict.model = model
        verdict.requested_model = model
        verdict.source = "meta-model-api"
        verdicts[event_id] = verdict

    for event in events:
        if event.event_id not in verdicts:
            verdict = offline.triage(event, model=model)
            verdict.kill_chain_stage = verdict.kill_chain_stage or (
                event.kill_chain_stage or kill_chain_stage_for(event.event_type)
            )
            verdicts[event.event_id] = verdict
    return [verdicts[e.event_id] for e in events]
