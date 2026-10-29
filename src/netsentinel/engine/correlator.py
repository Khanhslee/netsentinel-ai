"""Attack kill-chain correlation.

The detector emits *discrete* events (a beacon here, a port scan there). Analysts
need the story: which host did what, in which order, and how the individual
behaviours chain into a campaign. This module groups events by source host and
time proximity and then lifts them into an ordered kill-chain narrative.

Two campaign scopes are produced:

* ``host``        - events attributed to one source IP, time-clustered.
* ``linked``      - time-adjacent source/destination pivots across hosts.

The optional environment overview is a separate descriptive hypothesis. Time
proximity alone never establishes common ownership or a causal attack chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..mitre import (
    KILL_CHAIN_STAGES,
    kill_chain_order,
    kill_chain_stage_for,
    mitre_for,
    technique_id_for,
)
from ..models import SuspiciousEvent, stable_hash

#: Severity -> numeric weight used for risk scoring.
SEVERITY_SCORE = {
    "critical": 90.0,
    "high": 70.0,
    "medium": 50.0,
    "low": 30.0,
    "info": 10.0,
}

#: Maximum gap (seconds) between two events of the same host before the
#: correlator treats them as separate campaigns.
DEFAULT_MAX_GAP_SECONDS = 3600.0


@dataclass
class AttackCampaign:
    """A correlated set of events describing one attack campaign."""

    campaign_id: str
    scope: str  # "host" | "linked" | "environment"
    events: List[SuspiciousEvent] = field(default_factory=list)

    # -- identity -----------------------------------------------------------
    @property
    def name(self) -> str:
        if self.scope == "environment":
            return "Capture-wide temporal overview (unconfirmed relationship)"
        stages = self.observed_stages
        descriptor = " -> ".join(stages) if stages else "suspicious activity"
        return f"{self.primary_host}: {descriptor}"

    @property
    def src_ips(self) -> List[str]:
        return _dedupe(e.src_ip for e in self.events if e.src_ip)

    @property
    def victims(self) -> List[str]:
        return _dedupe(e.dst_ip for e in self.events if e.dst_ip)

    @property
    def event_types(self) -> List[str]:
        return _dedupe(e.event_type for e in self.events)

    @property
    def primary_host(self) -> str:
        return self.src_ips[0] if self.src_ips else "unknown"

    # -- timing -------------------------------------------------------------
    @property
    def start_time(self) -> float:
        times = [e.timestamp for e in self.events if e.timestamp]
        return min(times) if times else 0.0

    @property
    def end_time(self) -> float:
        times = [
            e.last_seen or e.timestamp
            for e in self.events
            if (e.last_seen or e.timestamp)
        ]
        return max(times) if times else 0.0

    @property
    def duration_sec(self) -> float:
        return round(max(0.0, self.end_time - self.start_time), 2)

    # -- kill chain ---------------------------------------------------------
    @property
    def observed_stages(self) -> List[str]:
        stages = {
            e.kill_chain_stage or kill_chain_stage_for(e.event_type) for e in self.events
        }
        return sorted(stages, key=kill_chain_order)

    @property
    def kill_chain(self) -> List[Dict[str, Any]]:
        """Full kill-chain matrix (every stage, with an ``observed`` flag)."""
        matrix: List[Dict[str, Any]] = []
        for stage in KILL_CHAIN_STAGES:
            stage_events = [e for e in self.events if _stage_of(e) == stage]
            matrix.append(
                {
                    "stage": stage,
                    "observed": bool(stage_events),
                    "event_count": len(stage_events),
                    "event_types": _dedupe(e.event_type for e in stage_events),
                    "techniques": _dedupe(
                        e.mitre_technique or technique_id_for(e.event_type)
                        for e in stage_events
                    ),
                    "first_seen": min((e.timestamp for e in stage_events), default=0.0),
                    "last_seen": max(
                        (e.last_seen or e.timestamp for e in stage_events), default=0.0
                    ),
                }
            )
        return matrix

    @property
    def techniques(self) -> List[str]:
        return _dedupe(
            e.mitre_technique or technique_id_for(e.event_type) for e in self.events
        )

    @property
    def tactics(self) -> List[str]:
        return _dedupe(
            e.mitre_tactic or mitre_for(e.event_type).get("tactic", "")
            for e in self.events
        )

    @property
    def iocs(self) -> List[str]:
        return _dedupe(ioc for e in self.events for ioc in e.iocs)


    # -- scoring ------------------------------------------------------------
    @property
    def severity(self) -> str:
        best = "info"
        for event in self.events:
            if SEVERITY_SCORE.get(event.severity, 0) > SEVERITY_SCORE.get(best, 0):
                best = event.severity
        return best

    @property
    def risk_score(self) -> int:
        """0-100 campaign risk: severity base + kill-chain coverage bonus."""
        if not self.events:
            return 0
        base = max(SEVERITY_SCORE.get(e.severity, 10.0) for e in self.events)
        stage_count = len(self.observed_stages)
        score = base + max(0, stage_count - 1) * 7.0
        if "exfiltration" in self.event_types:
            score += 8.0
        if "port_scan" in self.event_types and stage_count > 1:
            score += 3.0
        return int(min(100.0, round(score)))

    # -- narrative ----------------------------------------------------------
    @property
    def kill_chain_narrative(self) -> str:
        return build_narrative(self)

    @property
    def summary(self) -> str:
        if not self.events:
            return "No correlated activity."
        hosts = ", ".join(self.src_ips[:3]) or "unknown host"
        stages = " -> ".join(self.observed_stages)
        return (
            f"{len(self.events)} correlated events from {hosts} spanning "
            f"{len(self.observed_stages)} kill-chain stage(s): {stages}."
        )

    @property
    def recommended_actions(self) -> List[str]:
        actions: List[str] = []
        if "exfiltration" in self.event_types:
            actions.append(
                "IMMEDIATE: block the exfiltration destination and preserve the "
                "outbound transfer logs as evidence."
            )
        for event in self.events:
            for action in mitre_for(event.event_type).get("mitigation", []):
                if action not in actions:
                    actions.append(action)
        actions.append(
            "Hunt the correlated IOCs across the fleet and validate containment "
            "before restoring the affected hosts."
        )
        return actions

    def events_by_stage(self, stage: str) -> List[SuspiciousEvent]:
        return [e for e in self.events if _stage_of(e) == stage]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "scope": self.scope,
            "correlation_basis": (
                "Capture overview only; common campaign attribution is unconfirmed"
                if self.scope == "environment" else
                "Source/destination pivot and time proximity; causality requires analyst validation"
                if self.scope == "linked" else
                "Shared source IP and time proximity; causality requires analyst validation"
            ),
            "name": self.name,
            "summary": self.summary,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "src_ips": self.src_ips,
            "victims": self.victims,
            "event_types": self.event_types,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "observed_stages": self.observed_stages,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_sec": self.duration_sec,
            "kill_chain": self.kill_chain,
            "kill_chain_narrative": self.kill_chain_narrative,
            "iocs": self.iocs,
            "recommended_actions": self.recommended_actions,
            "event_ids": [e.event_id for e in self.events],
            "timeline": [
                {
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "kill_chain_stage": _stage_of(e),
                    "mitre_technique": e.mitre_technique or technique_id_for(e.event_type),
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "description": e.description,
                }
                for e in sorted(self.events, key=lambda e: (e.timestamp, e.event_type))
            ],
        }


@dataclass
class CorrelationReport:
    campaigns: List[AttackCampaign] = field(default_factory=list)
    environment_overview: Optional[AttackCampaign] = None

    @property
    def host_campaigns(self) -> List[AttackCampaign]:
        return [c for c in self.campaigns if c.scope == "host"]

    @property
    def environment_campaign(self) -> Optional[AttackCampaign]:
        return self.environment_overview

    @property
    def top_campaign(self) -> Optional[AttackCampaign]:
        return self.campaigns[0] if self.campaigns else None

    @property
    def max_risk_score(self) -> int:
        return max((c.risk_score for c in self.campaigns), default=0)

    @property
    def kill_chain_summary(self) -> List[Dict[str, Any]]:
        """Environment-wide kill chain (used by reports and the UI)."""
        environment = self.environment_campaign
        if environment is not None:
            return environment.kill_chain
        if self.campaigns:
            return self.campaigns[0].kill_chain
        return AttackCampaign(campaign_id="empty", scope="host", events=[]).kill_chain

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_count": len(self.campaigns),
            "max_risk_score": self.max_risk_score,
            "campaigns": [c.to_dict() for c in self.campaigns],
            "environment_overview": (
                self.environment_overview.to_dict() if self.environment_overview else None
            ),
            "kill_chain_summary": self.kill_chain_summary,
        }


# ---------------------------------------------------------------------------
# Correlation entry points
# ---------------------------------------------------------------------------
def correlate_events(
    events: Sequence[SuspiciousEvent],
    max_gap_seconds: float = DEFAULT_MAX_GAP_SECONDS,
    include_environment: bool = True,
) -> CorrelationReport:
    """Correlate shared actors/pivots in bounded time; retain all event evidence."""
    if max_gap_seconds <= 0:
        raise ValueError("max_gap_seconds must be greater than zero")
    events = list({e.event_id: e for e in events if e is not None}.values())
    if not events:
        return CorrelationReport(campaigns=[])

    campaigns: List[AttackCampaign] = []
    by_host: Dict[str, List[SuspiciousEvent]] = {}
    for event in events:
        by_host.setdefault(event.src_ip or "unknown", []).append(event)

    for src_ip, host_events in by_host.items():
        for cluster in _time_clusters(host_events, max_gap_seconds):
            campaigns.append(
                AttackCampaign(
                    campaign_id=_campaign_id(src_ip, cluster),
                    scope="host",
                    events=cluster,
                )
            )

    # Merge only actor pivots (A -> B followed by B -> C), never two unrelated
    # clients merely sharing a DNS resolver, CDN, or popular destination.
    changed = True
    while changed:
        changed = False
        for i, left in enumerate(campaigns):
            for j in range(i + 1, len(campaigns)):
                right = campaigns[j]
                if not _linked_in_time(left, right, max_gap_seconds):
                    continue
                merged = sorted(left.events + right.events, key=lambda e: (e.timestamp, e.event_type))
                campaigns[i] = AttackCampaign(_campaign_id("linked", merged), "linked", merged)
                campaigns.pop(j)
                changed = True
                break
            if changed:
                break

    overview = None
    if include_environment:
        stages = {_stage_of(e) for e in events}
        if len(stages) >= 2 and len(events) >= 2:
            overview = AttackCampaign(
                    campaign_id=_campaign_id("environment", events),
                    scope="environment",
                    events=sorted(events, key=lambda e: (e.timestamp, e.event_type)),
            )

    campaigns.sort(key=lambda c: (-c.risk_score, -len(c.events), c.campaign_id))
    return CorrelationReport(campaigns=campaigns, environment_overview=overview)


def correlate(events: Sequence[SuspiciousEvent], **kwargs: Any) -> CorrelationReport:
    """Alias for :func:`correlate_events` (short form used across the codebase)."""
    return correlate_events(events, **kwargs)


# ---------------------------------------------------------------------------
# Narrative generation
# ---------------------------------------------------------------------------
def build_narrative(campaign: AttackCampaign) -> str:
    """Deterministic kill-chain story built from the forensic evidence."""
    if not campaign.events:
        return "No correlated activity."

    ordered = sorted(campaign.events, key=lambda e: (e.timestamp, e.event_type))
    lines = [
        f"Attack campaign {campaign.campaign_id} ({campaign.scope} scope) observed "
        f"{len(ordered)} events across {len(campaign.observed_stages)} kill-chain stage(s), "
        f"risk score {campaign.risk_score}/100."
    ]
    if campaign.scope == "environment":
        lines = [
            "Capture-wide temporal overview; the following hosts are not proven to "
            "belong to one campaign. Stage ordering is a framework view, not proof "
            "of chronological progression."
        ]
    for index, stage in enumerate(campaign.observed_stages, start=1):
        stage_events = [e for e in ordered if _stage_of(e) == stage]
        details = "; ".join(_event_phrase(e) for e in stage_events[:3])
        lines.append(f"Phase {index} - {stage}: {details}.")
    if "exfiltration" in campaign.event_types:
        lines.append(
            "Assessment: the asymmetric transfer is a possible exfiltration signal. "
            "Validate the business purpose and endpoint telemetry, preserve evidence, "
            "and prioritize containment if unauthorized. No staging or data theft is proven."
        )
    elif set(campaign.event_types) & {"beacon", "dns_tunneling", "dga", "nxdomain_storm"}:
        lines.append(
            "Assessment: the traffic is consistent with a possible command-and-control "
            "channel. Validate endpoint process evidence before confirming compromise."
        )
    else:
        lines.append(
            "Assessment: activity is consistent with pre-compromise reconnaissance; "
            "harden exposed services and keep the source under watch."
        )
    return " ".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _event_phrase(event: SuspiciousEvent) -> str:
    """One-line, evidence-rich description of an event for the narrative."""
    f = event.features
    if event.event_type == "port_scan":
        return (
            f"{event.src_ip} probed {f.get('distinct_ports', '?')} ports on "
            f"{event.dst_ip} at {f.get('ports_per_second', 0)} ports/s "
            f"(MITRE {event.mitre_technique or 'T1046'})"
        )
    if event.event_type == "beacon":
        return (
            f"{event.src_ip} beaconed to {f.get('destination', event.dst_ip)} "
            f"{f.get('connections', '?')} times with delta-t jitter "
            f"{f.get('jitter_pct', 0)}% (MITRE {event.mitre_technique or 'T1071.001'})"
        )
    if event.event_type == "dga":
        return (
            f"{event.src_ip} queried {f.get('count', '?')} algorithmic-looking domains "
            f"averaging {f.get('shannon_entropy', 0)} bits/char entropy "
            f"(MITRE {event.mitre_technique or 'T1568.002'})"
        )
    if event.event_type == "nxdomain_storm":
        return (
            f"{event.src_ip} generated {f.get('nxdomain_count', '?')} NXDOMAIN responses "
            f"across {f.get('families', '?')} domain families "
            f"(MITRE {event.mitre_technique or 'T1568.002'})"
        )
    if event.event_type == "dns_tunneling":
        return (
            f"{event.src_ip} sent possible tunnel traffic under '{f.get('base_domain', '?')}' with "
            f"{f.get('query_count', '?')} queries, entropy "
            f"{f.get('shannon_entropy', 0)} bits/char "
            f"(MITRE {event.mitre_technique or 'T1071.004'})"
        )
    if event.event_type == "exfiltration":
        return (
            f"{event.src_ip} uploaded {f.get('bytes_out', 0):,} bytes to "
            f"{event.dst_ip}:{f.get('dst_port', '?')} with a "
            f"{f.get('upload_ratio', 0)}:1 upload/download ratio "
            f"(MITRE {event.mitre_technique or 'T1041'})"
        )
    return f"{event.src_ip or 'unknown'} - {event.description}"


def _stage_of(event: SuspiciousEvent) -> str:
    return event.kill_chain_stage or kill_chain_stage_for(event.event_type)


def _dedupe(values: Iterable[str]) -> List[str]:
    seen: Dict[str, None] = {}
    for value in values:
        if value and value not in seen:
            seen[value] = None
    return list(seen)


def _time_clusters(
    events: List[SuspiciousEvent], max_gap_seconds: float
) -> List[List[SuspiciousEvent]]:
    """Split a host's events into clusters separated by long quiet periods."""
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_type))
    clusters: List[List[SuspiciousEvent]] = []
    current: List[SuspiciousEvent] = []
    last_time = 0.0
    for event in ordered:
        when = event.timestamp
        if current and ((bool(when) != bool(last_time)) or
                        (when and last_time and (when - last_time) > max_gap_seconds)):
            clusters.append(current)
            current = []
        current.append(event)
        last_time = max(last_time, event.last_seen or when)
    if current:
        clusters.append(current)
    return clusters


def _campaign_id(scope: str, events: Sequence[SuspiciousEvent]) -> str:
    seed = "|".join(
        sorted(f"{e.src_ip}:{e.dst_ip}:{e.event_type}:{round(e.timestamp, 3)}" for e in events)
    )
    prefix = {"environment": "ENV", "linked": "LINK"}.get(scope, "HOST")
    return f"CP-{prefix}-{stable_hash(seed)[:8]}"


def _linked_in_time(left: AttackCampaign, right: AttackCampaign, gap: float) -> bool:
    if not left.start_time or not right.start_time:
        return False
    distance = max(0.0, max(left.start_time, right.start_time) - min(left.end_time, right.end_time))
    if distance > gap:
        return False
    return any(
        a.timestamp and b.timestamp
        and max(0.0, max(a.timestamp, b.timestamp) -
                min(a.last_seen or a.timestamp, b.last_seen or b.timestamp)) <= gap
        and ((a.dst_ip and a.dst_ip == b.src_ip) or (b.dst_ip and b.dst_ip == a.src_ip))
        for a in left.events for b in right.events
    )
