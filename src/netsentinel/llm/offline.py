"""Deterministic, rule-based expert engine (the "never crash" fallback).

Even with no API key, no network, an exhausted credit balance or an HTTP
401/403/429 from the Meta Model API, NetSentinel must still deliver a deep
analysis. This engine encodes the same reasoning the LLM is prompted for -
kill-chain stage, ATT&CK mapping, IOCs, root-cause analysis and containment
guidance - purely from the forensic features computed by the detectors.

Every statement it produces is backed by a number from ``event.features`` so the
output reads like a real analyst wrote it, not like a template.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from ..mitre import kill_chain_stage_for, mitre_for, technique_id_for
from ..models import SuspiciousEvent
from .schemas import ThreatAssessment, TriageVerdict, event_ioc_bundle

#: Severity -> triage priority (1 = lowest, 5 = urgent).
_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


class OfflineReasoningEngine:
    """Rule-based SOC analyst used whenever the Meta Model API is unreachable."""

    def __init__(self, name: str = "offline-deterministic") -> None:
        self.name = name

    # -- public API ---------------------------------------------------------
    def assess(
        self, event: SuspiciousEvent, model: str = "offline-deterministic"
    ) -> ThreatAssessment:
        """Produce a complete ThreatAssessment for one event."""
        info = mitre_for(event.event_type)
        technique = event.mitre_technique or technique_id_for(event.event_type)
        confidence = self.confidence(event)
        iocs = list(event.iocs)
        return ThreatAssessment(
            threat_summary=self.summary(event, info),
            kill_chain_stage=event.kill_chain_stage
            or kill_chain_stage_for(event.event_type),
            mitre_tactic=event.mitre_tactic or info.get("tactic", ""),
            mitre_technique_id=technique,
            technique_name=info.get("name", ""),
            confidence_score=confidence,
            iocs=iocs,
            ioc_details=event_ioc_bundle(event),
            root_cause_analysis=self.root_cause(event),
            recommended_actions=self.actions(event),
            severity=event.severity,
            natural_language_explanation=self.explanation(event, confidence),
            model=self.name,
            requested_model=model if model != self.name else "",
            reasoning_source="offline-deterministic",
            latency_ms=0.0,
        )

    def triage(
        self, event: SuspiciousEvent, model: str = "offline-deterministic"
    ) -> TriageVerdict:
        """Fast Tier-1 verdict used when the Muse Spark call is unavailable."""
        confidence = self.confidence(event)
        priority = _PRIORITY.get(event.severity, 3)
        if priority >= 4 and confidence >= 0.8:
            priority = 5
        return TriageVerdict(
            event_id=event.event_id,
            event_type=event.event_type,
            priority=priority,
            is_noise=priority <= 2 and confidence < 0.6,
            confidence_score=confidence,
            kill_chain_stage=event.kill_chain_stage
            or kill_chain_stage_for(event.event_type),
            rationale=(
                f"{event.event_type} on {event.src_ip}: severity={event.severity}, "
                f"evidence confidence={confidence:.2f}"
            ),
            model=self.name,
            requested_model=model if model != self.name else "",
            source="offline-deterministic",
            latency_ms=0.0,
        )

    # -- evidence-scored confidence ----------------------------------------
    def confidence(self, event: SuspiciousEvent) -> float:
        """Confidence derived from how far the evidence exceeds its threshold."""
        f = event.features
        kind = event.event_type
        score = 0.6
        if kind == "beacon":
            jitter = float(f.get("jitter_ratio", 0.15))
            sessions = float(f.get("connections", 0))
            score = 0.95 - min(0.35, jitter * 2.0) + min(0.03, sessions / 500.0)
        elif kind == "dga":
            entropy = float(f.get("shannon_entropy", f.get("avg_entropy", 3.4)))
            threshold = float(f.get("entropy_threshold", 3.4))
            score = 0.55 + min(0.4, max(0.0, (entropy - threshold)) * 0.8)
        elif kind == "nxdomain_storm":
            count = float(f.get("nxdomain_count", 0))
            score = 0.6 + min(0.3, count / 100.0)
        elif kind == "dns_tunneling":
            label = float(f.get("max_label_len", 0))
            entropy = float(f.get("shannon_entropy", 0.0))
            score = 0.55 + min(0.25, label / 120.0) + min(0.15, entropy / 25.0)
        elif kind == "port_scan":
            ports = float(f.get("distinct_ports", 0))
            score = 0.6 + min(0.3, ports / 200.0)
        elif kind == "exfiltration":
            ratio = float(f.get("upload_ratio", 0.0))
            score = 0.6 + min(0.3, ratio / 500.0)
        return round(max(0.5, min(0.98, score)), 2)

    # -- narrative pieces ---------------------------------------------------
    def summary(self, event: SuspiciousEvent, info: Dict[str, Any]) -> str:
        f = event.features
        technique = event.mitre_technique or technique_id_for(event.event_type)
        kind = event.event_type

        if kind == "beacon":
            body = (
                f"Host {event.src_ip} established {f.get('connections', '?')} sessions to "
                f"{f.get('destination', event.dst_ip)} with a mean inter-arrival of "
                f"{f.get('mean_interval', 0)}s and a coefficient of variation of "
                f"{f.get('coefficient_of_variation', 0)} ({f.get('jitter_pct', 0)}% jitter). "
                "Periodic timing is consistent with automated C2 polling, but may also "
                "reflect monitoring, software updates or scheduled business activity."
            )
        elif kind == "dga":
            body = (
                f"Host {event.src_ip} queried {f.get('count', '?')} high-entropy domains "
                f"(mean Shannon entropy {f.get('shannon_entropy', 0)} bits/char, max "
                f"{f.get('max_entropy', 0)}, threshold {f.get('entropy_threshold', 3.4)}). "
                "DGA-based fallback domains let malware re-establish C2 even when "
                "individual domains are taken down."
            )
        elif kind == "nxdomain_storm":
            body = (
                f"Host {event.src_ip} produced {f.get('nxdomain_count', '?')} distinct "
                f"NXDOMAIN responses across {f.get('families', '?')} domain families "
                f"(top family '{f.get('top_family', 'n/a')}', mean entropy "
                f"{f.get('shannon_entropy', 0)}). Bursts of failed resolutions are one of "
                "candidate DGA / domain-fuzzing signals; resolver misconfiguration and "
                "unavailable services are alternative causes."
            )
        elif kind == "dns_tunneling":
            body = (
                f"Host {event.src_ip} sent {f.get('query_count', '?')} queries under "
                f"'{f.get('base_domain', '?')}' with a longest label of "
                f"{f.get('max_label_len', 0)} chars (threshold "
                f"{f.get('label_len_threshold', 20)}), subdomain entropy "
                f"{f.get('shannon_entropy', 0)} bits/char and a unique-name ratio of "
                f"{f.get('unique_name_ratio', 0)}. The pattern is consistent with data "
                f"encoded into DNS labels (TXT={f.get('txt_queries', False)})."
            )
        elif kind == "port_scan":
            body = (
                f"Host {event.src_ip} probed {f.get('distinct_ports', '?')} distinct ports on "
                f"{event.dst_ip} within {f.get('time_span', 0)}s "
                f"({f.get('ports_per_second', 0)} ports/s, "
                f"{f.get('packets_per_second', 0)} packets/s), hitting "
                f"{f.get('well_known_ports_hit', 0)} well-known ports. This is consistent with "
                "active service discovery; validate approved vulnerability scans."
            )
        elif kind == "exfiltration":
            body = (
                f"Host {event.src_ip} uploaded {f.get('bytes_out', 0):,} bytes to "
                f"{event.dst_ip}:{f.get('dst_port', '?')} while receiving only "
                f"{f.get('bytes_in', 0):,} bytes (ratio {f.get('upload_ratio', 0)}:1, "
                f"{f.get('throughput_bps', 0)} B/s). Asymmetric egress flows are the classic "
                "exfiltration signature."
            )
        else:
            body = event.description

        return (
            f"{body} Mapped to MITRE ATT&CK {technique} "
            f"({info.get('name', 'unknown technique')}) in the "
            f"{info.get('tactic', 'unknown')} tactic."
        )


    def root_cause(self, event: SuspiciousEvent) -> str:
        f = event.features
        kind = event.event_type
        if kind == "beacon":
            return (
                "Working root-cause hypothesis: timer-driven software produces periodic "
                f"egress (coefficient of variation {f.get('coefficient_of_variation', '?')}). "
                "A C2 implant is one possibility; legitimate health checks can produce the "
                "same cadence. Correlate endpoint process/socket telemetry and destination "
                "ownership before confirming compromise."
            )
        if kind == "dga":
            return (
                "Working root-cause hypothesis: generated domain names may provide C2 "
                "rendezvous points. Observed entropy exceeds the "
                f"{f.get('entropy_threshold', 3.4)} bits/char threshold. Entropy alone does "
                "not prove a DGA or failed resolution; compare DNS response codes, domain "
                "reputation and endpoint process lineage, including legitimate CDN names."
            )
        if kind == "nxdomain_storm":
            return (
                "Working root-cause hypothesis: repeated failed resolutions may represent "
                "DGA rendezvous attempts or domain fuzzing. Stale configuration and resolver "
                "failures are plausible alternatives. Confirm via query chronology, resolver "
                "health and the originating process; no malware identity is established."
            )
        if kind == "dns_tunneling":
            return (
                "Working root-cause hypothesis: long or TXT-heavy DNS labels may encode a "
                "tunnel. High entropy and uniqueness support this hypothesis when observed, "
                "but telemetry and legitimate security products can look similar. Inspect "
                "decoded query contents, authoritative-server ownership and process telemetry "
                "before asserting data theft or attacker control."
            )
        if kind == "port_scan":
            return (
                "Working root-cause hypothesis: automated probing enumerates the target's TCP/UDP surface. "
                "The burst rate and port diversity exceed normal connection churn, which "
                "suggests scanning. The exact tool and authorization status require host and "
                "asset-inventory evidence; packet metadata does not identify nmap or masscan."
            )
        if kind == "exfiltration":
            return (
                "Working root-cause hypothesis: asymmetric egress is consistent with a bulk "
                "upload or possible exfiltration. Backups, replication and legitimate transfers "
                "are alternatives. Validate destination ownership, business approvals and DLP "
                "or endpoint evidence; the capture alone does not reveal stolen content."
            )
        return (
            "The event crossed a configured heuristic threshold; inspect the triggering "
            "measurements and endpoint telemetry to establish a root cause."
        )

    def actions(self, event: SuspiciousEvent) -> List[str]:
        actions = list(mitre_for(event.event_type).get("mitigation", []))
        f = event.features
        if event.event_type == "beacon" and event.dst_ip:
            actions.insert(
                0,
                f"Block egress to {event.dst_ip}"
                + (f":{event.dst_port}" if event.dst_port else "")
                + " and reset all live sessions from the host.",
            )
        if event.event_type == "exfiltration" and event.dst_ip:
            actions.insert(0, f"Block {event.dst_ip} immediately and snapshot the host.")
        if event.event_type in ("dga", "nxdomain_storm", "dns_tunneling"):
            domain = f.get("base_domain") or f.get("top_family")
            if domain:
                actions.insert(
                    0, f"Review '{domain}' for a scoped DNS sinkhole/blocklist entry after validation."
                )
        if event.event_type == "port_scan" and event.dst_ip:
            actions.insert(
                0,
                f"Rate-limit/deny further probes from {event.src_ip} to {event.dst_ip} and "
                "validate which discovered services are reachable from that segment.",
            )
        actions.append(
            "Preserve packet captures and flow records for the affected host as forensic "
            "evidence."
        )
        return actions

    def chat(self, question: str, context: Iterable[str]) -> str:
        """Useful evidence-grounded answer when a caller has no custom fallback."""
        evidence = "\n\n".join(str(item) for item in context if item)[:10000]
        if not evidence:
            return ("Deterministic SOC copilot: run an analysis first. Provide the packet "
                    "capture or flow records, then inspect detections, correlated timelines, "
                    "ATT&CK mappings and containment recommendations.")
        return ("Deterministic SOC copilot (Meta API unavailable). Relevant analysis context:\n\n"
                + evidence + "\n\nCorrelations and root causes remain hypotheses until validated "
                "with endpoint process telemetry, asset ownership and approved activity. "
                "Containment commands are recommendations and have not been executed.")

    def explanation(self, event: SuspiciousEvent, confidence: float) -> str:
        info = mitre_for(event.event_type)
        stage = event.kill_chain_stage or kill_chain_stage_for(event.event_type)
        technique = event.mitre_technique or technique_id_for(event.event_type)
        return (
            f"The heuristic detector fired on {event.event_type.upper()} behaviour and the "
            f"deterministic expert engine scored the evidence at {confidence:.2f} confidence. "
            f"The behaviour sits in the '{stage}' kill-chain phase and maps to "
            f"{technique} ({info.get('name', 'unknown')}, {info.get('tactic', 'unknown')} "
            f"tactic). {event.description} Treat the event as "
            f"{event.severity.upper()} severity until the listed IOCs are triaged."
        )
