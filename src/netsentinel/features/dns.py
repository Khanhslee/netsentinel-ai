"""DNS anomaly detection: DGA entropy, NXDOMAIN storms, and DNS tunneling."""
from __future__ import annotations

from collections import defaultdict
from typing import List

from ..config import DetectionConfig
from ..mitre import kill_chain_stage_for, mitre_for
from ..models import Flow, SuspiciousEvent
from .flows import entropy_profile, label_length_stats, shannon_entropy, throughput


def _dns_flows(flows: List[Flow]) -> List[Flow]:
    return [f for f in flows if f.dns_qname]


def _client_ip(f: Flow) -> str:
    """Attribute a DNS packet to the querying host (query: src, response: dst)."""
    if f.dns_is_query is not None:
        return f.src_ip if f.dns_is_query else f.dst_ip
    return f.dst_ip if f.src_port == 53 else f.src_ip


def _time_window(flows: List[Flow]) -> tuple:
    times = [f.start_time for f in flows if f.start_time]
    if not times:
        return 0.0, 0.0
    return min(times), max((f.end_time or f.start_time for f in flows), default=max(times))


def detect_dga(flows: List[Flow], cfg: DetectionConfig) -> List[SuspiciousEvent]:
    """Flag high-entropy, machine-generated domain names (DGA heuristic)."""
    mitre = mitre_for("dga")
    by_host: "defaultdict" = defaultdict(list)
    seen_by_host: "defaultdict" = defaultdict(set)
    evidence_flows: "defaultdict" = defaultdict(list)
    for f in _dns_flows(flows):
        domain = f.dns_qname.lower()
        # DGA randomness lives in the *registered* domain (SLD+TLD), not in
        # subdomains - subdomain randomness is the DNS-tunneling signal.
        registered = _second_level_domain(domain)
        ent = shannon_entropy(registered)
        if ent >= cfg.dga_entropy_threshold and len(registered) >= cfg.dga_min_length:
            host = _client_ip(f)
            evidence_flows[host].append(f)
            if registered not in seen_by_host[host]:
                seen_by_host[host].add(registered)
                by_host[host].append((registered, ent))

    events: List[SuspiciousEvent] = []
    for src_ip, hits in by_host.items():
        avg_ent = sum(e for _, e in hits) / len(hits)
        domains = sorted({d for d, _ in hits})
        profile = entropy_profile(domains)
        lengths = label_length_stats(domains)
        first_seen, last_seen = _time_window(evidence_flows[src_ip])
        window = max(last_seen - first_seen, 1e-6)
        events.append(
            SuspiciousEvent(
                event_type="dga",
                severity=_entropy_severity(avg_ent),
                description=(
                    f"{src_ip} queried {len(domains)} high-entropy, algorithmically-looking "
                    f"domains (avg entropy {avg_ent:.2f}), a DGA / C2 fallback indicator."
                ),
                src_ip=src_ip,
                iocs=domains[:25],
                features={
                    "domains": domains[:25],
                    "count": len(domains),
                    "avg_entropy": round(avg_ent, 3),
                    # --- forensic evidence (Phase 2) -------------------------
                    "shannon_entropy": round(avg_ent, 3),
                    "max_entropy": profile["max"],
                    "min_entropy": profile["min"],
                    "entropy_threshold": cfg.dga_entropy_threshold,
                    "entropy_profile": profile,
                    "avg_domain_length": round(
                        sum(len(d) for d in domains) / max(1, len(domains)), 2
                    ),
                    "max_label_len": lengths["max"],
                    "avg_label_len": lengths["avg"],
                    "queries_per_second": throughput(len(domains), window),
                    "domain_entropy": [
                        {"domain": d, "entropy": round(e, 3)} for d, e in hits[:10]
                    ],
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                },
                mitre_technique=mitre.get("sub_technique_id") or mitre.get("technique_id", ""),
                mitre_tactic=mitre.get("tactic", ""),
                kill_chain_stage=kill_chain_stage_for("dga"),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )
    return events


def detect_nxdomain_storm(flows: List[Flow], cfg: DetectionConfig) -> List[SuspiciousEvent]:
    """Flag hosts generating large bursts of failed (NXDOMAIN) lookups."""
    mitre = mitre_for("nxdomain_storm")
    by_host: "defaultdict" = defaultdict(set)
    by_sld: "defaultdict" = defaultdict(set)
    evidence_flows: "defaultdict" = defaultdict(list)
    response_counts: "defaultdict" = defaultdict(int)
    for flow in _dns_flows(flows):
        if flow.dns_is_query is False or (flow.dns_is_query is None and flow.src_port == 53):
            response_counts[_client_ip(flow)] += 1
    for f in _dns_flows(flows):
        if f.dns_rcode == 3:  # NXDOMAIN
            domain = f.dns_qname.lower()
            host = _client_ip(f)
            by_host[host].add(domain)
            evidence_flows[host].append(f)
            sld = _second_level_domain(domain)
            by_sld[(host, sld)].add(domain)

    events: List[SuspiciousEvent] = []
    for src_ip, names in by_host.items():
        if len(names) < cfg.nxdomain_storm_threshold:
            continue
        # Identify the most active domain family (SLD) for pivoting.
        families = [
            (sld, len(v)) for (host, sld), v in by_sld.items() if host == src_ip
        ]
        families.sort(key=lambda x: -x[1])
        top_sld = families[0][0] if families else ""
        first_seen, last_seen = _time_window(evidence_flows[src_ip])
        window = max(last_seen - first_seen, 1e-6)
        profile = entropy_profile(sorted(names))
        events.append(
            SuspiciousEvent(
                event_type="nxdomain_storm",
                severity="high",
                description=(
                    f"{src_ip} generated {len(names)} failed (NXDOMAIN) lookups across "
                    f"{len(families)} domain families, consistent with DGA probing."
                ),
                src_ip=src_ip,
                iocs=list(dict.fromkeys([top_sld] + sorted(names)[:25])),
                features={
                    "nxdomain_count": len(names),
                    "families": len(families),
                    "top_family": top_sld,
                    "sample_names": sorted(names)[:25],
                    # --- forensic evidence (Phase 2) -------------------------
                    "shannon_entropy": profile["avg"],
                    "avg_entropy": profile["avg"],
                    "max_entropy": profile["max"],
                    "entropy_profile": profile,
                    "nxdomain_ratio": round(len(evidence_flows[src_ip]) /
                                            max(1, response_counts[src_ip]), 3),
                    "nxdomain_per_second": throughput(len(names), window),
                    "family_breakdown": [
                        {"family": sld, "nxdomain_count": cnt}
                        for sld, cnt in families[:10]
                    ],
                    "threshold": cfg.nxdomain_storm_threshold,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                },
                mitre_technique=mitre.get("sub_technique_id") or mitre.get("technique_id", ""),
                mitre_tactic=mitre.get("tactic", ""),
                kill_chain_stage=kill_chain_stage_for("nxdomain_storm"),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )
    return events


def detect_dns_tunneling(flows: List[Flow], cfg: DetectionConfig) -> List[SuspiciousEvent]:
    """Flag repeated, long-label or TXT-heavy queries under one base domain.

    Tunneling encodes data in *subdomains*, so queries to ``<data>.tunnel.evil``
    must be grouped by their base (registered) domain rather than the full FQDN.
    """
    mitre = mitre_for("dns_tunneling")
    groups: "defaultdict" = defaultdict(list)
    order: List[tuple] = []
    for f in _dns_flows(flows):
        if f.dns_is_query:
            domain = f.dns_qname.lower()
            base = _second_level_domain(domain)
            key = (_client_ip(f), base)
            if key not in groups:
                order.append(key)
            groups[key].append((domain, f))

    events: List[SuspiciousEvent] = []
    for src_ip, base in order:
        members = groups[(src_ip, base)]
        distinct_names = {d for d, _ in members}
        max_label = max(
            (max((len(l) for l in d.split(".")), default=0) for d, _ in members),
            default=0,
        )
        is_txt = any(f.dns_qtype == "TXT" for _, f in members)
        if len(members) >= cfg.dns_tunnel_query_threshold and (
            max_label > cfg.dns_tunnel_max_label_len or is_txt
        ):
            flows_in_group = [f for _, f in members]
            first_seen, last_seen = _time_window(flows_in_group)
            window = max(last_seen - first_seen, 1e-6)
            subdomain_labels = [
                d.split(".")[0] for d in distinct_names if "." in d
            ]
            entropies = [shannon_entropy(label) for label in subdomain_labels]
            avg_ent = sum(entropies) / len(entropies) if entropies else 0.0
            lengths = label_length_stats(distinct_names)
            total_bytes = sum(f.src_bytes for f in flows_in_group)
            txt_count = sum(1 for f in flows_in_group if f.dns_qtype == "TXT")
            events.append(
                SuspiciousEvent(
                    event_type="dns_tunneling",
                    severity="high",
                    description=(
                        f"{src_ip} sent {len(members)} DNS queries under '{base}' "
                        f"(max label {max_label} chars, TXT={is_txt}), a DNS tunneling indicator."
                    ),
                    src_ip=src_ip,
                    iocs=[base],
                    features={
                        "base_domain": base,
                        "query_count": len(members),
                        "distinct_names": len(distinct_names),
                        "max_label_len": max_label,
                        "txt_queries": is_txt,
                        # --- forensic evidence (Phase 2) ---------------------
                        "shannon_entropy": round(avg_ent, 3),
                        "avg_entropy": round(avg_ent, 3),
                        "max_entropy": round(max(entropies), 3) if entropies else 0.0,
                        "entropy_threshold": cfg.dga_entropy_threshold,
                        "avg_label_len": lengths["avg"],
                        "label_len_threshold": cfg.dns_tunnel_max_label_len,
                        "query_rate_per_sec": throughput(len(members), window),
                        "unique_name_ratio": round(len(distinct_names) / max(1, len(members)), 3),
                        "txt_ratio": round(txt_count / max(1, len(members)), 3),
                        "query_payload_bytes": total_bytes,
                        "encoded_label_characters": sum(len(d.split(".")[0]) for d, _ in members),
                        "bytes_per_query": round(total_bytes / max(1, len(members)), 1),
                        "sample_queries": sorted(distinct_names)[:5],
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                    },
                    mitre_technique=mitre.get("sub_technique_id") or mitre.get("technique_id", ""),
                    mitre_tactic=mitre.get("tactic", ""),
                    kill_chain_stage=kill_chain_stage_for("dns_tunneling"),
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )
    return events


def _second_level_domain(fqdn: str) -> str:
    labels = [l for l in fqdn.rstrip(".").split(".") if l]
    if len(labels) <= 1:
        return labels[0] if labels else ""
    return ".".join(labels[-2:])


def _entropy_severity(ent: float) -> str:
    if ent >= 3.8:
        return "critical"
    if ent >= 3.4:
        return "high"
    return "medium"
