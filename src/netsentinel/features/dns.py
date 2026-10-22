"""DNS anomaly detection: DGA entropy, NXDOMAIN storms, and DNS tunneling."""
from __future__ import annotations

from collections import defaultdict
from typing import List

from ..config import DetectionConfig
from ..mitre import mitre_for
from ..models import Flow, SuspiciousEvent
from .flows import shannon_entropy


def _dns_flows(flows: List[Flow]) -> List[Flow]:
    return [f for f in flows if f.dns_qname]


def _client_ip(f: Flow) -> str:
    """Attribute a DNS packet to the querying host (query: src, response: dst)."""
    return f.src_ip if f.dns_is_query else f.dst_ip


def detect_dga(flows: List[Flow], cfg: DetectionConfig) -> List[SuspiciousEvent]:
    """Flag high-entropy, machine-generated domain names (DGA heuristic)."""
    mitre = mitre_for("dga")
    by_host: "defaultdict" = defaultdict(list)
    seen_by_host: "defaultdict" = defaultdict(set)
    for f in _dns_flows(flows):
        domain = f.dns_qname.lower()
        # DGA randomness lives in the *registered* domain (SLD+TLD), not in
        # subdomains - subdomain randomness is the DNS-tunneling signal.
        registered = _second_level_domain(domain)
        ent = shannon_entropy(registered)
        if ent >= cfg.dga_entropy_threshold and len(registered) >= cfg.dga_min_length:
            host = _client_ip(f)
            if registered not in seen_by_host[host]:
                seen_by_host[host].add(registered)
                by_host[host].append((registered, ent))

    events: List[SuspiciousEvent] = []
    for src_ip, hits in by_host.items():
        avg_ent = sum(e for _, e in hits) / len(hits)
        domains = sorted({d for d, _ in hits})
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
                },
                mitre_technique=mitre.get("sub_technique_id") or mitre.get("technique_id", ""),
            )
        )
    return events


def detect_nxdomain_storm(flows: List[Flow], cfg: DetectionConfig) -> List[SuspiciousEvent]:
    """Flag hosts generating large bursts of failed (NXDOMAIN) lookups."""
    mitre = mitre_for("nxdomain_storm")
    by_host: "defaultdict" = defaultdict(set)
    by_sld: "defaultdict" = defaultdict(set)
    for f in _dns_flows(flows):
        if f.dns_rcode == 3:  # NXDOMAIN
            domain = f.dns_qname.lower()
            by_host[_client_ip(f)].add(domain)
            sld = _second_level_domain(domain)
            by_sld[(_client_ip(f), sld)].add(domain)

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
        events.append(
            SuspiciousEvent(
                event_type="nxdomain_storm",
                severity="high",
                description=(
                    f"{src_ip} generated {len(names)} failed (NXDOMAIN) lookups across "
                    f"{len(families)} domain families, consistent with DGA probing."
                ),
                src_ip=src_ip,
                iocs=[top_sld] + sorted(names)[:25],
                features={
                    "nxdomain_count": len(names),
                    "families": len(families),
                    "top_family": top_sld,
                    "sample_names": sorted(names)[:25],
                },
                mitre_technique=mitre.get("sub_technique_id") or mitre.get("technique_id", ""),
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
                    },
                    mitre_technique=mitre.get("sub_technique_id") or mitre.get("technique_id", ""),
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
