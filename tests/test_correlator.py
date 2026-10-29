"""Correlation requires an actor relationship and respects the event timeline."""
from netsentinel.engine.correlator import correlate_events
from netsentinel.models import SuspiciousEvent


def event(kind, at, src="10.0.0.5", dst="203.0.113.10", until=None):
    return SuspiciousEvent(kind, "high", kind, src, dst_ip=dst,
                           first_seen=at, last_seen=at if until is None else until)


def test_shared_host_orders_chain_and_retains_actual_timeline():
    events = [event("exfiltration", 300), event("port_scan", 100), event("beacon", 200)]
    report = correlate_events(events)
    assert len(report.campaigns) == 1
    campaign = report.campaigns[0]
    assert campaign.observed_stages == ["Reconnaissance", "Command and Control", "Actions on Objectives"]
    assert [row["timestamp"] for row in campaign.to_dict()["timeline"]] == [100, 200, 300]
    assert "No staging or data theft is proven" in campaign.kill_chain_narrative
    assert 0 <= campaign.risk_score <= 100


def test_temporal_gap_splits_but_overlapping_intervals_remain_related():
    a = event("beacon", 100, until=800)
    b = event("exfiltration", 700)
    c = event("port_scan", 2000)
    report = correlate_events([a, b, c], max_gap_seconds=300)
    assert sorted(len(c.events) for c in report.campaigns) == [1, 2]


def test_destination_actor_pivot_links_hosts_without_shared_resolver_join():
    pivot = correlate_events([event("port_scan", 100, dst="10.0.0.6"),
                              event("beacon", 150, src="10.0.0.6")])
    assert len(pivot.campaigns) == 1
    assert pivot.campaigns[0].scope == "linked"
    unrelated = correlate_events([event("dga", 100, dst="8.8.8.8"),
                                  event("exfiltration", 150, src="10.0.0.9", dst="8.8.8.8")])
    assert len(unrelated.campaigns) == 2
    assert "not proven" in unrelated.environment_campaign.kill_chain_narrative
    dga_campaign = next(c for c in unrelated.campaigns if "dga" in c.event_types)
    assert "possible command-and-control" in dga_campaign.kill_chain_narrative


def test_empty_unknown_timestamps_and_duplicate_evidence():
    assert correlate_events([]).to_dict()["campaign_count"] == 0
    a, b = event("beacon", 0), event("port_scan", 100)
    report = correlate_events([a, a, b], include_environment=False)
    assert len(report.campaigns) == 2
    assert sum(len(c.events) for c in report.campaigns) == 2
    assert report.environment_campaign is None


def test_stale_pivot_does_not_link_otherwise_active_campaigns():
    a = event("port_scan", 100, dst="10.0.0.6")
    continuation = [event("beacon", t, dst="203.0.113.99") for t in range(200, 1100, 100)]
    b = event("exfiltration", 1000, src="10.0.0.6", dst="198.51.100.10")
    report = correlate_events([a, *continuation, b], max_gap_seconds=150)
    assert len(report.campaigns) == 2
