# NetSentinel AI Incident Report

Generated: 2026-10-29T18:40:20.010764+00:00

## Executive assessment

6 behavioural alerts across 98 network flows; 1 critical and 4 high. Findings are hypotheses supported by network evidence; validate with endpoint and business context.

**Reasoning provenance:** offline-deterministic

**Source:** data/demo.pcap

## Capture metrics

| Metric | Value |
| --- | ---: |
| Packets | 122 |
| Flows | 98 |
| Total bytes | 1501919 |
| Affected source hosts | 5 |
| Alerts | 6 |
| Critical / High | 1 / 4 |

## Attack kill-chain correlation

| Kill-chain stage | Observed alerts |
| --- | ---: |
| Reconnaissance | 1 |
| Weaponization | 0 |
| Delivery | 0 |
| Exploitation | 0 |
| Installation | 0 |
| Command and Control | 4 |
| Actions on Objectives | 1 |

### 10.0.0.5: Command and Control

**Scope:** host · **Risk:** 90/100

Attack campaign CP-HOST-0f4e3c14 (host scope) observed 1 events across 1 kill-chain stage(s), risk score 90/100. Phase 1 - Command and Control: 10.0.0.5 beaconed to 203.0.113.10:8080 10 times with delta-t jitter 0.0% (MITRE T1071.001). Assessment: the traffic is consistent with a possible command-and-control channel. Validate endpoint process evidence before confirming compromise.

### 10.0.0.6: Command and Control

**Scope:** host · **Risk:** 70/100

Attack campaign CP-HOST-50d862fe (host scope) observed 2 events across 1 kill-chain stage(s), risk score 70/100. Phase 1 - Command and Control: 10.0.0.6 queried 14 algorithmic-looking domains averaging 3.687 bits/char entropy (MITRE T1568.002); 10.0.0.6 generated 15 NXDOMAIN responses across 15 domain families (MITRE T1568.002). Assessment: the traffic is consistent with a possible command-and-control channel. Validate endpoint process evidence before confirming compromise.

### 10.0.0.7: Reconnaissance

**Scope:** host · **Risk:** 70/100

Attack campaign CP-HOST-10c17a8f (host scope) observed 1 events across 1 kill-chain stage(s), risk score 70/100. Phase 1 - Reconnaissance: 10.0.0.7 probed 40 ports on 10.0.0.50 at 10.26 ports/s (MITRE T1046). Assessment: activity is consistent with pre-compromise reconnaissance; harden exposed services and keep the source under watch.

### 10.0.0.8: Command and Control

**Scope:** host · **Risk:** 70/100

Attack campaign CP-HOST-36f11810 (host scope) observed 1 events across 1 kill-chain stage(s), risk score 70/100. Phase 1 - Command and Control: 10.0.0.8 sent possible tunnel traffic under 'tunnel.evil' with 12 queries, entropy 4.237 bits/char (MITRE T1071.004). Assessment: the traffic is consistent with a possible command-and-control channel. Validate endpoint process evidence before confirming compromise.

### 10.0.0.9: Actions on Objectives

**Scope:** host · **Risk:** 58/100

Attack campaign CP-HOST-68775df7 (host scope) observed 1 events across 1 kill-chain stage(s), risk score 58/100. Phase 1 - Actions on Objectives: 10.0.0.9 uploaded 1,500,000 bytes to 198.51.100.5:443 with a 1500000.0:1 upload/download ratio (MITRE T1041). Assessment: the asymmetric transfer is a possible exfiltration signal. Validate the business purpose and endpoint telemetry, preserve evidence, and prioritize containment if unauthorized. No staging or data theft is proven.

### Capture-wide context (unconfirmed relationship)

Capture-wide temporal overview; the following hosts are not proven to belong to one campaign. Stage ordering is a framework view, not proof of chronological progression. Phase 1 - Reconnaissance: 10.0.0.7 probed 40 ports on 10.0.0.50 at 10.26 ports/s (MITRE T1046). Phase 2 - Command and Control: 10.0.0.5 beaconed to 203.0.113.10:8080 10 times with delta-t jitter 0.0% (MITRE T1071.001); 10.0.0.6 queried 14 algorithmic-looking domains averaging 3.687 bits/char entropy (MITRE T1568.002); 10.0.0.6 generated 15 NXDOMAIN responses across 15 domain families (MITRE T1568.002). Phase 3 - Actions on Objectives: 10.0.0.9 uploaded 1,500,000 bytes to 198.51.100.5:443 with a 1500000.0:1 upload/download ratio (MITRE T1041). Assessment: the asymmetric transfer is a possible exfiltration signal. Validate the business purpose and endpoint telemetry, preserve evidence, and prioritize containment if unauthorized. No staging or data theft is proven.


## Forensic evidence & structured assessments

### BEACON — 10.0.0.5

**Severity:** critical · **ATT&CK:** T1071.001 · **Stage:** Command and Control

10.0.0.5 maintained 10 TCP connections to 203.0.113.10:8080 at a mean interval of 60.0s (jitter 0.000), consistent with C2 beaconing.

Host 10.0.0.5 established 10 sessions to 203.0.113.10:8080 with a mean inter-arrival of 60.0s and a coefficient of variation of 0.0 (0.0% jitter). Periodic timing is consistent with automated C2 polling, but may also reflect monitoring, software updates or scheduled business activity. Mapped to MITRE ATT&amp;CK T1071.001 (Application Layer Protocol: Web Protocols) in the Command and Control tactic.

**Root cause / interpretation:** Working root-cause hypothesis: timer-driven software produces periodic egress (coefficient of variation 0.0). A C2 implant is one possibility; legitimate health checks can produce the same cadence. Correlate endpoint process/socket telemetry and destination ownership before confirming compromise.

**Confidence:** 0.97 · **Source:** offline-deterministic

| Observed feature | Value |
| --- | --- |
| Proto | tcp |
| Connections | 10 |
| Mean interval (seconds) | 60.0 |
| Interval standard deviation (seconds) | 0.0 |
| Jitter ratio | 0.0 |
| Coefficient of variation | 0.0 |
| Mean delta t sec | 60.0 |
| Std delta t sec | 0.0 |
| Median delta t sec | 60.0 |
| Min delta t sec | 60.0 |
| Max delta t sec | 60.0 |
| Inter-arrival jitter (%) | 0.0 |
| Periodicity score | 1.0 |
| Observation window sec | 540.0 |
| First seen | 100.0 |
| Last seen | 640.0 |
| Destination | 203.0.113.10:8080 |

**Recommended actions**

- Block egress to 203.0.113.10:8080 and reset all live sessions from the host.
- Block the destination IP/domain and port at the perimeter firewall/proxy.
- Isolate the source host and inspect for additional persistence or implants.
- Hunt for outbound connections on the same cadence across the fleet.
- Enable egress filtering and DNS/Domain fronting inspection.
- Preserve packet captures and flow records for the affected host as forensic evidence.
### PORT\_SCAN — 10.0.0.7

**Severity:** high · **ATT&CK:** T1046 · **Stage:** Reconnaissance

10.0.0.7 probed 40 ports on 10.0.0.50 (SYN) within 3.9s, indicating network reconnaissance.

Host 10.0.0.7 probed 40 distinct ports on 10.0.0.50 within 3.9s (10.26 ports/s, 10.26 packets/s), hitting 40 well-known ports. This is consistent with active service discovery; validate approved vulnerability scans. Mapped to MITRE ATT&amp;CK T1046 (Network Service Discovery) in the Discovery tactic.

**Root cause / interpretation:** Working root-cause hypothesis: automated probing enumerates the target's TCP/UDP surface. The burst rate and port diversity exceed normal connection churn, which suggests scanning. The exact tool and authorization status require host and asset-inventory evidence; packet metadata does not identify nmap or masscan.

**Confidence:** 0.8 · **Source:** offline-deterministic

| Observed feature | Value |
| --- | --- |
| Kind | SYN |
| Distinct destination ports | 40 |
| Ports | \[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40\] |
| Time span | 3.9 |
| Packets sent | 40 |
| Packets / second | 10.26 |
| Distinct ports / second | 10.26 |
| Unique src ports | 40 |
| Port range | \{"max": 40, "min": 1\} |
| Well known ports hit | 40 |
| Scan window limit sec | 60.0 |
| Threshold ports | 20 |
| First seen | 200.0 |
| Last seen | 203.9 |

**Recommended actions**

- Rate-limit/deny further probes from 10.0.0.7 to 10.0.0.50 and validate which discovered services are reachable from that segment.
- Block/quarantine the scanning host.
- Review exposed services on the targeted host for further attacks.
- Tune IDS thresholds to alert on horizontal/vertical scans.
- Preserve packet captures and flow records for the affected host as forensic evidence.
### NXDOMAIN\_STORM — 10.0.0.6

**Severity:** high · **ATT&CK:** T1568.002 · **Stage:** Command and Control

10.0.0.6 generated 15 failed (NXDOMAIN) lookups across 15 domain families, consistent with DGA probing.

Host 10.0.0.6 produced 15 distinct NXDOMAIN responses across 15 domain families (top family 'tkgnkuhmpxnhtqg.net', mean entropy 3.657). Bursts of failed resolutions are one of candidate DGA / domain-fuzzing signals; resolver misconfiguration and unavailable services are alternative causes. Mapped to MITRE ATT&amp;CK T1568.002 (Dynamic Resolution: Domain Generation Algorithms) in the Command and Control tactic.

**Root cause / interpretation:** Working root-cause hypothesis: repeated failed resolutions may represent DGA rendezvous attempts or domain fuzzing. Stale configuration and resolver failures are plausible alternatives. Confirm via query chronology, resolver health and the originating process; no malware identity is established.

**Confidence:** 0.75 · **Source:** offline-deterministic

| Observed feature | Value |
| --- | --- |
| Nxdomain count | 15 |
| Families | 15 |
| Top family | tkgnkuhmpxnhtqg.net |
| Sample names | \["amammhvambytjkdj.info", "cjevwgfarzqu.org", "gjrvqnvugbejwjcg.net", "gnjjzmqlwfaqzji.net", "hsmcaohzbnjuv.org", "hxuxqrwqebvtad.com", "jjfbdvnkamkox.info", "oubdtmjfmxkpt.info", "pdxmppxmoesoo.info", "pgerimpiysseyyk.net", "qtngthblmwkx.org", "tkgnkuhmpxnhtqg.net", "vmgarmtjuhusknrf.org", "wwulweumpeldoxq.info", "ykbvcpxfckgobo.net"\] |
| Shannon entropy (bits/character) | 3.657 |
| Mean label entropy (bits/character) | 3.657 |
| Max entropy | 3.948 |
| Entropy profile | \{"avg": 3.657, "count": 15, "max": 3.948, "min": 3.239\} |
| Nxdomain ratio | 1.0 |
| Nxdomain per second | 1.07 |
| Family breakdown | \[\{"family": "tkgnkuhmpxnhtqg.net", "nxdomain\_count": 1\}, \{"family": "oubdtmjfmxkpt.info", "nxdomain\_count": 1\}, \{"family": "cjevwgfarzqu.org", "nxdomain\_count": 1\}, \{"family": "pdxmppxmoesoo.info", "nxdomain\_count": 1\}, \{"family": "hsmcaohzbnjuv.org", "nxdomain\_count": 1\}, \{"family": "gjrvqnvugbejwjcg.net", "nxdomain\_count": 1\}, \{"family": "vmgarmtjuhusknrf.org", "nxdomain\_count": 1\}, \{"family": "ykbvcpxfckgobo.net", "nxdomain\_count": 1\}, \{"family": "jjfbdvnkamkox.info", "nxdomain\_count": 1\}, \{"family": "pgerimpiysseyyk.net", "nxdomain\_count": 1\}\] |
| Threshold | 10 |
| First seen | 300.05 |
| Last seen | 314.05 |

**Recommended actions**

- Review 'tkgnkuhmpxnhtqg.net' for a scoped DNS sinkhole/blocklist entry after validation.
- Add the parent/sinkhole domain to the DNS blocklist.
- Correlate NXDOMAIN volume with endpoint process telemetry.
- Alert analysts on sustained NXDOMAIN storms from a single host.
- Preserve packet captures and flow records for the affected host as forensic evidence.
### DNS\_TUNNELING — 10.0.0.8

**Severity:** high · **ATT&CK:** T1071.004 · **Stage:** Command and Control

10.0.0.8 sent 12 DNS queries under 'tunnel.evil' (max label 30 chars, TXT=True), a DNS tunneling indicator.

Host 10.0.0.8 sent 12 queries under 'tunnel.evil' with a longest label of 30 chars (threshold 20), subdomain entropy 4.237 bits/char and a unique-name ratio of 1.0. The pattern is consistent with data encoded into DNS labels (TXT=True). Mapped to MITRE ATT&amp;CK T1071.004 (Application Layer Protocol: DNS) in the Command and Control tactic.

**Root cause / interpretation:** Working root-cause hypothesis: long or TXT-heavy DNS labels may encode a tunnel. High entropy and uniqueness support this hypothesis when observed, but telemetry and legitimate security products can look similar. Inspect decoded query contents, authoritative-server ownership and process telemetry before asserting data theft or attacker control.

**Confidence:** 0.95 · **Source:** offline-deterministic

| Observed feature | Value |
| --- | --- |
| Base domain | tunnel.evil |
| Query count | 12 |
| Distinct names | 12 |
| Max label len | 30 |
| Txt queries | True |
| Shannon entropy (bits/character) | 4.237 |
| Mean label entropy (bits/character) | 4.237 |
| Max entropy | 4.507 |
| Entropy threshold | 3.4 |
| Avg label len | 30.0 |
| Label len threshold | 20 |
| Query rate per sec | 1.09 |
| Unique name ratio | 1.0 |
| Txt ratio | 1.0 |
| Query payload bytes | 720 |
| Encoded label characters | 360 |
| Bytes per query | 60.0 |
| Sample queries | \["0y9dom5igqpki7p5tb94874frhocn9.tunnel.evil", "1t2tala753lc58drc11ertj5pht0hl.tunnel.evil", "30t9nt3w5uzbikcidkwnnhj7xvg0fn.tunnel.evil", "3j2d54i3qk2iagl58kxo9t7e8g8jdp.tunnel.evil", "3kx7eedtjvzhwjr64dpja1wj0tpac5.tunnel.evil"\] |
| First seen | 400.0 |
| Last seen | 411.0 |

**Recommended actions**

- Review 'tunnel.evil' for a scoped DNS sinkhole/blocklist entry after validation.
- Enforce DNS filtering and rate-limit queries per host.
- Block the tunnel domain and pivot to sinkholing.
- Inspect originating process for DNS tunneling tooling.
- Flag long query names / high TXT query volume via IDS.
- Preserve packet captures and flow records for the affected host as forensic evidence.
### DGA — 10.0.0.6

**Severity:** high · **ATT&CK:** T1568.002 · **Stage:** Command and Control

10.0.0.6 queried 14 high-entropy, algorithmically-looking domains (avg entropy 3.69), a DGA / C2 fallback indicator.

Host 10.0.0.6 queried 14 high-entropy domains (mean Shannon entropy 3.687 bits/char, max 3.948, threshold 3.4). DGA-based fallback domains let malware re-establish C2 even when individual domains are taken down. Mapped to MITRE ATT&amp;CK T1568.002 (Dynamic Resolution: Domain Generation Algorithms) in the Command and Control tactic.

**Root cause / interpretation:** Working root-cause hypothesis: generated domain names may provide C2 rendezvous points. Observed entropy exceeds the 3.4 bits/char threshold. Entropy alone does not prove a DGA or failed resolution; compare DNS response codes, domain reputation and endpoint process lineage, including legitimate CDN names.

**Confidence:** 0.78 · **Source:** offline-deterministic

| Observed feature | Value |
| --- | --- |
| Domains | \["amammhvambytjkdj.info", "cjevwgfarzqu.org", "gjrvqnvugbejwjcg.net", "gnjjzmqlwfaqzji.net", "hsmcaohzbnjuv.org", "hxuxqrwqebvtad.com", "jjfbdvnkamkox.info", "oubdtmjfmxkpt.info", "pgerimpiysseyyk.net", "qtngthblmwkx.org", "tkgnkuhmpxnhtqg.net", "vmgarmtjuhusknrf.org", "wwulweumpeldoxq.info", "ykbvcpxfckgobo.net"\] |
| Count | 14 |
| Mean label entropy (bits/character) | 3.687 |
| Shannon entropy (bits/character) | 3.687 |
| Max entropy | 3.948 |
| Min entropy | 3.432 |
| Entropy threshold | 3.4 |
| Entropy profile | \{"avg": 3.687, "count": 14, "max": 3.948, "min": 3.432\} |
| Avg domain length | 18.5 |
| Max label len | 16 |
| Avg label len | 14.21 |
| Queries per second | 1.0 |
| Domain entropy | \[\{"domain": "tkgnkuhmpxnhtqg.net", "entropy": 3.432\}, \{"domain": "oubdtmjfmxkpt.info", "entropy": 3.725\}, \{"domain": "cjevwgfarzqu.org", "entropy": 3.75\}, \{"domain": "hsmcaohzbnjuv.org", "entropy": 3.852\}, \{"domain": "gjrvqnvugbejwjcg.net", "entropy": 3.546\}, \{"domain": "vmgarmtjuhusknrf.org", "entropy": 3.784\}, \{"domain": "ykbvcpxfckgobo.net", "entropy": 3.725\}, \{"domain": "jjfbdvnkamkox.info", "entropy": 3.614\}, \{"domain": "pgerimpiysseyyk.net", "entropy": 3.432\}, \{"domain": "amammhvambytjkdj.info", "entropy": 3.69\}\] |
| First seen | 300.0 |
| Last seen | 314.05 |

**Recommended actions**

- Sinkhole the affected domains via DNS and block via proxy category.
- Deploy a DGA detection rule/model on the recursive resolver.
- Identify and remediate the implant on the source host.
- Monitor NXDOMAIN response volume for the same hosts.
- Preserve packet captures and flow records for the affected host as forensic evidence.
### EXFILTRATION — 10.0.0.9

**Severity:** medium · **ATT&CK:** T1041 · **Stage:** Actions on Objectives

10.0.0.9 transferred 1,500,000 bytes to 198.51.100.5:443 while receiving only 0 bytes back (ratio 1500000:1), a potential data exfiltration channel.

Host 10.0.0.9 uploaded 1,500,000 bytes to 198.51.100.5:443 while receiving only 0 bytes (ratio 1500000.0:1, 6250000.0 B/s). Asymmetric egress flows are the classic exfiltration signature. Mapped to MITRE ATT&amp;CK T1041 (Exfiltration Over C2 Channel) in the Exfiltration tactic.

**Root cause / interpretation:** Working root-cause hypothesis: asymmetric egress is consistent with a bulk upload or possible exfiltration. Backups, replication and legitimate transfers are alternatives. Validate destination ownership, business approvals and DLP or endpoint evidence; the capture alone does not reveal stolen content.

**Confidence:** 0.9 · **Source:** offline-deterministic

| Observed feature | Value |
| --- | --- |
| Proto | tcp |
| Dst port | 443 |
| Src bytes | 1500000 |
| Dst bytes | 0 |
| Upload / download byte ratio | 1500000.0 |
| Upload download ratio | 1500000.0 |
| Ratio denominator bytes | 1 |
| Download observed | False |
| Ratio note | upload / max(1, download); no reply bytes means a guarded ratio, not measured infinity |
| Download upload ratio | 0.0 |
| Outbound bytes | 1500000 |
| Inbound bytes | 0 |
| Total bytes | 1500000 |
| Src packets | 25 |
| Dst packets | 0 |
| Duration sec | 0.24 |
| Throughput bps | 6250000.0 |
| Avg packet size | 60000.0 |
| Threshold bytes | 1000000 |
| Threshold ratio | 10.0 |
| First seen | 500.0 |
| Last seen | 500.24 |

**Recommended actions**

- Block 198.51.100.5 immediately and snapshot the host.
- Block the destination immediately and inspect the host.
- Verify whether the transfer matches a known business process.
- Enable DLP and egress volume alerting.
- Preserve packet captures and flow records for the affected host as forensic evidence.

## Observed indicators

Indicators are hunt pivots, including affected internal hosts; an indicator alone does not establish maliciousness.

| Type | Value |
| --- | --- |
| Domain / observed string | 198.51.100.5:443 |
| Domain / observed string | 203.0.113.10:8080 |
| Domain / observed string | amammhvambytjkdj.info |
| Domain / observed string | cjevwgfarzqu.org |
| Domain / observed string | gjrvqnvugbejwjcg.net |
| Domain / observed string | gnjjzmqlwfaqzji.net |
| Domain / observed string | hsmcaohzbnjuv.org |
| Domain / observed string | hxuxqrwqebvtad.com |
| Domain / observed string | jjfbdvnkamkox.info |
| Domain / observed string | oubdtmjfmxkpt.info |
| Domain / observed string | pdxmppxmoesoo.info |
| Domain / observed string | pgerimpiysseyyk.net |
| Domain / observed string | qtngthblmwkx.org |
| Domain / observed string | tkgnkuhmpxnhtqg.net |
| Domain / observed string | tunnel.evil |
| Domain / observed string | vmgarmtjuhusknrf.org |
| Domain / observed string | wwulweumpeldoxq.info |
| Domain / observed string | ykbvcpxfckgobo.net |
| IP address | 10.0.0.5 |
| IP address | 10.0.0.50 |
| IP address | 10.0.0.6 |
| IP address | 10.0.0.7 |
| IP address | 10.0.0.8 |
| IP address | 10.0.0.9 |
| IP address | 198.51.100.5 |
| IP address | 203.0.113.10 |

## Suricata rules

Review and tune these IOC/behaviour watch rules before deployment.

```text
alert tcp 10.0.0.5 any -> 203.0.113.10 8080 (msg:"NetSentinel BEACON T1071.001 observed IOC/behaviour watch"; flow:established,to_server; threshold:type both, track by_src, count 3, seconds 600; classtype:trojan-activity; metadata: mitre_technique_id T1071.001, event_type beacon, severity critical; sid:9000001; rev:1;)
alert tcp 10.0.0.7 any -> 10.0.0.50 any (msg:"NetSentinel PORT_SCAN T1046 observed IOC/behaviour watch"; flow:stateless; flags:S; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-recon; metadata: mitre_technique_id T1046, event_type port_scan, severity high; sid:9000002; rev:1;)
alert dns 10.0.0.6 any -> any 53 (msg:"NetSentinel NXDOMAIN_STORM T1568.002 observed IOC/behaviour watch"; flow:to_server; dns.query; pcre:"/(?:^|\.)(?:tkgnkuhmpxnhtqg\.net|amammhvambytjkdj\.info|cjevwgfarzqu\.org|gjrvqnvugbejwjcg\.net|gnjjzmqlwfaqzji\.net|hsmcaohzbnjuv\.org|hxuxqrwqebvtad\.com|jjfbdvnkamkox\.info|oubdtmjfmxkpt\.info|pdxmppxmoesoo\.info|pgerimpiysseyyk\.net|qtngthblmwkx\.org|vmgarmtjuhusknrf\.org|wwulweumpeldoxq\.info|ykbvcpxfckgobo\.net)$/i"; classtype:attempted-recon; metadata: mitre_technique_id T1568.002, event_type nxdomain_storm, severity high; sid:9000003; rev:1;)
alert dns 10.0.0.8 any -> any 53 (msg:"NetSentinel DNS_TUNNELING T1071.004 observed IOC/behaviour watch"; flow:to_server; dns.query; content:"tunnel.evil"; nocase; endswith; pcre:"/(?:^|\.)tunnel\.evil$/i"; classtype:trojan-activity; metadata: mitre_technique_id T1071.004, event_type dns_tunneling, severity high; sid:9000004; rev:1;)
alert dns 10.0.0.6 any -> any 53 (msg:"NetSentinel DGA T1568.002 observed IOC/behaviour watch"; flow:to_server; dns.query; pcre:"/(?:^|\.)(?:amammhvambytjkdj\.info|cjevwgfarzqu\.org|gjrvqnvugbejwjcg\.net|gnjjzmqlwfaqzji\.net|hsmcaohzbnjuv\.org|hxuxqrwqebvtad\.com|jjfbdvnkamkox\.info|oubdtmjfmxkpt\.info|pgerimpiysseyyk\.net|qtngthblmwkx\.org|tkgnkuhmpxnhtqg\.net|vmgarmtjuhusknrf\.org|wwulweumpeldoxq\.info|ykbvcpxfckgobo\.net)$/i"; classtype:trojan-activity; metadata: mitre_technique_id T1568.002, event_type dga, severity high; sid:9000005; rev:1;)
alert tcp 10.0.0.9 any -> 198.51.100.5 443 (msg:"NetSentinel EXFILTRATION T1041 observed IOC/behaviour watch"; flow:established,to_server; dsize:>1200; threshold:type both, track by_src, count 50, seconds 60; classtype:policy-violation; metadata: mitre_technique_id T1041, event_type exfiltration, severity medium; sid:9000006; rev:1;)
```

## YARA rules

Observed-string hunts for files and memory; corroborate matches with endpoint telemetry.

```yara
rule NetSentinel_beacon_d238fcd97016
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed beacon IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1071.001"
        mitre_technique = "T1071.001"
        date = "2026-10-29"
        severity = "critical"
        source_event = "5952c688a058"
    strings:
        $ioc_0 = "203.0.113.10" ascii nocase
        $ioc_1 = "203.0.113.10:8080" ascii nocase
    condition:
        any of them
}

rule NetSentinel_port_scan_f79ce4e459ec
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed port_scan IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1046"
        mitre_technique = "T1046"
        date = "2026-10-29"
        severity = "high"
        source_event = "1e684ac2848c"
    strings:
        $ioc_0 = "10.0.0.7" ascii nocase
        $ioc_1 = "10.0.0.50" ascii nocase
    condition:
        any of them
}

rule NetSentinel_nxdomain_storm_4873b1e0b3f8
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed nxdomain_storm IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1568.002"
        mitre_technique = "T1568.002"
        date = "2026-10-29"
        severity = "high"
        source_event = "a2ce06db6784"
    strings:
        $ioc_0 = "tkgnkuhmpxnhtqg.net" ascii nocase
        $ioc_1 = "amammhvambytjkdj.info" ascii nocase
        $ioc_2 = "cjevwgfarzqu.org" ascii nocase
        $ioc_3 = "gjrvqnvugbejwjcg.net" ascii nocase
        $ioc_4 = "gnjjzmqlwfaqzji.net" ascii nocase
        $ioc_5 = "hsmcaohzbnjuv.org" ascii nocase
        $ioc_6 = "hxuxqrwqebvtad.com" ascii nocase
        $ioc_7 = "jjfbdvnkamkox.info" ascii nocase
        $ioc_8 = "oubdtmjfmxkpt.info" ascii nocase
        $ioc_9 = "pdxmppxmoesoo.info" ascii nocase
        $ioc_10 = "pgerimpiysseyyk.net" ascii nocase
        $ioc_11 = "qtngthblmwkx.org" ascii nocase
        $ioc_12 = "vmgarmtjuhusknrf.org" ascii nocase
        $ioc_13 = "wwulweumpeldoxq.info" ascii nocase
        $ioc_14 = "ykbvcpxfckgobo.net" ascii nocase
    condition:
        any of them
}

rule NetSentinel_dns_tunneling_4d7b358d06fc
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed dns_tunneling IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1071.004"
        mitre_technique = "T1071.004"
        date = "2026-10-29"
        severity = "high"
        source_event = "abb0ed60aa74"
    strings:
        $ioc_0 = "tunnel.evil" ascii nocase
    condition:
        any of them
}

rule NetSentinel_dga_b21f027a106f
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed dga IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1568.002"
        mitre_technique = "T1568.002"
        date = "2026-10-29"
        severity = "high"
        source_event = "165a7ec67b03"
    strings:
        $ioc_0 = "amammhvambytjkdj.info" ascii nocase
        $ioc_1 = "cjevwgfarzqu.org" ascii nocase
        $ioc_2 = "gjrvqnvugbejwjcg.net" ascii nocase
        $ioc_3 = "gnjjzmqlwfaqzji.net" ascii nocase
        $ioc_4 = "hsmcaohzbnjuv.org" ascii nocase
        $ioc_5 = "hxuxqrwqebvtad.com" ascii nocase
        $ioc_6 = "jjfbdvnkamkox.info" ascii nocase
        $ioc_7 = "oubdtmjfmxkpt.info" ascii nocase
        $ioc_8 = "pgerimpiysseyyk.net" ascii nocase
        $ioc_9 = "qtngthblmwkx.org" ascii nocase
        $ioc_10 = "tkgnkuhmpxnhtqg.net" ascii nocase
        $ioc_11 = "vmgarmtjuhusknrf.org" ascii nocase
        $ioc_12 = "wwulweumpeldoxq.info" ascii nocase
        $ioc_13 = "ykbvcpxfckgobo.net" ascii nocase
    condition:
        any of them
}

rule NetSentinel_exfiltration_7b98db61c746
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed exfiltration IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1041"
        mitre_technique = "T1041"
        date = "2026-10-29"
        severity = "medium"
        source_event = "41c8483929e7"
    strings:
        $ioc_0 = "198.51.100.5" ascii nocase
        $ioc_1 = "198.51.100.5:443" ascii nocase
    condition:
        any of them
}
```

## Containment playbook

Commands are provided for analyst review and are never executed by NetSentinel.

```text
# Review ownership and preserve console/management access before containment.
# Linux gateway: quarantine affected hosts in the forwarding path.
sudo iptables -I FORWARD -s 10.0.0.5 -j DROP
sudo iptables -I FORWARD -d 10.0.0.5 -j DROP
sudo iptables -I FORWARD -s 10.0.0.7 -j DROP
sudo iptables -I FORWARD -d 10.0.0.7 -j DROP
sudo iptables -I FORWARD -s 10.0.0.6 -j DROP
sudo iptables -I FORWARD -d 10.0.0.6 -j DROP
sudo iptables -I FORWARD -s 10.0.0.8 -j DROP
sudo iptables -I FORWARD -d 10.0.0.8 -j DROP
sudo iptables -I FORWARD -s 10.0.0.9 -j DROP
sudo iptables -I FORWARD -d 10.0.0.9 -j DROP

# Windows: run on each affected endpoint with an elevated console.
# Blocks inbound/outbound traffic until these rules are removed.
netsh advfirewall firewall add rule name="NetSentinel-Isolate-Out" dir=out action=block remoteip=any
netsh advfirewall firewall add rule name="NetSentinel-Isolate-In" dir=in action=block remoteip=any

# Rollback after incident review:
netsh advfirewall firewall delete rule name="NetSentinel-Isolate-Out"
netsh advfirewall firewall delete rule name="NetSentinel-Isolate-In"
sudo iptables -D FORWARD -s 10.0.0.5 -j DROP
sudo iptables -D FORWARD -d 10.0.0.5 -j DROP
sudo iptables -D FORWARD -s 10.0.0.7 -j DROP
sudo iptables -D FORWARD -d 10.0.0.7 -j DROP
sudo iptables -D FORWARD -s 10.0.0.6 -j DROP
sudo iptables -D FORWARD -d 10.0.0.6 -j DROP
sudo iptables -D FORWARD -s 10.0.0.8 -j DROP
sudo iptables -D FORWARD -d 10.0.0.8 -j DROP
sudo iptables -D FORWARD -s 10.0.0.9 -j DROP
sudo iptables -D FORWARD -d 10.0.0.9 -j DROP
```

## Evidence limitations

Network heuristics do not identify the originating process, prove compromise, or demonstrate that bytes contain sensitive data. Campaign correlation expresses shared observable context; investigate attribution separately.
