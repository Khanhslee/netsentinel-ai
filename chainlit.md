# 🛡️ NetSentinel AI

**From network anomalies to evidence-driven SOC investigations.**

NetSentinel combines mathematical network heuristics with **Meta Muse Spark
(`muse-spark-1.3`)** for batch triage and **Meta Muse Wonder (`muse-wonder-1.0`)**
for deep analysis and SOC conversations, through the Meta Model API at
`https://api.meta.ai/v1`.

Analyze PCAP, PCAPNG, CSV, JSON, or Zeek connection logs to investigate six
behavioral signals: C2 beacons, port scans, NXDOMAIN storms, DNS tunneling,
domain generation algorithms, and asymmetric outbound transfers. Review
measured evidence, MITRE ATT&CK mappings, and correlations across endpoints and
time. Correlations are investigation hypotheses; telemetry alone does not
establish a single campaign or prove compromise.

## Start with one click

Use the action buttons in the chat:

1. **🔍 Run Full Demo PCAP Analysis** — analyze the bundled `data/demo.pcap`.
2. **🔗 View Attack Kill-Chain Correlation** — inspect linked findings and the
   separate temporal overview.
3. **🛡️ Generate Suricata & YARA Rules** — download compact detection rules.
4. **📊 Export HTML & Markdown SOC Report** — download a standalone dark-mode
   dashboard, incident report, and ATT&CK Navigator layer.

You can also upload a capture or paste a local file path. The welcome message
shows the configured model names and credential status. Successful API calls
are distinguished from offline reasoning in the analysis result. Without a key,
or when a model request fails, the deterministic expert engine supplies
evidence-based assessments and response artifacts.

## Investigate the evidence

| Command | Result |
| --- | --- |
| `summary` | Capture counts, severity breakdown, and reasoning source |
| `events` | Numbered findings |
| `beacons` | Beacon findings |
| `explain 1` | Evidence and ATT&CK reasoning for finding 1 |
| `evidence` | Forensic metrics from the detectors |
| `iocs` | Observed indicators |
| `kill-chain` | Correlated attack hypotheses |
| `rules` | Generated Suricata and YARA rules |
| `playbook 1` | Investigation and containment guidance for finding 1 |
| `help` | Available commands |

After a successful model-backed analysis, ask free-form questions such as
"Which evidence supports the beacon finding?" or "What telemetry would help
validate this hypothesis?" The copilot grounds answers in the current analysis.

Containment commands are provided for analyst review; NetSentinel does not
execute firewall changes.

