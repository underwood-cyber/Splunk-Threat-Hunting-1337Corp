# Technical Investigation: Active Intrusion & Exfiltration Analysis (Splunk SIEM)

## Executive Summary
Conducted an end-to-end incident response investigation using Splunk SIEM to analyze multi-source log telemetry from `1337Corp`. Identified an active network intrusion featuring automated credential abuse, lateral movement via Python scripting, Command & Control (C2) beaconing, and staged data exfiltration over non-standard egress channels.

---

## Technical Investigation & Attack Lifecycle

### 1. Account Compromise & Automated Lateral Movement
* **Compromised Identity:** Account `PCannon` exhibited rapid, high-volume authentication attempts across multiple endpoints and servers within sub-second timeframes—a pattern confirming automated exploitation.
* **Execution Vector:** Correlated `CorpSysLogs` telemetry to identify synchronized execution of unauthorized Python-based client scripts across compromised hosts.

### 2. Firewall Anomaly & Protocol Abuse Analysis
Analysis of outbound network traffic at `3/4/26 10:52:53 AM` revealed multi-vector protocol abuse across non-standard ports:
* **Port 3128 (HTTP Proxy):** Uniform connection bursts (approx. 20 events per host) operating as automated Command & Control (C2) heartbeat beaconing.
* **Port 161 (SNMP):** Atypical workstation-originated traffic utilized for remote network enumeration and internal polling.
* **Port 20 (FTP):** Authorized channel abuse leveraged for data staging and exfiltration.

### 3. Indicators of Compromise (IoCs)
* **Anomalous Routing:** Outbound traffic explicitly targeted Multicast (`227.x.x.x`, `235.x.x.x`) and Reserved (`245.x.x.x`) IP space—a primary indicator of post-exploitation framework automation.
* **Threat Intel Cross-Referencing:** Source IP addresses validated against **AbuseIPDB** and **VirusTotal** confirmed known malicious reputation score history.

---

## Key Splunk Search Queries (SPL)

```spl
(source="*1337CorpADServer.csv" OR source="*1337CorpSysLogs.csv" OR source="*1337CorpFirewall.csv")
| stats count by _time, src_ip, dest_ip, dest_port, user, action
| sort - count
