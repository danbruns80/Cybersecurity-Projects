# Azure Sentinel RDP Honeypot & Threat Telemetry Visualization

## Overview

This project documents the **design, deployment, enhancement, and operationalization** of a Windows-based RDP honeypot in **Microsoft Azure**, integrated with **Microsoft Sentinel** and **Log Analytics** to collect, enrich, detect, and automate response to real-world attack telemetry.

The objective was to simulate an exposed RDP endpoint, observe hostile authentication behavior at scale, and evolve the lab into a realistic SOC-aligned detection engineering environment using **KQL, Analytics Rules, Watchlists, Automation Rules, and SOAR Playbooks** — while maintaining strict cloud security hygiene.

This repository demonstrates practical, defensive security engineering aligned with real-world SOC and Blue Team workflows.

---

# Architecture Summary

## Cloud Platform
- Microsoft Azure

## Core Components
- Windows Virtual Machine (RDP exposed)
- Network Security Group (NSG)
- Log Analytics Workspace
- Microsoft Sentinel (SIEM) 
- Azure Monitor / Data Collection Rules (DCR)
- Microsoft Defender for Cloud (baseline telemetry)
- Sentinel Watchlists (Threat Intelligence Simulation)
- Analytics Rules (Detection Engineering)
- Automation Rules
- Logic App Playbook (SOAR)

---

# 🔄 High-Level Data Flow

```

Internet
↓
Azure VM (RDP Endpoint)
↓
Windows Security Events (Event ID 4625)
↓
Azure Monitor / DCR
↓
Log Analytics Workspace
↓
Microsoft Sentinel
↓
KQL Parsing & Detection
↓
Incident Creation
↓
Automation Rule
↓
Logic App Playbook (SOAR)

```

---

# Threat Model & Scope

This lab intentionally exposed **only RDP (TCP/3389)** to collect:

- Failed authentication attempts
- Username enumeration behavior
- Geographic source patterns
- Brute-force characteristics

---

# Security Constraints

- No production assets exposed
- No credential reuse
- No lateral movement possible
- No inbound access to Azure management planes
- VM isolated in a dedicated resource group
- Sensitive identifiers redacted
- VM powered down when not actively collecting telemetry

---

# Telemetry Collected

## Primary Signal
- Windows Security Event ID **4625** (Failed Logon)

## Enrichment Fields
- Source IP
- Latitude / Longitude
- Country
- Timestamp
- Attempt count
- Parsed raw event data

## Custom Log Table
```

FAILED_RDP_WITH_GEO_CL

````

---

# KQL Parsing & Geo Enrichment

```kql
FAILED_RDP_WITH_GEO_CL
| extend
    Latitude  = todouble(extract(@"latitude:([-]?\d+(\.\d+)?)", 1, RawData)),
    Longitude = todouble(extract(@"longitude:([-]?\d+(\.\d+)?)", 1, RawData)),
    Country   = trim(" ", tostring(extract(@"country:([^,]+)", 1, RawData)))
| where isnotnull(Latitude) and isnotnull(Longitude)
| summarize FailedAttempts = count()
    by Country, Latitude, Longitude
````

### Demonstrates:

* Regex-based field extraction
* Type casting and validation
* Log normalization
* Aggregation for visualization
* SIEM-ready query design

---

# Detection Engineering

## Brute Force Threshold Detection Rule

A Sentinel Analytics Rule was created to detect excessive failed authentication attempts:

```kql
FAILED_RDP_WITH_GEO_CL
| extend SourceIP = tostring(extract(@"sourcehost:([^,]+)", 1, RawData))
| summarize AttemptCount = count() by SourceIP
| where AttemptCount > 15
| order by AttemptCount desc
```

This converts raw telemetry into actionable incident creation logic.

---

# Threat Intelligence Correlation

A custom Threat Intelligence watchlist was created to simulate correlation against known malicious IPs.

### Validate Watchlist

```kql
_GetWatchlist('ThreatIntelIPs')
| take 5
```

### Correlation Query

```kql
let TI = (_GetWatchlist('ThreatIntelIPs')
| project TI_IP = tostring(IPAddress));

FAILED_RDP_WITH_GEO_CL
| extend SourceIP = tostring(extract(@"sourcehost:([^,]+)", 1, RawData))
| join kind=inner TI on $left.SourceIP == $right.TI_IP
| summarize Attempts = count() by SourceIP
```

### Demonstrates:

* Watchlist ingestion
* Join operations
* Context enrichment
* Detection amplification

---

# Automation & SOAR

## Sentinel Automation Rule

Trigger:

* When incident is created

Condition:

* Title contains `RDP Brute Force`

Action:

* Run Playbook → `PBK_AddIP_To_KnownBadIPs`

---

## Logic App Playbook (SOAR)

The playbook performs:

* Trigger on Sentinel incident
* Extract malicious Source IP
* Append IP to Watchlist (`KnownBadIPs`)
* Add incident comment
* Prepare for optional firewall blocking

This simulates real-world SOC automation and containment workflows.

---

# Incident Response Playbook

A formal IR playbook was developed for this lab including:

* Detection criteria
* Triage workflow
* Investigation procedures
* Containment strategy
* Escalation thresholds
* Documentation requirements

This elevates the project from telemetry analysis to structured security operations.

---

# Visualization

## Failed RDP World Map Workbook

The Sentinel Workbook renders:

* Global attacker distribution
* Bubble size by attempt volume
* Adjustable time ranges (24h → 90d)
* Regional clustering trends

Provides:

* Immediate attacker distribution insight
* Geographic clustering analysis
* Volume-based trend analysis

---

# Operational Lessons Learned

1. Time range configuration directly impacts perceived data visibility.
2. DCR misconfiguration can silently block telemetry ingestion.
3. Log ingestion delay is normal.
4. Join failures are commonly caused by column naming mismatches.
5. Watchlists must be validated before correlation.
6. Automation rules require explicit Sentinel permissions.
7. High attack volume does not imply successful compromise.
8. Lab isolation is critical for safe telemetry collection.

---

# Why This Matters

This lab mirrors real SOC workflows:

* Telemetry ingestion engineering
* Data normalization
* Detection rule creation
* Threat intelligence enrichment
* Incident automation
* SOAR integration
* Incident response documentation

This demonstrates **defensive security engineering**, not exploitation.

---

# Potential Future Enhancements

* MITRE ATT&CK technique mapping
* ASN enrichment
* External IP reputation API integration
* Azure Firewall auto-block integration
* Executive-level reporting dashboard

---

# Disclaimer

This project is for educational and defensive security research purposes only.
No unauthorized access was attempted or permitted.

---

# Author

**Dan Bruns**
IT Systems & Cybersecurity
Focus: SIEM, Detection Engineering, Cloud Security
