# Azure Sentinel RDP Honeypot & Threat Telemetry Visualization

![Failed RDP World Map](images/14-world-map.png)

## Overview

This project documents the design, deployment, enhancement, and operationalization of a Windows-based RDP honeypot in Microsoft Azure, integrated with Microsoft Sentinel and Log Analytics to collect, enrich, detect, and automate response to real-world attack telemetry.

The objective was to simulate an exposed RDP endpoint, observe hostile authentication behavior at scale, and evolve the lab into a realistic SOC-aligned detection engineering environment using KQL, Analytics Rules, Watchlists, Automation Rules, and SOAR Playbooks.

This repository demonstrates practical defensive security engineering aligned with real-world SOC and Blue Team workflows.

---

# Architecture Summary

## Cloud Platform
Microsoft Azure

## Core Components
- Windows Virtual Machine (RDP exposed)
- Network Security Group (NSG)
- Log Analytics Workspace
- Microsoft Sentinel (SIEM)
- Azure Monitor / Data Collection Rules (DCR)
- Microsoft Defender for Cloud
- Sentinel Watchlists
- Analytics Rules
- Automation Rules
- Logic App Playbook (SOAR)

## High-Level Data Flow

```text
Internet
↓
Azure VM (RDP Endpoint)
↓
Windows Security Events (Event ID 4625)
↓
Azure Monitor / Data Collection Rule
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

This lab intentionally exposed an RDP-enabled Windows VM to the internet in order to collect and analyze hostile authentication activity.

## Observed Behaviors

- Failed authentication attempts
- Username enumeration behavior
- Brute-force activity
- Geographic attack-source patterns

## Security Constraints

- No production assets exposed
- No credential reuse
- No lateral movement possible
- Dedicated isolated resource group
- Sensitive identifiers redacted where appropriate
- VM powered down when not actively collecting telemetry

---

# Step 1 — Deploy the Honeypot VM

A Windows virtual machine was created in Azure to act as the exposed RDP endpoint. This VM served as the telemetry source for failed logon activity and was isolated inside a dedicated lab resource group.

## What was configured

- Windows VM deployed in Azure
- Public IP assigned
- Dedicated lab resource group
- NIC attached to virtual network and subnet

### VM Overview
![VM Overview](images/01-vm-overview.png)

### Resource Group Overview
![Resource Group Overview](images/03-resource-group-overview.png)

---

# Step 2 — Configure Network Exposure

The honeypot VM was intentionally exposed to inbound internet traffic so it could collect RDP attack attempts.

## What was configured

- Public IP attached to VM
- Network interface verified
- Network Security Group attached
- Inbound rules validated

### Network Security Configuration
![Network Settings and NSG](images/02-network-settings-nsg.png)

---

# Step 3 — Create the Log Analytics Workspace

A Log Analytics Workspace was created to receive and store security telemetry from the honeypot.

### Log Analytics Workspace
![Log Analytics Workspace Overview](images/04-log-analytics-workspace.png)

---

# Step 4 — Configure Data Collection Rule (DCR)

A Data Collection Rule was created to define what Windows telemetry would be collected and where it would be sent.

### DCR Configuration
![DCR Overview](images/05-dcr-overview.png)

---

# Step 5 — Collect and Query Failed RDP Telemetry

Failed RDP authentication events were ingested into the custom table:

```kusto
FAILED_RDP_WITH_GEO_CL
```

## Source IP Aggregation Query

```kusto
FAILED_RDP_WITH_GEO_CL
| extend SourceIP = tostring(extract(@"sourcehost:([^,]+)", 1, RawData))
| summarize count() by SourceIP
| order by count_ desc
```

### Log Query Results
![Log Analytics Query Results](images/06-log-analytics-query-results.png)

### Log Query Chart
![Log Analytics Query Chart](images/07-log-analytics-chart.png)

---

# Step 6 — Enable Microsoft Sentinel

Microsoft Sentinel was connected to the workspace to enable SIEM functionality.

### Sentinel Overview
![Sentinel Overview](images/08-sentinel-overview.png)

---

# Step 7 — Build Detection Rules in Sentinel

Custom analytics rules were created to identify brute-force activity.

## Example Detection Query

```kusto
FAILED_RDP_WITH_GEO_CL
| extend SourceIP = tostring(extract(@"sourcehost:([^,]+)", 1, RawData))
| summarize FailedAttempts = count() by SourceIP, bin(TimeGenerated, 5m)
| where FailedAttempts >= 20
```

### Analytics Rules
![Analytics Rules](images/09-analytics-rules.png)

### Analytics Rule Detail
![Analytics Rule Detail](images/10-analytics-rule-details.png)

---

# Step 8 — Create Threat Intelligence Watchlists

Watchlists were created to simulate threat intelligence enrichment.

### Watchlist
![Threat Intel Watchlist](images/11-threatintel-watchlist.png)

### Watchlist Query
![Watchlist Query](images/12-watchlist-query.png)

---

# Step 9 — Threat Intelligence Correlation

```kusto
let TI = (_GetWatchlist('ThreatIntelIPs')
| project TI_IP = tostring(IPAddress));

FAILED_RDP_WITH_GEO_CL
| extend SourceIP = tostring(extract(@"sourcehost:([^,]+)", 1, RawData))
| join kind=inner TI on $left.SourceIP == $right.TI_IP
| summarize Attempts = count() by SourceIP
```

---

# Step 10 — Automation Rule for SOC Response

Sentinel automation rules were configured to trigger response actions.

### Automation Rule
![Automation Rule](images/13-automation-rule.png)

---

# Step 11 — Global Attack Visualization

A Sentinel workbook was created to visualize attack origins on a world map.

### World Attack Map
![Failed RDP World Map](images/14-world-map.png)

### Map Query
![World Map Query](images/15-world-map-query.png)

---

# Operational Lessons Learned

- Time range selection impacts data visibility
- DCR misconfiguration can block telemetry
- Log ingestion delays are normal
- Join failures often result from field mismatches
- Watchlists must be validated
- Automation rules require Sentinel permissions

---

# Skills Demonstrated

### Cloud Security
- Microsoft Azure
- Microsoft Sentinel
- Log Analytics
- Azure Monitor
- Data Collection Rules

### Detection Engineering
- KQL
- Regex extraction
- Detection rule design
- Threat intelligence correlation

### SOC Operations
- Incident automation
- Threat monitoring
- Security telemetry visualization
- Blue team workflows

---

# Author

**Dan Bruns**  
IT Systems & Cybersecurity Focus  
SIEM | Detection Engineering | Cloud Security
