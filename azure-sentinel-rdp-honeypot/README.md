# Azure Sentinel RDP Honeypot & Threat Telemetry Visualization

## Overview

This project documents the design, deployment, and analysis of a Windows-based RDP honeypot in **Microsoft Azure**, integrated with **Microsoft Sentinel** and **Log Analytics** to collect, enrich, and visualize real-world attack telemetry.

The objective was to simulate an exposed RDP endpoint, observe hostile authentication behavior at scale, and build **SIEM-ready detections and geo-visualizations** using **KQL**, while maintaining strict cloud security hygiene.

This repository demonstrates practical, defensive security engineering aligned with SOC and Blue Team workflows.

---

## Architecture Summary

### Cloud Platform
- Microsoft Azure

### Core Components
- Windows Virtual Machine (RDP exposed)
- Network Security Group (NSG)
- Log Analytics Workspace
- Microsoft Sentinel (SIEM)
- Azure Monitor / Data Collection Rules (DCR)
- Microsoft Defender for Cloud (baseline telemetry)

---

## High-Level Data Flow

- Azure VM (RDP Endpoint)
- to
- Windows Security Events
- to
- Azure Monitor / DCR
- to
- Log Analytics Workspace
- to
- Microsoft Sentinel
- to
- KQL Parsing & Visualization
  
---

## Threat Model & Scope

This lab intentionally exposed **only RDP (TCP/3389)** to collect:

- Failed authentication attempts
- Username enumeration behavior
- Geographic source patterns
- Brute-force characteristics

### Important Constraints
- No production assets exposed
- No credential reuse
- No lateral movement possible
- No inbound access to Azure management planes
- VM isolated in a dedicated resource group
- Sensitive identifiers redacted

---

## Telemetry Collected

### Primary Signal
- Failed RDP authentication attempts (Windows Security Events)

### Enrichment Fields
- Source IP
- Latitude / Longitude
- Country
- Timestamp
- Attempt count
- Parsed raw event data

### Custom Log Table

FAILED_RDP_WITH_GEO_CL

---

## KQL Parsing & Aggregation

The following query extracts geographic metadata from raw log payloads and aggregates failed login attempts by country and coordinates.

```kql
FAILED_RDP_WITH_GEO_CL
| extend
    Latitude  = todouble(extract(@"latitude:([-]?\d+(\.\d+)?)", 1, RawData)),
    Longitude = todouble(extract(@"longitude:([-]?\d+(\.\d+)?)", 1, RawData)),
    Country   = trim(" ", tostring(extract(@"country:([^,]+)", 1, RawData)))
| where isnotnull(Latitude) and isnotnull(Longitude)
| summarize FailedAttempts = count()
    by Country, Latitude, Longitude

---

## STEP 2 — Click **“Commit changes”** (Top Right)

When the popup appears:

- **Commit message:**  
- Leave everything else default
- Click **Commit changes**

---

## STEP 3 — Verify It Worked

1. Click **Cybersecurity-Projects**
2. Click **azure-sentinel-rdp-honeypot**
3. You should now see a **fully rendered professional README**

If you see formatted headers, code blocks, and sections — you’re done.

Congrats You’ve created:

A real SOC-style project

With SIEM architecture

KQL parsing

Threat telemetry

Cloud security hygiene

Disclaimer

This project is for educational and defensive security research purposes only.
No unauthorized access was attempted or permitted.

Author

Dan
IT Systems & Cybersecurity
Focus: SIEM, Detection Engineering, Cloud Security
