# Phishing Email Analysis & Threat Intelligence Investigation

## Overview
This project simulates a SOC Level 1 phishing email investigation involving email header analysis, IOC extraction, threat intelligence enrichment, MITRE ATT&CK mapping, and Splunk-based phishing detection.

---

## Objectives
- Analyze phishing email headers
- Identify spoofed infrastructure
- Extract Indicators of Compromise (IOCs)
- Enrich indicators using threat intelligence platforms
- Detect phishing activity using Splunk SPL queries
- Map attacker behavior to MITRE ATT&CK framework
- Create SOC-style incident documentation

---

## Tools Used
- Splunk Enterprise
- VirusTotal
- AbuseIPDB
- Cisco Talos Intelligence
- Google Message Header Analyzer
- Microsoft Excel

---

## Threat Intelligence Evidence

Threat intelligence enrichment was performed using external intelligence platforms to investigate suspicious phishing infrastructure.

Platforms used:
- VirusTotal
- AbuseIPDB
- Cisco Talos Intelligence

### Key Findings
- VirusTotal analysis identified multiple vendor detections associated with the suspicious sender IP address.
- Threat intelligence analysis supported phishing-related infrastructure suspicion.
- Suspicious Office365-themed spoofed domain behavior was investigated.

### Evidence Screenshots
- virustotal-ip-analysis.png
- abuseipdb-analysis.png
- talos-domain-analysis.png

## Investigation Workflow

1. Phishing email collection
2. Email header analysis
3. IOC extraction
4. Threat intelligence enrichment
5. Splunk log ingestion
6. SPL-based phishing detection
7. MITRE ATT&CK mapping
8. Incident reporting

---

## Key Findings

- SPF authentication failure detected
- DMARC policy failure identified
- Missing DKIM signature observed
- Suspicious Office365-themed spoofed domain identified
- Potential credential harvesting attempt detected
- Repeated suspicious sender IP activity identified in Splunk

---

## MITRE ATT&CK Mapping

| Attack Activity | MITRE Technique | Description |
|---|---|---|
| Phishing Email Delivery | T1566 | Phishing email used for initial access |
| Spearphishing Link | T1566.002 | Malicious verification link used |
| Credential Harvesting | T1056 | Attempt to capture user credentials |

---

## Splunk Detection Queries

### Detect phishing-themed email subjects

```spl
index=main
| search subject="*Urgent*" OR subject="*Password*" OR subject="*Security*"
| table timestamp sender recipient subject sender_ip
```

---
